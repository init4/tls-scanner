"""
Core scanning primitives.

Design notes
-------------
* Everything here deliberately connects with certificate verification
  DISABLED (ssl.CERT_NONE / check_hostname=False). This tool is meant to
  probe internal services, bare IPs and boxes with self-signed or expired
  certs -- the kind of thing a normal TLS client would refuse to talk to.
  We still *inspect and report* on the certificate; we just don't let a
  broken chain stop the scan.
* Every probe has its own short socket timeout and every probe is
  independent, so callers can run them concurrently in a thread pool
  (see app/main.py) to keep wall-clock scan time low.
"""
from __future__ import annotations

import os
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .models import CertificateInfo, CipherResult, LegacyCheckResult, ProtocolResult, PqcGroupResult

# ---------------------------------------------------------------------------
# Protocol probing
# ---------------------------------------------------------------------------

PROTOCOL_VERSIONS = [
    ("SSLv3", None),  # handled specially -- see probe_protocol(), uses the raw-socket path below
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


def _bare_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Allow legacy renegotiation/weak settings to not get in our own way --
    # we WANT to be able to reach weak servers in order to report on them.
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def probe_protocol(host: str, port: int, name: str, version, sni: Optional[str],
                    timeout: float) -> ProtocolResult:
    if version is None:
        if name == "SSLv3":
            # Modern OpenSSL (1.1.0+) removed the SSLv3 protocol outright, so
            # there's no ssl.TLSVersion.SSLv3 and no way to ask the Python
            # ssl module to negotiate it -- test it directly over a raw
            # socket instead (see probe_sslv3_raw below).
            return probe_sslv3_raw(host, port, timeout)
        return ProtocolResult(
            name=name, supported=None, tested=False,
            note="Not probed: no longer negotiable via the local OpenSSL/Python ssl stack",
        )
    try:
        ctx = _bare_context()
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                tls.do_handshake()
                return ProtocolResult(name=name, supported=True, tested=True)
    except ssl.SSLError as e:
        return ProtocolResult(name=name, supported=False, tested=True, note=str(e))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return ProtocolResult(name=name, supported=False, tested=True,
                               note=f"connection issue: {e}")


# ---------------------------------------------------------------------------
# Raw-socket legacy protocol / extension probing
#
# Modern OpenSSL (1.1.0+) removed the SSLv3 protocol outright -- there's no
# ssl.TLSVersion.SSLv3 and no build flag brings it back, so the Python ssl
# module can never be used to test it. A handful of other checks
# (secure renegotiation, TLS compression/CRIME, the TLS_FALLBACK_SCSV
# downgrade guard) live at the handshake-extension level, which ssl also
# doesn't expose. For all of these we hand-build a ClientHello and speak the
# record layer directly over a raw socket -- independent of whatever
# protocol/extension support the local TLS stack happens to have. This is
# the same technique dedicated scanners like testssl.sh use for the same
# reason.
# ---------------------------------------------------------------------------

_TLS_RECORD_ALERT = 21
_TLS_RECORD_HANDSHAKE = 22
_HANDSHAKE_CLIENT_HELLO = 1
_HANDSHAKE_SERVER_HELLO = 2

_ALERT_DESCRIPTIONS = {
    40: "handshake_failure", 70: "protocol_version", 86: "inappropriate_fallback",
}

# Cipher suite codepoints are shared across protocol versions -- offering a
# spread of old and new ones just maximizes the chance *some* suite matches
# whatever the server is willing to negotiate, so a probe failure reflects
# the thing being tested rather than a cipher-list mismatch.
_SSLV3_CIPHER_SUITES = [0x0004, 0x0005, 0x000A, 0x002F, 0x0035]  # RC4-MD5/SHA, 3DES, AES128/256-SHA
_MODERN_CIPHER_SUITES = [0xC02F, 0xC030, 0xC013, 0xC014, 0x002F, 0x0035, 0x000A, 0x0005]
_FALLBACK_SCSV = 0x5600
_RENEGOTIATION_INFO_EXT = 0xFF01
_SERVER_NAME_EXT = 0x0000


def _encode_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _encode_sni_extension(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    entry = b"\x00" + struct.pack(">H", len(name)) + name  # name_type 0 == host_name
    name_list = struct.pack(">H", len(entry)) + entry
    return _encode_extension(_SERVER_NAME_EXT, name_list)


def _build_client_hello(version: tuple[int, int], cipher_suites: list[int],
                         compression_methods: list[int], extensions: bytes = b"") -> bytes:
    body = struct.pack(">BB", *version)
    body += os.urandom(32)
    body += b"\x00"  # session_id length: no session to resume
    body += struct.pack(">H", len(cipher_suites) * 2)
    for cs in cipher_suites:
        body += struct.pack(">H", cs)
    body += struct.pack(">B", len(compression_methods)) + bytes(compression_methods)
    if extensions:
        body += struct.pack(">H", len(extensions)) + extensions
    handshake = struct.pack(">B", _HANDSHAKE_CLIENT_HELLO) + len(body).to_bytes(3, "big") + body
    record = struct.pack(">BBB", _TLS_RECORD_HANDSHAKE, *version) + struct.pack(">H", len(handshake)) + handshake
    return record


def _modern_client_hello(version: tuple[int, int], cipher_suites: list[int],
                          compression_methods: list[int], sni: Optional[str],
                          extra_extensions: bytes = b"") -> bytes:
    extensions = extra_extensions
    if sni:
        try:
            extensions += _encode_sni_extension(sni)
        except UnicodeEncodeError:
            pass  # non-ASCII SNI: skip rather than fail the whole probe
    return _build_client_hello(version, cipher_suites, compression_methods, extensions)


def _recv_exact(sock: socket.socket, n: int, deadline: float) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None  # connection closed
        buf += chunk
    return buf


def _recv_record(sock: socket.socket, deadline: float) -> Optional[tuple[int, bytes]]:
    header = _recv_exact(sock, 5, deadline)
    if header is None:
        return None
    content_type = header[0]
    length = struct.unpack(">H", header[3:5])[0]
    payload = _recv_exact(sock, length, deadline)
    if payload is None:
        return None
    return content_type, payload


def _parse_server_hello(body: bytes) -> Optional[dict]:
    try:
        pos = 2 + 32  # version (unused: client_version already pins the negotiated floor) + random
        session_id_len = body[pos]
        pos += 1 + session_id_len
        cipher_suite = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        compression_method = body[pos]
        pos += 1
        extensions: dict[int, bytes] = {}
        if pos < len(body):
            ext_total_len = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2
            end = pos + ext_total_len
            while pos < end:
                ext_type = struct.unpack(">H", body[pos:pos + 2])[0]
                ext_len = struct.unpack(">H", body[pos + 2:pos + 4])[0]
                pos += 4
                extensions[ext_type] = body[pos:pos + ext_len]
                pos += ext_len
        return {"cipher_suite": cipher_suite, "compression_method": compression_method,
                "extensions": extensions}
    except (IndexError, struct.error):
        return None


def _send_client_hello_and_read(host: str, port: int, timeout: float,
                                 client_hello: bytes) -> tuple[str, object]:
    """Sends a hand-built ClientHello and classifies the response.

    Returns (kind, data) where kind is one of:
      "server_hello" -- data is the dict from _parse_server_hello()
      "alert"        -- data is (level, description) as raw byte values
      "closed"       -- connection closed with no handshake data at all
      "timeout"      -- no response within the timeout
      "error"        -- data is a short string describing what went wrong
    """
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(client_hello)
            handshake_buf = b""
            expected_len = None
            while True:
                rec = _recv_record(sock, deadline)
                if rec is None:
                    if handshake_buf:
                        return "error", "connection closed mid-handshake-message"
                    return "closed", None
                content_type, payload = rec
                if content_type == _TLS_RECORD_ALERT:
                    if len(payload) >= 2:
                        return "alert", (payload[0], payload[1])
                    return "error", "malformed alert record"
                if content_type != _TLS_RECORD_HANDSHAKE:
                    return "error", f"unexpected record type {content_type}"
                handshake_buf += payload
                if expected_len is None and len(handshake_buf) >= 4:
                    expected_len = 4 + int.from_bytes(handshake_buf[1:4], "big")
                if expected_len is not None and len(handshake_buf) >= expected_len:
                    break
            msg_type = handshake_buf[0]
            if msg_type != _HANDSHAKE_SERVER_HELLO:
                return "error", f"unexpected handshake message type {msg_type}"
            parsed = _parse_server_hello(handshake_buf[4:expected_len])
            if parsed is None:
                return "error", "could not parse ServerHello"
            return "server_hello", parsed
    except socket.timeout:
        return "timeout", None
    except (ConnectionRefusedError, OSError) as e:
        return "error", f"connection issue: {e}"


def probe_sslv3_raw(host: str, port: int, timeout: float) -> ProtocolResult:
    # SSLv3 predates both SNI and the extensions mechanism entirely, so a
    # real SSLv3 client sends neither -- we don't either. And since (3,0) is
    # already the lowest version number that exists, any ServerHello we get
    # back in response can only mean the server actually negotiated SSLv3
    # (there's nothing lower it could have fallen back to).
    hello = _build_client_hello((3, 0), _SSLV3_CIPHER_SUITES, [0])
    kind, data = _send_client_hello_and_read(host, port, timeout, hello)
    if kind == "server_hello":
        return ProtocolResult(
            name="SSLv3", supported=True, tested=True,
            note="Server completed an SSLv3 handshake (hand-rolled ClientHello over a raw "
                 "socket -- the local OpenSSL/Python ssl stack no longer supports SSLv3 at all).")
    if kind == "alert":
        desc = _ALERT_DESCRIPTIONS.get(data[1], f"alert {data[1]}")
        return ProtocolResult(name="SSLv3", supported=False, tested=True,
                               note=f"Server rejected SSLv3 ({desc}).")
    if kind == "closed":
        return ProtocolResult(name="SSLv3", supported=False, tested=True,
                               note="Connection closed without responding to the SSLv3 ClientHello.")
    if kind == "timeout":
        return ProtocolResult(name="SSLv3", supported=False, tested=True, note="Timed out.")
    return ProtocolResult(name="SSLv3", supported=None, tested=True, note=f"Could not determine: {data}")


def _legacy_untestable(name: str, kind: str, data: object) -> LegacyCheckResult:
    reason = {"closed": "connection closed without responding",
              "timeout": "timed out"}.get(kind, str(data))
    return LegacyCheckResult(
        name=name, supported=None,
        note=f"Could not determine ({reason}) -- most likely this probe's ClientHello doesn't "
             f"match anything the server is willing to negotiate (e.g. a TLS-1.3-only server).")


def probe_secure_renegotiation(host: str, port: int, sni: Optional[str],
                                timeout: float) -> LegacyCheckResult:
    hello = _modern_client_hello((3, 3), _MODERN_CIPHER_SUITES, [0], sni,
                                  extra_extensions=_encode_extension(_RENEGOTIATION_INFO_EXT, b"\x00"))
    kind, data = _send_client_hello_and_read(host, port, timeout, hello)
    if kind == "server_hello":
        supported = _RENEGOTIATION_INFO_EXT in data["extensions"]
        note = ("Server echoed the renegotiation_info extension (RFC 5746)." if supported else
                "Server did not echo renegotiation_info -- if it allows renegotiation at all, "
                "it's exposed to the plaintext-injection renegotiation attack (CVE-2009-3555).")
        return LegacyCheckResult(name="secure_renegotiation", supported=supported, note=note)
    return _legacy_untestable("secure_renegotiation", kind, data)


def probe_compression(host: str, port: int, sni: Optional[str], timeout: float) -> LegacyCheckResult:
    hello = _modern_client_hello((3, 3), _MODERN_CIPHER_SUITES, [1, 0], sni)  # offer DEFLATE, then null
    kind, data = _send_client_hello_and_read(host, port, timeout, hello)
    if kind == "server_hello":
        supported = data["compression_method"] != 0
        note = ("Server selected non-null TLS compression -- exposed to CRIME-style plaintext "
                "recovery." if supported else "Server did not select TLS compression.")
        return LegacyCheckResult(name="tls_compression", supported=supported, note=note)
    return _legacy_untestable("tls_compression", kind, data)


def probe_fallback_scsv(host: str, port: int, sni: Optional[str], timeout: float) -> LegacyCheckResult:
    # Deliberately claims only TLS 1.0 (the whole point of this check is to
    # simulate a client that has already fallen back after earlier failures)
    # while also offering the TLS_FALLBACK_SCSV signal cipher.
    hello = _modern_client_hello((3, 1), [_FALLBACK_SCSV] + _MODERN_CIPHER_SUITES[:4], [0], sni)
    kind, data = _send_client_hello_and_read(host, port, timeout, hello)
    if kind == "alert":
        if data[1] == 86:  # inappropriate_fallback
            return LegacyCheckResult(name="fallback_scsv", supported=True,
                                      note="Server rejects version fallback via TLS_FALLBACK_SCSV (RFC 7507).")
        return _legacy_untestable("fallback_scsv", kind, data)
    if kind == "server_hello":
        return LegacyCheckResult(
            name="fallback_scsv", supported=False,
            note="Server accepted a TLS 1.0 ClientHello carrying TLS_FALLBACK_SCSV instead of "
                 "rejecting it. Only a real downgrade risk if the server also negotiates a newer "
                 "version elsewhere (see protocol results) and some client actually falls back.")
    return _legacy_untestable("fallback_scsv", kind, data)


# ---------------------------------------------------------------------------
# Cipher suite enumeration
# ---------------------------------------------------------------------------

# A representative spread of TLS 1.2-and-below cipher suites: modern AEAD
# suites through to intentionally weak/legacy ones, so the scorer has
# something meaningful to grade against.
TLS12_CANDIDATE_CIPHERS = [
    # (openssl_name, strength, forward_secrecy, aead)
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "strong", True, True),
    ("ECDHE-RSA-AES256-GCM-SHA384", "strong", True, True),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "strong", True, True),
    ("ECDHE-RSA-CHACHA20-POLY1305", "strong", True, True),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "strong", True, True),
    ("ECDHE-RSA-AES128-GCM-SHA256", "strong", True, True),
    ("DHE-RSA-AES256-GCM-SHA384", "acceptable", True, True),
    ("DHE-RSA-AES128-GCM-SHA256", "acceptable", True, True),
    ("ECDHE-RSA-AES256-SHA384", "acceptable", True, False),
    ("ECDHE-RSA-AES128-SHA256", "acceptable", True, False),
    ("AES256-GCM-SHA384", "weak", False, True),
    ("AES128-GCM-SHA256", "weak", False, True),
    ("AES256-SHA256", "weak", False, False),
    ("AES128-SHA", "weak", False, False),
    ("DES-CBC3-SHA", "insecure", False, False),
    ("RC4-SHA", "insecure", False, False),
    ("RC4-MD5", "insecure", False, False),
    ("EXP-RC4-MD5", "insecure", False, False),
    ("NULL-SHA", "insecure", False, False),
    ("ADH-AES256-SHA", "insecure", True, False),
]

TLS13_CANDIDATE_SUITES = [
    ("TLS_AES_256_GCM_SHA384", "strong"),
    ("TLS_CHACHA20_POLY1305_SHA256", "strong"),
    ("TLS_AES_128_GCM_SHA256", "strong"),
    ("TLS_AES_128_CCM_SHA256", "acceptable"),
    ("TLS_AES_128_CCM_8_SHA256", "weak"),
]


def probe_tls12_cipher(host: str, port: int, sni: Optional[str], timeout: float,
                        cipher_name: str, strength: str, pfs: bool,
                        aead: bool) -> Optional[CipherResult]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(f"{cipher_name}:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                tls.do_handshake()
                return CipherResult(name=cipher_name, protocol="TLSv1.2", supported=True,
                                     strength=strength, forward_secrecy=pfs, aead=aead)
    except ssl.SSLError:
        return CipherResult(name=cipher_name, protocol="TLSv1.2", supported=False,
                             strength=strength, forward_secrecy=pfs, aead=aead)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None  # transport-level failure, not a useful signal either way


def probe_tls13_suite(host: str, port: int, sni: Optional[str], timeout: float,
                       suite_name: str, strength: str) -> Optional[CipherResult]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        if not hasattr(ctx, "set_ciphersuites"):
            # Some Python/OpenSSL builds don't expose per-suite pinning for
            # TLS 1.3. Degrade gracefully rather than crashing the scan --
            # the protocol-level TLSv1.3 probe still reports support/no-support.
            return None
        ctx.set_ciphersuites(suite_name)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                tls.do_handshake()
                return CipherResult(name=suite_name, protocol="TLSv1.3", supported=True,
                                     strength=strength, forward_secrecy=True, aead=True)
    except ssl.SSLError:
        return CipherResult(name=suite_name, protocol="TLSv1.3", supported=False,
                             strength=strength, forward_secrecy=True, aead=True)
    except (socket.timeout, ConnectionRefusedError, OSError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Post-quantum / hybrid key-exchange group probing
#
# We shell out to the system `openssl` CLI for this because the Python `ssl`
# module has no portable API for pinning a specific TLS 1.3 key-share group.
# Support for these group names depends entirely on the OpenSSL version
# baked into the container image (see backend/Containerfile):
#   * OpenSSL >= 3.5  -> native ML-KEM hybrids (X25519MLKEM768, etc.)
#   * OpenSSL 3.2/3.3 -> draft Kyber hybrids only, via oqs-provider if installed
#   * older           -> none of these will be recognised; reported as untestable
# ---------------------------------------------------------------------------

PQC_CANDIDATE_GROUPS = [
    ("X25519MLKEM768", "hybrid-final"),
    ("SecP256r1MLKEM768", "hybrid-final"),
    ("SecP384r1MLKEM1024", "hybrid-final"),
    ("X25519Kyber768Draft00", "hybrid-draft"),
    ("X25519", "classical"),
    ("secp256r1", "classical"),
    ("secp384r1", "classical"),
]


def get_openssl_version() -> str:
    try:
        out = subprocess.run(["openssl", "version"], capture_output=True, text=True,
                              timeout=3)
        return out.stdout.strip() or "unknown"
    except Exception as e:  # noqa: BLE001
        return f"unavailable ({e})"


def probe_pqc_group(host: str, port: int, sni: Optional[str], timeout: float,
                     group_name: str, kind: str) -> PqcGroupResult:
    target = f"{host}:{port}"
    cmd = [
        "openssl", "s_client",
        "-connect", target,
        "-tls1_3",
        "-groups", group_name,
        "-brief",
    ]
    if sni:
        cmd += ["-servername", sni]
    try:
        proc = subprocess.run(
            cmd, input="", capture_output=True, text=True, timeout=timeout + 2,
        )
        output = (proc.stdout or "") + (proc.stderr or "")

        # Confirmed against a live openssl 3.0.13 client: an unrecognised
        # group name fails locally, before any network I/O, with a message
        # of this shape (not "unknown group" as one might guess):
        #   "Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed"
        #   "...group 'X25519MLKEM768' cannot be set"
        if "SSL_CONF_cmd" in output or "cannot be set" in output:
            return PqcGroupResult(name=group_name, kind=kind, supported=None,
                                   note="local OpenSSL build does not recognise this group name")

        # In `-brief` mode a completed handshake prints "CONNECTION ESTABLISHED"
        # (NOT the plain "CONNECTED(...)" used without -brief) plus a
        # "Ciphersuite:" line. Confirmed against a live handshake.
        negotiated = "CONNECTION ESTABLISHED" in output and "Ciphersuite:" in output
        if negotiated:
            return PqcGroupResult(name=group_name, kind=kind, supported=True)
        return PqcGroupResult(name=group_name, kind=kind, supported=False,
                               note="handshake did not complete with this group offered")
    except subprocess.TimeoutExpired:
        return PqcGroupResult(name=group_name, kind=kind, supported=False,
                               note="timed out")
    except FileNotFoundError:
        return PqcGroupResult(name=group_name, kind=kind, supported=None,
                               note="openssl CLI not available in this container")


# ---------------------------------------------------------------------------
# Certificate inspection
# ---------------------------------------------------------------------------

def get_certificate_info(host: str, port: int, sni: Optional[str],
                          timeout: float) -> Optional[CertificateInfo]:
    try:
        ctx = _bare_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return None
        cert = x509.load_der_x509_certificate(der)

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        self_signed = subject == issuer

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days
        expired = now > not_after

        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_type, key_bits = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_bits = "EC", pub.curve.key_size
        else:
            key_type, key_bits = type(pub).__name__, 0

        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            dns_names = list(san_ext.get_values_for_type(x509.DNSName))
            ip_names = [str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress)]
            sans = dns_names + ip_names
        except x509.ExtensionNotFound:
            sans = []

        if self_signed:
            trust_note = "Self-signed: not chained to any CA. Expected for internal/dev hosts."
        else:
            trust_note = ("Chain verification was skipped by design (this tool talks to "
                           "untrusted/self-signed endpoints on purpose); trust was not "
                           "independently established.")

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            self_signed=self_signed,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            days_until_expiry=days_left,
            expired=expired,
            key_type=key_type,
            key_bits=key_bits,
            signature_algorithm=cert.signature_algorithm_oid._name,
            sans=list(sans) if sans else [],
            trust_note=trust_note,
        )
    except Exception:  # noqa: BLE001
        return None


def resolve_ip(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None
