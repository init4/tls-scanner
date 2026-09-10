from __future__ import annotations

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import scanner
from .models import (
    CipherResult,
    ProtocolResult,
    PqcGroupResult,
    ScanRequest,
    ScanResult,
    TargetInfo,
)
from .scoring import compute_scoring

app = FastAPI(
    title="TLS / PQC Readiness Scanner",
    description="Probes a host's TLS configuration -- protocols, cipher suites, "
                "certificate health, and post-quantum hybrid key-exchange readiness.",
    version="1.0.0",
)

# The shipped frontend (both `vite dev` and the built nginx image) talks to
# this API through a same-origin reverse proxy, so no cross-origin access is
# needed by default -- and this API has no auth, so a wildcard origin would
# let any website's JS fetch() a scan (against whatever internal host/IP it
# asks for) and read the response. Only widen this if you have a genuine
# cross-origin caller, e.g. CORS_ALLOW_ORIGINS=https://dashboard.example.com.
_allowed_origins = os.environ.get("CORS_ALLOW_ORIGINS", "")
if _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if _allowed_origins == "*" else _allowed_origins.split(","),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

_executor = ThreadPoolExecutor(max_workers=16)

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-\.:]{0,253})$")


def _clean_host(raw: str) -> str:
    host = raw.strip()
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", host)  # strip scheme if pasted
    host = host.split("/", 1)[0]  # strip any path
    host = host.rstrip(".")
    # If someone pastes "host:port" alongside the separate port field, drop
    # the redundant suffix -- but only a single ":digits" suffix, so we don't
    # mangle IPv6 literals (which contain multiple colons).
    if host.count(":") == 1:
        maybe_host, maybe_port = host.split(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
    if not host or not _HOST_RE.match(host):
        raise HTTPException(status_code=400, detail=f"'{raw}' doesn't look like a valid host or IP")
    return host


@app.get("/api/health")
def health():
    return {"status": "ok", "openssl_version": scanner.get_openssl_version()}


@app.post("/api/scan", response_model=ScanResult)
def scan(req: ScanRequest):
    host = _clean_host(req.host)
    port = req.port
    sni = req.sni.strip() if req.sni else (host if not _looks_like_ip(host) else None)
    timeout = req.timeout

    start = time.monotonic()
    errors: list[str] = []

    futures = {}

    for name, version in scanner.PROTOCOL_VERSIONS:
        futures[("protocol", name)] = _executor.submit(
            scanner.probe_protocol, host, port, name, version, sni, timeout
        )

    for cipher_name, strength, pfs, aead in scanner.TLS12_CANDIDATE_CIPHERS:
        futures[("cipher12", cipher_name)] = _executor.submit(
            scanner.probe_tls12_cipher, host, port, sni, timeout, cipher_name, strength, pfs, aead
        )

    for suite_name, strength in scanner.TLS13_CANDIDATE_SUITES:
        futures[("cipher13", suite_name)] = _executor.submit(
            scanner.probe_tls13_suite, host, port, sni, timeout, suite_name, strength
        )

    for group_name, kind in scanner.PQC_CANDIDATE_GROUPS:
        futures[("pqc", group_name)] = _executor.submit(
            scanner.probe_pqc_group, host, port, sni, timeout, group_name, kind
        )

    cert_future = _executor.submit(scanner.get_certificate_info, host, port, sni, timeout)
    ip_future = _executor.submit(scanner.resolve_ip, host)

    protocols: list[ProtocolResult] = []
    ciphers: list[CipherResult] = []
    pqc_groups: list[PqcGroupResult] = []

    for (kind, key), fut in futures.items():
        try:
            result = fut.result()
        except Exception as e:  # noqa: BLE001
            errors.append(f"{kind}:{key} raised {e}")
            continue
        if result is None:
            continue
        if kind == "protocol":
            protocols.append(result)
        elif kind in ("cipher12", "cipher13"):
            ciphers.append(result)
        elif kind == "pqc":
            pqc_groups.append(result)

    try:
        certificate = cert_future.result()
    except Exception as e:  # noqa: BLE001
        errors.append(f"certificate lookup raised {e}")
        certificate = None

    try:
        resolved_ip = ip_future.result()
    except Exception:
        resolved_ip = None

    if not any(p.supported for p in protocols if p.supported is not None):
        errors.append("Could not establish a TLS session on any protocol version -- "
                      "check host/port and that the service is reachable from this container.")

    tls13_supported = any(p.name == "TLSv1.3" and p.supported for p in protocols)
    tls13_ciphers_identified = any(c.protocol == "TLSv1.3" for c in ciphers)
    if tls13_supported and not tls13_ciphers_identified:
        # TLS 1.3 mandates AEAD-only cipher suites, so a successful protocol
        # handshake is itself proof of a strong suite even when this Python
        # build can't pin/enumerate which exact one was negotiated.
        errors.append("TLS 1.3 is supported but the specific cipher suite could not be "
                      "identified (local Python ssl build lacks per-suite pinning).")
        ciphers.append(CipherResult(
            name="(TLS 1.3 suite not identified)", protocol="TLSv1.3", supported=True,
            strength="strong", forward_secrecy=True, aead=True,
        ))

    scoring = compute_scoring(protocols, ciphers, certificate, pqc_groups)

    duration_ms = int((time.monotonic() - start) * 1000)

    return ScanResult(
        target=TargetInfo(host=host, port=port, sni=sni, resolved_ip=resolved_ip),
        scanned_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=duration_ms,
        openssl_version=scanner.get_openssl_version(),
        protocols=protocols,
        ciphers=ciphers,
        key_exchange_groups=pqc_groups,
        certificate=certificate,
        scoring=scoring,
        errors=errors,
    )


def _looks_like_ip(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in host  # crude IPv6 check
