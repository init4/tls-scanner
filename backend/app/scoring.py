"""
Turns raw protocol/cipher/certificate/PQC data into scores, a letter grade,
and a findings list the frontend can render as a checklist.

Grading philosophy
-------------------
* The headline grade (A+ .. F, or T) reflects CLASSICAL TLS hygiene:
  protocol versions, cipher strength, certificate health -- including, as
  of the chain-trust check, whether the certificate is actually trusted by
  a standard CA store. A server can't reach a good letter grade without
  that: an untrusted/self-signed chain forces the grade to "T" (Trust
  Issues) regardless of how clean everything else is, the same convention
  Qualys SSL Labs uses. This is a deliberate policy, not an oversight --
  self-signed certs used to be explicitly excluded from scoring (this tool
  is built to reach them on purpose), but "perfect protocol/cipher config,
  nobody can actually verify who they're talking to" isn't a good score.
* PQC readiness and HTTP security headers are each reported as their OWN
  separate score/label rather than blended into the headline grade -- PQC
  because almost no server today negotiates a hybrid group (folding it in
  would make every score look artificially bad for forward-looking info,
  not a pass/fail on today's baseline), and HTTP headers because they're a
  different security layer entirely (application-layer hardening, not
  transport-layer crypto) that happens to be useful to check alongside TLS.
"""
from __future__ import annotations

from typing import List

from .models import (
    CertificateInfo,
    CipherResult,
    DnsCaaResult,
    Finding,
    HttpSecurityHeaders,
    LegacyCheckResult,
    ProtocolResult,
    PqcGroupResult,
    Scoring,
)


def _protocol_score(protocols: List[ProtocolResult], legacy_checks: List[LegacyCheckResult],
                     findings: List[Finding]) -> int:
    by_name = {p.name: p for p in protocols}
    score = 100
    tls13 = by_name.get("TLSv1.3")
    tls12 = by_name.get("TLSv1.2")
    tls11 = by_name.get("TLSv1.1")
    tls10 = by_name.get("TLSv1.0")
    sslv3 = by_name.get("SSLv3")

    if sslv3 and sslv3.supported:
        score = 0
        findings.append(Finding(severity="critical",
                                 message="SSLv3 is supported. This protocol is broken (POODLE) and must be disabled."))
    if tls10 and tls10.supported:
        score = min(score, 55)
        findings.append(Finding(severity="high",
                                 message="TLS 1.0 is supported. Deprecated by all major browsers and PCI-DSS; disable it."))
    if tls11 and tls11.supported:
        score = min(score, 60)
        findings.append(Finding(severity="high",
                                 message="TLS 1.1 is supported. Deprecated; disable it in favor of 1.2/1.3 only."))
    if tls12 and tls12.supported is False and (not tls13 or not tls13.supported):
        score = min(score, 20)
        findings.append(Finding(severity="critical",
                                 message="Neither TLS 1.2 nor TLS 1.3 could be negotiated."))
    if tls13 and tls13.supported:
        findings.append(Finding(severity="info", message="TLS 1.3 is supported. Good."))
    else:
        score = min(score, 75)
        findings.append(Finding(severity="medium",
                                 message="TLS 1.3 is not supported. Modern clients prefer it for speed and security."))
    if tls12 and tls12.supported and not (tls13 and tls13.supported):
        findings.append(Finding(severity="low",
                                 message="TLS 1.2 is supported but TLS 1.3 is not; consider enabling 1.3 as well."))

    by_legacy_name = {c.name: c for c in legacy_checks}
    compression = by_legacy_name.get("tls_compression")
    if compression and compression.supported:
        score = min(score, 30)
        findings.append(Finding(severity="critical", message=f"TLS compression is enabled. {compression.note}"))

    secure_reneg = by_legacy_name.get("secure_renegotiation")
    if secure_reneg and secure_reneg.supported is False:
        score = min(score, 50)
        findings.append(Finding(severity="high", message=secure_reneg.note))
    elif secure_reneg and secure_reneg.supported:
        findings.append(Finding(severity="info", message="Secure renegotiation (RFC 5746) is supported."))

    fallback = by_legacy_name.get("fallback_scsv")
    if fallback and fallback.supported is False:
        findings.append(Finding(severity="low", message=fallback.note))
    elif fallback and fallback.supported:
        findings.append(Finding(severity="info", message=fallback.note))

    return max(0, min(100, score))


def _cipher_score(ciphers: List[CipherResult], findings: List[Finding]) -> int:
    supported = [c for c in ciphers if c.supported]
    if not supported:
        findings.append(Finding(severity="critical",
                                 message="No cipher suite could be enumerated as supported; the server may be unreachable."))
        return 0

    score = 100
    insecure = [c for c in supported if c.strength == "insecure"]
    weak = [c for c in supported if c.strength == "weak"]
    strong_aead_pfs = [c for c in supported if c.strength == "strong" and c.forward_secrecy and c.aead]

    for c in insecure:
        score -= 35
        findings.append(Finding(severity="critical",
                                 message=f"Insecure cipher suite negotiable: {c.name} ({c.protocol})."))
    for c in weak:
        score -= 12
        findings.append(Finding(severity="medium",
                                 message=f"Weak cipher suite negotiable: {c.name} ({c.protocol}) -- no forward secrecy or AEAD."))
    if strong_aead_pfs:
        findings.append(Finding(severity="info",
                                 message=f"{len(strong_aead_pfs)} strong AEAD cipher suite(s) with forward secrecy are supported."))
    else:
        score -= 20
        findings.append(Finding(severity="high",
                                 message="No modern AEAD cipher suite with forward secrecy was found."))
    return max(0, min(100, score))


def _certificate_score(cert: CertificateInfo | None, dns_caa: DnsCaaResult | None,
                        findings: List[Finding]) -> int:
    if cert is None:
        findings.append(Finding(severity="medium",
                                 message="Certificate could not be retrieved or parsed."))
        return 50

    score = 100
    if cert.chain_trusted is False:
        score = min(score, 30)
        findings.append(Finding(
            severity="critical",
            message=f"Certificate chain is not trusted by a standard CA trust store "
                    f"({cert.chain_trust_note or 'verification failed'}). This overrides the "
                    f"overall letter grade to 'T' (Trust Issues) regardless of protocol/cipher "
                    f"configuration."))
    elif cert.chain_trusted is True:
        findings.append(Finding(severity="info",
                                 message="Certificate chain is verified and trusted by a standard CA trust store."))
    else:
        findings.append(Finding(severity="low",
                                 message="Could not determine whether the certificate chain is trusted "
                                         "(the trust-verification probe failed independently of the certificate lookup)."))

    if cert.self_signed:
        findings.append(Finding(severity="info",
                                 message="Certificate is self-signed -- see the chain-of-trust finding "
                                         "above for how that affects the grade."))

    if dns_caa is not None and dns_caa.applicable:
        if dns_caa.records:
            tags = sorted({f"{r.tag}={r.value}" for r in dns_caa.records})
            findings.append(Finding(severity="info",
                                     message=f"DNS CAA record(s) present, restricting certificate issuance: {', '.join(tags)}."))
        elif dns_caa.note is None:
            score -= 5
            findings.append(Finding(severity="low",
                                     message="No DNS CAA record found -- any publicly trusted CA can issue "
                                             "certificates for this domain. Adding one limits mis-issuance risk."))
        else:
            findings.append(Finding(severity="low", message=f"Could not check for a DNS CAA record: {dns_caa.note}"))

    if cert.expired:
        score -= 60
        findings.append(Finding(severity="critical", message="Certificate is expired."))
    elif cert.days_until_expiry < 14:
        score -= 20
        findings.append(Finding(severity="high",
                                 message=f"Certificate expires in {cert.days_until_expiry} day(s)."))
    elif cert.days_until_expiry < 30:
        score -= 8
        findings.append(Finding(severity="low",
                                 message=f"Certificate expires in {cert.days_until_expiry} day(s)."))

    if cert.key_type == "RSA" and cert.key_bits < 2048:
        score -= 50
        findings.append(Finding(severity="critical",
                                 message=f"RSA key is only {cert.key_bits} bits; 2048+ is the minimum acceptable size."))
    if cert.key_type == "EC" and cert.key_bits < 224:
        score -= 50
        findings.append(Finding(severity="critical",
                                 message=f"EC key uses a {cert.key_bits}-bit curve, weaker than recommended."))

    sig_alg = cert.signature_algorithm.lower()
    if "md5" in sig_alg or "sha1" in sig_alg:
        score -= 40
        findings.append(Finding(severity="high",
                                 message=f"Certificate is signed with {cert.signature_algorithm}, a broken/weak hash."))

    return max(0, min(100, score))


def _pqc_readiness(groups: List[PqcGroupResult], findings: List[Finding]):
    final_supported = [g for g in groups if g.kind == "hybrid-final" and g.supported is True]
    draft_supported = [g for g in groups if g.kind == "hybrid-draft" and g.supported is True]
    all_untestable = all(g.supported is None for g in groups if g.kind != "classical")

    if all_untestable:
        findings.append(Finding(severity="info",
                                 message="PQC hybrid groups could not be tested: the scanner's local OpenSSL build "
                                         "doesn't recognise the ML-KEM group names. Rebuild the backend image with "
                                         "OpenSSL 3.5+ to enable this check."))
        return 0, "Untestable (upgrade scanner's OpenSSL)"

    if final_supported:
        score = min(100, 40 * len(final_supported) + 20)
        findings.append(Finding(severity="info",
                                 message=f"Server negotiates {len(final_supported)} standardized ML-KEM hybrid "
                                         f"group(s): {', '.join(g.name for g in final_supported)}."))
        label = "Hybrid PQC ready" if len(final_supported) >= 1 else "Partial"
        return score, label

    if draft_supported:
        findings.append(Finding(severity="info",
                                 message="Server only supports a DRAFT (pre-standard) Kyber hybrid group, not the "
                                         "final ML-KEM codepoints. Treat as legacy interop, not production PQC readiness."))
        return 15, "Draft support only"

    findings.append(Finding(severity="low",
                             message="No post-quantum hybrid key-exchange group was negotiated. This is normal for "
                                     "most servers today, but worth planning for as PQC migration timelines firm up."))
    return 0, "Not PQC-ready"


def _grade_from_score(score: int, protocols: List[ProtocolResult], ciphers: List[CipherResult],
                       certificate: CertificateInfo | None) -> str:
    by_name = {p.name: p for p in protocols}
    sslv3 = by_name.get("SSLv3")
    tls10 = by_name.get("TLSv1.0")
    has_insecure_cipher = any(c.supported and c.strength == "insecure" for c in ciphers)

    if (sslv3 and sslv3.supported) or has_insecure_cipher:
        return "F"
    # "T" (Trust Issues) -- same convention Qualys SSL Labs uses -- overrides
    # every other consideration. A server with a flawless protocol/cipher
    # config but a chain nothing trusts hasn't earned an A-F grade at all;
    # chain_trusted is None (probe inconclusive) deliberately does NOT
    # trigger this, only a confirmed failure does.
    if certificate is not None and certificate.chain_trusted is False:
        return "T"
    if tls10 and tls10.supported:
        score = min(score, 65)

    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _http_headers_score(headers: HttpSecurityHeaders, findings: List[Finding]) -> tuple[int, str]:
    if not headers.checked:
        findings.append(Finding(severity="low",
                                 message=f"HTTP security headers could not be checked: {headers.note or 'request failed'}."))
        return 0, "Untestable"

    by_name = {h.header: h for h in headers.headers}
    present = [h for h in headers.headers if h.present]
    missing = [h for h in headers.headers if not h.present and h.note is None]
    covered_by_alt = [h for h in headers.headers if not h.present and h.note]

    for h in present:
        findings.append(Finding(severity="info", message=f"{h.header} is set ({h.value})."))
    for h in covered_by_alt:
        findings.append(Finding(severity="info", message=f"{h.header} is not set, but: {h.note}"))
    hsts = by_name.get("Strict-Transport-Security")
    for h in missing:
        severity = "medium" if h.header in ("Strict-Transport-Security", "Content-Security-Policy") else "low"
        findings.append(Finding(severity=severity, message=f"{h.header} is not set."))

    effective_present = len(present) + len(covered_by_alt)
    total = len(headers.headers)
    score = round(100 * effective_present / total) if total else 0

    if effective_present == total:
        label = "Fully hardened"
    elif hsts and hsts.present:
        label = "Partial"
    else:
        label = "Minimal" if effective_present else "None set"
    return score, label


def compute_scoring(protocols: List[ProtocolResult], ciphers: List[CipherResult],
                     certificate: CertificateInfo | None,
                     pqc_groups: List[PqcGroupResult],
                     legacy_checks: List[LegacyCheckResult],
                     dns_caa: DnsCaaResult | None,
                     http_headers: HttpSecurityHeaders) -> Scoring:
    findings: List[Finding] = []

    protocol_score = _protocol_score(protocols, legacy_checks, findings)
    cipher_score = _cipher_score(ciphers, findings)
    certificate_score = _certificate_score(certificate, dns_caa, findings)
    pqc_score, pqc_label = _pqc_readiness(pqc_groups, findings)
    http_headers_score, http_headers_label = _http_headers_score(http_headers, findings)

    overall_score = round(
        protocol_score * 0.40 + cipher_score * 0.35 + certificate_score * 0.25
    )
    overall_grade = _grade_from_score(overall_score, protocols, ciphers, certificate)

    return Scoring(
        protocol_score=protocol_score,
        cipher_score=cipher_score,
        certificate_score=certificate_score,
        overall_score=overall_score,
        overall_grade=overall_grade,
        pqc_readiness_score=pqc_score,
        pqc_readiness_label=pqc_label,
        http_headers_score=http_headers_score,
        http_headers_label=http_headers_label,
        findings=findings,
    )
