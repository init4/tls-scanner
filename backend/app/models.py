"""
Pydantic models describing the JSON contract returned by the scan API.
Keeping this centralized means the frontend can rely on a stable shape
regardless of how the scanning internals change.
"""
from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    host: str = Field(..., description="Hostname or IP address to scan")
    port: int = Field(443, ge=1, le=65535)
    sni: Optional[str] = Field(
        None, description="Override SNI servername sent during the handshake"
    )
    timeout: float = Field(4.0, ge=1.0, le=15.0)


class ProtocolResult(BaseModel):
    name: str
    supported: Optional[bool] = None  # None => could not be determined
    tested: bool = True
    note: Optional[str] = None


class CipherResult(BaseModel):
    name: str
    protocol: str
    supported: bool
    strength: str  # "strong" | "acceptable" | "weak" | "insecure"
    forward_secrecy: bool
    aead: bool


class PqcGroupResult(BaseModel):
    name: str
    kind: str  # "hybrid-final" | "hybrid-draft" | "classical"
    supported: Optional[bool] = None  # None => untestable locally
    note: Optional[str] = None


class CertificateInfo(BaseModel):
    subject: str
    issuer: str
    self_signed: bool
    not_before: str
    not_after: str
    days_until_expiry: int
    expired: bool
    key_type: str
    key_bits: int
    signature_algorithm: str
    sans: List[str] = []
    trust_note: str


class Finding(BaseModel):
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    message: str


class Scoring(BaseModel):
    protocol_score: int
    cipher_score: int
    certificate_score: int
    overall_score: int
    overall_grade: str
    pqc_readiness_score: int
    pqc_readiness_label: str
    findings: List[Finding]


class TargetInfo(BaseModel):
    host: str
    port: int
    sni: Optional[str]
    resolved_ip: Optional[str]


class ScanResult(BaseModel):
    target: TargetInfo
    scanned_at: str
    duration_ms: int
    openssl_version: str
    protocols: List[ProtocolResult]
    ciphers: List[CipherResult]
    key_exchange_groups: List[PqcGroupResult]
    certificate: Optional[CertificateInfo]
    scoring: Scoring
    errors: List[str] = []
