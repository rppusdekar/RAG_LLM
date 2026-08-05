"""
Core data models for the CBOM scanner.
Follows the CycloneDX 1.6 cryptographic-asset schema.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import uuid


class QuantumRisk(str, Enum):
    """Quantum threat classification."""
    VULNERABLE = "vulnerable"   # Broken by Shor's algorithm (RSA, ECC, DH)
    WEAKENED   = "weakened"     # Grover halves effective key size (AES-128, SHA-256)
    SAFE       = "safe"         # Sufficient margin at current key size (AES-256, SHA-384+)
    PQC        = "pqc"          # NIST-standardised post-quantum (ML-KEM, ML-DSA, SLH-DSA)
    UNKNOWN    = "unknown"


class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    PROTOCOL  = "protocol"
    KEY       = "key"
    LIBRARY   = "library"


class Primitive(str, Enum):
    PKE          = "pke"           # Public-key encryption / KEM
    SIGNATURE    = "signature"
    KEY_EXCHANGE = "key-agreement"
    HASH         = "hash"
    AE           = "ae"            # Authenticated encryption
    SYMMETRIC    = "symmetric"
    MAC          = "mac"
    PROTOCOL     = "protocol"
    OTHER        = "other"


# Maps QuantumRisk → human label + emoji
RISK_LABEL: dict[QuantumRisk, tuple[str, str]] = {
    QuantumRisk.VULNERABLE: ("VULNERABLE",  "🔴"),
    QuantumRisk.WEAKENED:   ("WEAKENED",    "🟡"),
    QuantumRisk.SAFE:       ("SAFE",        "🟢"),
    QuantumRisk.PQC:        ("PQC",         "✅"),
    QuantumRisk.UNKNOWN:    ("UNKNOWN",     "⚪"),
}


@dataclass
class CryptoFinding:
    """One detected cryptographic asset in source code."""
    bom_ref: str              = field(default_factory=lambda: f"cf-{uuid.uuid4().hex[:8]}")
    name: str                 = ""
    asset_type: AssetType     = AssetType.ALGORITHM
    primitive: Primitive      = Primitive.OTHER
    key_size: Optional[int]   = None
    mode: str                 = ""           # e.g. GCM, CBC, ECB
    quantum_risk: QuantumRisk = QuantumRisk.UNKNOWN
    file_path: str            = ""
    line_number: int          = 0
    evidence: str             = ""           # matched code snippet (≤120 chars)
    pqc_replacement: str      = ""           # recommended NIST alternative
    oid: str                  = ""           # algorithm OID when known
    library: str              = ""           # e.g. cryptography, OpenSSL

    @property
    def risk_emoji(self) -> str:
        return RISK_LABEL[self.quantum_risk][1]

    @property
    def risk_label(self) -> str:
        return RISK_LABEL[self.quantum_risk][0]


@dataclass
class ScanResult:
    """Aggregate output of scanning a target path."""
    target_path: str                   = ""
    findings: list[CryptoFinding]      = field(default_factory=list)
    files_scanned: int                 = 0
    files_skipped: int                 = 0
    scan_duration_s: float             = 0.0
    scanner_version: str               = "0.1.0"

    # ── convenience counters ──────────────────────────────────────────────────
    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.quantum_risk == QuantumRisk.VULNERABLE)

    @property
    def weakened_count(self) -> int:
        return sum(1 for f in self.findings if f.quantum_risk == QuantumRisk.WEAKENED)

    @property
    def safe_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.quantum_risk in (QuantumRisk.SAFE, QuantumRisk.PQC))

    @property
    def unique_algorithms(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for f in self.findings:
            if f.name not in seen:
                seen.add(f.name)
                out.append(f.name)
        return out
