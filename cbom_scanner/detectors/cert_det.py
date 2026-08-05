"""
X.509 Certificate file detector.

Reads .pem / .crt / .cer / .der files from the filesystem and extracts
cryptographic asset findings from each certificate:
  - Public key algorithm + key size
  - Signature hash algorithm
  - Validity period / expiry
  - Subject CN + SANs
  - CNSA 2.0 compliance notes

Integrates with BaseDetector so the scanner orchestrator picks it up
automatically when it encounters certificate files.
"""

from __future__ import annotations
import datetime
from pathlib import Path
from typing import Optional

from .base import BaseDetector
from ..models import (
    AssetType, CryptoFinding, Primitive, QuantumRisk,
)

_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p7b", ".p7c"}


class CertDetector(BaseDetector):
    """Detect cryptographic assets in X.509 certificate files."""

    supported_extensions: set[str] = _CERT_EXTENSIONS

    def detect(self, path: Path) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        raw = path.read_bytes()

        certs = _load_certs(raw, path)
        for cert in certs:
            findings.extend(_analyse_cert(cert, str(path)))

        return findings


# ── Certificate loading ───────────────────────────────────────────────────────

def _load_certs(raw: bytes, path: Path):
    """Load one or more X.509 certs from raw bytes (PEM bundle or DER)."""
    try:
        from cryptography import x509
    except ImportError:
        return []

    certs = []

    # Try PEM (may be a bundle with multiple certs)
    if b"BEGIN CERTIFICATE" in raw:
        import re
        pem_blocks = re.findall(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            raw,
            re.DOTALL,
        )
        for block in pem_blocks:
            try:
                certs.append(x509.load_pem_x509_certificate(block))
            except Exception:
                pass
    else:
        # Try DER
        try:
            certs.append(x509.load_der_x509_certificate(raw))
        except Exception:
            pass

    return certs


# ── Per-certificate analysis ──────────────────────────────────────────────────

def _analyse_cert(cert, file_path: str) -> list[CryptoFinding]:
    findings: list[CryptoFinding] = []

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
    except ImportError:
        return findings

    # Subject CN
    try:
        cn = cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value
    except (IndexError, Exception):
        cn = Path(file_path).name

    # SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []

    # Expiry
    try:
        expires = (cert.not_valid_after_utc
                   if hasattr(cert, "not_valid_after_utc")
                   else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc))
        now       = datetime.datetime.now(datetime.timezone.utc)
        days_left = (expires - now).days
        expiry_str = expires.strftime("%Y-%m-%d")
    except Exception:
        days_left  = 9999
        expiry_str = "unknown"

    # Public key
    pub_key   = cert.public_key()
    key_size: Optional[int] = None
    algo_name = "Unknown"
    risk      = QuantumRisk.VULNERABLE
    pqc_rep   = ""

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size  = pub_key.key_size
        algo_name = f"RSA-{key_size}"
        pqc_rep   = "ML-DSA-65 (FIPS 204) for signatures"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_size  = pub_key.key_size
        algo_name = f"EC-{pub_key.curve.name}"
        pqc_rep   = "ML-DSA-65 (FIPS 204) for signatures"
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        algo_name = "Ed25519"
        pqc_rep   = "ML-DSA-44 (FIPS 204)"
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        algo_name = "Ed448"
        pqc_rep   = "ML-DSA-87 (FIPS 204)"
    else:
        algo_name = type(pub_key).__name__
        risk      = QuantumRisk.UNKNOWN

    # Expiry annotation
    if days_left < 0:
        expiry_note = "EXPIRED"
        exp_risk    = QuantumRisk.VULNERABLE
    elif days_left < 30:
        expiry_note = f"expires in {days_left}d ⚠️"
        exp_risk    = QuantumRisk.VULNERABLE
    elif days_left < 366:
        expiry_note = f"expires {expiry_str}"
        exp_risk    = QuantumRisk.WEAKENED
    else:
        expiry_note = f"expires {expiry_str}"
        exp_risk    = risk  # inherit public-key risk

    san_note = f" SAN={','.join(sans[:3])}" if sans else ""
    evidence  = f"CN={cn}{san_note} | {expiry_note}"

    # Main public-key finding
    findings.append(CryptoFinding(
        name         = f"Cert: {algo_name}",
        asset_type   = AssetType.KEY,
        primitive    = Primitive.SIGNATURE,
        quantum_risk = risk,
        key_size     = key_size,
        file_path    = file_path,
        line_number  = 0,
        evidence     = evidence,
        pqc_replacement = pqc_rep,
        oid          = "2.5.4.3",
    ))

    # Signature hash finding
    sig_hash = cert.signature_hash_algorithm
    if sig_hash:
        sig_name = sig_hash.name.upper()
        if "SHA1" in sig_name or sig_name == "SHA":
            findings.append(CryptoFinding(
                name         = "SHA-1 Cert Signature",
                asset_type   = AssetType.ALGORITHM,
                primitive    = Primitive.HASH,
                quantum_risk = QuantumRisk.VULNERABLE,
                file_path    = file_path,
                line_number  = 0,
                evidence     = f"CN={cn} signed with SHA-1 — classically and quantum-broken",
                pqc_replacement = "Reissue certificate with SHA-384 or SHA-512 signature hash",
            ))
        elif "SHA256" in sig_name:
            findings.append(CryptoFinding(
                name         = "SHA-256 Cert Signature",
                asset_type   = AssetType.ALGORITHM,
                primitive    = Primitive.HASH,
                quantum_risk = QuantumRisk.WEAKENED,
                file_path    = file_path,
                line_number  = 0,
                evidence     = f"CN={cn} signed with SHA-256 (Grover-weakened)",
                pqc_replacement = "Prefer SHA-384 or SHA-512 for quantum margin",
            ))

    # CNSA 2.0 RSA key-size advisory
    if isinstance(pub_key, rsa.RSAPublicKey) and key_size and key_size < 3072:
        findings.append(CryptoFinding(
            name         = f"RSA-{key_size} below CNSA 2.0 minimum",
            asset_type   = AssetType.KEY,
            primitive    = Primitive.PKE,
            quantum_risk = QuantumRisk.VULNERABLE,
            key_size     = key_size,
            file_path    = file_path,
            line_number  = 0,
            evidence     = f"CN={cn}: RSA-{key_size} < 3072-bit CNSA 2.0 minimum",
            pqc_replacement = "Reissue with RSA-4096 (interim) or migrate to ML-DSA-65",
        ))

    # CNSA 2.0 expiry: any cert expiring after 2030 should already use PQC
    if days_left > 0 and expires.year >= 2030:
        findings.append(CryptoFinding(
            name         = "Cert validity extends past CNSA 2.0 PQC deadline",
            asset_type   = AssetType.KEY,
            primitive    = Primitive.SIGNATURE,
            quantum_risk = QuantumRisk.VULNERABLE,
            file_path    = file_path,
            line_number  = 0,
            evidence     = f"CN={cn} valid until {expiry_str} — post-2030 certs must use PQC algorithms",
            pqc_replacement = "Issue a new certificate using ML-DSA-65 (FIPS 204) before the CNSA 2.0 deadline",
        ))

    return findings
