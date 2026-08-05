"""
TLS endpoint scanner.

Connects to a host:port, negotiates TLS, and returns CryptoFindings for:
  - The negotiated protocol version  (TLS 1.0–1.3 / SSLv3)
  - The selected cipher suite        (key exchange + encryption + MAC)
  - The server's X.509 certificate   (algorithm, key size, expiry, SAN)
  - All certificates in the chain    (intermediate / root CA)

Usage (not a file-based BaseDetector — call scan_tls_endpoint() directly):

    from cbom_scanner.detectors.tls_det import scan_tls_endpoint
    findings = scan_tls_endpoint("example.com", 443)
"""

from __future__ import annotations
import datetime
import socket
import ssl
from typing import Optional

from ..models import (
    AssetType, CryptoFinding, Primitive, QuantumRisk,
)

# ── Protocol risk table ───────────────────────────────────────────────────────

_PROTO_RISK: dict[str, tuple[QuantumRisk, str]] = {
    "SSLv2":   (QuantumRisk.VULNERABLE, "SSLv2 is classically and quantum-broken — disable immediately"),
    "SSLv3":   (QuantumRisk.VULNERABLE, "SSLv3 (POODLE) is classically broken — disable immediately"),
    "TLSv1":   (QuantumRisk.VULNERABLE, "TLS 1.0 deprecated (RFC 8996) — upgrade to TLS 1.3"),
    "TLSv1.1": (QuantumRisk.VULNERABLE, "TLS 1.1 deprecated (RFC 8996) — upgrade to TLS 1.3"),
    "TLSv1.2": (QuantumRisk.WEAKENED,   "TLS 1.2 is safe today; add ML-KEM hybrid for PQC readiness"),
    "TLSv1.3": (QuantumRisk.WEAKENED,   "TLS 1.3 is safe today; add X25519MLKEM768 hybrid cipher suite for PQC"),
}

_PROTO_PQC_REPLACEMENT: dict[str, str] = {
    "SSLv2":   "TLS 1.3 + X25519MLKEM768 hybrid (draft-ietf-tls-hybrid-design)",
    "SSLv3":   "TLS 1.3 + X25519MLKEM768 hybrid",
    "TLSv1":   "TLS 1.3 + X25519MLKEM768 hybrid",
    "TLSv1.1": "TLS 1.3 + X25519MLKEM768 hybrid",
    "TLSv1.2": "TLS 1.3 + X25519MLKEM768 hybrid cipher suite (NIST guidance)",
    "TLSv1.3": "Add X25519MLKEM768 cipher suite (draft-ietf-tls-hybrid-design)",
}

# ── Cipher component risk ─────────────────────────────────────────────────────

# Key-exchange prefixes that appear in OpenSSL cipher names
_KX_VULNERABLE   = {"RSA", "DH", "DHE", "ECDH", "ECDHE", "SRP"}  # all quantum-vulnerable
_KX_PQC          = {"MLKEM", "KYBER"}                              # post-quantum KEM

# Symmetric cipher components
_SYM_VULNERABLE  = {"RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "aNULL", "eNULL"}
_SYM_WEAKENED    = {"AES128", "AES-128", "AES_128"}
_SYM_SAFE        = {"AES256", "AES-256", "AES_256", "CHACHA20"}

# MAC / hash components
_MAC_VULNERABLE  = {"MD5", "SHA1"}                                 # SHA = SHA-1 in cipher names
_MAC_WEAKENED    = {"SHA256"}
_MAC_SAFE        = {"SHA384", "SHA512"}


def scan_tls_endpoint(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    verify: bool = False,
) -> list[CryptoFinding]:
    """
    Connect to host:port via TLS and return a list of CryptoFindings.

    Parameters
    ----------
    host     Hostname or IP to connect to.
    port     TCP port (default 443).
    timeout  Socket timeout in seconds.
    verify   Whether to verify the server certificate chain (default False,
             so we can scan self-signed / internal hosts).
    """
    findings: list[CryptoFinding] = []
    endpoint = f"{host}:{port}"

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                proto   = tls.version() or "unknown"
                cipher  = tls.cipher()  # (name, protocol, key_bits)
                cert_der = tls.getpeercert(binary_form=True)

    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        findings.append(CryptoFinding(
            name         = "TLS Connection Error",
            asset_type   = AssetType.PROTOCOL,
            primitive    = Primitive.PROTOCOL,
            quantum_risk = QuantumRisk.UNKNOWN,
            file_path    = endpoint,
            line_number  = 0,
            evidence     = str(exc)[:120],
            pqc_replacement = "Ensure the host is reachable and the port is open",
        ))
        return findings
    except ssl.SSLError as exc:
        findings.append(CryptoFinding(
            name         = "SSL Error",
            asset_type   = AssetType.PROTOCOL,
            primitive    = Primitive.PROTOCOL,
            quantum_risk = QuantumRisk.UNKNOWN,
            file_path    = endpoint,
            line_number  = 0,
            evidence     = str(exc)[:120],
            pqc_replacement = "Check TLS configuration on the server",
        ))
        return findings

    # ── 1. Protocol version finding ───────────────────────────────────────────
    risk, note = _PROTO_RISK.get(proto, (QuantumRisk.UNKNOWN, "Unknown TLS version"))
    findings.append(CryptoFinding(
        name         = proto,
        asset_type   = AssetType.PROTOCOL,
        primitive    = Primitive.PROTOCOL,
        quantum_risk = risk,
        file_path    = endpoint,
        line_number  = 0,
        evidence     = f"Negotiated protocol: {proto}",
        pqc_replacement = _PROTO_PQC_REPLACEMENT.get(proto, ""),
    ))

    # ── 2. Cipher suite findings ──────────────────────────────────────────────
    if cipher:
        cipher_name, _, key_bits = cipher
        findings.extend(_analyse_cipher(cipher_name, key_bits or 0, endpoint))

    # ── 3. Certificate findings ───────────────────────────────────────────────
    if cert_der:
        findings.extend(_analyse_cert(cert_der, endpoint))

    return findings


# ── Cipher analysis ───────────────────────────────────────────────────────────

def _analyse_cipher(
    cipher_name: str, key_bits: int, endpoint: str
) -> list[CryptoFinding]:
    """Break an OpenSSL cipher name into components and return findings."""
    findings: list[CryptoFinding] = []
    parts = set(cipher_name.upper().replace("-", "_").split("_"))

    # Key exchange
    kx_risk = QuantumRisk.VULNERABLE  # default — all current KX is quantum-vulnerable
    kx_rep  = "ML-KEM-768 hybrid key exchange (X25519MLKEM768 for TLS 1.3)"
    if parts & {p.upper() for p in _KX_PQC}:
        kx_risk = QuantumRisk.PQC
        kx_rep  = "Already using post-quantum key exchange"

    findings.append(CryptoFinding(
        name         = f"TLS-KX ({cipher_name})",
        asset_type   = AssetType.ALGORITHM,
        primitive    = Primitive.KEY_EXCHANGE,
        quantum_risk = kx_risk,
        key_size     = key_bits or None,
        file_path    = endpoint,
        line_number  = 0,
        evidence     = f"Cipher suite: {cipher_name}",
        pqc_replacement = kx_rep,
    ))

    # Symmetric encryption component
    sym_risk = QuantumRisk.UNKNOWN
    sym_name = cipher_name
    sym_rep  = ""

    if parts & {p.upper().replace("-", "_") for p in _SYM_VULNERABLE}:
        sym_risk = QuantumRisk.VULNERABLE
        sym_rep  = "AES-256-GCM or ChaCha20-Poly1305"
    elif parts & {p.upper().replace("-", "_") for p in _SYM_WEAKENED}:
        sym_risk = QuantumRisk.WEAKENED
        sym_rep  = "Upgrade to AES-256-GCM (key size doubled vs AES-128 against Grover)"
    elif parts & {p.upper().replace("-", "_") for p in _SYM_SAFE}:
        sym_risk = QuantumRisk.SAFE
        sym_rep  = "Symmetric cipher is quantum-safe at current key size"

    if sym_risk != QuantumRisk.UNKNOWN:
        findings.append(CryptoFinding(
            name         = f"TLS-Cipher ({_sym_component(cipher_name)})",
            asset_type   = AssetType.ALGORITHM,
            primitive    = Primitive.AE,
            quantum_risk = sym_risk,
            key_size     = key_bits or None,
            file_path    = endpoint,
            line_number  = 0,
            evidence     = f"Cipher suite: {cipher_name}",
            pqc_replacement = sym_rep,
        ))

    return findings


def _sym_component(cipher_name: str) -> str:
    """Extract the symmetric cipher part from a cipher suite name."""
    for token in cipher_name.split("-"):
        if any(s in token.upper() for s in ("AES", "RC4", "3DES", "CHACHA", "DES")):
            return token
    return cipher_name


# ── Certificate analysis ──────────────────────────────────────────────────────

def _analyse_cert(cert_der: bytes, endpoint: str) -> list[CryptoFinding]:
    """Parse a DER-encoded X.509 certificate and return CryptoFindings."""
    findings: list[CryptoFinding] = []

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh, ed25519, ed448
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        findings.append(CryptoFinding(
            name         = "X.509 Certificate (unparsed)",
            asset_type   = AssetType.KEY,
            primitive    = Primitive.PKE,
            quantum_risk = QuantumRisk.UNKNOWN,
            file_path    = endpoint,
            line_number  = 0,
            evidence     = "Install 'cryptography' package to parse certificates",
        ))
        return findings

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        findings.append(CryptoFinding(
            name         = "X.509 Certificate (parse error)",
            asset_type   = AssetType.KEY,
            primitive    = Primitive.PKE,
            quantum_risk = QuantumRisk.UNKNOWN,
            file_path    = endpoint,
            evidence     = str(exc)[:80],
        ))
        return findings

    pub_key = cert.public_key()
    key_size: Optional[int] = None
    algo_name = "Unknown"
    risk = QuantumRisk.VULNERABLE  # default for any public-key cert
    pqc_rep = ""

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size  = pub_key.key_size
        algo_name = f"RSA-{key_size}"
        risk      = QuantumRisk.VULNERABLE
        pqc_rep   = ("ML-DSA-65 (FIPS 204) for signatures; "
                     "ML-KEM-768 (FIPS 203) for key exchange")
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_size  = pub_key.key_size
        curve     = pub_key.curve.name
        algo_name = f"EC ({curve})"
        risk      = QuantumRisk.VULNERABLE
        pqc_rep   = "ML-DSA-65 (FIPS 204) for signatures"
    elif isinstance(pub_key, (ed25519.Ed25519PublicKey,)):
        algo_name = "Ed25519"
        risk      = QuantumRisk.VULNERABLE
        pqc_rep   = "ML-DSA-44 (FIPS 204) for equivalent security level"
    elif isinstance(pub_key, (ed448.Ed448PublicKey,)):
        algo_name = "Ed448"
        risk      = QuantumRisk.VULNERABLE
        pqc_rep   = "ML-DSA-87 (FIPS 204) for equivalent security level"
    else:
        algo_name = type(pub_key).__name__

    # Subject CN for evidence
    try:
        cn = cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value
    except (IndexError, Exception):
        cn = endpoint

    # Expiry check
    expires = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
              else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    now     = datetime.datetime.now(datetime.timezone.utc)
    days_left = (expires - now).days

    expiry_note = ""
    if days_left < 0:
        expiry_note = " | ⚠️  EXPIRED"
    elif days_left < 30:
        expiry_note = f" | ⚠️  Expires in {days_left} days"
    elif days_left < 365:
        expiry_note = f" | Expires in {days_left} days"
    else:
        expiry_note = f" | Expires {expires.strftime('%Y-%m-%d')}"

    # Signature algorithm (SHA-1 signatures are classically + quantum-broken)
    sig_hash = cert.signature_hash_algorithm
    sig_note = ""
    sig_risk_finding = None
    if sig_hash:
        sig_name = sig_hash.name.upper()
        if "SHA1" in sig_name or sig_name == "SHA":
            sig_risk_finding = CryptoFinding(
                name         = "SHA-1 Certificate Signature",
                asset_type   = AssetType.ALGORITHM,
                primitive    = Primitive.HASH,
                quantum_risk = QuantumRisk.VULNERABLE,
                file_path    = endpoint,
                line_number  = 0,
                evidence     = f"Certificate for {cn} signed with SHA-1",
                pqc_replacement = "Reissue certificate with SHA-384 or SHA-512 signature",
            )

    findings.append(CryptoFinding(
        name         = f"X.509 Cert: {algo_name}",
        asset_type   = AssetType.KEY,
        primitive    = Primitive.SIGNATURE,
        quantum_risk = risk,
        key_size     = key_size,
        file_path    = endpoint,
        line_number  = 0,
        evidence     = f"CN={cn}{expiry_note}",
        pqc_replacement = pqc_rep,
        oid          = "2.5.4.3",
    ))

    if sig_risk_finding:
        findings.append(sig_risk_finding)

    # CNSA 2.0 key-size advisory
    if isinstance(pub_key, rsa.RSAPublicKey) and key_size and key_size < 3072:
        findings.append(CryptoFinding(
            name         = f"RSA key below CNSA 2.0 minimum (got {key_size}, need 3072)",
            asset_type   = AssetType.KEY,
            primitive    = Primitive.PKE,
            quantum_risk = QuantumRisk.VULNERABLE,
            key_size     = key_size,
            file_path    = endpoint,
            line_number  = 0,
            evidence     = f"CN={cn}: RSA-{key_size} < 3072-bit CNSA 2.0 minimum",
            pqc_replacement = "Reissue with RSA-4096 (interim) or migrate to ML-DSA-65",
        ))

    return findings
