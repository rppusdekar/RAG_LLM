"""
Detection patterns for cryptographic assets.

Each entry maps a compiled regex → CryptoFinding template fields.
The scanner engine matches these against each source line and fills
in file_path, line_number, and evidence at match time.
"""

from __future__ import annotations
import re
from .models import AssetType, Primitive, QuantumRisk

# ─────────────────────────────────────────────────────────────────────────────
# Each pattern dict keys:
#   regex        – compiled pattern (case-insensitive)
#   name         – algorithm / asset name
#   asset_type   – AssetType enum
#   primitive    – Primitive enum
#   quantum_risk – QuantumRisk enum
#   key_size     – int or None  (overridden by capture group "bits" when present)
#   mode         – string or "" (overridden by capture group "mode" when present)
#   pqc_replacement – recommended alternative
#   oid          – algorithm OID (optional)
#   library      – hinted library (optional)
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS: list[dict] = [

    # ── Quantum-VULNERABLE: public-key / asymmetric ───────────────────────────

    {
        "regex": re.compile(
            r"RSA[._\-\s(]*(?P<bits>\d{3,5})?", re.IGNORECASE
        ),
        "name": "RSA",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.PKE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "ML-KEM-768 (FIPS 203) for key exchange; ML-DSA-65 (FIPS 204) for signatures",
        "oid": "1.2.840.113549.1.1.1",
    },
    {
        "regex": re.compile(
            r"\bEC(?:DSA|DH|ies)?\b|elliptic[_\s-]?curve", re.IGNORECASE
        ),
        "name": "ECC",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "ML-DSA-65 (FIPS 204) for signatures; ML-KEM-768 (FIPS 203) for key exchange",
        "oid": "1.2.840.10045.2.1",
    },
    {
        "regex": re.compile(
            r"\b(?:DHE?|ECDHE?|DiffieHellman|diffie[_\-]hellman)\b", re.IGNORECASE
        ),
        "name": "Diffie-Hellman",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.KEY_EXCHANGE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "ML-KEM-768 (FIPS 203) or X25519+ML-KEM-768 hybrid",
        "oid": "1.2.840.10046.2.1",
    },
    {
        "regex": re.compile(r"\bDSA\b(?!\s*-\s*(?:44|65|87))", re.IGNORECASE),
        "name": "DSA",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "ML-DSA-65 (FIPS 204)",
        "oid": "1.2.840.10040.4.1",
    },
    {
        "regex": re.compile(r"\bElGamal\b", re.IGNORECASE),
        "name": "ElGamal",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.PKE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "ML-KEM-768 (FIPS 203)",
        "oid": "",
    },

    # ── Quantum-WEAKENED: symmetric / hash (Grover halves effective key size) ─

    {
        "regex": re.compile(
            r"AES[._\-\s(\"']*(?P<bits>128|192|256)?(?:[._\-\s\"']*(?P<mode>GCM|CBC|CTR|ECB|CCM|SIV|OCB|CFB|OFB))?",
            re.IGNORECASE,
        ),
        "name": "AES",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.AE,
        "quantum_risk": QuantumRisk.WEAKENED,   # resolved to SAFE/WEAKENED in analyzer
        "key_size": None,
        "mode": "",
        "pqc_replacement": "AES-256-GCM is quantum-safe at NIST Level 1 (keep key ≥256 bits)",
        "oid": "2.16.840.1.101.3.4.1",
    },
    {
        "regex": re.compile(r"\bSHA[-_]?(?P<bits>1|224|256|384|512)\b", re.IGNORECASE),
        "name": "SHA",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.HASH,
        "quantum_risk": QuantumRisk.WEAKENED,   # resolved in analyzer
        "key_size": None,
        "mode": "",
        "pqc_replacement": "SHA-384 or SHA-512 (sufficient Grover margin)",
        "oid": "2.16.840.1.101.3.4.2",
    },
    {
        "regex": re.compile(r"\bMD5\b", re.IGNORECASE),
        "name": "MD5",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.HASH,
        "quantum_risk": QuantumRisk.VULNERABLE,  # classically broken too
        "key_size": 128,
        "mode": "",
        "pqc_replacement": "SHA-384 or SHA-512",
        "oid": "1.2.840.113549.2.5",
    },
    {
        "regex": re.compile(r"\bSHA[-_]?3[-_]?(?P<bits>224|256|384|512)\b", re.IGNORECASE),
        "name": "SHA-3",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.HASH,
        "quantum_risk": QuantumRisk.WEAKENED,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "SHA3-384 or SHA3-512 for quantum margin",
        "oid": "2.16.840.1.101.3.4.2.7",
    },
    {
        "regex": re.compile(
            r"\b(?:ChaCha20|CHACHA20)(?:[_\-]Poly1305)?\b", re.IGNORECASE
        ),
        "name": "ChaCha20-Poly1305",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.AE,
        "quantum_risk": QuantumRisk.SAFE,
        "key_size": 256,
        "mode": "",
        "pqc_replacement": "Already quantum-safe at 256-bit key",
        "oid": "",
    },
    {
        "regex": re.compile(r"\bHMAC\b", re.IGNORECASE),
        "name": "HMAC",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.MAC,
        "quantum_risk": QuantumRisk.WEAKENED,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "HMAC-SHA384 or HMAC-SHA512",
        "oid": "",
    },
    {
        "regex": re.compile(r"\b3DES\b|\bTripleDES\b|\bDES3\b", re.IGNORECASE),
        "name": "3DES",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.SYMMETRIC,
        "quantum_risk": QuantumRisk.VULNERABLE,  # classically weak + quantum
        "key_size": 112,
        "mode": "",
        "pqc_replacement": "AES-256-GCM",
        "oid": "1.2.840.113549.3.7",
    },
    {
        "regex": re.compile(r"\b(?:RC4|ARCFOUR)\b", re.IGNORECASE),
        "name": "RC4",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.SYMMETRIC,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "oid": "",
    },

    # ── NIST PQC standards (quantum-SAFE) ─────────────────────────────────────

    {
        "regex": re.compile(
            r"\bML[-_]KEM[-_]?(?P<bits>512|768|1024)?\b|CRYSTALS[-_]Kyber|kyber", re.IGNORECASE
        ),
        "name": "ML-KEM",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.PKE,
        "quantum_risk": QuantumRisk.PQC,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "Already NIST FIPS 203 (ML-KEM)",
        "oid": "",
    },
    {
        "regex": re.compile(
            r"\bML[-_]DSA[-_]?(?P<bits>44|65|87)?\b|CRYSTALS[-_]Dilithium|dilithium", re.IGNORECASE
        ),
        "name": "ML-DSA",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.PQC,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "Already NIST FIPS 204 (ML-DSA)",
        "oid": "",
    },
    {
        "regex": re.compile(
            r"\bSLH[-_]DSA\b|SPHINCS\+?|sphincs", re.IGNORECASE
        ),
        "name": "SLH-DSA",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.PQC,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "Already NIST FIPS 205 (SLH-DSA)",
        "oid": "",
    },
    {
        "regex": re.compile(r"\bFalcon\b", re.IGNORECASE),
        "name": "Falcon",
        "asset_type": AssetType.ALGORITHM,
        "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.PQC,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "Already PQC (NIST Round 4 alternate); prefer ML-DSA for FIPS compliance",
        "oid": "",
    },

    # ── TLS / Protocol versions ───────────────────────────────────────────────

    {
        "regex": re.compile(r"\bSSLv?[23]\b|TLS[v_\s]?1[._][012]\b", re.IGNORECASE),
        "name": "Deprecated TLS/SSL",
        "asset_type": AssetType.PROTOCOL,
        "primitive": Primitive.PROTOCOL,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "TLS 1.3 with ML-KEM hybrid cipher suite",
        "oid": "",
    },
    {
        "regex": re.compile(r"\bTLS[v_\s]?1[._]3\b|TLSv1_3", re.IGNORECASE),
        "name": "TLS 1.3",
        "asset_type": AssetType.PROTOCOL,
        "primitive": Primitive.PROTOCOL,
        "quantum_risk": QuantumRisk.WEAKENED,   # safe today; add ML-KEM for PQC
        "key_size": None,
        "mode": "",
        "pqc_replacement": "TLS 1.3 + X25519MLKEM768 hybrid (draft-ietf-tls-hybrid-design)",
        "oid": "",
    },

    # ── Crypto libraries (hints context, not algorithm itself) ────────────────

    {
        "regex": re.compile(r"\bopenssl\b", re.IGNORECASE),
        "name": "OpenSSL",
        "asset_type": AssetType.LIBRARY,
        "primitive": Primitive.OTHER,
        "quantum_risk": QuantumRisk.UNKNOWN,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "OpenSSL 3.x + OQS provider for PQC",
        "oid": "",
    },
    {
        "regex": re.compile(r"\bbouncycastle\b|BouncyCastle|org\.bouncycastle", re.IGNORECASE),
        "name": "Bouncy Castle",
        "asset_type": AssetType.LIBRARY,
        "primitive": Primitive.OTHER,
        "quantum_risk": QuantumRisk.UNKNOWN,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "Bouncy Castle PQC module or liboqs-java",
        "oid": "",
    },
    {
        "regex": re.compile(r"\bliboqs\b|open.?quantum.?safe", re.IGNORECASE),
        "name": "liboqs",
        "asset_type": AssetType.LIBRARY,
        "primitive": Primitive.OTHER,
        "quantum_risk": QuantumRisk.PQC,
        "key_size": None,
        "mode": "",
        "pqc_replacement": "Already using Open Quantum Safe library",
        "oid": "",
    },
]
