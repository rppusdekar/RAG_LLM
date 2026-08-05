"""
AST-based Python detector.

Walks the Python AST to find:
  - Import statements (from cryptography.hazmat... import ...)
  - Function calls with crypto-related names
  - String literals that look like algorithm names

Complements GenericDetector with higher-fidelity Python-specific findings.
"""

from __future__ import annotations
import ast
from pathlib import Path
from .base import BaseDetector
from ..models import (
    AssetType, CryptoFinding, Primitive, QuantumRisk,
)

# Map import module prefixes → finding templates
_IMPORT_MAP: dict[str, dict] = {
    "cryptography.hazmat.primitives.asymmetric.rsa": {
        "name": "RSA", "primitive": Primitive.PKE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "ML-KEM-768 (FIPS 203) or ML-DSA-65 (FIPS 204)",
    },
    "cryptography.hazmat.primitives.asymmetric.ec": {
        "name": "ECC", "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "ML-DSA-65 (FIPS 204)",
    },
    "cryptography.hazmat.primitives.asymmetric.dh": {
        "name": "Diffie-Hellman", "primitive": Primitive.KEY_EXCHANGE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "ML-KEM-768 (FIPS 203)",
    },
    "cryptography.hazmat.primitives.asymmetric.dsa": {
        "name": "DSA", "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "ML-DSA-65 (FIPS 204)",
    },
    "cryptography.hazmat.primitives.ciphers.algorithms": {
        "name": "AES", "primitive": Primitive.AE,
        "quantum_risk": QuantumRisk.WEAKENED,
        "pqc_replacement": "AES-256-GCM (quantum-safe at 256-bit)",
    },
    "Crypto.PublicKey.RSA": {
        "name": "RSA (PyCryptodome)", "primitive": Primitive.PKE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "ML-KEM-768 (FIPS 203)",
    },
    "Crypto.PublicKey.ECC": {
        "name": "ECC (PyCryptodome)", "primitive": Primitive.SIGNATURE,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "ML-DSA-65 (FIPS 204)",
    },
    "ssl": {
        "name": "ssl module (TLS)", "primitive": Primitive.PROTOCOL,
        "quantum_risk": QuantumRisk.WEAKENED,
        "pqc_replacement": "TLS 1.3 + ML-KEM hybrid cipher suite",
    },
    "oqs": {
        "name": "liboqs (Open Quantum Safe)", "primitive": Primitive.OTHER,
        "quantum_risk": QuantumRisk.PQC,
        "pqc_replacement": "Already using PQC library",
    },
    "hashlib": {
        "name": "hashlib", "primitive": Primitive.HASH,
        "quantum_risk": QuantumRisk.WEAKENED,
        "pqc_replacement": "Use SHA-384/SHA-512 variants for quantum margin",
    },
    "hmac": {
        "name": "HMAC", "primitive": Primitive.MAC,
        "quantum_risk": QuantumRisk.WEAKENED,
        "pqc_replacement": "HMAC-SHA384 or HMAC-SHA512",
    },
    "jwt": {
        "name": "PyJWT (JWT library)", "primitive": Primitive.OTHER,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "Post-Quantum Token (PQT) with ML-DSA-65 signatures",
    },
    "jose": {
        "name": "JOSE (JWT/JWE/JWK)", "primitive": Primitive.OTHER,
        "quantum_risk": QuantumRisk.VULNERABLE,
        "pqc_replacement": "Post-Quantum Token (PQT) with ML-DSA-65 signatures",
    },
}


class PythonDetector(BaseDetector):
    """AST-based detector for Python source files."""

    supported_extensions: set[str] = {".py", ".pyw"}

    def detect(self, path: Path) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError):
            return findings

        lines = source.splitlines()

        def evidence(lineno: int) -> str:
            if 1 <= lineno <= len(lines):
                return lines[lineno - 1].strip()[:120]
            return ""

        def make(template: dict, lineno: int, extra_name: str = "") -> CryptoFinding:
            return CryptoFinding(
                name         = extra_name or template["name"],
                asset_type   = AssetType.ALGORITHM,
                primitive    = template["primitive"],
                quantum_risk = template["quantum_risk"],
                pqc_replacement = template.get("pqc_replacement", ""),
                file_path    = str(path),
                line_number  = lineno,
                evidence     = evidence(lineno),
                library      = template.get("library", ""),
            )

        for node in ast.walk(tree):
            # ── import foo.bar ──────────────────────────────────────────────
            if isinstance(node, ast.Import):
                for alias in node.names:
                    tmpl = self._match_import(alias.name)
                    if tmpl:
                        findings.append(make(tmpl, node.lineno))

            # ── from foo.bar import baz ─────────────────────────────────────
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                tmpl = self._match_import(module)
                if tmpl:
                    findings.append(make(tmpl, node.lineno))

            # ── hashlib.new("md5") / hashlib.sha256() ──────────────────────
            elif isinstance(node, ast.Call):
                self._check_hashlib_call(node, path, evidence, findings)

        return findings

    # ── helpers ─────────────────────────────────────────────────────────────

    def _match_import(self, module: str) -> dict | None:
        """Return the best matching template for a module path."""
        for prefix, tmpl in _IMPORT_MAP.items():
            if module == prefix or module.startswith(prefix + "."):
                return tmpl
        return None

    def _check_hashlib_call(
        self,
        node: ast.Call,
        path: Path,
        evidence_fn,
        findings: list[CryptoFinding],
    ) -> None:
        """Detect hashlib.new("md5") and hashlib.<alg>() patterns."""
        weak_hashes = {"md5", "sha1", "sha"}
        safe_hashes = {"sha384", "sha512", "sha3_384", "sha3_512"}

        # hashlib.new("md5", ...)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
            and node.func.attr == "new"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            alg = str(node.args[0].value).lower().replace("-", "")
            risk = (
                QuantumRisk.VULNERABLE if alg in weak_hashes
                else QuantumRisk.SAFE if alg in safe_hashes
                else QuantumRisk.WEAKENED
            )
            findings.append(CryptoFinding(
                name         = f"hashlib.{node.args[0].value}",
                asset_type   = AssetType.ALGORITHM,
                primitive    = Primitive.HASH,
                quantum_risk = risk,
                pqc_replacement = "SHA-384 or SHA-512",
                file_path    = str(path),
                line_number  = node.lineno,
                evidence     = evidence_fn(node.lineno),
            ))
