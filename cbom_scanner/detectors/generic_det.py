"""
Generic line-by-line regex detector.

Applies every pattern in patterns.PATTERNS to each line of a text file.
Works for Python, JavaScript, Java, Go, C/C++, YAML, config files, etc.
"""

from __future__ import annotations
import copy
from pathlib import Path

from .base import BaseDetector
from ..models import CryptoFinding, QuantumRisk
from ..patterns import PATTERNS

# File extensions this detector accepts (broad — covers most source + config)
_SUPPORTED = {
    ".py", ".pyw",
    ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".scala",
    ".go",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    ".cs",
    ".rb",
    ".php",
    ".rs",
    ".swift",
    ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".env",
    ".json",
    ".xml",
    ".sh", ".bash", ".zsh",
    ".tf",           # Terraform
    ".gradle",
    ".pom",
}

# Lines longer than this are truncated in evidence to avoid noise
_MAX_EVIDENCE = 120


class GenericDetector(BaseDetector):
    """Regex-based detector — language-agnostic, line-by-line."""

    supported_extensions: set[str] = _SUPPORTED

    def detect(self, path: Path) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return findings

        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            for pat in PATTERNS:
                m = pat["regex"].search(line)
                if not m:
                    continue

                finding = CryptoFinding(
                    name         = pat["name"],
                    asset_type   = pat["asset_type"],
                    primitive    = pat["primitive"],
                    quantum_risk = pat["quantum_risk"],
                    key_size     = pat.get("key_size"),
                    mode         = pat.get("mode", ""),
                    pqc_replacement = pat.get("pqc_replacement", ""),
                    oid          = pat.get("oid", ""),
                    file_path    = str(path),
                    line_number  = lineno,
                    evidence     = line[:_MAX_EVIDENCE],
                )

                # Extract named capture groups when present
                try:
                    bits = m.group("bits")
                    if bits:
                        finding.key_size = int(bits)
                except IndexError:
                    pass

                try:
                    mode = m.group("mode")
                    if mode:
                        finding.mode = mode.upper()
                except IndexError:
                    pass

                findings.append(finding)

        return findings
