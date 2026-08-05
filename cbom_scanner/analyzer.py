"""
Quantum risk analyzer.

Post-processes raw CryptoFindings to:
  1. Refine QuantumRisk based on detected key sizes
     (AES-128 = WEAKENED, AES-256 = SAFE; SHA-256 = WEAKENED, SHA-384 = SAFE)
  2. Deduplicate findings by (name, file, line)
  3. Produce a summary risk scorecard
"""

from __future__ import annotations
from collections import Counter
from .models import CryptoFinding, QuantumRisk, ScanResult, RISK_LABEL


# Key-size thresholds for "safe" symmetric / hash
_AES_SAFE_BITS   = 256
_SHA_SAFE_BITS   = 384
_SHA3_SAFE_BITS  = 384


def refine(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """Apply key-size aware risk refinement to a finding list."""
    out: list[CryptoFinding] = []
    for f in findings:
        f = _refine_one(f)
        out.append(f)
    return out


def deduplicate(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """Remove duplicate (name, file_path, line_number) triplets."""
    seen: set[tuple] = set()
    out: list[CryptoFinding] = []
    for f in findings:
        key = (f.name, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def scorecard(result: ScanResult) -> dict:
    """
    Return a structured risk scorecard for the scan result.

    Returned dict:
      total_findings   int
      by_risk          dict[str, int]   { "vulnerable": N, ... }
      by_algorithm     dict[str, int]   { "RSA": N, ... }
      migration_priority list[str]      algorithms to replace first
      risk_score       int              0–100 (100 = fully quantum-ready)
    """
    risk_counts: Counter = Counter()
    algo_counts: Counter = Counter()

    for f in result.findings:
        risk_counts[f.quantum_risk.value] += 1
        algo_counts[f.name] += 1

    total = len(result.findings)
    vulnerable = risk_counts.get("vulnerable", 0)
    weakened   = risk_counts.get("weakened",   0)
    safe_pqc   = risk_counts.get("safe", 0) + risk_counts.get("pqc", 0)

    # Score: 100 = all findings are safe/PQC.  Vulnerable penalises most.
    if total == 0:
        score = 100
    else:
        score = int(100 * safe_pqc / total - 30 * (vulnerable / total))
        score = max(0, min(100, score))

    # Priority: sort vulnerable > weakened by frequency
    priority: list[str] = []
    for alg, _ in sorted(
        [(a, c) for a, c in algo_counts.items()],
        key=lambda x: -x[1]
    ):
        findings_for_alg = [f for f in result.findings if f.name == alg]
        if any(f.quantum_risk == QuantumRisk.VULNERABLE for f in findings_for_alg):
            priority.append(alg)
    # then weakened
    for alg, _ in sorted(
        [(a, c) for a, c in algo_counts.items()],
        key=lambda x: -x[1]
    ):
        if alg not in priority:
            findings_for_alg = [f for f in result.findings if f.name == alg]
            if any(f.quantum_risk == QuantumRisk.WEAKENED for f in findings_for_alg):
                priority.append(alg)

    return {
        "total_findings":    total,
        "files_scanned":     result.files_scanned,
        "by_risk":           dict(risk_counts),
        "by_algorithm":      dict(algo_counts),
        "migration_priority": priority,
        "risk_score":        score,
        "risk_grade":        _grade(score),
    }


# ── private helpers ──────────────────────────────────────────────────────────

def _refine_one(f: CryptoFinding) -> CryptoFinding:
    name_upper = f.name.upper()

    if "AES" in name_upper:
        if f.key_size is None:
            f.quantum_risk = QuantumRisk.WEAKENED  # assume worst
        elif f.key_size >= _AES_SAFE_BITS:
            f.quantum_risk = QuantumRisk.SAFE
        else:
            f.quantum_risk = QuantumRisk.WEAKENED

    elif "SHA-3" in name_upper or "SHA3" in name_upper:
        if f.key_size and f.key_size >= _SHA3_SAFE_BITS:
            f.quantum_risk = QuantumRisk.SAFE
        else:
            f.quantum_risk = QuantumRisk.WEAKENED

    elif "SHA" in name_upper:
        if f.key_size == 1:          # SHA-1
            f.quantum_risk = QuantumRisk.VULNERABLE
        elif f.key_size and f.key_size >= _SHA_SAFE_BITS:
            f.quantum_risk = QuantumRisk.SAFE
        else:
            f.quantum_risk = QuantumRisk.WEAKENED

    return f


def _grade(score: int) -> str:
    if score >= 90:
        return "A — Quantum-Ready"
    if score >= 70:
        return "B — Mostly Safe"
    if score >= 50:
        return "C — Mixed (action needed)"
    if score >= 25:
        return "D — High Risk"
    return "F — Critically Vulnerable"
