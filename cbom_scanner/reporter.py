"""
Output formatters for CBOM scan results.

  - CycloneDX 1.6 JSON  (machine-readable, standard)
  - Console table       (human-readable, for the terminal)
  - HTML report         (shareable, self-contained)
"""

from __future__ import annotations
import json
import datetime
from pathlib import Path
from .models import ScanResult, CryptoFinding, QuantumRisk, AssetType, RISK_LABEL
from .analyzer import scorecard


# ── CycloneDX 1.6 CBOM JSON ─────────────────────────────────────────────────

def to_cyclonedx(result: ScanResult) -> dict:
    """Return a CycloneDX 1.6 CBOM dict (ready for json.dumps)."""
    card = scorecard(result)

    components = []
    for f in result.findings:
        comp: dict = {
            "type":    f.asset_type.value,
            "bom-ref": f.bom_ref,
            "name":    f.name,
            "evidence": {
                "occurrences": [{
                    "location": f.file_path,
                    "line":     f.line_number,
                    "offset":   0,
                    "symbol":   f.evidence[:80],
                }]
            },
            "cryptoProperties": {
                "assetType": f.asset_type.value,
            },
        }

        if f.asset_type == AssetType.ALGORITHM:
            algo_props: dict = {
                "primitive": f.primitive.value,
                "executionEnvironment": "software",
                "implementationPlatform": "any",
                "certificationLevel": ["none"],
            }
            if f.key_size:
                algo_props["parameterSetIdentifier"] = str(f.key_size)
            if f.mode:
                algo_props["mode"] = f.mode.lower()
            comp["cryptoProperties"]["algorithmProperties"] = algo_props

        if f.oid:
            comp["cryptoProperties"]["oid"] = f.oid

        # CBOM extension: quantum risk annotation
        comp["_quantumRisk"] = {
            "level":           f.quantum_risk.value,
            "pqcReplacement":  f.pqc_replacement,
        }

        components.append(comp)

    return {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.6",
        "version":     1,
        "serialNumber": f"urn:uuid:{_now_uuid()}",
        "metadata": {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "tools": [{
                "vendor":  "cbom-scanner",
                "name":    "cbom-scanner",
                "version": "0.1.0",
            }],
            "component": {
                "type":    "application",
                "name":    Path(result.target_path).name,
                "version": "unknown",
            },
            "properties": [
                {"name": "cbom:filesScanned",   "value": str(result.files_scanned)},
                {"name": "cbom:scanDurationSec","value": f"{result.scan_duration_s:.2f}"},
                {"name": "cbom:riskScore",      "value": str(card["risk_score"])},
                {"name": "cbom:riskGrade",      "value": card["risk_grade"]},
            ],
        },
        "components": components,
    }


def write_cyclonedx(result: ScanResult, output_path: str) -> None:
    doc = to_cyclonedx(result)
    Path(output_path).write_text(json.dumps(doc, indent=2), encoding="utf-8")


# ── Console table ────────────────────────────────────────────────────────────

def print_table(result: ScanResult) -> None:
    card = scorecard(result)
    W = 100

    print("\n" + "=" * W)
    print(f"  CBOM SCAN REPORT — {result.target_path}")
    print("=" * W)
    print(f"  Files scanned : {result.files_scanned}  |  "
          f"Findings : {card['total_findings']}  |  "
          f"Duration : {result.scan_duration_s:.2f}s  |  "
          f"Risk score : {card['risk_score']}/100  ({card['risk_grade']})")
    print()

    # Risk summary bar
    counts = card["by_risk"]
    vuln = counts.get("vulnerable", 0)
    weak = counts.get("weakened",   0)
    safe = counts.get("safe",       0)
    pqc  = counts.get("pqc",        0)
    print(f"  🔴 Vulnerable : {vuln:3d}   🟡 Weakened : {weak:3d}   "
          f"🟢 Safe : {safe:3d}   ✅ PQC : {pqc:3d}")
    print()

    if card["migration_priority"]:
        print("  Migration priority (fix these first):")
        for i, alg in enumerate(card["migration_priority"], 1):
            findings = [f for f in result.findings if f.name == alg]
            rep = findings[0].pqc_replacement if findings else ""
            print(f"    {i}. {alg:30s} → {rep}")
        print()

    if not result.findings:
        print("  No cryptographic assets detected.\n")
        return

    # Detail table
    col = [8, 22, 14, 8, 8, 35]
    hdr = ["Risk", "Algorithm", "File", "Line", "Key", "Evidence"]
    sep = "  ".join("-" * c for c in col)
    fmt = "  ".join(f"{{:<{c}}}" for c in col)

    print("  " + fmt.format(*hdr))
    print("  " + sep)

    # Sort: vulnerable first, then weakened, then others
    order = {QuantumRisk.VULNERABLE: 0, QuantumRisk.WEAKENED: 1,
             QuantumRisk.UNKNOWN: 2, QuantumRisk.SAFE: 3, QuantumRisk.PQC: 4}
    for f in sorted(result.findings, key=lambda x: (order.get(x.quantum_risk, 9), x.file_path)):
        emoji, label = RISK_LABEL[f.quantum_risk]
        file_short = Path(f.file_path).name[:col[2]]
        key_str = f"{f.key_size}b" if f.key_size else ""
        evid = f.evidence[:col[5]]
        print("  " + fmt.format(
            f"{emoji} {label[:6]}",
            f.name[:col[1]],
            file_short,
            str(f.line_number),
            key_str,
            evid,
        ))

    print("=" * W + "\n")


# ── HTML report ──────────────────────────────────────────────────────────────

def write_html(result: ScanResult, output_path: str) -> None:
    card = scorecard(result)
    counts = card["by_risk"]
    vuln = counts.get("vulnerable", 0)
    weak = counts.get("weakened",   0)
    safe = counts.get("safe",       0) + counts.get("pqc", 0)

    RISK_COLOR = {
        QuantumRisk.VULNERABLE: "#dc2626",
        QuantumRisk.WEAKENED:   "#d97706",
        QuantumRisk.SAFE:       "#16a34a",
        QuantumRisk.PQC:        "#2563eb",
        QuantumRisk.UNKNOWN:    "#6b7280",
    }

    rows = ""
    order = {QuantumRisk.VULNERABLE: 0, QuantumRisk.WEAKENED: 1,
             QuantumRisk.UNKNOWN: 2, QuantumRisk.SAFE: 3, QuantumRisk.PQC: 4}
    for f in sorted(result.findings, key=lambda x: (order.get(x.quantum_risk, 9), x.file_path)):
        color = RISK_COLOR[f.quantum_risk]
        emoji, label = RISK_LABEL[f.quantum_risk]
        rows += (
            f"<tr>"
            f"<td style='color:{color};font-weight:bold'>{emoji} {label}</td>"
            f"<td>{f.name}</td>"
            f"<td>{Path(f.file_path).name}</td>"
            f"<td>{f.line_number}</td>"
            f"<td>{f.key_size or ''}</td>"
            f"<td><code>{f.evidence[:80]}</code></td>"
            f"<td style='font-size:0.85em'>{f.pqc_replacement}</td>"
            f"</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CBOM Scan Report — {result.target_path}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1e293b; }}
  h1   {{ color: #0f172a; }}
  .scorecard {{ display:flex; gap:2rem; margin:1rem 0 2rem; flex-wrap:wrap; }}
  .card {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px;
           padding:1rem 1.5rem; min-width:140px; text-align:center; }}
  .card .num {{ font-size:2rem; font-weight:bold; }}
  .vuln  {{ color:#dc2626; }}
  .weak  {{ color:#d97706; }}
  .safe  {{ color:#16a34a; }}
  .pqc   {{ color:#2563eb; }}
  table  {{ border-collapse:collapse; width:100%; font-size:0.9rem; }}
  th     {{ background:#1e293b; color:#fff; padding:0.5rem; text-align:left; }}
  td     {{ padding:0.4rem 0.6rem; border-bottom:1px solid #e2e8f0; }}
  tr:hover {{ background:#f1f5f9; }}
  code   {{ background:#f1f5f9; padding:0.1rem 0.3rem; border-radius:3px;
            font-size:0.82rem; }}
  .grade {{ font-size:1.2rem; font-weight:bold; margin-top:0.25rem; }}
</style>
</head>
<body>
<h1>CBOM Scan Report</h1>
<p><strong>Target:</strong> {result.target_path} &nbsp;|&nbsp;
   <strong>Scanned:</strong> {result.files_scanned} files &nbsp;|&nbsp;
   <strong>Generated:</strong> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>

<div class="scorecard">
  <div class="card"><div class="num vuln">{vuln}</div>Vulnerable</div>
  <div class="card"><div class="num weak">{weak}</div>Weakened</div>
  <div class="card"><div class="num safe">{safe}</div>Safe / PQC</div>
  <div class="card">
    <div class="num">{card['risk_score']}</div>
    <div class="grade">{card['risk_grade']}</div>
  </div>
</div>

<h2>Findings</h2>
<table>
<thead>
  <tr><th>Risk</th><th>Algorithm</th><th>File</th><th>Line</th>
      <th>Key bits</th><th>Evidence</th><th>PQC Replacement</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")


# ── helpers ──────────────────────────────────────────────────────────────────

def _now_uuid() -> str:
    import uuid
    return str(uuid.uuid4())
