"""
cbom-scan CLI entry point.

Usage:
    python -m cbom_scanner.cli <path> [options]

Examples:
    python -m cbom_scanner.cli .                         # scan whole project
    python -m cbom_scanner.cli pqc_phase4 --format json  # JSON output
    python -m cbom_scanner.cli pqc_phase3 --output report.html --format html
    python -m cbom_scanner.cli pqc_phase4 --format cyclonedx --output cbom.json
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from .scanner import scan
from .reporter import print_table, write_cyclonedx, write_html, to_cyclonedx


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cbom-scan",
        description="Cryptographic Bill of Materials (CBOM) scanner — "
                    "detect crypto assets, classify quantum risk, output CycloneDX 1.6.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        help="File or directory to scan",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "cyclonedx", "html"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help="Write output to this file (default: stdout for json/cyclonedx, "
             "required for html)",
    )
    parser.add_argument(
        "--max-file-size", "-m",
        type=int,
        default=500,
        metavar="KB",
        help="Skip files larger than this (default: 500 KB)",
    )
    parser.add_argument(
        "--min-risk",
        choices=["vulnerable", "weakened", "safe", "pqc", "unknown"],
        default=None,
        help="Only show findings at or above this risk level",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output (non-table formats)",
    )

    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"Scanning {target} …", file=sys.stderr)

    result = scan(target, max_file_size_kb=args.max_file_size)

    # Filter by minimum risk level if requested
    if args.min_risk:
        _RISK_ORDER = {"vulnerable": 0, "weakened": 1, "unknown": 2, "safe": 3, "pqc": 4}
        min_level = _RISK_ORDER[args.min_risk]
        result.findings = [
            f for f in result.findings
            if _RISK_ORDER.get(f.quantum_risk.value, 9) <= min_level
        ]

    # ── Output ───────────────────────────────────────────────────────────────
    fmt = args.format

    if fmt == "table":
        print_table(result)

    elif fmt in ("json", "cyclonedx"):
        doc = to_cyclonedx(result)
        payload = json.dumps(doc, indent=2)
        if args.output:
            Path(args.output).write_text(payload, encoding="utf-8")
            if not args.quiet:
                print(f"CycloneDX CBOM written to {args.output}", file=sys.stderr)
        else:
            print(payload)

    elif fmt == "html":
        if not args.output:
            print("Error: --output is required for HTML format", file=sys.stderr)
            return 2
        write_html(result, args.output)
        if not args.quiet:
            print(f"HTML report written to {args.output}", file=sys.stderr)

    # Exit code: 1 if any vulnerable findings, 0 otherwise
    from .models import QuantumRisk
    has_vuln = any(f.quantum_risk == QuantumRisk.VULNERABLE for f in result.findings)
    return 1 if has_vuln else 0


if __name__ == "__main__":
    sys.exit(main())
