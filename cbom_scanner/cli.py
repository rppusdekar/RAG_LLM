"""
cbom-scan CLI entry point.

Usage:
    python -m cbom_scanner.cli <path> [options]
    python -m cbom_scanner.cli --tls <host>[:<port>] [options]
    python -m cbom_scanner.cli <path> --tls <host>[:<port>] [options]

Examples:
    # Source code scan
    python -m cbom_scanner.cli .
    python -m cbom_scanner.cli pqc_phase4 --format json

    # Live TLS endpoint scan
    python -m cbom_scanner.cli --tls github.com
    python -m cbom_scanner.cli --tls internal.corp:8443 --no-verify

    # Combined: source code + TLS endpoint
    python -m cbom_scanner.cli src/ --tls api.example.com

    # HTML report
    python -m cbom_scanner.cli . --tls api.example.com --format html --output report.html

    # CI gate — exits 1 if VULNERABLE findings exist
    python -m cbom_scanner.cli src/ --tls api.example.com --min-risk vulnerable
"""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from .scanner import scan, scan_tls
from .reporter import print_table, write_html, to_cyclonedx
from .models import ScanResult, QuantumRisk


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cbom-scan",
        description=(
            "Cryptographic Bill of Materials (CBOM) scanner.\n"
            "Detect crypto assets in source code and live TLS endpoints,\n"
            "classify quantum risk, and output CycloneDX 1.6 CBOM JSON."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="File or directory to scan for crypto assets (optional if --tls is provided)",
    )
    parser.add_argument(
        "--tls", "-t",
        metavar="HOST[:PORT]",
        help="Also scan a live TLS endpoint (default port: 443)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip TLS certificate verification (for self-signed / internal hosts)",
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
        help="Write output to this file (required for html; optional for json/cyclonedx)",
    )
    parser.add_argument(
        "--max-file-size", "-m",
        type=int,
        default=500,
        metavar="KB",
        help="Skip source files larger than this (default: 500 KB)",
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
        help="Suppress progress messages on stderr",
    )

    args = parser.parse_args()

    if not args.target and not args.tls:
        parser.print_help()
        return 2

    # ── Source code scan ──────────────────────────────────────────────────────
    result: ScanResult | None = None

    if args.target:
        target = Path(args.target)
        if not target.exists():
            print(f"Error: path not found: {target}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"Scanning source: {target} …", file=sys.stderr)
        result = scan(target, max_file_size_kb=args.max_file_size)

    # ── TLS endpoint scan ─────────────────────────────────────────────────────
    if args.tls:
        host, port = _parse_hostport(args.tls)
        if not args.quiet:
            print(f"Scanning TLS endpoint: {host}:{port} …", file=sys.stderr)
        tls_result = scan_tls(host, port, verify=not args.no_verify)

        if result is None:
            result = tls_result
        else:
            # Merge TLS findings into the source-code result
            result.findings.extend(tls_result.findings)

    if result is None:
        return 0

    # ── Risk filter ───────────────────────────────────────────────────────────
    if args.min_risk:
        _RISK_ORDER = {
            "vulnerable": 0, "weakened": 1,
            "unknown": 2, "safe": 3, "pqc": 4,
        }
        min_level = _RISK_ORDER[args.min_risk]
        result.findings = [
            f for f in result.findings
            if _RISK_ORDER.get(f.quantum_risk.value, 9) <= min_level
        ]

    # ── Output ────────────────────────────────────────────────────────────────
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

    # Exit code 1 if any VULNERABLE findings (CI-friendly)
    has_vuln = any(f.quantum_risk == QuantumRisk.VULNERABLE for f in result.findings)
    return 1 if has_vuln else 0


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_hostport(value: str) -> tuple[str, int]:
    """Parse 'host' or 'host:port' → (host, port)."""
    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass
    return value, 443


if __name__ == "__main__":
    sys.exit(main())
