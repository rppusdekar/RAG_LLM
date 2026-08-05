# CBOM Scanner

A **Cryptographic Bill of Materials (CBOM)** scanner that inventories cryptographic assets in source code, classifies quantum risk, and outputs industry-standard **CycloneDX 1.6 CBOM JSON**.

Built to support the role of a **Cryptographic Inventory Analyst** — the person responsible for knowing exactly what crypto an organisation is running, which is vulnerable to a quantum computer, and what the migration path to NIST PQC looks like.

---

## What it does

```
Source code  →  Detect crypto assets  →  Classify quantum risk  →  CycloneDX CBOM
```

| Step | Detail |
|---|---|
| **Detect** | Regex + Python AST detectors across `.py`, `.js`, `.java`, `.go`, `.c`, `.yaml`, config files, and more |
| **Classify** | Vulnerable (Shor) / Weakened (Grover) / Safe / PQC — with key-size refinement |
| **Report** | Console table, CycloneDX 1.6 JSON, self-contained HTML |

---

## Quick start

```bash
# Scan a directory — console table
python -m cbom_scanner.cli pqc_phase4

# Export CycloneDX CBOM JSON
python -m cbom_scanner.cli pqc_phase4 --format cyclonedx --output cbom.json

# HTML report
python -m cbom_scanner.cli . --format html --output cbom_report.html

# Only show vulnerable + weakened findings
python -m cbom_scanner.cli . --min-risk weakened

# Exit code 1 if any VULNERABLE findings found (useful in CI)
python -m cbom_scanner.cli src/ && echo "No quantum-vulnerable crypto found"
```

---

## Output formats

### Console table (default)
```
====================================================================================================
  CBOM SCAN REPORT — pqc_phase4
====================================================================================================
  Files scanned : 6  |  Findings : 14  |  Duration : 0.12s  |  Risk score : 72/100  (B — Mostly Safe)

  🔴 Vulnerable :   2   🟡 Weakened :   5   🟢 Safe :   3   ✅ PQC :   4

  Migration priority (fix these first):
    1. RSA                           → ML-KEM-768 (FIPS 203) or ML-DSA-65 (FIPS 204)
    2. SHA                           → SHA-384 or SHA-512
```

### CycloneDX 1.6 CBOM JSON
Standard format for supply-chain tooling, SBOM dashboards, and compliance systems.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [{
    "type": "algorithm",
    "name": "RSA",
    "cryptoProperties": {
      "assetType": "algorithm",
      "algorithmProperties": {
        "primitive": "pke",
        "parameterSetIdentifier": "2048"
      },
      "oid": "1.2.840.113549.1.1.1"
    },
    "_quantumRisk": {
      "level": "vulnerable",
      "pqcReplacement": "ML-KEM-768 (FIPS 203) for key exchange; ML-DSA-65 (FIPS 204) for signatures"
    }
  }]
}
```

### HTML report
Self-contained single-file report with risk scorecard and sortable findings table. Open in any browser — no server needed.

---

## Detection coverage

### Quantum-VULNERABLE (🔴 — broken by Shor's algorithm)
| Algorithm | Examples detected |
|---|---|
| RSA | `RSA.generate(2048)`, `from cryptography...rsa import`, `RSA_2048` |
| ECC / ECDSA / ECDH | `ECDSA`, `ec.generate_private_key`, `ECDHE` |
| Diffie-Hellman | `DHE`, `DiffieHellman`, `dh.generate_parameters` |
| DSA | `DSA.generate`, `from cryptography...dsa` |
| MD5 | `hashlib.md5`, `MD5` |
| 3DES / RC4 | Classically weak + quantum-broken |
| Deprecated TLS | `SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`, `TLSv1.2` |

### Quantum-WEAKENED (🟡 — Grover halves effective key size)
| Algorithm | Safe threshold |
|---|---|
| AES | AES-256 → Safe ✅; AES-128 → Weakened |
| SHA | SHA-384/512 → Safe ✅; SHA-256 → Weakened |
| SHA-3 | SHA3-384/512 → Safe ✅ |
| HMAC | HMAC-SHA384+ → Safe ✅ |
| TLS 1.3 | Safe today; add ML-KEM hybrid for PQC |

### NIST PQC Standards (✅ — quantum-resistant)
| Algorithm | Standard |
|---|---|
| ML-KEM (Kyber) | NIST FIPS 203 |
| ML-DSA (Dilithium) | NIST FIPS 204 |
| SLH-DSA (SPHINCS+) | NIST FIPS 205 |
| Falcon | NIST Round 4 alternate |

---

## Project structure

```
cbom_scanner/
├── __init__.py
├── models.py          Dataclasses: CryptoFinding, ScanResult, QuantumRisk
├── patterns.py        Regex pattern library (20+ algorithms)
├── analyzer.py        Key-size refinement, deduplication, risk scorecard
├── reporter.py        CycloneDX JSON, console table, HTML report
├── scanner.py         Directory walker + detector orchestrator
├── cli.py             CLI entry point (python -m cbom_scanner.cli)
└── detectors/
    ├── base.py        BaseDetector ABC
    ├── generic_det.py Regex detector (all file types)
    └── python_det.py  AST detector (Python-specific, high precision)
```

---

## CI integration

```yaml
# GitHub Actions example
- name: CBOM Scan
  run: |
    python -m cbom_scanner.cli src/ --format cyclonedx --output cbom.json
    # Fails if quantum-vulnerable crypto is found (exit code 1)
    python -m cbom_scanner.cli src/ --min-risk vulnerable
```

---

## Risk scoring

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | A — Quantum-Ready | Nearly all assets are safe or PQC |
| 70–89  | B — Mostly Safe | Minor gaps to address |
| 50–69  | C — Mixed | Action needed |
| 25–49  | D — High Risk | Many vulnerable algorithms in use |
| 0–24   | F — Critically Vulnerable | Immediate migration required |

---

## Relation to job role: Cryptographic Inventory Analyst

A Cryptographic Inventory Analyst is responsible for:

| Responsibility | This tool |
|---|---|
| Discover all crypto in use | `scanner.py` + `detectors/` |
| Classify quantum risk | `analyzer.py` + `patterns.py` |
| Produce machine-readable CBOM | `reporter.to_cyclonedx()` → CycloneDX 1.6 JSON |
| Prioritise migration | `analyzer.scorecard()` → `migration_priority` |
| Report to stakeholders | `reporter.write_html()` → self-contained HTML |
| Integrate into CI/CD | CLI exit code 1 on vulnerable findings |
| Track remediation over time | Re-run after each fix; compare CBOM versions |
