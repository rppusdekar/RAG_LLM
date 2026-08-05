# AcmeCorp Banking API — Sample Client

**Fictional codebase used as a CBOM scanner portfolio demonstration.**

Represents a realistic pre-PQC-migration enterprise banking API: Python backend,
nginx TLS config, YAML crypto settings, and X.509 certificates — all using
algorithms that were industry-standard in 2019 but are now quantum-vulnerable.

## Crypto in use (pre-migration state)

| Component | Algorithm | Issue |
|---|---|---|
| JWT signing | RSA-2048 / RS256 | Shor-vulnerable; tokens valid 8 hrs |
| Transaction signing | ECDSA P-256 | Shor-vulnerable; 10-year archive at risk |
| PII encryption | AES-128-CBC | Grover-weakened; unauthenticated |
| Legacy DB fields | 3DES-ECB | Classically weak + quantum-broken |
| Report export | RC4 | Classically broken |
| Password hashing | MD5 | Classically broken |
| Session IDs | SHA-1 | Deprecated (NIST SP 800-131A) |
| TLS | TLSv1.1 / TLSv1.2 | No TLS 1.3; no PQC hybrid |
| Certificates | RSA-2048 | Below CNSA 2.0 minimum (3072-bit) |

## To regenerate the CBOM report

```bash
# From project root
PYTHONPATH=/home/runner/workspace python3 -m cbom_scanner.cli sample_client \
  --format html --output sample_client/cbom_report.html

PYTHONPATH=/home/runner/workspace python3 -m cbom_scanner.cli sample_client \
  --format cyclonedx --output sample_client/cbom.json
```
