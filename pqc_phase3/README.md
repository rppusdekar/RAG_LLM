# Phase 3 — PQC with liboqs-python

Hands-on walkthroughs of all three NIST post-quantum cryptography standards
using the Open Quantum Safe library (`liboqs-python`).

## Files

| File | Standard | Purpose |
|---|---|---|
| `01_ml_kem.py` | FIPS 203 | ML-KEM — Key encapsulation (replaces ECDH/X25519) |
| `02_ml_dsa.py` | FIPS 204 | ML-DSA — Digital signatures (replaces RSA/ECDSA) |
| `03_slh_dsa.py` | FIPS 205 | SLH-DSA — Hash-based signatures (conservative backup) |
| `04_compare_all.py` | all three | Side-by-side benchmarks + decision guide |
| `run_all.py` | — | Run every demo in sequence |

## Run

```bash
# Run a single demo
python3 pqc_phase3/01_ml_kem.py
python3 pqc_phase3/02_ml_dsa.py
python3 pqc_phase3/03_slh_dsa.py
python3 pqc_phase3/04_compare_all.py

# Run all demos step by step
python3 pqc_phase3/run_all.py
```

## What each demo covers

### 01 — ML-KEM (Key Encapsulation)
- Full KeyGen → Encaps → Decaps cycle with printed byte sizes
- All three parameter sets (512 / 768 / 1024)
- Comparison table with timing
- Explains *why* ML-KEM replaces Diffie-Hellman

### 02 — ML-DSA (Digital Signatures)
- Full KeyGen → Sign → Verify cycle
- Tampered-message and wrong-key rejection tests
- Practical example: signing an API response payload
- Size comparison vs RSA-2048, ECDSA, Ed25519

### 03 — SLH-DSA (Hash-Based Signatures)
- Demos for all four security/speed corners (128f, 128s, 256f, 256s)
- 1-bit tampering resistance test
- Practical example: long-lived Root CA certificate signing
- Explains fast (-f) vs small (-s) variants

### 04 — Full Comparison
- Benchmarks all eight algorithm variants in one run
- Decision guide: which algorithm for which API use case
- Hybrid transition strategy (classical + PQC in parallel)
- Algorithm ancestry map (competition names → FIPS names → liboqs names)

## Key numbers to remember

```
ML-KEM-768    public key  1184 B  |  ciphertext  1088 B  |  shared secret  32 B
ML-DSA-65     verify key  1952 B  |  signature   3293 B
SLH-DSA-256s  verify key    64 B  |  signature  29792 B
```

## Library quick reference

```python
import warnings
warnings.filterwarnings("ignore")   # suppress version-mismatch notice
import oqs

# List available algorithms
oqs.get_enabled_kem_mechanisms()    # KEMs: ML-KEM-*, Kyber*, BIKE*, ...
oqs.get_enabled_sig_mechanisms()    # Sigs: ML-DSA-*, Dilithium*, SPHINCS+*, ...

# ML-KEM — key encapsulation
with oqs.KeyEncapsulation("ML-KEM-768") as alice:
    public_key = alice.generate_keypair()
    secret_key = alice.export_secret_key()

with oqs.KeyEncapsulation("ML-KEM-768") as bob:
    ciphertext, shared_secret_bob = bob.encap_secret(public_key)

shared_secret_alice = alice.decap_secret(ciphertext)
assert shared_secret_alice == shared_secret_bob   # ✓

# ML-DSA — signatures
with oqs.Signature("ML-DSA-65") as signer:
    verify_key = signer.generate_keypair()
    signature  = signer.sign(b"my message")

with oqs.Signature("ML-DSA-65") as verifier:
    valid = verifier.verify(b"my message", signature, verify_key)  # True

# Algorithm details
oqs.KeyEncapsulation("ML-KEM-768").details
# → {'length_public_key': 1184, 'length_ciphertext': 1088, ...}
```

## Learning notes

- **Always use the FIPS names** (`ML-KEM-*`, `ML-DSA-*`) in new code. The old
  names (`Kyber*`, `Dilithium*`) are aliases kept for backward compatibility.
- **ML-KEM ≠ a drop-in for RSA encrypt/decrypt.** It is a *key encapsulation*:
  you use it to agree on a symmetric key, then encrypt with AES-GCM.
- **Shared secrets from ML-KEM should go through a KDF** (e.g. HKDF) before
  use — never use the raw 32-byte output as a key directly.
- **Hybrid mode is the safe default today**: run X25519 + ML-KEM-768 together
  and XOR (or KDF) the two shared secrets. Both must be broken to lose security.
- The version mismatch warning (`liboqs 0.13 vs 0.16`) is cosmetic — all
  algorithms in this demo set work correctly with the installed library.
