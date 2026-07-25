"""
Phase 3 — FIPS 204: ML-DSA (Module Lattice Digital Signature Algorithm)
========================================================================
Previously known as CRYSTALS-Dilithium.

WHAT IT DOES
------------
ML-DSA lets a signer prove that a message came from them and was not
tampered with — the digital-signature equivalent of a hand-written
signature, but mathematically unforgeable even by a quantum computer.

HOW IT WORKS (conceptually)
----------------------------
1. KeyGen   → Signer produces a SIGNING key (private) and a VERIFY key (public)
2. Sign     → Signer uses the signing key + message → produces a signature σ
3. Verify   → Anyone with the verify key checks that σ is valid for that message

REAL-WORLD API USE CASES
--------------------------
• Signing JWT tokens (replacing RS256/ES256 with a PQC variant)
• Signing API responses so clients can verify integrity
• Code-signing for software packages
• Certificate Authority signatures in TLS certificates

PARAMETER SETS (FIPS 204, Table 1)
-----------------------------------
  ML-DSA-44  → NIST security level 2  (≈ AES-128)
  ML-DSA-65  → NIST security level 3  (≈ AES-192)   ← recommended default
  ML-DSA-87  → NIST security level 5  (≈ AES-256)
"""

import warnings
import time
import json

warnings.filterwarnings("ignore")
import oqs


# ── helpers ──────────────────────────────────────────────────────────────────

def hr(title: str = "") -> None:
    width = 60
    if title:
        print(f"\n{'─' * 4} {title} {'─' * (width - len(title) - 6)}")
    else:
        print("─" * width)


def show_bytes(label: str, data: bytes, max_bytes: int = 16) -> None:
    preview = data[:max_bytes].hex()
    dots = "…" if len(data) > max_bytes else ""
    print(f"  {label:<26} {len(data):>6} bytes  |  {preview}{dots}")


# ── single algorithm walkthrough ─────────────────────────────────────────────

def demo_ml_dsa(alg: str) -> dict:
    hr(alg)

    # ── Step 1: KeyGen ───────────────────────────────────────────────────────
    print("\n[1] KEY GENERATION (Signer's side)")
    t0 = time.perf_counter()
    with oqs.Signature(alg) as signer:
        verify_key  = signer.generate_keypair()     # share with anyone
        signing_key = signer.export_secret_key()    # never share
        t_keygen = time.perf_counter() - t0

        show_bytes("Verify key  (public)", verify_key)
        show_bytes("Signing key (secret)", signing_key)

        # ── Step 2: Sign ─────────────────────────────────────────────────────
        print("\n[2] SIGNING")
        message = b'{"user_id": 42, "role": "admin", "exp": 9999999999}'
        print(f"    Message: {message.decode()}")

        t1 = time.perf_counter()
        signature = signer.sign(message)
        t_sign = time.perf_counter() - t1

        show_bytes("Signature (σ)",        signature)

        # ── Step 3: Verify — valid message ───────────────────────────────────
        print("\n[3] VERIFICATION — valid message")
        with oqs.Signature(alg) as verifier:
            t2 = time.perf_counter()
            is_valid = verifier.verify(message, signature, verify_key)
            t_verify = time.perf_counter() - t2

        status = "✓  Valid signature — message is authentic and untampered" if is_valid \
                 else "✗  Invalid!"
        print(f"    {status}")

        # ── Step 4: Tampered message ─────────────────────────────────────────
        print("\n[4] VERIFICATION — tampered message")
        tampered = b'{"user_id": 42, "role": "superuser", "exp": 9999999999}'
        print(f"    Tampered: {tampered.decode()}")
        with oqs.Signature(alg) as verifier:
            is_valid_tampered = verifier.verify(tampered, signature, verify_key)
        status = "✗  INVALID — tampering detected (expected)" if not is_valid_tampered \
                 else "PASS (unexpected — something is wrong)"
        print(f"    {status}")

        # ── Step 5: Wrong key ────────────────────────────────────────────────
        print("\n[5] VERIFICATION — wrong verify key (impersonation attempt)")
        with oqs.Signature(alg) as attacker:
            wrong_verify_key = attacker.generate_keypair()
            is_valid_wrong_key = attacker.verify(message, signature, wrong_verify_key)
        status = "✗  INVALID — wrong key detected (expected)" if not is_valid_wrong_key \
                 else "PASS (unexpected — something is wrong)"
        print(f"    {status}")

        # ── Details ──────────────────────────────────────────────────────────
        details = oqs.Signature(alg).details
        print("\n[6] ALGORITHM DETAILS")
        print(f"    Claimed NIST level    : {details['claimed_nist_level']}")
        print(f"    EUF-CMA secure        : {details['is_euf_cma']}")
        print(f"    Verify key size       : {details['length_public_key']} bytes")
        print(f"    Signing key size      : {details['length_secret_key']} bytes")
        print(f"    Signature size        : {details['length_signature']} bytes")

        return {
            "alg":      alg,
            "vk_bytes": details["length_public_key"],
            "sk_bytes": details["length_secret_key"],
            "sig_bytes": details["length_signature"],
            "nist":     details["claimed_nist_level"],
            "t_keygen": t_keygen * 1000,
            "t_sign":   t_sign * 1000,
            "t_verify": t_verify * 1000,
            "ok":       is_valid and not is_valid_tampered and not is_valid_wrong_key,
        }


# ── API token signing example ─────────────────────────────────────────────────

def demo_api_token_signing() -> None:
    """
    Practical example: sign an API response payload with ML-DSA-65
    so any client holding the verify key can confirm authenticity.
    """
    hr("PRACTICAL EXAMPLE — API Response Signing")

    alg = "ML-DSA-65"
    print(f"\nUsing: {alg}")
    print("Scenario: An API server signs its responses. Clients verify before trusting.")

    with oqs.Signature(alg) as server:
        verify_key  = server.generate_keypair()
        # (verify_key would be distributed in a well-known endpoint, like a JWKS URI)

        # Server signs a JSON payload
        payload = json.dumps({
            "status": "ok",
            "data": {"balance": 10_000, "currency": "USD"},
            "issued_at": "2026-07-25T00:00:00Z",
        }, separators=(",", ":")).encode()

        signature = server.sign(payload)
        print(f"\n  Payload  : {payload.decode()}")
        print(f"  Signature: {signature[:24].hex()}… ({len(signature)} bytes)")

        # Client verifies
        with oqs.Signature(alg) as client:
            valid = client.verify(payload, signature, verify_key)
        print(f"\n  Client verification: {'✓  Trusted response' if valid else '✗  Rejected'}")

        print("""
  In a real API:
  • verify_key is published at GET /.well-known/pqc-keys
  • Each response carries an X-PQC-Signature header
  • Clients cache the verify key and check it for every sensitive response
  • Rotate the signing keypair regularly; the verify key is cheap to republish
""")


# ── comparison of ML-DSA vs classical signatures ──────────────────────────────

def compare_with_classical() -> None:
    hr("ML-DSA vs CLASSICAL SIGNATURES")
    print("""
  Algorithm       Key type   Pub key   Priv key   Signature   Quantum-safe?
  ─────────────────────────────────────────────────────────────────────────
  RSA-2048        integer      256 B     1192 B       256 B        ✗  No
  ECDSA P-256     elliptic      64 B       32 B        64 B        ✗  No
  Ed25519         elliptic      32 B       64 B        64 B        ✗  No
  ML-DSA-44       lattice     1312 B     2528 B      2420 B        ✓  Yes
  ML-DSA-65       lattice     1952 B     4000 B      3293 B        ✓  Yes
  ML-DSA-87       lattice     2592 B     4864 B      4595 B        ✓  Yes

  Observations:
  • ML-DSA signatures are larger (2–4 KB vs 64–256 bytes for classical).
  • This matters for bandwidth-sensitive APIs — plan for it.
  • Speed is comparable to RSA-2048 and faster than many ECC operations.
  • The mathematical hardness (Module LWE) is unaffected by Shor's algorithm.
""")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print(" FIPS 204 — ML-DSA (Digital Signature Algorithm)")
    print("=" * 60)
    print("""
Scenario: An API server needs to sign responses and tokens so
that clients can verify authenticity even if TLS is compromised.
""")

    variants = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    results  = [demo_ml_dsa(v) for v in variants]

    # ── Comparison table ─────────────────────────────────────────────────────
    hr("COMPARISON TABLE")
    hdr = f"  {'Algorithm':<12} {'NIST':>5} {'VK':>7} {'SK':>7} {'Sig':>7} " \
          f"{'KeyGen':>9} {'Sign':>9} {'Verify':>9}"
    print(hdr)
    print("  " + "─" * (len(hdr) - 2))
    units = f"  {'':12} {'lvl':>5} {'bytes':>7} {'bytes':>7} {'bytes':>7} " \
            f"{'ms':>9} {'ms':>9} {'ms':>9}"
    print(units)
    print("  " + "─" * (len(hdr) - 2))
    for r in results:
        ok = "✓" if r["ok"] else "✗"
        print(f"  {r['alg']:<12} {r['nist']:>5} {r['vk_bytes']:>7} "
              f"{r['sk_bytes']:>7} {r['sig_bytes']:>7} "
              f"{r['t_keygen']:>8.3f}  {r['t_sign']:>8.3f}  {r['t_verify']:>8.3f}  {ok}")

    demo_api_token_signing()
    compare_with_classical()

    print("""
KEY TAKEAWAYS
─────────────
• ML-DSA-65 is the recommended default for APIs (NIST level 3).
• EUF-CMA security: an adversary cannot forge a valid signature even
  with access to a signing oracle — critical for API authentication.
• Key insight for API developers: ML-DSA replaces the signing step in
  JWTs, webhooks, and response integrity checks — the API design stays
  the same, only the algorithm underneath changes.
""")


if __name__ == "__main__":
    main()
