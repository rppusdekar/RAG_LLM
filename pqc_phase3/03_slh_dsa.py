"""
Phase 3 — FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
================================================================================
Previously known as SPHINCS+.

WHAT IT DOES
------------
SLH-DSA is a digital signature scheme like ML-DSA — but built entirely on
hash functions instead of lattices. This makes it a conservative, "last-resort"
backup: even if lattice math is broken in the future, SLH-DSA security depends
only on the collision resistance of SHA-2 or SHAKE — functions we've trusted
for decades.

WHY TWO SIGNATURE STANDARDS?
------------------------------
NIST standardised BOTH ML-DSA and SLH-DSA on purpose:
  • ML-DSA  → fast, compact signatures. Use it for high-throughput APIs.
  • SLH-DSA → conservative baseline. Use it when you want proof that security
              does NOT depend on any new mathematical assumption.

The trade-off: SLH-DSA has much larger signatures (8–50 KB) and slower
signing, but verification is fast.

PARAMETER SET NAMING CONVENTION
---------------------------------
  SPHINCS+-<hash>-<security>-<variant>

  <hash>   : SHA2 or SHAKE    — underlying hash function family
  <security>: 128 / 192 / 256 — bits of classical security
  <variant> : f (fast)  or  s (small)
                f → smaller signature count, faster signing
                s → smallest signatures, slower signing

  Examples:
    SPHINCS+-SHA2-128f-simple  → SHA-2, 128-bit security, fast variant
    SPHINCS+-SHA2-256s-simple  → SHA-2, 256-bit security, small variant

  All variants here correspond to FIPS 205 SLH-DSA. liboqs exposes them
  under the SPHINCS+ name (the pre-standardisation name).
"""

import warnings
import time

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
    print(f"  {label:<30} {len(data):>6} bytes  |  {preview}{dots}")


# ── representative parameter sets ────────────────────────────────────────────

# We pick one from each security / speed corner to keep output readable.
DEMO_PARAMS = [
    "SPHINCS+-SHA2-128f-simple",   # 128-bit, fast  → smallest signatures in group
    "SPHINCS+-SHA2-128s-simple",   # 128-bit, small → slowest signing, smallest sig
    "SPHINCS+-SHA2-256f-simple",   # 256-bit, fast  → highest security, faster
    "SPHINCS+-SHA2-256s-simple",   # 256-bit, small → highest security, smallest sig
]


# ── single algorithm walkthrough ─────────────────────────────────────────────

def demo_slh_dsa(alg: str) -> dict:
    hr(alg)

    # ── Step 1: KeyGen ───────────────────────────────────────────────────────
    print("\n[1] KEY GENERATION")
    t0 = time.perf_counter()
    with oqs.Signature(alg) as signer:
        verify_key  = signer.generate_keypair()
        signing_key = signer.export_secret_key()
        t_keygen = time.perf_counter() - t0

        show_bytes("Verify key  (public)", verify_key)
        show_bytes("Signing key (secret)", signing_key)

        # ── Step 2: Sign ─────────────────────────────────────────────────────
        print("\n[2] SIGNING")
        message = b"CRITICAL: Revoke certificate CN=evil.example.com"
        print(f"    Message: {message.decode()}")

        t1 = time.perf_counter()
        signature = signer.sign(message)
        t_sign = time.perf_counter() - t1

        show_bytes("Signature (σ)",        signature)

        # ── Step 3: Verify ───────────────────────────────────────────────────
        print("\n[3] VERIFICATION")
        with oqs.Signature(alg) as verifier:
            t2 = time.perf_counter()
            is_valid = verifier.verify(message, signature, verify_key)
            t_verify = time.perf_counter() - t2

        status = "✓  Valid" if is_valid else "✗  Invalid!"
        print(f"    {status}")

        # ── Step 4: Tampered ─────────────────────────────────────────────────
        print("\n[4] TAMPERING RESISTANCE")
        # Flip a single bit in the signature
        sig_tampered = bytearray(signature)
        sig_tampered[0] ^= 0x01
        with oqs.Signature(alg) as verifier:
            still_valid = verifier.verify(message, bytes(sig_tampered), verify_key)
        print(f"    1-bit flip in signature: {'✗  Detected (expected)' if not still_valid else 'NOT detected — bug!'}")

        details = oqs.Signature(alg).details
        print("\n[5] ALGORITHM DETAILS")
        print(f"    NIST security level : {details['claimed_nist_level']}")
        print(f"    Verify key size     : {details['length_public_key']} bytes")
        print(f"    Signing key size    : {details['length_secret_key']} bytes")
        print(f"    Signature size      : {details['length_signature']} bytes")

        return {
            "alg":       alg,
            "vk_bytes":  details["length_public_key"],
            "sk_bytes":  details["length_secret_key"],
            "sig_bytes": details["length_signature"],
            "nist":      details["claimed_nist_level"],
            "t_keygen":  t_keygen * 1000,
            "t_sign":    t_sign * 1000,
            "t_verify":  t_verify * 1000,
            "ok":        is_valid and not still_valid,
        }


# ── use-case: long-lived root CA certificate signing ─────────────────────────

def demo_root_ca_use_case() -> None:
    hr("PRACTICAL EXAMPLE — Long-Lived Certificate Signing")
    print("""
  Scenario: A Root CA signs intermediate CA certificates.
  These certs may be valid for 20 years — well into the quantum era.
  ML-DSA is fast but is a newer assumption. SLH-DSA is the conservative
  choice for signatures that must remain valid far into the future.
""")

    alg = "SPHINCS+-SHA2-256s-simple"   # highest security, smallest sig in group
    print(f"  Using: {alg}  (256-bit security, minimal signature size)")

    with oqs.Signature(alg) as ca:
        verify_key = ca.generate_keypair()

        cert_data = (
            b"ISSUER=Root-CA-PQC, SUBJECT=Intermediate-CA-1, "
            b"VALID=2026-01-01/2046-01-01, "
            b"KEY_USAGE=CertSign,CRLSign"
        )
        print(f"\n  Certificate data: {cert_data.decode()}")

        t0 = time.perf_counter()
        signature = ca.sign(cert_data)
        t_sign = time.perf_counter() - t0

        with oqs.Signature(alg) as validator:
            valid = validator.verify(cert_data, signature, verify_key)

        print(f"  Signature size : {len(signature)} bytes")
        print(f"  Signing time   : {t_sign*1000:.1f} ms")
        print(f"  Verification   : {'✓  Valid' if valid else '✗  Invalid'}")

    print("""
  Note: For a root CA you sign very rarely (tens of certs per year),
  so slow signing is acceptable. Verification (done constantly by TLS
  clients) is fast for all SLH-DSA variants — the right trade-off here.
""")


# ── fast vs small variant explained ──────────────────────────────────────────

def explain_f_vs_s() -> None:
    hr("FAST (f) vs SMALL (s) VARIANTS EXPLAINED")
    print("""
  Both variants use a hypertree of Merkle trees internally.

  FAST  (-f)  → fewer layers in the hypertree, more leaves per tree
               → signing needs FEWER hash computations → FASTER signing
               → but the signature must include more authentication path data
               → LARGER signatures

  SMALL (-s)  → more layers, fewer leaves
               → signing needs MORE hash computations → SLOWER signing
               → authentication path is shorter → SMALLER signatures

  Verification is fast in both variants: it just re-hashes the path once.

  Which to choose for your API?
  ────────────────────────────
  • High-frequency signatures (e.g., every API response) → use ML-DSA
  • Occasional, long-lived signatures (certs, software releases, audit logs)
    that must stay valid for 10–20 years → SLH-DSA-256s is the gold standard
  • SLH-DSA-128f is a reasonable middle ground if you need PQC conservative
    security but can tolerate ~10 KB signatures
""")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print(" FIPS 205 — SLH-DSA (Hash-Based Signature)")
    print("=" * 60)
    print("""
Use case: Long-lived signatures where conservative security matters
more than compact size — root CA certificates, code signing,
audit-log integrity proofs.
""")

    results = [demo_slh_dsa(p) for p in DEMO_PARAMS]

    # ── Comparison table ─────────────────────────────────────────────────────
    hr("COMPARISON TABLE")
    hdr = (f"  {'Algorithm':<32} {'NIST':>5} {'VK':>5} {'SK':>5} "
           f"{'Sig':>7} {'KeyGen':>8} {'Sign':>8} {'Verify':>8}")
    print(hdr)
    print("  " + "─" * (len(hdr) - 2))
    units = (f"  {'':32} {'lvl':>5} {'B':>5} {'B':>5} "
             f"{'B':>7} {'ms':>8} {'ms':>8} {'ms':>8}")
    print(units)
    print("  " + "─" * (len(hdr) - 2))
    for r in results:
        ok = "✓" if r["ok"] else "✗"
        print(f"  {r['alg']:<32} {r['nist']:>5} {r['vk_bytes']:>5} "
              f"{r['sk_bytes']:>5} {r['sig_bytes']:>7} "
              f"{r['t_keygen']:>7.1f}  {r['t_sign']:>7.1f}  "
              f"{r['t_verify']:>7.1f}  {ok}")

    demo_root_ca_use_case()
    explain_f_vs_s()

    print("""
KEY TAKEAWAYS
─────────────
• SLH-DSA security rests ONLY on hash-function collision resistance
  — no new math, no new assumptions. This is its main advantage over ML-DSA.
• Signatures are 8–50 KB; plan for this in protocols and storage.
• Verification is fast (< 2 ms) across all variants — safe for clients.
• For high-throughput APIs prefer ML-DSA; use SLH-DSA for long-lived,
  high-stakes artefacts (root certs, software release signatures, audit logs).
• NIST recommends deploying BOTH: ML-DSA for speed, SLH-DSA as a fallback.
""")


if __name__ == "__main__":
    main()
