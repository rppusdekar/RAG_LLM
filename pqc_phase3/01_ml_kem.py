"""
Phase 3 — FIPS 203: ML-KEM (Module Lattice Key Encapsulation Mechanism)
========================================================================
Previously known as CRYSTALS-Kyber.

WHAT IT DOES
------------
ML-KEM lets two parties (Alice and Bob) agree on a shared secret key over
an insecure channel WITHOUT ever sending that key — even if an adversary
records all traffic today and gets a quantum computer later.

HOW IT WORKS (conceptually)
----------------------------
1. KeyGen   → Alice produces a PUBLIC key (share freely) and a SECRET key (keep private)
2. Encaps   → Bob uses Alice's public key to generate:
                • a random shared secret  K
                • a ciphertext           c  (c encapsulates K for Alice)
3. Decaps   → Alice uses her secret key + c to recover the SAME K

After step 3 both sides hold K without K ever crossing the wire.

PARAMETER SETS (FIPS 203, Table 2)
-----------------------------------
  ML-KEM-512   → NIST security level 1 (≈ AES-128)
  ML-KEM-768   → NIST security level 3 (≈ AES-192)   ← recommended default
  ML-KEM-1024  → NIST security level 5 (≈ AES-256)
"""

import warnings
import time

warnings.filterwarnings("ignore")   # suppress version-mismatch warning
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
    print(f"  {label:<22} {len(data):>4} bytes  |  {preview}{dots}")


# ── single algorithm walkthrough ─────────────────────────────────────────────

def demo_ml_kem(alg: str) -> dict:
    """
    Run one full KeyGen → Encaps → Decaps cycle and print every step.
    Returns timing data for the comparison table.
    """
    hr(alg)

    # ── Step 1: KeyGen ───────────────────────────────────────────────────────
    print("\n[1] KEY GENERATION (Alice's side)")
    print("    Alice runs KeyGen to get a key pair.")

    t0 = time.perf_counter()
    with oqs.KeyEncapsulation(alg) as alice:
        public_key  = alice.generate_keypair()     # safe to publish
        secret_key  = alice.export_secret_key()    # Alice keeps this secret

        t_keygen = time.perf_counter() - t0

        show_bytes("Public key (ek)",  public_key)
        show_bytes("Secret key (dk)",  secret_key)

        # ── Step 2: Encaps ───────────────────────────────────────────────────
        print("\n[2] ENCAPSULATION (Bob's side)")
        print("    Bob uses Alice's public key to produce a ciphertext + shared secret.")

        t1 = time.perf_counter()
        with oqs.KeyEncapsulation(alg) as bob:
            ciphertext, shared_secret_bob = bob.encap_secret(public_key)
        t_encaps = time.perf_counter() - t1

        show_bytes("Ciphertext (c)",         ciphertext)
        show_bytes("Shared secret (Bob)",    shared_secret_bob)

        # ── Step 3: Decaps ───────────────────────────────────────────────────
        print("\n[3] DECAPSULATION (Alice's side)")
        print("    Alice uses her secret key + ciphertext to recover the shared secret.")

        t2 = time.perf_counter()
        shared_secret_alice = alice.decap_secret(ciphertext)
        t_decaps = time.perf_counter() - t2

        show_bytes("Shared secret (Alice)",  shared_secret_alice)

        # ── Verification ─────────────────────────────────────────────────────
        print("\n[4] VERIFICATION")
        match = shared_secret_alice == shared_secret_bob
        status = "✓  Shared secrets MATCH — key agreement successful!" if match \
                 else "✗  MISMATCH — something went wrong"
        print(f"    {status}")

        # ── Key details ──────────────────────────────────────────────────────
        details = oqs.KeyEncapsulation(alg).details
        print("\n[5] ALGORITHM DETAILS")
        print(f"    Claimed NIST level : {details['claimed_nist_level']}")
        print(f"    IND-CCA secure     : {details['is_ind_cca']}")
        print(f"    Public key size    : {details['length_public_key']} bytes")
        print(f"    Secret key size    : {details['length_secret_key']} bytes")
        print(f"    Ciphertext size    : {details['length_ciphertext']} bytes")
        print(f"    Shared secret size : {details['length_shared_secret']} bytes")

        return {
            "alg":       alg,
            "pk_bytes":  details["length_public_key"],
            "sk_bytes":  details["length_secret_key"],
            "ct_bytes":  details["length_ciphertext"],
            "ss_bytes":  details["length_shared_secret"],
            "nist":      details["claimed_nist_level"],
            "t_keygen":  t_keygen * 1000,
            "t_encaps":  t_encaps * 1000,
            "t_decaps":  t_decaps * 1000,
            "ok":        match,
        }


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print(" FIPS 203 — ML-KEM (Key Encapsulation Mechanism)")
    print("=" * 60)
    print("""
Scenario: Alice is an API server.  Bob is a client.
Goal    : Establish a shared secret so they can encrypt traffic
          using AES-GCM — without any key ever crossing the wire.
""")

    variants = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    results  = [demo_ml_kem(v) for v in variants]

    # ── Comparison table ─────────────────────────────────────────────────────
    hr("COMPARISON TABLE")
    hdr = f"  {'Algorithm':<16} {'NIST':>5} {'PK':>7} {'SK':>7} {'CT':>7} " \
          f"{'SS':>5} {'KeyGen':>9} {'Encaps':>9} {'Decaps':>9}"
    print(hdr)
    print("  " + "─" * (len(hdr) - 2))
    units = f"  {'':16} {'lvl':>5} {'bytes':>7} {'bytes':>7} {'bytes':>7} " \
            f"{'bytes':>5} {'ms':>9} {'ms':>9} {'ms':>9}"
    print(units)
    print("  " + "─" * (len(hdr) - 2))
    for r in results:
        print(f"  {r['alg']:<16} {r['nist']:>5} {r['pk_bytes']:>7} "
              f"{r['sk_bytes']:>7} {r['ct_bytes']:>7} {r['ss_bytes']:>5} "
              f"{r['t_keygen']:>8.3f}  {r['t_encaps']:>8.3f}  {r['t_decaps']:>8.3f}")

    print("""
KEY TAKEAWAYS
─────────────
• Higher parameter set → larger keys/ciphertext + slower, but more secure.
• ML-KEM-768 is the recommended default for most API use cases.
• The shared secret (32 bytes) is fixed-size regardless of parameter set —
  you feed it into a KDF (e.g. HKDF) to derive your actual session keys.
• ML-KEM is IND-CCA2 secure: even an adversary who can trigger decapsulation
  on chosen ciphertexts cannot learn the shared secret.
• Unlike Diffie-Hellman, ML-KEM security does NOT rely on discrete logs —
  Shor's algorithm cannot break it on a quantum computer.
""")


if __name__ == "__main__":
    main()
