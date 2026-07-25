"""
Phase 3 — Side-by-Side Comparison of All Three NIST PQC Standards
==================================================================
Runs all three algorithms at their recommended security levels and
prints a single decision-guide table for API developers.
"""

import warnings
import time

warnings.filterwarnings("ignore")
import oqs


def hr(title: str = "") -> None:
    width = 68
    if title:
        print(f"\n{'─' * 4} {title} {'─' * (width - len(title) - 6)}")
    else:
        print("─" * width)


def bench_kem(alg: str) -> dict:
    with oqs.KeyEncapsulation(alg) as alice:
        t0 = time.perf_counter()
        pk = alice.generate_keypair()
        t_kg = time.perf_counter() - t0

        with oqs.KeyEncapsulation(alg) as bob:
            t1 = time.perf_counter()
            ct, ss_bob = bob.encap_secret(pk)
            t_enc = time.perf_counter() - t1

        t2 = time.perf_counter()
        ss_alice = alice.decap_secret(ct)
        t_dec = time.perf_counter() - t2

        d = oqs.KeyEncapsulation(alg).details
        return {
            "alg": alg, "type": "KEM",
            "pk": d["length_public_key"], "sk": d["length_secret_key"],
            "ct_or_sig": d["length_ciphertext"], "ss": d["length_shared_secret"],
            "nist": d["claimed_nist_level"],
            "t1": t_kg * 1000, "t2": t_enc * 1000, "t3": t_dec * 1000,
            "ok": ss_alice == ss_bob,
        }


def bench_sig(alg: str) -> dict:
    msg = b"benchmark message for signing"
    with oqs.Signature(alg) as signer:
        t0 = time.perf_counter()
        vk = signer.generate_keypair()
        t_kg = time.perf_counter() - t0

        t1 = time.perf_counter()
        sig = signer.sign(msg)
        t_sign = time.perf_counter() - t1

        with oqs.Signature(alg) as verifier:
            t2 = time.perf_counter()
            ok = verifier.verify(msg, sig, vk)
            t_ver = time.perf_counter() - t2

        d = oqs.Signature(alg).details
        return {
            "alg": alg, "type": "SIG",
            "pk": d["length_public_key"], "sk": d["length_secret_key"],
            "ct_or_sig": d["length_signature"], "ss": 0,
            "nist": d["claimed_nist_level"],
            "t1": t_kg * 1000, "t2": t_sign * 1000, "t3": t_ver * 1000,
            "ok": ok,
        }


def main() -> None:
    print("=" * 68)
    print(" Phase 3 — All Three NIST PQC Standards: Side-by-Side")
    print("=" * 68)

    # ── Collect benchmarks ────────────────────────────────────────────────────
    print("\nBenchmarking … (this takes a few seconds for SLH-DSA)\n")

    results = [
        # ML-KEM — recommended level
        bench_kem("ML-KEM-768"),
        # Classical reference (Kyber is the pre-standard name, same math)
        bench_kem("ML-KEM-512"),
        bench_kem("ML-KEM-1024"),
        # ML-DSA
        bench_sig("ML-DSA-65"),
        bench_sig("ML-DSA-44"),
        bench_sig("ML-DSA-87"),
        # SLH-DSA
        bench_sig("SPHINCS+-SHA2-128f-simple"),
        bench_sig("SPHINCS+-SHA2-256s-simple"),
    ]

    # ── KEM table ─────────────────────────────────────────────────────────────
    hr("ML-KEM (FIPS 203) — Key Encapsulation")
    print(f"  {'Algorithm':<16} {'NIST':>5} {'PK':>6} {'SK':>6} {'CT':>6} {'SS':>4}"
          f"  {'KeyGen':>8} {'Encaps':>8} {'Decaps':>8}  {'OK':>3}")
    print(f"  {'':16} {'lvl':>5} {'B':>6} {'B':>6} {'B':>6} {'B':>4}"
          f"  {'ms':>8} {'ms':>8} {'ms':>8}")
    print("  " + "─" * 70)
    for r in results:
        if r["type"] != "KEM":
            continue
        ok = "✓" if r["ok"] else "✗"
        print(f"  {r['alg']:<16} {r['nist']:>5} {r['pk']:>6} {r['sk']:>6} "
              f"{r['ct_or_sig']:>6} {r['ss']:>4}  "
              f"{r['t1']:>7.2f}  {r['t2']:>7.2f}  {r['t3']:>7.2f}  {ok}")

    # ── Signature table ────────────────────────────────────────────────────────
    hr("ML-DSA (FIPS 204) + SLH-DSA (FIPS 205) — Signatures")
    print(f"  {'Algorithm':<34} {'NIST':>5} {'VK':>5} {'SK':>5} {'Sig':>7}"
          f"  {'KeyGen':>8} {'Sign':>8} {'Verify':>8}  {'OK':>3}")
    print(f"  {'':34} {'lvl':>5} {'B':>5} {'B':>5} {'B':>7}"
          f"  {'ms':>8} {'ms':>8} {'ms':>8}")
    print("  " + "─" * 76)
    for r in results:
        if r["type"] != "SIG":
            continue
        ok = "✓" if r["ok"] else "✗"
        print(f"  {r['alg']:<34} {r['nist']:>5} {r['pk']:>5} {r['sk']:>5} "
              f"{r['ct_or_sig']:>7}  "
              f"{r['t1']:>7.2f}  {r['t2']:>7.2f}  {r['t3']:>7.2f}  {ok}")

    # ── Decision guide ────────────────────────────────────────────────────────
    hr("DECISION GUIDE FOR API DEVELOPERS")
    print("""
  Use case                                        Recommended algorithm
  ──────────────────────────────────────────────────────────────────────
  TLS key exchange / session key establishment    ML-KEM-768
  API request/response signing (JWT, webhooks)    ML-DSA-65
  Long-lived certs (CA, code signing, audit logs) SLH-DSA-256s
  Highest throughput, relaxed security level      ML-KEM-512 / ML-DSA-44
  Regulatory / government requirement (level 5)   ML-KEM-1024 / ML-DSA-87

  HYBRID TRANSITION STRATEGY (recommended today)
  ───────────────────────────────────────────────
  Classical + PQC in parallel until quantum threat is certain:
    Key exchange  →  X25519  +  ML-KEM-768   (XOR the shared secrets)
    Signatures    →  Ed25519  +  ML-DSA-65   (require BOTH to verify)

  Why hybrid? If lattice math is broken tomorrow, X25519/Ed25519 still
  protects you. If a classical break happens, ML-KEM/ML-DSA protects you.
  Both must be broken simultaneously — raising the bar significantly.

  SIZE BUDGET CHECKLIST
  ─────────────────────
  ML-KEM-768  public key :  1184 B  → fine in TLS handshake, X.509 cert
  ML-DSA-65   signature  :  3293 B  → exceeds typical JWT header budget;
                                       put in a dedicated header or body field
  SLH-DSA-256s signature :  29792 B → store out-of-band (separate endpoint)
""")

    # ── Algorithm ancestry map ────────────────────────────────────────────────
    hr("ALGORITHM ANCESTRY MAP")
    print("""
  NIST Competition Name   →  FIPS Standard  →  liboqs name
  ──────────────────────────────────────────────────────────
  CRYSTALS-Kyber          →  FIPS 203        →  ML-KEM-{512,768,1024}
                                                 (also Kyber{512,768,1024})
  CRYSTALS-Dilithium      →  FIPS 204        →  ML-DSA-{44,65,87}
                                                 (also Dilithium{2,3,5})
  SPHINCS+                →  FIPS 205        →  SPHINCS+-SHA2/SHAKE-*
                                                 (no ML-DSA rename yet)
  HQC                     →  FIPS 206 (draft)→  HQC-*  (KEM backup)
  FALCON                  →  FIPS 206 (draft)→  Falcon-{512,1024} (small sigs)

  Note: liboqs 0.13 (installed here) keeps both old and new names.
  Always use the ML-KEM-* / ML-DSA-* names in new code — the Kyber/
  Dilithium aliases exist for backward compatibility only.
""")


if __name__ == "__main__":
    main()
