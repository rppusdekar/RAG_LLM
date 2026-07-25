"""
Phase 3 — Run all PQC demos in sequence.
Usage:  python3 pqc_phase3/run_all.py
"""

import warnings
warnings.filterwarnings("ignore")

import importlib, sys

MODULES = [
    ("01_ml_kem",      "ML-KEM  (FIPS 203) — Key Encapsulation"),
    ("02_ml_dsa",      "ML-DSA  (FIPS 204) — Digital Signatures"),
    ("03_slh_dsa",     "SLH-DSA (FIPS 205) — Hash-Based Signatures"),
    ("04_compare_all", "Side-by-Side Comparison & Decision Guide"),
]

if __name__ == "__main__":
    sys.path.insert(0, "pqc_phase3")
    for mod_name, title in MODULES:
        print(f"\n\n{'#' * 68}")
        print(f"#  {title}")
        print(f"{'#' * 68}\n")
        mod = importlib.import_module(mod_name)
        mod.main()
        input("\n  ── Press Enter to continue to the next demo ──\n")
