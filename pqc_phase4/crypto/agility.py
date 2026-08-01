"""
Crypto-Agility Registry
========================
Crypto-agility means the algorithm is a configuration value, not a
hard-coded constant.  When a new algorithm is standardised (or an old
one is broken), you change one env var — nothing else.

Pattern used here:
  • KEM_ALGORITHM  env var controls key exchange  (default: ML-KEM-768)
  • SIG_ALGORITHM  env var controls signatures    (default: ML-DSA-65)
  • Each algorithm name maps to a capability dict (key sizes, security level)
  • AlgorithmRegistry validates the config at startup, not at request time

Real-world guidance:
  • Keep the old algorithm active in parallel while rolling out the new one
  • Add the new algorithm's verify key to /.well-known/pqc-keys BEFORE
    you start signing with it — clients need time to cache it
  • Clients should accept tokens signed by ANY key in the JWKS, not just
    the latest one (key rotation grace period)
"""

import os
import warnings
warnings.filterwarnings("ignore")
import oqs


# ── Supported algorithm names (validated at startup) ─────────────────────────

SUPPORTED_KEMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

SUPPORTED_SIGS = [
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-256s-simple",
]


def _kem_details(alg: str) -> dict:
    """Fetch details for one KEM algorithm (called lazily)."""
    with oqs.KeyEncapsulation(alg) as k:
        return k.details


def _sig_details(alg: str) -> dict:
    """Fetch details for one SIG algorithm (called lazily)."""
    with oqs.Signature(alg) as s:
        return s.details


# ── Registry ──────────────────────────────────────────────────────────────────

class AlgorithmRegistry:
    """
    Single source of truth for which algorithms the server is using.
    Reads KEM_ALGORITHM and SIG_ALGORITHM from environment on init.
    Algorithm details are fetched lazily on first access.
    """

    DEFAULT_KEM = "ML-KEM-768"
    DEFAULT_SIG = "ML-DSA-65"

    def __init__(self):
        self.kem_alg = os.environ.get("KEM_ALGORITHM", self.DEFAULT_KEM)
        self.sig_alg = os.environ.get("SIG_ALGORITHM", self.DEFAULT_SIG)
        self._validate()
        self._kem_cache: dict[str, dict] = {}
        self._sig_cache: dict[str, dict] = {}

    def _validate(self):
        if self.kem_alg not in SUPPORTED_KEMS:
            raise ValueError(
                f"KEM_ALGORITHM '{self.kem_alg}' is not supported. "
                f"Choose from: {SUPPORTED_KEMS}"
            )
        if self.sig_alg not in SUPPORTED_SIGS:
            raise ValueError(
                f"SIG_ALGORITHM '{self.sig_alg}' is not supported. "
                f"Choose from: {SUPPORTED_SIGS}"
            )

    def _get_kem(self, alg: str) -> dict:
        if alg not in self._kem_cache:
            self._kem_cache[alg] = _kem_details(alg)
        return self._kem_cache[alg]

    def _get_sig(self, alg: str) -> dict:
        if alg not in self._sig_cache:
            self._sig_cache[alg] = _sig_details(alg)
        return self._sig_cache[alg]

    @property
    def kem_info(self) -> dict:
        d = self._get_kem(self.kem_alg)
        return {
            "algorithm":       self.kem_alg,
            "nist_level":      d["claimed_nist_level"],
            "public_key_B":    d["length_public_key"],
            "ciphertext_B":    d["length_ciphertext"],
            "shared_secret_B": d["length_shared_secret"],
        }

    @property
    def sig_info(self) -> dict:
        d = self._get_sig(self.sig_alg)
        return {
            "algorithm":    self.sig_alg,
            "nist_level":   d["claimed_nist_level"],
            "verify_key_B": d["length_public_key"],
            "signature_B":  d["length_signature"],
        }

    def summary(self) -> dict:
        return {
            "kem": self.kem_info,
            "sig": self.sig_info,
            "hybrid_classical": "X25519",
            "note": (
                "Change KEM_ALGORITHM or SIG_ALGORITHM env vars and restart "
                "to switch algorithms — no code change required."
            ),
        }

    def available(self) -> dict:
        return {
            "kem_algorithms": [
                {
                    "alg":    alg,
                    "nist":   self._get_kem(alg)["claimed_nist_level"],
                    "pk_B":   self._get_kem(alg)["length_public_key"],
                    "ct_B":   self._get_kem(alg)["length_ciphertext"],
                    "active": alg == self.kem_alg,
                }
                for alg in SUPPORTED_KEMS
            ],
            "sig_algorithms": [
                {
                    "alg":    alg,
                    "nist":   self._get_sig(alg)["claimed_nist_level"],
                    "vk_B":   self._get_sig(alg)["length_public_key"],
                    "sig_B":  self._get_sig(alg)["length_signature"],
                    "active": alg == self.sig_alg,
                }
                for alg in SUPPORTED_SIGS
            ],
        }


# ── Singleton used by the FastAPI app ─────────────────────────────────────────
registry = AlgorithmRegistry()
