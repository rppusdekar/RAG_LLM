"""
Hybrid Key Exchange: X25519 + ML-KEM-768
=========================================
Why hybrid?  During the transition period we can't be certain either:
  • Classical (X25519) holds forever, OR
  • Lattice math (ML-KEM) holds forever.

Running both in parallel means an attacker must break BOTH simultaneously.
This is the recommended approach by NIST, NSA (CNSA 2.0), and IETF RFC 9180.

Protocol (one round-trip):
──────────────────────────
  Client:
    1. Generate ephemeral X25519 keypair  (c_x_pk, c_x_sk)
    2. Generate ephemeral ML-KEM keypair  (c_k_pk, c_k_sk)
    3. POST /kex  { x25519_pk, mlkem_pk }

  Server:
    1. Generate ephemeral X25519 keypair  (s_x_pk, s_x_sk)
    2. DH: x25519_ss = X25519(s_x_sk, c_x_pk)
    3. Encaps: mlkem_ct, mlkem_ss = ML-KEM.Encaps(c_k_pk)
    4. session_key = HKDF(x25519_ss ‖ mlkem_ss)
    5. Return  { x25519_pk: s_x_pk, mlkem_ct }

  Client:
    1. DH: x25519_ss = X25519(c_x_sk, s_x_pk)
    2. Decaps: mlkem_ss = ML-KEM.Decaps(c_k_sk, mlkem_ct)
    3. session_key = HKDF(x25519_ss ‖ mlkem_ss)
    → Both sides now hold the same 32-byte session_key.
"""

import base64
import hashlib
import warnings

warnings.filterwarnings("ignore")

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs


# ── helpers ──────────────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()

def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")


# ── HKDF key derivation ───────────────────────────────────────────────────────

def derive_session_key(
    x25519_shared: bytes,
    mlkem_shared:  bytes,
    info:          bytes = b"hybrid-kem-session-key",
    length:        int   = 32,
) -> bytes:
    """
    Combine both shared secrets into one session key using HKDF-SHA256.

    We concatenate (not XOR) the secrets so that even if one is all-zeros
    (worst-case broken algorithm) the other still contributes entropy.
    Salt = SHA-256(x25519_shared ⊕ mlkem_shared) adds a light mixing step.
    """
    combined = x25519_shared + mlkem_shared
    salt = hashlib.sha256(
        bytes(a ^ b for a, b in zip(x25519_shared.ljust(32, b"\x00"),
                                     mlkem_shared.ljust(32, b"\x00")))
    ).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(combined)


# ── Client side ───────────────────────────────────────────────────────────────

class HybridKEMClient:
    """
    Client half of the hybrid KEM handshake.
    Create once per session; call initiate() then finish().
    """

    def __init__(self, kem_alg: str = "ML-KEM-768"):
        self._kem_alg = kem_alg
        # X25519 ephemeral keypair
        self._x25519_sk = X25519PrivateKey.generate()
        self._x25519_pk = self._x25519_sk.public_key()
        # ML-KEM ephemeral keypair
        self._kem = oqs.KeyEncapsulation(kem_alg)
        self._mlkem_pk = self._kem.generate_keypair()   # bytes
        self.session_key: bytes | None = None

    def initiate(self) -> dict:
        """Return the payload to POST to /kex."""
        return {
            "x25519_pk": _b64(
                self._x25519_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
            ),
            "mlkem_pk": _b64(self._mlkem_pk),
            "kem_alg":  self._kem_alg,
        }

    def finish(self, server_response: dict) -> bytes:
        """
        Process server response, derive session key, return it.
        server_response = { x25519_pk, mlkem_ct }
        """
        # X25519 DH
        s_x25519_pk = X25519PublicKey.from_public_bytes(_unb64(server_response["x25519_pk"]))
        x25519_ss   = self._x25519_sk.exchange(s_x25519_pk)

        # ML-KEM decapsulation
        mlkem_ct = _unb64(server_response["mlkem_ct"])
        mlkem_ss = self._kem.decap_secret(mlkem_ct)

        self.session_key = derive_session_key(x25519_ss, mlkem_ss)
        return self.session_key

    def __del__(self):
        try:
            self._kem.free()
        except Exception:
            pass


# ── Server side ───────────────────────────────────────────────────────────────

def server_respond_to_kex(client_payload: dict) -> tuple[dict, bytes]:
    """
    Server side: given the client's initiation payload, produce:
      - response dict to send back to the client
      - session_key bytes (store server-side, keyed by session_id)

    Returns (response, session_key).
    """
    kem_alg = client_payload.get("kem_alg", "ML-KEM-768")

    # X25519 DH
    s_x25519_sk = X25519PrivateKey.generate()
    s_x25519_pk = s_x25519_sk.public_key()
    c_x25519_pk = X25519PublicKey.from_public_bytes(_unb64(client_payload["x25519_pk"]))
    x25519_ss   = s_x25519_sk.exchange(c_x25519_pk)

    # ML-KEM encapsulation
    c_mlkem_pk = _unb64(client_payload["mlkem_pk"])
    with oqs.KeyEncapsulation(kem_alg) as kem:
        mlkem_ct, mlkem_ss = kem.encap_secret(c_mlkem_pk)

    session_key = derive_session_key(x25519_ss, mlkem_ss)

    response = {
        "x25519_pk": _b64(s_x25519_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "mlkem_ct":  _b64(mlkem_ct),
        "kem_alg":   kem_alg,
    }
    return response, session_key
