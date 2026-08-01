"""
Post-Quantum Token (PQT) — ML-DSA signed token, JWT-compatible structure
=========================================================================
Format (same 3-part structure as JWT, different algorithm):

    base64url(header) . base64url(payload) . base64url(signature)

    Header  : { "alg": "ML-DSA-65", "typ": "PQT" }
    Payload : { "sub": "user_id", "role": "...", "iat": ..., "exp": ... }
    Signature: ML-DSA-65 signature over "header.payload" bytes

Why not regular JWT?
────────────────────
RS256 / ES256 rely on RSA / ECDSA — both broken by Shor's algorithm.
Swapping to ML-DSA-65 keeps the same token shape so existing middleware
(parsing, transport, caching) needs no changes, only the verify step.

Key sizes to plan for:
    Verify key  : 1952 bytes  (vs 64 bytes for Ed25519)
    Signature   : ~3300 bytes (vs 64 bytes for Ed25519)
    → distribute the verify key once via /.well-known/pqc-keys
    → token is larger; consider header compression or a dedicated field
"""

import base64
import json
import time
import warnings

warnings.filterwarnings("ignore")
import oqs


# ── encoding helpers ──────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _unb64url(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


# ── Server-side token authority ───────────────────────────────────────────────

class TokenAuthority:
    """
    Holds the server's long-term ML-DSA signing keypair.
    Instantiate once at app startup and keep in memory.
    """

    def __init__(self, alg: str = "ML-DSA-65"):
        self.alg = alg
        self._signer = oqs.Signature(alg)
        self.verify_key: bytes = self._signer.generate_keypair()
        self._signing_key: bytes = self._signer.export_secret_key()

    # ── Issue ─────────────────────────────────────────────────────────────────

    def issue(
        self,
        subject: str,
        claims: dict,
        ttl_seconds: int = 3600,
    ) -> str:
        """
        Create and sign a PQT token.

        subject   : user id (goes into 'sub' claim)
        claims    : extra payload fields (role, scope, etc.)
        ttl_seconds: token lifetime
        Returns   : the token string (header.payload.signature)
        """
        now = int(time.time())
        header  = {"alg": self.alg, "typ": "PQT"}
        payload = {
            "sub": subject,
            "iat": now,
            "exp": now + ttl_seconds,
            **claims,
        }

        h = _b64url(json.dumps(header,  separators=(",", ":")).encode())
        p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()

        # Re-hydrate signer with stored secret key
        with oqs.Signature(self.alg, self._signing_key) as signer:
            sig = signer.sign(signing_input)

        return f"{h}.{p}.{_b64url(sig)}"

    # ── Verify ────────────────────────────────────────────────────────────────

    def verify(self, token: str) -> dict:
        """
        Verify a PQT token. Returns the decoded payload dict on success.
        Raises ValueError with a descriptive message on failure.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token: expected 3 parts")

        h_raw, p_raw, sig_raw = parts
        signing_input = f"{h_raw}.{p_raw}".encode()

        # ── Signature check ───────────────────────────────────────────────────
        try:
            sig = _unb64url(sig_raw)
        except Exception:
            raise ValueError("Malformed token: invalid base64 in signature")

        with oqs.Signature(self.alg) as verifier:
            if not verifier.verify(signing_input, sig, self.verify_key):
                raise ValueError("Invalid signature — token rejected")

        # ── Decode payload ────────────────────────────────────────────────────
        try:
            payload = json.loads(_unb64url(p_raw))
        except Exception:
            raise ValueError("Malformed token: invalid JSON payload")

        # ── Expiry check ──────────────────────────────────────────────────────
        if "exp" in payload and int(time.time()) > payload["exp"]:
            raise ValueError(f"Token expired at {payload['exp']}")

        return payload

    # ── Public key export ─────────────────────────────────────────────────────

    def public_key_info(self) -> dict:
        """Return the verify key in a JWKS-like structure for /.well-known/pqc-keys."""
        return {
            "keys": [{
                "kty":   "PQC",
                "alg":   self.alg,
                "use":   "sig",
                "key":   _b64url(self.verify_key),
                "bytes": len(self.verify_key),
            }]
        }

    def __del__(self):
        try:
            self._signer.free()
        except Exception:
            pass


# ── Client-side verification (standalone, no server dependency) ────────────────

def verify_token_with_key(token: str, verify_key: bytes, alg: str = "ML-DSA-65") -> dict:
    """
    Verify a PQT token using a raw verify_key bytes object.
    Use this on the client side after fetching the verify key from /.well-known/pqc-keys.
    """
    authority = TokenAuthority.__new__(TokenAuthority)
    authority.alg        = alg
    authority.verify_key = verify_key
    return authority.verify(token)
