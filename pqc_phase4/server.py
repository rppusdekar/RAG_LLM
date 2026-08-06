"""
Phase 4 — PQC FastAPI Server
============================
Endpoints:
  GET  /health                   — liveness check
  GET  /algorithms               — current algorithm config (crypto-agility)
  GET  /algorithms/available     — all supported algorithms with sizes
  GET  /.well-known/pqc-keys     — server's ML-DSA verify key (JWKS-like)
  POST /kex                      — hybrid X25519 + ML-KEM key exchange
  POST /auth/token               — issue a Post-Quantum Token (PQT)
  GET  /api/profile              — protected endpoint; response is PQC-signed
  GET  /api/data                 — protected endpoint; response is PQC-signed

Run:
  uvicorn pqc_phase4.server:app --reload --port 8001
"""

import base64
import hashlib
import os
import time
import uuid
import warnings

warnings.filterwarnings("ignore")

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

from .crypto import (
    server_respond_to_kex,
    TokenAuthority,
    registry,
)

# ── App & startup state ───────────────────────────────────────────────────────

app = FastAPI(
    title="PQC API — Phase 4",
    description="A FastAPI server demonstrating hybrid KEM, PQC-signed responses, and Post-Quantum Tokens.",
    version="4.0.0",
)

# Initialised once at startup — these are long-term server keys
_token_authority: TokenAuthority | None = None
# In-memory session store: session_id → session_key (hex)
# In production this would be Redis / a secure KV store
_sessions: dict[str, str] = {}


@app.on_event("startup")
def startup():
    global _token_authority
    _token_authority = TokenAuthority(alg=registry.sig_alg)
    print(f"[PQC Server] KEM  algorithm : {registry.kem_alg}")
    print(f"[PQC Server] SIG  algorithm : {registry.sig_alg}")
    print(f"[PQC Server] Token authority ready (verify key {len(_token_authority.verify_key)} bytes)")


# ── Resume viewer ────────────────────────────────────────────────────────────

@app.get("/resume", response_class=HTMLResponse, include_in_schema=False)
def serve_resume():
    """Serve the edited resume HTML so it can be opened in any browser."""
    resume_path = os.path.join(os.path.dirname(__file__), "..", "resume_edited", "Rahul_Pusdekar_Crypto_Inventory_Analyst.html")
    with open(os.path.abspath(resume_path), "r", encoding="utf-8") as f:
        return f.read()


# ── Response signing middleware ───────────────────────────────────────────────

def _sign_body(body: bytes) -> str:
    """Sign response body with the server's ML-DSA key. Returns hex signature."""
    import oqs
    with oqs.Signature(registry.sig_alg, _token_authority._signing_key) as signer:
        sig = signer.sign(body)
    return base64.urlsafe_b64encode(sig).decode()


def signed_response(data: dict, status_code: int = 200) -> JSONResponse:
    """
    Build a JSONResponse whose body is signed with ML-DSA.
    Adds three headers:
      X-PQC-Signature   — ML-DSA signature over the response body
      X-PQC-Algorithm   — algorithm used
      X-PQC-Timestamp   — Unix timestamp (prevents replay outside TTL)
    """
    import json
    body = json.dumps(data, separators=(",", ":")).encode()
    sig  = _sign_body(body)
    response = JSONResponse(content=data, status_code=status_code)
    response.headers["X-PQC-Signature"] = sig
    response.headers["X-PQC-Algorithm"]  = registry.sig_alg
    response.headers["X-PQC-Timestamp"]  = str(int(time.time()))
    return response


# ── Auth dependency ───────────────────────────────────────────────────────────

def require_token(request: Request) -> dict:
    """FastAPI dependency: extracts and verifies the PQT from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = auth.removeprefix("Bearer ")
    try:
        return _token_authority.verify(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


# ── Request / response models ─────────────────────────────────────────────────

class KexRequest(BaseModel):
    x25519_pk: str          # base64url-encoded X25519 public key (32 bytes)
    mlkem_pk:  str          # base64url-encoded ML-KEM public key
    kem_alg:   str = "ML-KEM-768"

class AuthRequest(BaseModel):
    username: str
    password: str


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "server": "PQC Phase 4",
        "kem":    registry.kem_alg,
        "sig":    registry.sig_alg,
        "time":   int(time.time()),
    }


@app.get("/algorithms")
def algorithms():
    """Show which algorithms are currently active (crypto-agility demo)."""
    return registry.summary()


@app.get("/algorithms/available")
def algorithms_available():
    """List all supported algorithms with sizes and mark the active ones."""
    return registry.available()


@app.get("/.well-known/pqc-keys")
def pqc_keys():
    """
    Publish the server's ML-DSA verify key.
    Clients fetch this once and cache it to verify signed responses and PQT tokens.
    Analogous to a JWKS endpoint for classical JWTs.
    """
    return _token_authority.public_key_info()


@app.post("/kex")
def key_exchange(req: KexRequest):
    """
    Hybrid Key Exchange: X25519 + ML-KEM.

    Client sends both public keys → server encapsulates → both derive
    the same session_key via HKDF without it ever crossing the wire.

    The session_id in the response is a handle; the server stores the
    derived session_key server-side mapped to this id.
    """
    try:
        response_payload, session_key = server_respond_to_kex(req.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"KEM failed: {exc}")

    session_id = str(uuid.uuid4())
    _sessions[session_id] = session_key.hex()

    return {
        **response_payload,
        "session_id":       session_id,
        "session_key_bits": len(session_key) * 8,
        "note": (
            "Both sides now hold the same session_key. "
            "Use it with AES-256-GCM for symmetric encryption. "
            "The key was derived from X25519 + ML-KEM — secure against both classical and quantum adversaries."
        ),
    }


@app.post("/auth/token")
def auth_token(req: AuthRequest):
    """
    Issue a Post-Quantum Token (PQT).

    In a real app you'd verify the password against a database here.
    This demo accepts any username with password 'pqc-demo'.

    The token uses the same 3-part structure as a JWT but is signed
    with ML-DSA-65 instead of RS256/ES256.
    """
    # Demo credential check (replace with real auth in production)
    if req.password != "pqc-demo":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Map username → role for the demo
    role = "admin" if req.username == "alice" else "user"

    token = _token_authority.issue(
        subject=req.username,
        claims={"role": role, "scope": "read write"},
        ttl_seconds=3600,
    )

    return {
        "token":      token,
        "token_type": "PQT",                      # Post-Quantum Token
        "alg":        registry.sig_alg,
        "expires_in": 3600,
        "note": (
            f"This token is ~{len(token)} bytes. Classical JWTs (ES256) are ~180 bytes. "
            "The size increase is the cost of quantum resistance. "
            "Distribute the verify key via GET /.well-known/pqc-keys."
        ),
    }


@app.get("/api/profile")
def api_profile(claims: dict = Depends(require_token)):
    """
    Protected endpoint — requires a valid PQT token.
    Response body is ML-DSA signed (verify with X-PQC-Signature header).
    """
    data = {
        "user":   claims["sub"],
        "role":   claims.get("role", "user"),
        "scope":  claims.get("scope", ""),
        "issued": claims.get("iat"),
        "server": "PQC Phase 4",
    }
    return signed_response(data)


@app.get("/api/data")
def api_data(claims: dict = Depends(require_token)):
    """
    Another protected endpoint — demonstrates that any response can be
    independently verified by the client using the server's ML-DSA verify key.
    The X-PQC-Signature header lets clients detect tampering even if TLS is stripped.
    """
    data = {
        "records": [
            {"id": 1, "value": "alpha",   "ts": int(time.time()) - 100},
            {"id": 2, "value": "beta",    "ts": int(time.time()) - 50},
            {"id": 3, "value": "gamma",   "ts": int(time.time())},
        ],
        "total": 3,
        "signed_at": int(time.time()),
    }
    return signed_response(data)
