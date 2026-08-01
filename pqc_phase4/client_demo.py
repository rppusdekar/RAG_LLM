"""
Phase 4 — PQC API Client Demo
==============================
Exercises every endpoint of the PQC FastAPI server in sequence:

  1. Health check
  2. Show active algorithms  (crypto-agility)
  3. Fetch server's ML-DSA verify key
  4. Hybrid KEM handshake  (X25519 + ML-KEM-768)
  5. Authenticate → receive a Post-Quantum Token (PQT)
  6. Call a protected endpoint → verify the ML-DSA response signature
  7. Tamper-detection demo

Usage:
  # Terminal 1 — start the server
  python3 -m uvicorn pqc_phase4.server:app --port 8001

  # Terminal 2 — run this demo
  python3 pqc_phase4/client_demo.py
"""

import base64
import json
import sys
import time
import warnings

warnings.filterwarnings("ignore")

import httpx
import oqs

from pqc_phase4.crypto.hybrid_kem import HybridKEMClient
from pqc_phase4.crypto.pqc_token import verify_token_with_key

BASE_URL = "http://localhost:8000"


# ── Pretty-printing helpers ───────────────────────────────────────────────────

def hr(title: str = "", width: int = 62) -> None:
    if title:
        print(f"\n{'─' * 4} {title} {'─' * (width - len(title) - 6)}")
    else:
        print("─" * width)

def ok(msg: str)   -> None: print(f"  ✓  {msg}")
def fail(msg: str) -> None: print(f"  ✗  {msg}"); sys.exit(1)
def info(msg: str) -> None: print(f"     {msg}")

def show_json(label: str, data: dict, keys: list[str] | None = None) -> None:
    subset = {k: data[k] for k in keys if k in data} if keys else data
    for k, v in subset.items():
        val = str(v)
        if len(val) > 72:
            val = val[:72] + "…"
        print(f"  {k:<22} {val}")


# ── Steps ─────────────────────────────────────────────────────────────────────

def step_health(client: httpx.Client) -> None:
    hr("STEP 1 — Health Check")
    r = client.get("/health")
    r.raise_for_status()
    d = r.json()
    ok(f"Server is up  |  KEM: {d['kem']}  |  SIG: {d['sig']}")


def step_algorithms(client: httpx.Client) -> None:
    hr("STEP 2 — Crypto-Agility: Active Algorithms")
    r = client.get("/algorithms")
    r.raise_for_status()
    d = r.json()
    info("KEM (key exchange):")
    show_json("", d["kem"], ["algorithm", "nist_level", "public_key_B", "ciphertext_B"])
    info("SIG (signatures):")
    show_json("", d["sig"], ["algorithm", "nist_level", "verify_key_B", "signature_B"])
    info(d.get("note", ""))

    r2 = client.get("/algorithms/available")
    r2.raise_for_status()
    av = r2.json()
    info("\n  All available KEM algorithms:")
    for entry in av["kem_algorithms"]:
        active = " ← active" if entry["active"] else ""
        info(f"    {entry['alg']:<16}  NIST {entry['nist']}  pk={entry['pk_B']}B  ct={entry['ct_B']}B{active}")
    info("\n  All available SIG algorithms:")
    for entry in av["sig_algorithms"]:
        active = " ← active" if entry["active"] else ""
        info(f"    {entry['alg']:<34}  NIST {entry['nist']}  sig={entry['sig_B']}B{active}")
    ok("Crypto-agility confirmed: change KEM_ALGORITHM/SIG_ALGORITHM env var to swap")


def step_fetch_verify_key(client: httpx.Client) -> tuple[bytes, str]:
    hr("STEP 3 — Fetch Server ML-DSA Verify Key  (/.well-known/pqc-keys)")
    r = client.get("/.well-known/pqc-keys")
    r.raise_for_status()
    d  = r.json()
    entry      = d["keys"][0]
    alg        = entry["alg"]
    verify_key = base64.urlsafe_b64decode(entry["key"] + "==")
    ok(f"Algorithm  : {alg}")
    ok(f"Verify key : {len(verify_key)} bytes  |  {verify_key[:16].hex()}…")
    info("(Cache this key — used to verify every signed response and PQT token)")
    return verify_key, alg


def step_hybrid_kem(client: httpx.Client) -> None:
    hr("STEP 4 — Hybrid Key Exchange  (X25519 + ML-KEM-768)")

    # Client side: generate ephemeral keypairs
    kem_client = HybridKEMClient(kem_alg="ML-KEM-768")
    initiation = kem_client.initiate()

    info("Client sends:")
    info(f"  x25519_pk   32 B  |  {base64.urlsafe_b64decode(initiation['x25519_pk'] + '==').hex()[:32]}…")
    pk_bytes = base64.urlsafe_b64decode(initiation['mlkem_pk'] + '==')
    info(f"  mlkem_pk  {len(pk_bytes):4d} B  |  {pk_bytes[:16].hex()}…")

    # Send to server
    r = client.post("/kex", json=initiation)
    r.raise_for_status()
    response = r.json()

    info("\nServer responds with:")
    info(f"  x25519_pk   32 B  (server ephemeral)")
    ct_bytes = base64.urlsafe_b64decode(response['mlkem_ct'] + '==')
    info(f"  mlkem_ct  {len(ct_bytes):4d} B  (ML-KEM ciphertext — only client can decapsulate)")
    info(f"  session_id  {response['session_id']}")

    # Client finishes: derive session key
    session_key = kem_client.finish(response)

    ok(f"Session key derived  :  {session_key.hex()}")
    ok(f"Session key size     :  {len(session_key) * 8} bits")
    ok("Key never crossed the wire — secure against both classical and quantum attackers")
    info(response.get("note", ""))


def step_get_token(client: httpx.Client) -> tuple[str, bytes, str]:
    hr("STEP 5 — Post-Quantum Token  (PQT Authentication)")

    # Fetch verify key first
    r_keys = client.get("/.well-known/pqc-keys")
    entry     = r_keys.json()["keys"][0]
    alg       = entry["alg"]
    verify_key = base64.urlsafe_b64decode(entry["key"] + "==")

    # Get a token
    r = client.post("/auth/token", json={"username": "alice", "password": "pqc-demo"})
    r.raise_for_status()
    d     = r.json()
    token = d["token"]

    info(f"Token type      : {d['token_type']}")
    info(f"Algorithm       : {d['alg']}")
    info(f"Token length    : {len(token)} bytes  (vs ~180 bytes for ES256 JWT)")
    parts = token.split(".")
    info(f"Header          : {json.loads(base64.urlsafe_b64decode(parts[0] + '=='))}")
    info(f"Payload         : {json.loads(base64.urlsafe_b64decode(parts[1] + '=='))}")
    info(f"Signature       : {len(base64.urlsafe_b64decode(parts[2] + '=='))} bytes  |  {parts[2][:24]}…")

    # Client-side verify
    try:
        claims = verify_token_with_key(token, verify_key, alg)
        ok(f"Client-side PQT verification passed  →  sub={claims['sub']}  role={claims['role']}")
    except ValueError as e:
        fail(f"Token verification failed: {e}")

    info(d.get("note", ""))
    return token, verify_key, alg


def step_signed_response(client: httpx.Client, token: str, verify_key: bytes, sig_alg: str) -> None:
    hr("STEP 6 — PQC-Signed API Response  (ML-DSA response header)")

    r = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    body = r.content
    sig  = r.headers.get("X-PQC-Signature", "")
    alg_hdr = r.headers.get("X-PQC-Algorithm", sig_alg)
    ts   = r.headers.get("X-PQC-Timestamp", "0")

    info(f"Response body     : {r.text[:80]}…")
    info(f"X-PQC-Signature   : {sig[:48]}… ({len(base64.urlsafe_b64decode(sig + '=='))} bytes)")
    info(f"X-PQC-Algorithm   : {alg_hdr}")
    info(f"X-PQC-Timestamp   : {ts}  (age: {int(time.time()) - int(ts)}s)")

    # Verify the signature over the raw body
    sig_bytes = base64.urlsafe_b64decode(sig + "==")
    with oqs.Signature(alg_hdr) as verifier:
        valid = verifier.verify(body, sig_bytes, verify_key)

    if valid:
        ok("Signature verified — response is authentic and untampered")
    else:
        fail("Signature verification failed!")

    # Tamper demo
    hr("STEP 7 — Tamper Detection")
    tampered = body[:-1] + bytes([body[-1] ^ 0x01])   # flip last bit
    with oqs.Signature(alg_hdr) as verifier:
        still_valid = verifier.verify(tampered, sig_bytes, verify_key)
    if not still_valid:
        ok("1-bit flip in response body → signature INVALID  ✓  (tamper detected)")
    else:
        fail("Tamper not detected — something is wrong")


def step_protected_data(client: httpx.Client, token: str, verify_key: bytes, sig_alg: str) -> None:
    hr("STEP 8 — Protected Data Endpoint  (/api/data)")
    r = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    sig_bytes = base64.urlsafe_b64decode(r.headers["X-PQC-Signature"] + "==")
    with oqs.Signature(sig_alg) as verifier:
        valid = verifier.verify(r.content, sig_bytes, verify_key)
    data = r.json()
    ok(f"Records received  : {data['total']}")
    ok(f"Signature valid   : {valid}")
    info(f"Values            : {[rec['value'] for rec in data['records']]}")

    # Wrong-token demo
    r2 = client.get("/api/data")    # no Authorization header
    if r2.status_code == 401:
        ok("Request without token → 401 Unauthorized  ✓")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 62)
    print(" Phase 4 — PQC API Client Demo")
    print("=" * 62)
    print(f"\n  Server: {BASE_URL}")
    print("""
  This demo exercises every PQC feature of the server:
    • Crypto-agility  (algorithm config, no hard-coded constants)
    • Hybrid KEM      (X25519 + ML-KEM-768 → shared session key)
    • PQT tokens      (ML-DSA signed, JWT-compatible structure)
    • Signed responses (X-PQC-Signature header on every endpoint)
    • Tamper detection (1-bit flip is caught)
""")

    with httpx.Client(base_url=BASE_URL, timeout=30) as client:
        # Check server is reachable
        try:
            client.get("/health")
        except httpx.ConnectError:
            print(f"  ✗  Cannot connect to {BASE_URL}")
            print("     Start the server first:")
            print("     python3 -m uvicorn pqc_phase4.server:app --port 8001\n")
            sys.exit(1)

        step_health(client)
        step_algorithms(client)
        verify_key, sig_alg = step_fetch_verify_key(client)
        step_hybrid_kem(client)
        token, verify_key, sig_alg = step_get_token(client)
        step_signed_response(client, token, verify_key, sig_alg)
        step_protected_data(client, token, verify_key, sig_alg)

    hr()
    print("""
  All Phase 4 features working ✓

  What you built:
  ──────────────────────────────────────────────────────────
  POST /kex              Hybrid X25519 + ML-KEM key exchange
  POST /auth/token       Post-Quantum Token issuance (PQT)
  GET  /api/*            ML-DSA signed protected responses
  GET  /.well-known/...  Verify key distribution (JWKS-like)
  GET  /algorithms       Crypto-agility: swap alg via env var

  Next steps (Phase 5):
  ──────────────────────────────────────────────────────────
  • Wrap the session key in AES-256-GCM for payload encryption
  • Store tokens in Redis with revocation support
  • Add TLS 1.3 + ML-KEM hybrid cipher suite (nginx or stunnel)
  • Compliance: map endpoints to CNSA 2.0 requirements
""")


if __name__ == "__main__":
    main()
