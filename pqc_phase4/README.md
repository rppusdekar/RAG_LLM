# Phase 4 — PQC in a Real Python API

A FastAPI server demonstrating every core Phase 4 concept:
hybrid KEM, PQC-signed responses, Post-Quantum Tokens, and crypto-agility.

## Quick start

```bash
# Terminal 1 — start the server
python3 -m uvicorn pqc_phase4.server:app --host 0.0.0.0 --port 8000

# Terminal 2 — run the full client demo
PYTHONPATH=/home/runner/workspace python3 pqc_phase4/client_demo.py
```

## Endpoints

| Method | Path | What it demonstrates |
|--------|------|----------------------|
| GET | `/health` | Server liveness + active algorithms |
| GET | `/algorithms` | Crypto-agility: current config |
| GET | `/algorithms/available` | All supported algorithms with sizes |
| GET | `/.well-known/pqc-keys` | ML-DSA verify key (JWKS-like) |
| POST | `/kex` | Hybrid X25519 + ML-KEM key exchange |
| POST | `/auth/token` | Issue a Post-Quantum Token (PQT) |
| GET | `/api/profile` | Protected + ML-DSA signed response |
| GET | `/api/data` | Protected + ML-DSA signed response |

## Files

```
pqc_phase4/
├── server.py              FastAPI app — all routes
├── client_demo.py         End-to-end demo client
└── crypto/
    ├── hybrid_kem.py      X25519 + ML-KEM hybrid key exchange
    ├── pqc_token.py       ML-DSA signed tokens (JWT replacement)
    └── agility.py         Algorithm registry + crypto-agility
```

## Crypto-agility

Switch algorithms without touching code — just set env vars and restart:

```bash
KEM_ALGORITHM=ML-KEM-1024 SIG_ALGORITHM=ML-DSA-87 \
  python3 -m uvicorn pqc_phase4.server:app --port 8001
```

Supported values:
- `KEM_ALGORITHM`: `ML-KEM-512`, `ML-KEM-768` (default), `ML-KEM-1024`
- `SIG_ALGORITHM`: `ML-DSA-44`, `ML-DSA-65` (default), `ML-DSA-87`, `SPHINCS+-SHA2-128f-simple`, `SPHINCS+-SHA2-256s-simple`

## Hybrid KEM flow

```
Client                                  Server
──────                                  ──────
Generate X25519 keypair (ephemeral)
Generate ML-KEM keypair (ephemeral)
POST /kex { x25519_pk, mlkem_pk }  ──→
                                        DH(server_x25519_sk, client_x25519_pk) = ss1
                                        ML-KEM.Encaps(client_mlkem_pk) = ct, ss2
                                        session_key = HKDF(ss1 ‖ ss2)
                          ←──  { server_x25519_pk, mlkem_ct }
DH(client_x25519_sk, server_x25519_pk) = ss1
ML-KEM.Decaps(client_mlkem_sk, mlkem_ct) = ss2
session_key = HKDF(ss1 ‖ ss2)
→ Both sides hold the same session_key. It never crossed the wire.
```

## Post-Quantum Token (PQT) format

Same 3-part structure as JWT — only the algorithm changes:

```
base64url(header) . base64url(payload) . base64url(signature)

Header  : { "alg": "ML-DSA-65", "typ": "PQT" }
Payload : { "sub": "alice", "role": "admin", "iat": ..., "exp": ... }
Sig     : ML-DSA-65 signature over "header.payload"  (~3300 bytes)
```

Classical JWT (ES256) signature: 64 bytes  
PQT (ML-DSA-65) signature: ~3300 bytes — the cost of quantum resistance.

## Response signing

Every `/api/*` response carries three headers:

```
X-PQC-Signature : <base64url ML-DSA signature over response body>
X-PQC-Algorithm : ML-DSA-65
X-PQC-Timestamp : 1753401600
```

Clients verify with the key from `/.well-known/pqc-keys`.  
A 1-bit flip anywhere in the body invalidates the signature.

## Demo credentials

```
username: alice   password: pqc-demo  → role: admin
username: bob     password: pqc-demo  → role: user
```
