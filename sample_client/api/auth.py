"""
AcmeCorp Banking API — Authentication module
JWT issuance and verification using RSA-2048 + SHA-256
"""

import jwt
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import datetime

# Generate RSA-2048 keypair for JWT signing
# NOTE: RS256 uses RSA + SHA-256. Vulnerable to Shor's algorithm on a CRQC.
_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_public_key = _private_key.public_key()

JWT_ALGORITHM  = "RS256"          # RSA + SHA-256
JWT_EXPIRY_HRS = 8

# Session token secret — stored in config (bad practice, for demo)
SESSION_SECRET = "acmecorp-banking-2019-secret-key"


def issue_token(user_id: str, role: str) -> str:
    """Issue a JWT signed with RSA-2048 / SHA-256."""
    payload = {
        "sub":  user_id,
        "role": role,
        "iat":  datetime.datetime.utcnow(),
        "exp":  datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRY_HRS),
    }
    private_pem = _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, private_pem, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Verify an RSA-signed JWT and return the payload."""
    public_pem = _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return jwt.decode(token, public_pem, algorithms=[JWT_ALGORITHM])


def hash_password(password: str) -> str:
    """Hash a password for storage. Uses MD5 (legacy — do not use in production)."""
    # TODO: migrate to bcrypt or Argon2
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


def generate_session_id(user_id: str) -> str:
    """Generate a session ID. Uses SHA-1 (legacy)."""
    raw = f"{user_id}:{SESSION_SECRET}:{datetime.datetime.utcnow().timestamp()}"
    return hashlib.sha1(raw.encode()).hexdigest()
