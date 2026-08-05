"""
AcmeCorp Banking API — Payment signing module
Uses ECDSA (P-256) to sign transaction records for non-repudiation.
All signed transactions are archived for 10 years.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import json

# P-256 signing key — used for transaction non-repudiation
# WARNING: ECDSA on P-256 is vulnerable to Shor's algorithm.
# Archived signatures will be retroactively forgeable once a CRQC exists.
_signing_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
_verify_key  = _signing_key.public_key()


def sign_transaction(transaction: dict) -> str:
    """Sign a transaction dict with ECDSA P-256 / SHA-256."""
    canonical = json.dumps(transaction, sort_keys=True).encode()
    sig = _signing_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def verify_transaction(transaction: dict, signature_b64: str) -> bool:
    """Verify a transaction signature."""
    from cryptography.exceptions import InvalidSignature
    canonical = json.dumps(transaction, sort_keys=True).encode()
    sig = base64.b64decode(signature_b64)
    try:
        _verify_key.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def derive_payment_token(account_id: str, amount: float) -> str:
    """Derive a payment token using ECDH key agreement."""
    # Ephemeral key for ECDH
    ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key    = ephemeral_key.exchange(ec.ECDH(), _verify_key)
    return base64.urlsafe_b64encode(shared_key[:16]).decode()
