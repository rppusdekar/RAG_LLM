"""
AcmeCorp — Legacy cryptographic utilities
DEPRECATED: These functions are from the 2009 core banking migration.
Do not use in new code.
"""

import hashlib
import hmac


def checksum_md5(data: bytes) -> str:
    """MD5 checksum for file integrity. Classically broken — use SHA-256 minimum."""
    return hashlib.md5(data).hexdigest()


def checksum_sha1(data: bytes) -> str:
    """SHA-1 checksum. Deprecated (NIST SP 800-131A Rev 2: disallowed after 2030)."""
    return hashlib.sha1(data).hexdigest()


def hmac_sha1_sign(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA1 message authentication. Grover-weakened — use HMAC-SHA256 minimum."""
    return hmac.new(key, message, hashlib.sha1).digest()


def hmac_md5_sign(key: bytes, message: bytes) -> bytes:
    """HMAC-MD5. Classically broken — remove immediately."""
    return hmac.new(key, message, hashlib.md5).digest()


def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 (Bitcoin-style). Grover-weakened at 128-bit effective security."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
