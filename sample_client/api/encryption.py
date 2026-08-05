"""
AcmeCorp Banking API — Data encryption module
AES-128-CBC for PII at rest, 3DES for legacy DB fields, RC4 in one old report exporter.
"""

import os
import struct
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad

# AES-128 key for customer PII encryption
# 128-bit key is Grover-weakened to effective 64-bit security on a quantum computer.
AES_KEY = os.urandom(16)    # 16 bytes = 128 bits (should be 32 bytes = 256 bits)
AES_MODE = AES.MODE_CBC     # CBC mode — no authentication; vulnerable to padding oracle


def encrypt_pii(data: bytes) -> tuple[bytes, bytes]:
    """Encrypt PII with AES-128-CBC. Returns (ciphertext, iv)."""
    iv     = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size)), iv


def decrypt_pii(ciphertext: bytes, iv: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# Legacy 3DES for database fields imported from the 2008 core banking system
DES3_KEY = os.urandom(16)   # 112-bit effective security — classically weak


def encrypt_legacy_field(data: bytes) -> bytes:
    """Encrypt a legacy DB field with 3DES. Used only for backward compat."""
    cipher = DES3.new(DES3_KEY, DES3.MODE_ECB)
    return cipher.encrypt(pad(data, DES3.block_size))


def decrypt_legacy_field(data: bytes) -> bytes:
    cipher = DES3.new(DES3_KEY, DES3.MODE_ECB)
    return unpad(cipher.decrypt(data), DES3.block_size)


# Report exporter — RC4 stream cipher (legacy, should never have been used)
def export_report_rc4(data: bytes, key: bytes) -> bytes:
    """
    RC4-encrypt a compliance report for transmission.
    RC4 is broken — replace with AES-256-GCM immediately.
    """
    # RC4 implementation (simplified, illustrative)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)
