"""
Sampling algorithms (FIPS 203, §4.2).

SampleNTT    – uniform polynomial from SHAKE-128 XOF stream
SamplePolyCBD_eta – centred binomial distribution sampling
"""

import hashlib
from ._params import Q, N


# ── XOF / PRF / hash wrappers ─────────────────────────────────────────────────

def H(data: bytes) -> bytes:
    """H = SHA3-256 (FIPS 203, §4.1)"""
    return hashlib.sha3_256(data).digest()


def G(data: bytes) -> tuple[bytes, bytes]:
    """G = SHA3-512, split into two 32-byte halves (FIPS 203, §4.1)"""
    digest = hashlib.sha3_512(data).digest()
    return digest[:32], digest[32:]


def J(data: bytes) -> bytes:
    """J = SHAKE-256 with 32-byte output (FIPS 203, §4.1)"""
    return hashlib.shake_256(data).digest(32)


def PRF(eta: int, sigma: bytes, b: int) -> bytes:
    """PRF_eta(sigma, b) = SHAKE-256(sigma || b)[0 : 64*eta]  (FIPS 203, §4.1)"""
    return hashlib.shake_256(sigma + bytes([b])).digest(64 * eta)


def XOF(rho: bytes, i: int, j: int):
    """XOF(rho, i, j) = SHAKE-128(rho || i || j) – returns a streaming reader."""
    return hashlib.shake_128(rho + bytes([i, j]))


# ── Sampling ──────────────────────────────────────────────────────────────────

def sample_ntt(rho: bytes, i: int, j: int) -> list[int]:
    """
    SampleNTT: sample a uniform polynomial from the XOF stream.
    FIPS 203, Algorithm 7.

    i, j are the column-index, row-index used to domain-separate the XOF.
    """
    # Request bytes in large chunks to avoid repeated digest calls.
    CHUNK = 504          # divisible by 3
    xof = XOF(rho, i, j)
    buf_size = CHUNK
    buf = xof.digest(buf_size)
    pos = 0
    a_hat: list[int] = []

    while len(a_hat) < N:
        if pos + 3 > len(buf):
            buf_size += CHUNK
            buf = xof.digest(buf_size)

        b0, b1, b2 = buf[pos], buf[pos + 1], buf[pos + 2]
        pos += 3

        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2

        if d1 < Q:
            a_hat.append(d1)
        if d2 < Q and len(a_hat) < N:
            a_hat.append(d2)

    return a_hat


def sample_poly_cbd(eta: int, sigma: bytes, nonce: int) -> list[int]:
    """
    SamplePolyCBD_eta: sample a polynomial from the centred binomial
    distribution B_eta using PRF output.
    FIPS 203, Algorithm 8.
    """
    prf_out = PRF(eta, sigma, nonce)

    # Convert bytes to bits
    bits = []
    for byte in prf_out:
        for bit_idx in range(8):
            bits.append((byte >> bit_idx) & 1)

    f: list[int] = []
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)

    return f
