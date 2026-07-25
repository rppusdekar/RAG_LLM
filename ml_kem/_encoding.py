"""
Byte encoding / decoding and compression (FIPS 203, §4.2 and §4.4).

ByteEncode_d : Z_q^256  → bytes   (d bits per coefficient)
ByteDecode_d : bytes    → Z_q^256

Compress_d   : Z_q → {0..2^d-1}
Decompress_d : {0..2^d-1} → Z_q
"""

from ._params import Q, N


# ── Compression / decompression ──────────────────────────────────────────────

def compress(d: int, x: int) -> int:
    """Compress_d(x) = round(2^d / q * x) mod 2^d  (FIPS 203, Eq 4.7)"""
    # Use integer arithmetic: round(x * 2^d / q) mod 2^d
    return ((x * (1 << d) + Q // 2) // Q) % (1 << d)


def decompress(d: int, y: int) -> int:
    """Decompress_d(y) = round(q / 2^d * y)  (FIPS 203, Eq 4.8)"""
    return (y * Q + (1 << (d - 1))) >> d


def poly_compress(d: int, f: list[int]) -> list[int]:
    return [compress(d, c) % Q for c in f]   # keep as ints; encode separately


def poly_decompress(d: int, f: list[int]) -> list[int]:
    return [decompress(d, c) for c in f]


# ── ByteEncode / ByteDecode ───────────────────────────────────────────────────

def byte_encode(d: int, f: list[int]) -> bytes:
    """
    Encodes 256 integers (each < 2^d) into d*32 bytes.
    FIPS 203, Algorithm 4.
    """
    bits = 0
    bit_len = 0
    out = bytearray()
    for coeff in f:
        bits |= (int(coeff) & ((1 << d) - 1)) << bit_len
        bit_len += d
        while bit_len >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            bit_len -= 8
    if bit_len:
        out.append(bits & 0xFF)
    return bytes(out)


def byte_decode(d: int, b: bytes) -> list[int]:
    """
    Decodes d*32 bytes into 256 integers in [0, 2^d).
    FIPS 203, Algorithm 5.
    """
    bits = 0
    bit_len = 0
    out = []
    idx = 0
    mask = (1 << d) - 1
    for byte in b:
        bits |= byte << bit_len
        bit_len += 8
        while bit_len >= d and len(out) < N:
            out.append(bits & mask)
            bits >>= d
            bit_len -= d
    return out


# ── Convenience: encode/decode a vector of polynomials ───────────────────────

def encode_vec(d: int, vec: list[list[int]]) -> bytes:
    return b"".join(byte_encode(d, poly) for poly in vec)


def decode_vec(d: int, data: bytes, k: int) -> list[list[int]]:
    chunk = d * N // 8        # bytes per polynomial
    return [byte_decode(d, data[i * chunk:(i + 1) * chunk]) for i in range(k)]
