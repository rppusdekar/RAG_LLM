"""
Number Theoretic Transform (NTT) for ML-KEM (FIPS 203, §4.3)

Ring: Z_q[X] / (X^256 + 1),  q = 3329
Primitive 256th root of unity: ζ = 17

Zeta table: zeta[i] = 17^(brv7(i)) mod q  for i = 0..127
where brv7(x) is the bit-reversal of a 7-bit integer.
"""

from ._params import Q, N

# ── Precompute zeta table ────────────────────────────────────────────────────

def _brv7(x: int) -> int:
    """Bit-reverse a 7-bit integer."""
    result = 0
    for i in range(7):
        result |= ((x >> i) & 1) << (6 - i)
    return result

_GEN = 17  # primitive 256th root of unity mod Q

ZETAS: list[int] = [pow(_GEN, _brv7(i), Q) for i in range(128)]

# 256^{-1} mod 3329 = 3303
_N_INV = pow(N, -1, Q)


# ── Core transforms ──────────────────────────────────────────────────────────

def ntt(f: list[int]) -> list[int]:
    """
    In-place NTT on a 256-coefficient polynomial.
    Returns f̂ (the NTT domain representation).
    FIPS 203, Algorithm 9.
    """
    f_hat = list(f)
    k = 1
    length = 128
    while length >= 1:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
        length >>= 1
    return f_hat


def inv_ntt(f_hat: list[int]) -> list[int]:
    """
    Inverse NTT.  Returns the polynomial f from its NTT representation.
    FIPS 203, Algorithm 10.
    """
    f = list(f_hat)
    k = 127
    length = 1
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length <<= 1
    for i in range(N):
        f[i] = (f[i] * _N_INV) % Q
    return f


def multiply_ntts(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """
    Pointwise multiplication of two NTT-domain polynomials.
    Uses base-case multiplication for degree-2 factors.
    FIPS 203, Algorithm 11–12.
    """
    h_hat = [0] * N
    for i in range(128):
        a0, a1 = f_hat[2 * i], f_hat[2 * i + 1]
        b0, b1 = g_hat[2 * i], g_hat[2 * i + 1]
        gamma = ZETAS[64 + i]           # γ = ζ^{2·brv7(i)+1}
        h_hat[2 * i]     = (a0 * b0 + a1 * b1 * gamma) % Q
        h_hat[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h_hat


def poly_add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]
