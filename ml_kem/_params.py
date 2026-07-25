"""
ML-KEM Parameter Sets (FIPS 203, Table 2)

q  = 3329            – modulus
n  = 256             – polynomial degree
k  = module rank     – 2 / 3 / 4
η1, η2               – CBD noise parameters
du, dv               – compression parameters
"""

Q = 3329
N = 256

# (k, eta1, eta2, du, dv)
PARAMS = {
    "ML-KEM-512":  (2, 3, 2, 10, 4),
    "ML-KEM-768":  (3, 2, 2, 10, 4),
    "ML-KEM-1024": (4, 2, 2, 11, 5),
}
