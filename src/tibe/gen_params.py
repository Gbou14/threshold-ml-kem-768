#!/usr/bin/env python3
"""
Derivation script for src/tibe/params.h's concrete numeric constants.

Not part of the build -- this is a one-time (reproducible) derivation
recorded here so the choice of q (and, in a later phase, the ring-split
roots r1/r2 used by the identity-embedding map) isn't just a magic
number in params.h. Re-run this to reproduce every value byte-for-byte.

Deterministic: the Miller-Rabin witness stream is seeded from the paper's
eprint number (2025/1958) purely so a re-run is reproducible -- it does
not affect *which* q is found, since q is the smallest prime satisfying
a public, checkable condition (q >= 2^100 and q = 5 mod 8), and
`openssl prime` independently re-confirms primality (see README.md).
"""

import random


def is_probable_prime(n, rounds=64):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    rng = random.Random(1958)
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def find_q():
    """Smallest prime >= 2^100 with q = 5 mod 8 (BCHK_PAPER_SPEC.md Sec 1,
    Lemma 1's condition for R_q ~ F_{d/2} x F_{d/2})."""
    start = 1 << 100
    rem = start % 8
    candidate = start + ((5 - rem) % 8)
    while not is_probable_prime(candidate):
        candidate += 8
    return candidate


def find_split_roots(q):
    """r1 = sqrt(-1) mod q, r2 = -r1 mod q, satisfying
    X^d + 1 = (X^(d/2) - r1)(X^(d/2) - r2) mod q for any power-of-two d
    (BCHK_PAPER_SPEC.md Sec 7 open question #3). Uses the closed-form
    square-root formula for primes q = 5 (mod 8) (Cohen, "A Course in
    Computational Algebraic Number Theory," Algorithm 1.5.1)."""
    assert q % 8 == 5
    a = (q - 1) % q  # -1 mod q
    if pow(a, (q - 1) // 4, q) == 1:
        r1 = pow(a, (q + 3) // 8, q)
    else:
        r1 = (2 * a % q) * pow(4 * a % q, (q - 5) // 8, q) % q
    assert pow(r1, 2, q) == a, "sqrt(-1) construction failed"
    r2 = (-r1) % q
    return r1, r2


if __name__ == "__main__":
    q = find_q()
    print(f"q = {q}")
    print(f"q bit_length = {q.bit_length()}")
    print(f"q mod 8 = {q % 8}")
    print(f"q hex = {q:x}")

    r1, r2 = find_split_roots(q)
    print(f"r1 (sqrt(-1) mod q) = {r1}  (hex {r1:x})")
    print(f"r2 (-r1 mod q)      = {r2}  (hex {r2:x})")
