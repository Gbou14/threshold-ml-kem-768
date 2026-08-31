#ifndef TIBE_RING_H
#define TIBE_RING_H

#include <openssl/bn.h>
#include <stdint.h>

#include "params.h"

/*
 * R_q = Z[X]/(X^TIBE_D + 1), coefficients mod TIBE_Q, represented as an
 * array of TIBE_D BIGNUMs (one per coefficient, always kept reduced to
 * [0, q)). See README.md "Why BIGNUM" for why this trades performance
 * for minimizing new unvalidated low-level modular-arithmetic code.
 *
 * All functions taking a BN_CTX expect a non-NULL, already-created
 * context (BN_CTX_new()) -- callers own its lifetime, matching normal
 * OpenSSL BIGNUM usage.
 */
typedef struct
{
    BIGNUM* coeffs[TIBE_D];
} ring_elem;

/* The shared modulus q, lazily initialized on first call from
 * TIBE_Q_HEX. Owned by the library; callers must not free it. */
const BIGNUM* ring_modulus(void);

/* Allocate coeffs[0..D) as fresh BIGNUMs, all set to 0. Must be called
 * before any other ring_* function touches `r`. */
void ring_init(ring_elem* r);

/* Free coeffs[0..D). Safe to call on an already-freed or never-inited
 * (zeroed-struct) ring_elem. */
void ring_free(ring_elem* r);

/* Set every coefficient to 0. `r` must already be ring_init'd. */
void ring_zero(ring_elem* r);

/* dst := src. Both must already be ring_init'd. */
void ring_copy(ring_elem* dst, const ring_elem* src);

/* out := a + b (mod q, coefficient-wise). `out` may alias `a` or `b`. */
void ring_add(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx);

/* out := a - b (mod q, coefficient-wise). `out` may alias `a` or `b`. */
void ring_sub(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx);

/* out := -a (mod q, coefficient-wise). `out` may alias `a`. */
void ring_neg(ring_elem* out, const ring_elem* a, BN_CTX* ctx);

/* out := scalar * a (mod q, coefficient-wise). `out` may alias `a`. */
void ring_scalar_mul(ring_elem* out, const ring_elem* a, const BIGNUM* scalar, BN_CTX* ctx);

/* out := a * b in R_q (negacyclic convolution mod X^D+1, mod q).
 * Schoolbook, O(D^2) BIGNUM multiplications. `out` must NOT alias `a`
 * or `b` (the algorithm accumulates into `out` while reading `a`/`b`
 * coefficient-by-coefficient in a way that isn't alias-safe). */
void ring_mul(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx);

/* 1 if every coefficient of a and b is equal, 0 otherwise. */
int ring_eq(const ring_elem* a, const ring_elem* b);

/* out := uniformly random element of R_q, via BN_rand_range per
 * coefficient (OpenSSL's CSPRNG, same RNG source as this repo's
 * existing RAND_bytes usage elsewhere). `out` must already be
 * ring_init'd. */
void ring_random_uniform(ring_elem* out, BN_CTX* ctx);

/* Fixed-width serialization: TIBE_D * TIBE_Q_BYTES bytes, big-endian
 * per coefficient, zero-padded. `out` must have room for
 * ring_serialized_bytes(). */
size_t ring_serialized_bytes(void);
void ring_serialize(uint8_t* out, const ring_elem* a);
void ring_deserialize(ring_elem* out, const uint8_t* in);

#endif /* TIBE_RING_H */
