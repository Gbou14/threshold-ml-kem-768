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

/* One factor of R_q ~ F_{D/2} x F_{D/2} (Lemma 1, BCHK_PAPER_SPEC.md
 * Sec 1 / Sec 3.5): an element of Z_q[X]/(X^{D/2}-r) for r in
 * {TIBE_R1_HEX, TIBE_R2_HEX}, represented the same way as ring_elem
 * but with half as many coefficients. See ring_split/ring_unsplit/
 * field_mul below. */
typedef struct
{
    BIGNUM* c[TIBE_D / 2];
} field_elem;

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

/* out := a^-1 in R_q, i.e. a*out == 1. Requires `a` to be a unit
 * (invertible) in R_q -- undefined (garbage, not a crash) if it isn't.
 * Computed via the polynomial extended Euclidean algorithm over the
 * field Z_q (q prime), treating X^D+1 as an ordinary modulus
 * polynomial -- this works regardless of whether X^D+1 is irreducible
 * over Z_q (it isn't, per Lemma 1's R_q ~ F_{d/2} x F_{d/2} splitting;
 * gcd-based inversion doesn't require irreducibility, only that
 * gcd(a, X^D+1) = 1, guaranteed when `a` is genuinely a unit). O(D^2)
 * field operations, the same complexity class as a single ring_mul.
 * `out` must not alias `a`. */
void ring_inv(ring_elem* out, const ring_elem* a, BN_CTX* ctx);

/* Decomp_beta(x): coefficient-wise decomposition of x's *centered*
 * representative (each coefficient mapped from [0,q) to (-q/2, q/2]
 * first) as x_i = c0_i*beta + c1_i with |c1_i| <= beta/2, beta =
 * 2^TIBE_BETA_LOG2 (a power of two, so this is an exact bit-split, not
 * an approximation). BCHK_PAPER_SPEC.md Sec 1 "Decomp_beta". c0, c1
 * must already be ring_init'd and must not alias `x` or each other. */
void ring_decomp_beta(ring_elem* c0, ring_elem* c1, const ring_elem* x, BN_CTX* ctx);

/* field_elem lifecycle, mirroring ring_elem's. */
void field_init(field_elem* f);
void field_free(field_elem* f);
void field_zero(field_elem* f);
void field_copy(field_elem* dst, const field_elem* src);
void field_add(field_elem* out, const field_elem* a, const field_elem* b, BN_CTX* ctx);
int field_eq(const field_elem* a, const field_elem* b);
int field_is_zero(const field_elem* f);

/* out := a*b in Z_q[X]/(X^{D/2}-root) (root is TIBE_R1_HEX or
 * TIBE_R2_HEX as a BIGNUM, or any other root of the same defining
 * relation -- the reduction rule X^{D/2}==root is the only thing this
 * function needs). Schoolbook, O((D/2)^2) -- about 4x cheaper than a
 * full ring_mul over R_q. `out` must not alias `a` or `b`. */
void field_mul(field_elem* out, const field_elem* a, const field_elem* b, const BIGNUM* root, BN_CTX* ctx);

/* f: R_q -> F_{D/2} x F_{D/2}, the isomorphism from Lemma 1 (reduction
 * mod each of the two factors X^{D/2}-r1, X^{D/2}-r2 -- a ring
 * homomorphism onto each factor by construction, hence onto the
 * product by CRT, since gcd(X^{D/2}-r1, X^{D/2}-r2)=1 for r1!=r2).
 * Concretely: writing m = m_low + X^{D/2}*m_high (m_low = coefficients
 * [0,D/2), m_high = coefficients [D/2,D)), y1 = m_low + r1*m_high,
 * y2 = m_low + r2*m_high. y1, y2 must already be field_init'd. */
void ring_split(field_elem* y1, field_elem* y2, const ring_elem* m, BN_CTX* ctx);

/* f^-1: F_{D/2} x F_{D/2} -> R_q, the inverse of ring_split (CRT
 * reconstruction): m_high = (y1-y2)*(r1-r2)^-1, m_low = y1 - r1*m_high.
 * `m` must already be ring_init'd. */
void ring_unsplit(ring_elem* m, const field_elem* y1, const field_elem* y2, BN_CTX* ctx);

#endif /* TIBE_RING_H */
