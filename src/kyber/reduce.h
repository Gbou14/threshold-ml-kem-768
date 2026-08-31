#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include <stdint.h>

/*
 * R = 2^16 mod q, centered in (-q/2, q/2]: 65536 mod 3329 = 2285,
 * and 2285 - 3329 = -1044.
 */
#define KYBER_MONT (-1044)

/*
 * QINV = q^{-1} mod 2^16, as a signed 16-bit value.
 * Check: q * 62209 = 3329 * 62209 = 207093761 = 3160*65536 + 1,
 * so 3329 * 62209 = 1 (mod 65536), and 62209 - 65536 = -3327.
 */
#define KYBER_QINV (-3327)

/* Montgomery reduction: given a in [-q*2^15, q*2^15), returns
 * t in (-q, q) with t = a * R^{-1} (mod q). */
int16_t montgomery_reduce(int32_t a);

/* Barrett reduction: given a 16-bit a, returns the representative of
 * a (mod q) in (-q/2, q/2]. */
int16_t barrett_reduce(int16_t a);

/* Montgomery-domain multiply-then-reduce: a*b*R^{-1} mod q. */
int16_t fq_mul(int16_t a, int16_t b);

#endif /* KYBER_REDUCE_H */
