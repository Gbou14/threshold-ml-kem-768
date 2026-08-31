#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include <stdint.h>

/* zetas[i] holds zeta^{bitrev7(i)} in Montgomery domain, centered in
 * (-q/2, q/2], where zeta = 17 is the fixed primitive 256th root of
 * unity mod q = 3329 used by ML-KEM. Populated by kyber_ntt_init(). */
extern int16_t zetas[128];

/* Must be called once before any of the functions below are used. Safe
 * to call more than once (idempotent). */
void kyber_ntt_init(void);

/* In-place forward NTT. Input in standard order, output in bitreversed
 * order (as pairs of degree-1 coefficients per NTT "slot"). */
void ntt(int16_t r[256]);

/* In-place inverse NTT, scaled by the Montgomery factor R = 2^16.
 * Input in bitreversed order, output in standard order. */
void invntt(int16_t r[256]);

/* Multiplication of a, b in Z_q[X]/(X^2 - zeta), the quotient ring one
 * NTT "slot" represents. */
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif /* KYBER_NTT_H */
