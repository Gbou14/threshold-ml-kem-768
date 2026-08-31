#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include <stdint.h>

#include "params.h"

typedef struct
{
    int16_t coeffs[KYBER_N];
} poly;

void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);
void poly_reduce(poly *r);

void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

/* Deterministic noise sampling from a 32-byte seed and a one-byte
 * domain-separation nonce, via the SHAKE-256 PRF. */
void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);
void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

/* Lossy compression used for ciphertexts (KYBER_DU/KYBER_DV bits per
 * coefficient instead of the full 12). poly_decompress is an
 * approximate inverse -- compress/decompress round-trips introduce
 * bounded rounding noise by design. */
void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a);
void poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

/* Full-precision (lossless) 12-bit-per-coefficient serialization. */
void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

/* Encode/decode a 32-byte message as a polynomial with each bit spread
 * across KYBER_N/8 coefficients (each either 0 or round(q/2)). */
void poly_frommsg(poly *r, const uint8_t msg[KYBER_MSGBYTES]);
void poly_tomsg(uint8_t msg[KYBER_MSGBYTES], const poly *a);

#endif /* KYBER_POLY_H */
