#ifndef KYBER_POLYVEC_H
#define KYBER_POLYVEC_H

#include <stdint.h>

#include "params.h"
#include "poly.h"

typedef struct
{
    poly vec[KYBER_K];
} polyvec;

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);
void polyvec_reduce(polyvec *r);

void polyvec_ntt(polyvec *r);
void polyvec_invntt_tomont(polyvec *r);

/* r = sum_i a[i]*b[i] (in NTT domain), Montgomery-reduced and
 * Barrett-reduced. This is the inner product used by both the
 * matrix-vector product A*s and, later, the threshold layer's
 * share_i . u partial decryption. */
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

#endif /* KYBER_POLYVEC_H */
