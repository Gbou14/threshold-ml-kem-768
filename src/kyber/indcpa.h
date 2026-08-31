#ifndef KYBER_INDCPA_H
#define KYBER_INDCPA_H

#include <stdint.h>

#include "params.h"
#include "polyvec.h"

/* Deterministically generate the public matrix A (or its transpose)
 * from a 32-byte seed via SHAKE-128 rejection sampling. Exposed mainly
 * for testing/cross-validation. */
void kyber_gen_matrix(polyvec a[KYBER_K], const uint8_t seed[KYBER_SYMBYTES], int transposed);

/* IND-CPA-secure Kyber PKE, taking explicit randomness ("derand") so
 * runs are reproducible -- useful both for testing against known
 * vectors and, later, for the threshold layer where each shareholder
 * needs a fixed, agreed-upon key material derivation. */
void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                            uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                            const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif /* KYBER_INDCPA_H */
