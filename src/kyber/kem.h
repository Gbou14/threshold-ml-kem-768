#ifndef KYBER_KEM_H
#define KYBER_KEM_H

#include <stdint.h>

#include "params.h"

/*
 * Full CCA-secure ML-KEM-768: the IND-CPA PKE (indcpa.c) wrapped in a
 * Fujisaki-Okamoto-style transform that re-encrypts the decrypted
 * message and checks it against the ciphertext, falling back to a
 * pseudorandom (but deterministic, unforgeable-without-z) value on
 * mismatch. This is what defeats chosen-ciphertext attacks; the plain
 * PKE in indcpa.c does not.
 *
 * Not constant-time: the reference implementation uses branchless
 * verify()/cmov() throughout to resist timing side channels. This
 * research prototype uses ordinary memcmp and a branch instead --
 * logically equivalent (same accept/reject decision, same fallback
 * value), but not side-channel hardened. Fine for a research
 * correctness demonstration; would need fixing before any real
 * deployment.
 */

/* dk = dkPKE || ek || H(ek) || z. coins must be 2*KYBER_SYMBYTES bytes:
 * the first half seeds indcpa_keypair_derand, the second becomes z. */
void kyber_keypair_derand(uint8_t ek[KYBER_PUBLICKEYBYTES],
                           uint8_t dk[KYBER_SECRETKEYBYTES],
                           const uint8_t coins[2 * KYBER_SYMBYTES]);

/* coins (KYBER_SYMBYTES) is the message m; the KEM hashes it together
 * with H(ek) before it ever reaches indcpa_enc, unlike calling
 * indcpa_enc directly. */
void kyber_encaps_derand(uint8_t ct[KYBER_CIPHERTEXTBYTES],
                          uint8_t ss[KYBER_SSBYTES],
                          const uint8_t ek[KYBER_PUBLICKEYBYTES],
                          const uint8_t coins[KYBER_SYMBYTES]);

void kyber_decaps(uint8_t ss[KYBER_SSBYTES], const uint8_t ct[KYBER_CIPHERTEXTBYTES], const uint8_t dk[KYBER_SECRETKEYBYTES]);

/* The shared tail of Decaps, starting from an already-known m' (the
 * PKE-decrypted message) instead of computing it via indcpa_dec.
 * kyber_decaps calls this after its own indcpa_dec; the threshold path
 * (threshold_decaps in threshold.h) calls it after Lagrange-combining
 * shareholders' partial decryptions -- same completion logic either
 * way, written once so it can't drift between the two call sites. */
void kyber_decaps_from_m(uint8_t ss[KYBER_SSBYTES],
                          const uint8_t m[KYBER_MSGBYTES],
                          const uint8_t ct[KYBER_CIPHERTEXTBYTES],
                          const uint8_t ek[KYBER_PUBLICKEYBYTES],
                          const uint8_t z[KYBER_SYMBYTES]);

#endif /* KYBER_KEM_H */
