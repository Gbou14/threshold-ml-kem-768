#ifndef KYBER_SHAKE_H
#define KYBER_SHAKE_H

#include <stddef.h>
#include <stdint.h>

/* One-shot SHAKE-128/256 XOF: absorb in[0..inlen), squeeze outlen bytes
 * into out. Backed by OpenSSL's EVP_DigestFinalXOF. */
void shake128_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/* ML-KEM's noise PRF: SHAKE-256(seed || nonce), squeezed to outlen
 * bytes. seed is KYBER_SYMBYTES (32) bytes. */
void kyber_prf(uint8_t *out, size_t outlen, const uint8_t seed[32], uint8_t nonce);

#endif /* KYBER_SHAKE_H */
