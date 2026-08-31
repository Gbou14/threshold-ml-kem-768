#ifndef KYBER_CBD_H
#define KYBER_CBD_H

#include <stdint.h>

/* Sample 256 coefficients from a centered binomial distribution with
 * parameter eta=2 (range [-2, 2]) out of 2*256/4 = 128 uniformly random
 * input bytes. Used for both eta1 and eta2 in ML-KEM-768, since both
 * equal 2 at this parameter set. */
void cbd_eta2(int16_t coeffs[256], const uint8_t buf[128]);

#endif /* KYBER_CBD_H */
