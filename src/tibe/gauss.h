#ifndef TIBE_GAUSS_H
#define TIBE_GAUSS_H

#include "ring.h"

/*
 * Discrete-Gaussian-*approximating* sampling. See README.md "Gaussian
 * sampling" for why this is a practical approximation (continuous
 * Gaussian via Box-Muller, rounded to nearest integer) rather than the
 * paper's formal discrete Gaussian D_{R,sigma}, and what an exact,
 * constant-time sampler would need instead (BCHK_PAPER_SPEC.md open
 * question #2) -- not attempted in this pass.
 */

/* One coefficient, before reduction mod q: round(sigma * z) for a
 * standard-normal z sampled via Box-Muller from OpenSSL RAND_bytes.
 * Returned as a signed int64_t -- safe even at TIBE_SIGMA_P (2^47),
 * since realistic tail draws stay well under 2^63. */
int64_t gauss_sample_coeff(double sigma);

/* out := ring element with every coefficient independently sampled via
 * gauss_sample_coeff(sigma), then reduced into [0, q). `out` must
 * already be ring_init'd. */
void gauss_sample(ring_elem* out, double sigma, BN_CTX* ctx);

#endif /* TIBE_GAUSS_H */
