#ifndef TIBE_GAUSS_H
#define TIBE_GAUSS_H

#include <stddef.h>
#include <stdint.h>

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

/*
 * Deterministic ("derandomized") sampling, driven by a pre-squeezed
 * SHAKE-256 byte stream instead of RAND_bytes -- needed for the
 * BCHK+ TKEM's FO-style derandomized Encaps (tkem.c): Combine's
 * re-encryption consistency check must reproduce the exact same
 * ciphertext from a re-derived seed, which requires every random
 * draw TIBE.Encrypt makes (s, e[9], e') to be reproducible from that
 * seed, not fresh system randomness. Same Box-Muller approximation
 * and its caveats as gauss_sample_coeff/gauss_sample above -- only
 * the entropy source differs.
 */
typedef struct
{
    uint8_t* buf;
    size_t len;
    size_t pos;
} gauss_prg;

/* Squeezes SHAKE-256(seed) into a fresh out_len-byte internal buffer.
 * Caller must gauss_prg_free when done; `out_len` must be at least
 * 16*(number of coefficients this prg will be asked to sample) bytes
 * (8 bytes each for the two Box-Muller draws per coefficient) or
 * gauss_sample_coeff_from_prg/gauss_sample_from_prg will abort. */
void gauss_prg_init(gauss_prg* prg, const uint8_t* seed, size_t seed_len, size_t out_len);
void gauss_prg_free(gauss_prg* prg);

/* Same distribution as gauss_sample_coeff, but pulling uniform bits
 * from `prg` instead of RAND_bytes. */
int64_t gauss_sample_coeff_from_prg(gauss_prg* prg, double sigma);

/* Same as gauss_sample, but via gauss_sample_coeff_from_prg. */
void gauss_sample_from_prg(ring_elem* out, double sigma, gauss_prg* prg, BN_CTX* ctx);

#endif /* TIBE_GAUSS_H */
