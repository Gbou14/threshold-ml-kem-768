#ifndef TIBE_GAUSS_H
#define TIBE_GAUSS_H

#include <stddef.h>
#include <stdint.h>

#include "ring.h"

/*
 * Exact, constant-time-in-structure discrete Gaussian sampling over Z
 * (per-coefficient), at any of the four widths this project's Table 2
 * instantiation uses. See README.md "Gaussian sampling" for the full
 * design writeup; summary:
 *
 * - Small widths (TIBE_SIGMA=4, TIBE_SIGMA_A=8): sampled directly from
 *   an exact cumulative-distribution table (CDT), built once per
 *   distinct sigma via high-precision (256-bit fixed-point, BIGNUM)
 *   arithmetic and cached. Every sample does a fixed-length (tau*sigma
 *   dependent, but sigma is a *public* parameter) linear scan over the
 *   table -- the number of iterations and memory locations touched
 *   does not depend on the sampled value, only on the (public) sigma.
 * - Huge widths (TIBE_SIGMA_PRIME=2^19, TIBE_SIGMA_P=2^47): a direct
 *   CDT is infeasible (the table would need on the order of sigma
 *   entries). Built instead via Micciancio-Walter's convolution
 *   theorem (eprint 2017/259, Theorem 2.1): if x1, x2 are independent
 *   draws from D_{Z,s} and s exceeds a small smoothing-parameter-based
 *   bound, then k*x1 + x2 is statistically close to D_{Z,sqrt(k^2+1)*s}
 *   for any integer k respecting that bound. Recursively combining a
 *   small CDT-sampled base (sigma=16) through ~5-7 such steps (each
 *   roughly *squaring* the achievable width, since the bound on k
 *   grows with s) reaches 2^47 from a tiny table using only a shallow
 *   binary tree of base draws (~2^levels of them, all off a 417-entry
 *   table) -- see README.md for the derived schedules and the
 *   citation.
 *
 * Caveat carried over from the previous (Box-Muller) version of this
 * module: "constant-time" here means a fixed, sigma-determined
 * iteration count and memory-access pattern in this module's own C
 * code (no data-dependent loop bounds or table indices). It has not
 * been verified against microarchitectural side channels with a
 * dedicated tool (e.g. ctgrind, dudect) -- a real, honestly-flagged
 * limitation for a solo research implementation, same posture this
 * project has taken throughout (see README.md).
 */

/* One coefficient, exact discrete Gaussian D_{Z,sigma} (up to the
 * table/fixed-point precision documented in README.md -- bounded well
 * below any cryptographically meaningful threshold). sigma must be one
 * of this project's four Table 2 widths (or GAUSS_CONV_BASE_SIGMA);
 * passing an arbitrary sigma still works but builds (and leaks, per
 * ring.c's own established convention of never freeing its lazily
 * built globals) a new cached table/schedule for it. */
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
 * seed, not fresh system randomness. Same sampler (CDT / convolution)
 * as gauss_sample_coeff/gauss_sample above -- only the entropy source
 * differs.
 */
typedef struct
{
    uint8_t* buf;
    size_t len;
    size_t pos;
} gauss_prg;

/* Squeezes SHAKE-256(seed) into a fresh out_len-byte internal buffer.
 * Caller must gauss_prg_free when done; use gauss_bytes_per_coeff
 * (below) to size out_len correctly -- the byte cost per coefficient
 * varies by width (32 bytes for a direct-CDT width, up to
 * 32*2^levels for a convolution width), unlike the old Box-Muller
 * sampler's flat 16-bytes-per-coefficient budget. */
void gauss_prg_init(gauss_prg* prg, const uint8_t* seed, size_t seed_len, size_t out_len);
void gauss_prg_free(gauss_prg* prg);

/* Same distribution as gauss_sample_coeff, but pulling bytes from
 * `prg` instead of RAND_bytes. */
int64_t gauss_sample_coeff_from_prg(gauss_prg* prg, double sigma);

/* Same as gauss_sample, but via gauss_sample_coeff_from_prg. */
void gauss_sample_from_prg(ring_elem* out, double sigma, gauss_prg* prg, BN_CTX* ctx);

/* Bytes of PRG output one gauss_sample_coeff_from_prg(prg, sigma) call
 * consumes -- callers must size gauss_prg_init's out_len as (number of
 * coefficients to be drawn at this width) * gauss_bytes_per_coeff(sigma),
 * summed over every distinct width drawn from the same prg. Building
 * this (to determine whether sigma needs the convolution construction,
 * and if so how many levels) is itself cheap and cached, same as an
 * actual sample. */
size_t gauss_bytes_per_coeff(double sigma);

#endif /* TIBE_GAUSS_H */
