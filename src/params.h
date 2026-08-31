#ifndef PARAMS_H
#define PARAMS_H

/* ── Field modulus (small prime for toy LWE) ─────────────────────────────── */
#define Q           97

/* ── LWE secret vector dimension ─────────────────────────────────────────── */
#define VECTOR_DIM  4

/* ── Shamir scheme parameters ────────────────────────────────────────────── */
#define N_PARTIES   5       /* total share-holders */
#define THRESHOLD   3       /* minimum shares to reconstruct */

/* ── Encryption noise bound  ─────────────────────────────────────────────── */
/* noise is drawn from [-NOISE_BOUND, NOISE_BOUND] */
#define NOISE_BOUND 2

#endif /* PARAMS_H */
