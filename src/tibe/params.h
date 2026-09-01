#ifndef TIBE_PARAMS_H
#define TIBE_PARAMS_H

/*
 * BCHK+ threshold-KEM parameters (Lapiha & Prest, "A Lattice-Based
 * IND-CCA Threshold KEM from the BCHK+ Transform," Asiacrypt 2025,
 * eprint 2025/1958 -- see ../../BCHK_PAPER_SPEC.md), instantiated for
 * this repo's Phase 1 implementation pass. See README.md for the
 * T=5-vs-paper's-T=32 and BIGNUM-vs-fixed-width decisions.
 */

#define TIBE_D 4096 /* ring degree: R = Z[X]/(X^D + 1) */

/* q: smallest prime >= 2^100 with q = 5 mod 8, required by Lemma 1 for
 * the ring-splitting isomorphism R_q ~ F_{d/2} x F_{d/2} used by the
 * identity-embedding map (a later phase). Derived by gen_params.py
 * (exhaustive search from 2^100 upward + 64-round Miller-Rabin) and
 * independently confirmed prime by `openssl prime -hex 10...115`. */
#define TIBE_Q_HEX "10000000000000000000000115"
/* = 1267650600228229401496703205653, a 101-bit prime. */
#define TIBE_Q_BYTES 13 /* ceil(101/8) -- fixed-width per-coefficient serialization size */

#define TIBE_T 5  /* decryption threshold for this pass (paper's Table 2 proves T=32) */
#define TIBE_N 10 /* number of shareholders (paper leaves N free; must be >= TIBE_T) */

/* Discrete-Gaussian width parameters, Table 2, unchanged from the
 * paper's T=32 instantiation. Safe to reuse at T=5: the correctness
 * bound (BCHK_PAPER_SPEC.md Sec 4.7) depends on T only through a
 * sqrt(T*d) blinding-noise term that shrinks at smaller T, so these
 * widths stay correctness-valid; they are not re-derived as an
 * *optimized* small-T set (see README's security-margin note). */
#define TIBE_SIGMA_A 8.0             /* width for the TIBE master secret (s_a, e_a) */
#define TIBE_SIGMA 4.0               /* width for TIBE encryption randomness s, e, e' */
#define TIBE_SIGMA_P 140737488355328.0 /* = 2^47, per-shareholder blinding width (noise flooding) */

/* beta: offset constant in A0's construction / Decomp_beta, = 2^77. */
#define TIBE_BETA_LOG2 77

/* sigma_RLWE: width used only in the *security proof's* trapdoor-
 * embedding matrix R (BCHK_PAPER_SPEC.md Sec 4.1's proof machinery,
 * Lemma 15) -- not sampled by any real protocol algorithm, recorded
 * here only because sigma' below is defined in terms of it. */
#define TIBE_SIGMA_RLWE 4.0

/* sigma': the middle third of TIBE.Encrypt's noise vector e (Algorithm
 * 4 line 3, "e <- D_{R^3,ς} x D_{R^3,ς'} x D_{R^3,ς}") uses this
 * width instead of TIBE_SIGMA. Table 2 does not give sigma' directly
 * (see BCHK_PAPER_SPEC.md open question #6) -- it is pinned by
 * Theorem 3's correctness condition, Equation (10): sigma' >
 * 2*sqrt(6)*d*sigma_RLWE*sigma. With d=4096, sigma_RLWE=4, sigma=4,
 * that bound is 2*sqrt(6)*4096*4*4 ~= 321,080. 2^19 = 524288 clears it
 * with comfortable margin while staying a clean power of two, in the
 * same style as TIBE_SIGMA_P. */
#define TIBE_SIGMA_PRIME 524288.0 /* = 2^19 */

/* r1, r2: the ring-splitting roots (Phase 4), satisfying
 * X^D+1 = (X^{D/2}-r1)(X^{D/2}-r2) mod q for any power-of-two D --
 * r1 = sqrt(-1) mod q (guaranteed to exist since q = 5 mod 8 implies
 * q = 1 mod 4), r2 = -r1 mod q. Derived by gen_params.py and
 * re-verified there (r1^2 == -1 mod q) each run. */
#define TIBE_R1_HEX "ca19ff9800da9c26c4d00c489"
/* = 1000758434189149340966437569673 */
#define TIBE_R2_HEX "35e60067ff2563d93b2ff3c8c"
/* = 266892166039080060530265635980 */

#endif /* TIBE_PARAMS_H */
