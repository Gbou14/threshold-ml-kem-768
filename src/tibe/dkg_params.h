#ifndef TIBE_DKG_PARAMS_H
#define TIBE_DKG_PARAMS_H

/*
 * Phase 8d: distributed key generation for (s_a, e_a) via the "VSSS
 * with detection" tier of Espitau-Niot-Prest's V3S scheme (CRYPTO
 * 2024, eprint 2024/959, Section 4.3). See BCHK_TODO.md Phase 8d for
 * the full literature-pass writeup and gen_dkg_params.py for the
 * derivation these constants come from (re-run it to reproduce every
 * value below).
 *
 * d0/a0/A0 stay exactly as they already are (already "effectively
 * public" per threshold.h's own documentation -- see BCHK_TODO.md
 * Phase 8d) -- this DKG only distributes the generation of
 * (s_a, e_a), the one genuinely secret quantity tibe_setup currently
 * produces in one place.
 */

/* Each of TIBE_N parties locally samples its own candidate
 * contribution (s_a^(i), e_a^(i)) at this width -- deliberately equal
 * to GAUSS_CONV_BASE_SIGMA (gauss.c, Phase 8b), so x-sampling reuses
 * the already-implemented, already-validated exact CDT sampler with
 * zero new code. Also comfortably exceeds the sqrt(2)*eta_eps(Z) ~=
 * 8.43 minimum the Micciancio-Walter convolution theorem needs per
 * term for "sum of TIBE_N independent width-16 draws ~= a genuine
 * D_{Z,16*sqrt(TIBE_N)}" to be a provable claim, not just a heuristic
 * one. */
#define TIBE_DKG_LOCAL_SIGMA 16.0

/* The resulting joint width once all TIBE_N local contributions are
 * summed: 16*sqrt(10) ~= 50.5964. Documentation only (not itself a
 * sampled width anywhere) -- replaces the trusted dealer's direct
 * sigma_a=8 draw. Wider than the paper's proven sigma_a=8, but the
 * correctness bound (eprint 2025/1958 Theorem 5, Equation 13) is
 * dominated by beta/2 regardless of sigma_a (confirmed directly
 * against the paper's own page images, not just this project's
 * secondhand transcription -- see BCHK_TODO.md Phase 8d), so this
 * costs negligible correctness margin. */
#define TIBE_DKG_SIGMA_A_JOINT 50.5964

/* The V3S "random submersion" challenge matrix R: (2*kappa) x (2*D)
 * ternary, each entry 0 w.p. 1/2, +-1 w.p. 1/4 each (Espitau-Niot-
 * Prest Definition 8 + Lemma 2/3/4, reused verbatim -- a general-
 * purpose, already-proven construction, not redesigned here).
 * kappa=128 matches this project's security parameter throughout;
 * 2*D=8192 is the flattened Z-dimension of one party's
 * (s_a^(i), e_a^(i)) secret (2 ring elements, D=4096 coefficients
 * each). */
#define TIBE_DKG_R_ROWS 256  /* = 2*kappa, kappa=128 */
#define TIBE_DKG_R_COLS 8192 /* = 2*TIBE_D */

/* Width of the ephemeral Gaussian blinding vector y in
 * D_{TIBE_DKG_SIGMA_Y}^{TIBE_DKG_R_ROWS} (over Z directly, not the
 * ring -- 256 independent integer coefficients). Chosen (see
 * gen_dkg_params.py) so ||y|| dominates ||R*x|| for honest x
 * (~16x), and so the honest-accept region and Lemma 2's malicious-
 * reject floor are cleanly separated (see TIBE_DKG_B_ACCEPT below).
 * A clean power of two (2^14), matching this project's convention
 * elsewhere for widths not directly forced by a correctness
 * equation. Exceeds GAUSS_DIRECT_MAX_SIGMA, so sampling y also
 * reuses gauss.c's existing convolution machinery unmodified -- no
 * new sampler code needed for either x or y. */
#define TIBE_DKG_SIGMA_Y 16384.0

/* Accept threshold on ||R*x+y|| (V3S.Verify's norm check): honest
 * submissions land around ~262,656 (1.3x tail margin -> rounded up
 * to 342,000, see gen_dkg_params.py); Lemma 2 guarantees a submission
 * with ||x|| >= TIBE_DKG_B_REJECT produces ||R*x+y|| >=
 * 2,549,510 with overwhelming probability -- a ~7.45x margin between
 * the two, confirmed numerically, not eyeballed. */
#define TIBE_DKG_B_ACCEPT 342000.0

/* Documentation only, not directly coded anywhere: the norm above
 * which Lemma 2 guarantees rejection. ~493x the expected honest norm
 * (~1448) and ~3.77e18x below Lemma 2's own applicability ceiling
 * q/(82*TIBE_D) -- this project's q (~2^101) is astronomically larger
 * than eprint 2024/959's own (much more size-optimized, ~2^50-2^70)
 * modulus, which is why (confirmed numerically in
 * gen_dkg_params.py, not assumed) no enlarged "q_V3S" modulus is
 * needed for the V3S-internal Shamir sharing the way their own
 * Section 6.4 uses one -- this project's q already has enormous
 * headroom. */
#define TIBE_DKG_B_REJECT 1000000.0

#endif /* TIBE_DKG_PARAMS_H */
