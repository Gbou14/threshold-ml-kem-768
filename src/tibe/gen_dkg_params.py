#!/usr/bin/env python3
"""
Derivation script for src/tibe/dkg_params.h's concrete numeric constants
(Phase 8d, distributed key generation for (s_a, e_a) via the "VSSS with
detection" tier of Espitau-Niot-Prest's V3S scheme -- CRYPTO 2024, eprint
2024/959, Section 4.3/4.2). See BCHK_TODO.md Phase 8d for the full
literature-pass writeup and why this tier (not the stronger "Robust V3S"
tier their own Pelican DKG uses) is the right fit here.

Not part of the build -- a one-time, reproducible derivation, same role
gen_params.py plays for q/r1/r2. This script *computes* every DKG-specific
bound from first principles for this project's own parameters (per-party
secret dimension, sigma, q) rather than reusing eprint 2024/959's own
Table 2 numbers, which are tuned for their Pelican signature scheme's
much smaller/tighter modulus -- our q is astronomically larger (2^101 vs
their ~2^50-2^70), so the concrete margins differ substantially, even
though the *technique* (V3S, Lemma 2's ternary challenge matrix) is
reused directly, unmodified.

What's being derived, and why:

- Each of TIBE_N parties locally samples its own candidate contribution
  (s_a^(i), e_a^(i)) -- 2 ring elements, D=4096 coefficients each, i.e. a
  flattened Z-vector of dimension 2*D = 8192. The joint secret is
  (s_a, e_a) = sum_i (s_a^(i), e_a^(i)).
- DKG_LOCAL_SIGMA (the width each party samples its own local
  contribution at) is fixed at 16 -- deliberately reusing
  GAUSS_CONV_BASE_SIGMA from gauss.c (Phase 8b), an already-implemented,
  already-validated exact CDT width, needing no new sampler code. It
  also comfortably exceeds sqrt(2)*eta_eps(Z) ~= 8.49 (Micciancio-Walter,
  eprint 2017/259), the per-term minimum the convolution theorem needs
  for "sum of N independent width-16 draws ~= D_{Z, 16*sqrt(N)}" to be a
  *provable* (not just heuristic) statistical claim -- see BCHK_TODO.md
  Phase 8d for why this matters and the correctness-bound re-verification
  (against eprint 2025/1958's actual Theorem 5 proof, not just this
  project's own secondhand transcription of it) confirming a wider
  resulting sigma_a costs essentially nothing in correctness margin
  (Theorem 5's bound B is dominated by beta/2 regardless of sigma_a --
  the paper's own authors say as much on page 29: "we may simply
  increase sigma_a ... as long as Equation (13) is satisfied").
- The joint sigma_a this DKG produces is therefore DKG_LOCAL_SIGMA *
  sqrt(TIBE_N), replacing the trusted dealer's direct sigma_a=8 draw.
- The V3S "random submersion" matrix R is a fixed-shape ternary matrix
  (Espitau-Niot-Prest, Definition 8 + Lemma 2/3/4, following Nguyen22's
  thesis Lemma 3.2.5): R in {0,+-1}^{(2*kappa) x (dim of the secret
  being proven)}, each entry 0 w.p. 1/2 and +-1 w.p. 1/4 each. Reused
  here verbatim, unmodified -- it's a general-purpose, already-proven
  construction, not something this project has any reason to redesign.
- b_honest: the norm an honestly-generated per-party secret should stay
  under with overwhelming probability (tau=1.4, reusing the SAME
  tail-margin constant Espitau-Niot-Prest use for an analogous purpose
  in their own Section 6.2 -- a high-dimensional Gaussian's norm
  concentrates *more* tightly as dimension grows, so a constant proven
  sufficient at their n=256 is at least as safe at this project's much
  higher n=8192).
- b_reject (Lemma 2's "b"): the norm threshold above which a
  submission is treated as malicious. Must satisfy b <= q/(82*D) for
  Lemma 2's guarantee to apply (D = TIBE_D, since our secret's dimension
  2*D matches Lemma 2's "2n" with n=D exactly). Given this project's
  q ~ 2^101, that ceiling is astronomically larger than b_honest, so
  there's enormous headroom -- unlike Espitau-Niot-Prest's own tightly
  size-optimized q, we do NOT need an enlarged "q_V3S" modulus for the
  V3S-internal Shamir sharing the way their Section 6.4 does; q itself
  already has ample room. This script confirms that numerically rather
  than assuming it.
- sigma_y / B': the ephemeral blinding width and the accept-threshold
  on ||R*x+y||, chosen so honest submissions are comfortably accepted
  and Lemma-2-flagged (oversized) submissions are comfortably rejected,
  with real numeric margin computed below, not eyeballed.

Deterministic and reproducible: every number below is derived from
TIBE_D, TIBE_N, TIBE_Q_HEX, kappa=128, and DKG_LOCAL_SIGMA=16 via closed-
form arithmetic -- no randomness, nothing to seed.
"""

import math

TIBE_D = 4096
TIBE_N = 10
TIBE_Q_HEX = "10000000000000000000000115"
KAPPA = 128

DKG_LOCAL_SIGMA = 16.0  # = GAUSS_CONV_BASE_SIGMA (gauss.c, Phase 8b)


def eta_eps_Z(eps_log2=-160):
    """eta_eps(Z) <= sqrt(ln(2 + 2/eps)/pi) (Micciancio-Walter eprint
    2017/259, Sec 2) -- sanity-check that DKG_LOCAL_SIGMA clears the
    convolution theorem's per-term minimum sqrt(2)*eta_eps(Z)."""
    eps = 2.0 ** eps_log2
    return math.sqrt(math.log(2 + 2 / eps) / math.pi)


def main():
    q = int(TIBE_Q_HEX, 16)
    secret_dim = 2 * TIBE_D  # (s_a^(i), e_a^(i)) flattened: 2 ring elements * D coeffs

    print(f"q = {q}  (bit_length={q.bit_length()})")
    print(f"TIBE_D = {TIBE_D}, TIBE_N = {TIBE_N}, secret dimension (2*TIBE_D) = {secret_dim}")
    print()

    # --- convolution-theorem precondition check for DKG_LOCAL_SIGMA ---
    eta = eta_eps_Z()
    margin = math.sqrt(2) * eta
    print(f"eta_eps(Z) (eps=2^-160) ~= {eta:.4f}")
    print(f"sqrt(2)*eta_eps(Z) ~= {margin:.4f}  (per-term minimum for the convolution theorem)")
    assert DKG_LOCAL_SIGMA > margin, "DKG_LOCAL_SIGMA must exceed sqrt(2)*eta_eps(Z)"
    print(f"DKG_LOCAL_SIGMA = {DKG_LOCAL_SIGMA} > {margin:.4f}  -- OK, convolution theorem applies")

    sigma_a_joint = DKG_LOCAL_SIGMA * math.sqrt(TIBE_N)
    print(f"Joint sigma_a after summing {TIBE_N} local contributions = "
          f"{DKG_LOCAL_SIGMA}*sqrt({TIBE_N}) ~= {sigma_a_joint:.4f}")
    print(f"  (vs. paper's trusted-dealer sigma_a=8 -- wider, but per Theorem 5's B ~ beta/2, "
          f"costs negligible correctness margin -- see BCHK_TODO.md Phase 8d)")
    print()

    # --- V3S matrix R shape ---
    R_rows = 2 * KAPPA
    R_cols = secret_dim
    print(f"R shape: {R_rows} x {R_cols}, ternary {{0,+-1}}, entries 0 w.p. 1/2, +-1 w.p. 1/4 each")
    print()

    # --- b_honest: expected norm of an honest per-party secret, with tail margin ---
    tau = 1.4  # reused from Espitau-Niot-Prest Sec 6.2's own analogous tail-margin choice
    expected_norm = DKG_LOCAL_SIGMA * math.sqrt(secret_dim)
    b_honest = tau * expected_norm
    print(f"Expected ||x||_2 for an honest per-party secret = "
          f"{DKG_LOCAL_SIGMA}*sqrt({secret_dim}) ~= {expected_norm:.2f}")
    print(f"b_honest (tau={tau} tail margin) ~= {b_honest:.2f}")
    print()

    # --- b_reject (Lemma 2's b): must be <= q/(82*TIBE_D), comfortably above b_honest ---
    ceiling = q / (82 * TIBE_D)
    print(f"Lemma 2 ceiling q/(82*TIBE_D) ~= {ceiling:.3e}")
    b_reject = 1_000_000.0
    assert b_reject > 10 * b_honest, "b_reject should clear b_honest with real margin"
    assert b_reject < ceiling / 1000, "b_reject should sit far below Lemma 2's ceiling"
    print(f"b_reject = {b_reject:.0f}  "
          f"({b_reject / b_honest:.1f}x b_honest, "
          f"{ceiling / b_reject:.3e}x below the Lemma 2 ceiling -- enormous margin, "
          f"confirms no enlarged q_V3S modulus is needed for this project's q)")
    print()

    # --- sigma_y and B': honest-accept vs malicious-reject separation ---
    # ||R*x||_2: R in {0,+-1}^{R_rows x R_cols}, x_j ~ D_{DKG_LOCAL_SIGMA} i.i.d.
    # Each output coordinate is a sum of ~R_cols/2 nonzero +-x_j terms (R is 0
    # w.p. 1/2), variance ~= (R_cols/2) * DKG_LOCAL_SIGMA^2.
    Rx_coord_var = (R_cols / 2) * (DKG_LOCAL_SIGMA ** 2)
    Rx_norm = math.sqrt(R_rows * Rx_coord_var)
    print(f"Expected ||R*x||_2 (honest x) ~= {Rx_norm:.2f}")

    sigma_y = 16384.0
    y_norm = sigma_y * math.sqrt(R_rows)
    print(f"sigma_y = {sigma_y}, expected ||y||_2 = sigma_y*sqrt({R_rows}) ~= {y_norm:.2f}  "
          f"({y_norm / Rx_norm:.1f}x ||R*x||_2 -- y dominates, blinding x's contribution)")

    honest_v_norm = math.sqrt(y_norm ** 2 + Rx_norm ** 2)  # combined via quadrature
    B_accept = math.ceil(1.3 * honest_v_norm / 1000) * 1000  # 1.3x tail margin, rounded
    print(f"Expected honest ||R*x+y||_2 ~= {honest_v_norm:.2f}  "
          f"(1.3x tail margin -> B' = {B_accept:.0f})")

    reject_floor = 0.5 * b_reject * math.sqrt(26)  # Lemma 2's (1/2)*b*sqrt(26) bound
    print(f"Lemma 2 reject-floor (1/2)*b_reject*sqrt(26) ~= {reject_floor:.2f}")
    assert B_accept < reject_floor, "B' must sit below Lemma 2's guaranteed reject-floor"
    print(f"B' = {B_accept:.0f} < reject-floor {reject_floor:.2f}  "
          f"({reject_floor / B_accept:.2f}x margin) -- honest/malicious separation confirmed")
    print()

    print("Summary (-> dkg_params.h):")
    print(f"  TIBE_DKG_LOCAL_SIGMA = {DKG_LOCAL_SIGMA}")
    print(f"  TIBE_DKG_SIGMA_A_JOINT ~= {sigma_a_joint:.4f}  (documentation only, not a sampled width)")
    print(f"  TIBE_DKG_R_ROWS = {R_rows}")
    print(f"  TIBE_DKG_R_COLS = {R_cols}")
    print(f"  TIBE_DKG_SIGMA_Y = {sigma_y}")
    print(f"  TIBE_DKG_B_ACCEPT = {B_accept:.0f}")
    print(f"  TIBE_DKG_B_REJECT = {b_reject:.0f}  (documentation only -- soundness argument, not directly coded)")


if __name__ == "__main__":
    main()
