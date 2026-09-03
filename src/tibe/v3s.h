#ifndef TIBE_V3S_H
#define TIBE_V3S_H

#include <openssl/bn.h>
#include <stdint.h>

#include "dkg_params.h"
#include "merkle.h"
#include "params.h"

/*
 * V3S (Verifiable Short Secret Sharing), Espitau-Niot-Prest eprint
 * 2024/959, Figure 4 -- the "VSSS with detection" tier only
 * (Algorithms 1-3: Share/Verify/Reconstruct-that-returns-bottom-on-
 * inconsistency; Algorithm 4, RobustReconstruct, is tier 2 and is
 * *not* implemented here, per the tier-1 decision in BCHK_TODO.md
 * Phase 8d).
 *
 * Hardcoded to this project's one actual use: sharing a party's local
 * DKG contribution x = (s_a^(i), e_a^(i)) -- 2 ring elements, D=4096
 * coefficients each, flattened to a V3S_DIM_X=8192-dimensional signed
 * integer vector (x[0..D) = s_a^(i)'s coefficients, x[D..2D) =
 * e_a^(i)'s, a fixed documented convention) -- and the ephemeral
 * blinding vector y (V3S_DIM_Y=256, over Z directly, not the ring).
 * See dkg_params.h and gen_dkg_params.py for where the dimensions and
 * norm bounds come from. Not a generic reusable module (this project
 * never V3S-shares anything else), matching this project's practice
 * of not building genericity beyond what's actually needed.
 *
 * Representation: ring/Z_q coefficients are converted to *balanced*
 * signed representatives (in (-q/2, q/2]) for every norm/matrix
 * computation below -- required for ||.|| to mean anything (Espitau-
 * Niot-Prest's Lemma 2 is stated over "[+-q/2]^{2n}"), and exact
 * (lossless) here since this project's actual secret magnitudes are
 * always many orders of magnitude smaller than q.
 */

#define V3S_DIM_X TIBE_DKG_R_COLS /* 8192 = 2*TIBE_D */
#define V3S_DIM_Y TIBE_DKG_R_ROWS /* 256 = 2*kappa */

/* x flattened as balanced (signed) int64_t coefficients -- safe since
 * even TIBE_DKG_B_REJECT (1e6) is far under INT64_MAX, and every
 * per-coordinate value here is bounded by a small multiple of
 * TIBE_DKG_LOCAL_SIGMA, not q. */
typedef struct
{
    int64_t coeffs[V3S_DIM_X];
} v3s_secret;

/* The R matrix, derived once from a 32-byte seed (the Merkle root h)
 * via H_R (Espitau-Niot-Prest Definition 8's D_R: entries in
 * {0,+1,-1}, 0 w.p. 1/2, +-1 w.p. 1/4 each). Stored as int8_t (2MB at
 * this project's dimensions) rather than regenerated per use --
 * V3S.Verify needs it repeatedly. */
typedef struct
{
    int8_t entries[V3S_DIM_Y][V3S_DIM_X];
} v3s_matrix;

void v3s_matrix_derive(v3s_matrix* R, const uint8_t seed[MERKLE_HASH_BYTES]);

/* Full V3S.Share(TIBE_N, TIBE_T, x) output, computed once by the
 * party acting as dealer for its own local secret x. Holds every
 * party's x-share and y-share (needed since the dealer must extract
 * per-recipient (share, proof) pairs afterward), the Merkle root, and
 * every party's v_i = R*x_i + y_i mod q (public, not secret --
 * broadcast to everyone, unlike the x/y shares themselves). Caller
 * must v3s_share_free when done. */
typedef struct
{
    BIGNUM* x_shares[TIBE_N][V3S_DIM_X];
    BIGNUM* y_shares[TIBE_N][V3S_DIM_Y];
    BIGNUM* v_shares[TIBE_N][V3S_DIM_Y]; /* v_i, one per party, all public */
    uint8_t nonces[TIBE_N][MERKLE_HASH_BYTES];
    uint8_t root[MERKLE_HASH_BYTES];
    merkle_tree tree; /* kept so v3s_share_extract_proof can generate proofs on demand */
    v3s_matrix R;
} v3s_share_output;

void v3s_share(v3s_share_output* out, const v3s_secret* x, BN_CTX* ctx);
void v3s_share_free(v3s_share_output* out);

/* What one recipient (party `to_index`, 0-indexed) needs, sent
 * privately by the dealer: their x-share, y-share, nonce, and Merkle
 * inclusion proof. `v_shares`/`root` (needed for V3S.Verify's other
 * half) are the same for everyone and travel separately/publicly --
 * see v3s_share_output's own fields. */
typedef struct
{
    BIGNUM* x_share[V3S_DIM_X];
    BIGNUM* y_share[V3S_DIM_Y];
    uint8_t nonce[MERKLE_HASH_BYTES];
    merkle_proof proof;
} v3s_recipient_data;

void v3s_recipient_data_init(v3s_recipient_data* rd);
void v3s_recipient_data_free(v3s_recipient_data* rd);
void v3s_share_extract_recipient(v3s_recipient_data* rd, const v3s_share_output* out, int to_index);

/* V3S.Verify_i: run by the recipient at `my_index` (0-indexed). Checks
 * the Merkle proof, the local linear consistency v_i == R*x_i+y_i,
 * and the shortness bound (||v|| <= TIBE_DKG_B_ACCEPT, v reconstructed
 * from the full public v_shares tuple). Returns 1 (accept) or 0
 * (reject). `v_shares`/`root`/`R` are the dealer's broadcast public
 * data (same for every recipient); `rd` is what was sent privately to
 * `my_index`. */
int v3s_verify(int my_index, BIGNUM* const v_shares[TIBE_N][V3S_DIM_Y], const uint8_t root[MERKLE_HASH_BYTES],
                const v3s_matrix* R, const v3s_recipient_data* rd, BN_CTX* ctx);

/* V3S.Reconstruct: Lagrange-interpolates x from the x-shares held by
 * the parties in `act_x` (their Shamir x-coordinates, 1-indexed,
 * |act_x| >= TIBE_T), cross-checking against every other share in
 * act_x for consistency (Algorithm 3's tier-1 semantics: any
 * inconsistency returns 0/failure rather than attempting recovery --
 * Algorithm 4's Reed-Solomon RobustReconstruct is tier 2, not
 * implemented). Returns 1 on success (out filled), 0 on failure. */
int v3s_reconstruct(v3s_secret* out, BIGNUM* const x_shares[/* act_size */][V3S_DIM_X], const int* act_x,
                     int act_size, BN_CTX* ctx);

#endif /* TIBE_V3S_H */
