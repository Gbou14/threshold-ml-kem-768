#ifndef TIBE_DKG_H
#define TIBE_DKG_H

#include <openssl/bn.h>

#include "dkg_params.h"
#include "ring.h"
#include "v3s.h"

/*
 * Phase 8d: distributed generation of (s_a, e_a) -- the one genuinely
 * secret quantity tibe_setup currently produces in one place (Remark
 * 1's trusted dealer). d0/a0/A0 stay a separate, simpler question
 * (already "effectively public" per threshold.h's own comment) --
 * not addressed here. Likewise the pairwise PRF seeds
 * threshold_share.pairwise_seed needs (currently dealer-distributed
 * too) are a separate, smaller transport-level question, left for
 * Phase 8d's Docker-wiring step (checklist item 6, BCHK_TODO.md) --
 * the per-pair private channel this DKG already needs to deliver
 * v3s_recipient_data can plausibly also carry a pairwise seed
 * exchange, but that's a channel-design decision, not core
 * cryptography, and isn't solved here.
 *
 * This is THIS PROJECT'S OWN 3-round adaptation of Espitau-Niot-
 * Prest's Section 4.3 "VSSS with detection of malicious behavior"
 * (the simpler, single-dealer, tier-1 primitive), generalized to
 * TIBE_N simultaneous dealers (one per party, each sharing its own
 * local contribution) plus aggregation -- **not** a transcription of
 * the paper's own V1-V4/K1-K4 DKG blueprints, which are both built on
 * "Robust V3S" (tier 2, needing an honest supermajority this project
 * isn't assuming) -- see BCHK_TODO.md Phase 8d's 2026-09-03 correction
 * for why. Round shape:
 *
 * - Round 1: each party i generates its own local x^(i) =
 *   (s_a^(i), e_a^(i)) (flattened, dkg_round1), V3S.Shares it, and
 *   sends each recipient j its private v3s_recipient_data directly
 *   (this project's existing per-recipient-channel model, matching
 *   how tibe_dealer.c already distributes shares -- no new
 *   encryption machinery needed for a non-broadcast transport).
 * - Round 2: each party i V3S.Verifies what it privately received
 *   from every dealer j (dkg_round2), producing a length-TIBE_N
 *   verdict vector to broadcast.
 * - Round 3: a dealer j is *globally valid* iff every party's own
 *   verdict on j was positive (dkg_compute_valid_set); each party
 *   aggregates the private shares it received from every valid dealer
 *   (dkg_aggregate) into its own final Shamir share of the joint
 *   x = sum_{j in valid} x^(j) = (s_a, e_a) -- usable directly by the
 *   *existing*, unmodified threshold_round0/1/2/Combine exactly like
 *   a threshold_setup-issued share.
 *
 * Honest-broadcast assumption, flagged not silently assumed solved:
 * Round 3's consensus rule needs every party to see the same TIBE_N
 * verdict vectors -- an approximation this project's HTTP transport
 * will need to provide (e.g. via the coordinator/dealer relaying
 * consistently), not yet designed (Docker-wiring, checklist item 6).
 */

/* Party i's private round-1 state: its own local secret and the full
 * V3S.Share output (kept so dkg_round1_extract_recipient can pull out
 * what to send each recipient, and so dkg_round1_public can extract
 * the public broadcast payload). */
typedef struct
{
    v3s_secret x;
    v3s_share_output share;
} dkg_round1_state;

/* What party i broadcasts publicly after round 1 -- everyone else
 * needs this to V3S.Verify what they privately received from i.
 * Deliberately does NOT store R (2MB, V3S_DIM_Y*V3S_DIM_X ternary
 * entries): R is fully determined by `root` via v3s_matrix_derive,
 * so storing or transmitting it separately would be pure waste --
 * dkg_round2 re-derives it locally, once per dealer, from `root`
 * alone. */
typedef struct
{
    uint8_t root[MERKLE_HASH_BYTES];
    BIGNUM* v_shares[TIBE_N][V3S_DIM_Y];
} dkg_public_share;

void dkg_round1(dkg_round1_state* state, BN_CTX* ctx);
void dkg_round1_state_free(dkg_round1_state* state);

void dkg_public_share_init(dkg_public_share* pub);
void dkg_public_share_free(dkg_public_share* pub);
/* Extracts the public broadcast payload from a completed round-1 state. */
void dkg_round1_extract_public(dkg_public_share* pub, const dkg_round1_state* state);
/* Extracts what to send privately to recipient `to_index` (0-indexed). */
void dkg_round1_extract_recipient(v3s_recipient_data* rd, const dkg_round1_state* state, int to_index);

/* Party i's (0-indexed `my_index`) round-2 output: verdict[j] = 1 iff
 * i's own V3S.Verify of what it privately received from dealer j
 * (received[j]) succeeded against dealer j's public data (pub[j]). */
typedef struct
{
    int verdict[TIBE_N];
} dkg_round2_verdicts;

void dkg_round2(dkg_round2_verdicts* out, int my_index, const dkg_public_share pub[TIBE_N],
                const v3s_recipient_data received[TIBE_N], BN_CTX* ctx);

/* Round 3's consensus rule: valid_out[j] = 1 iff verdicts[k].verdict[j] == 1
 * for every k (every party's own verification of dealer j succeeded).
 * Same result for every party given consistent broadcast. */
void dkg_compute_valid_set(int valid_out[TIBE_N], const dkg_round2_verdicts verdicts[TIBE_N]);

/* Aggregates the private shares received from every valid dealer
 * (per `valid`) into this party's final Shamir share of the joint
 * (s_a, e_a) -- out_share_s_a/out_share_e_a must already be
 * ring_init'd. Matches threshold_share.share_s_a/share_e_a exactly,
 * so the result can be dropped directly into that struct. */
void dkg_aggregate(ring_elem* out_share_s_a, ring_elem* out_share_e_a, const int valid[TIBE_N],
                    const v3s_recipient_data received[TIBE_N], BN_CTX* ctx);

#endif /* TIBE_DKG_H */
