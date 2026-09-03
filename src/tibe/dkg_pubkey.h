#ifndef TIBE_DKG_PUBKEY_H
#define TIBE_DKG_PUBKEY_H

#include <openssl/bn.h>

#include "params.h"
#include "ring.h"
#include "v3s.h" /* v3s_secret */

/*
 * Phase 8d, completing the fully dealer-free system: distributed
 * generation of a0, d0, and b0 (=> ek.A0), the last pieces
 * tibe_setup's trusted dealer still had to provide even after
 * (s_a,e_a)'s own DKG (dkg.c/.h) -- see BCHK_TODO.md Phase 8d's
 * correction for why this is a real, separate piece of work, not
 * "much simpler" as originally assumed.
 *
 * a0, d0: need to be genuinely fresh and jointly unbiased per keygen
 * (the security proof needs a0 unpredictable in advance, matching how
 * Kyber-style schemes derive their own public matrix from fresh
 * randomness rather than a fixed system-wide constant -- a0/d0 can't
 * just be a public nothing-up-my-sleeve derivation the way q/r1/r2
 * are). Standard technique: commit-then-reveal coin-flipping --
 * Round P1 each party commits to its own random (a0_i,d0_i)
 * candidate, Round P2 reveals and verifies, then a0 := sum(a0_i),
 * d0 := sum(d0_i) over every committing party (sum of uniforms is
 * uniform; unbiased as long as at least one contributor is honest,
 * the standard coin-flipping guarantee).
 *
 * b0 = a0*s_a+e_a-beta is a direct function of the DKG'd secret, so
 * revealing it needs care. Naively having each party broadcast its
 * own b0_i = a0*s_a^(i)+e_a^(i) would publish N *separate* small-
 * secret samples under the same public a0 -- not obviously covered by
 * the base paper's own hardness assumptions, and not something to
 * just assume is fine. Instead this reuses the *exact* pairwise-
 * cancelling masking technique threshold.c's own decapsulation
 * protocol already uses and has already validated (see its h_mask/
 * derive_directional_seed): for each pair (i,j) with i<j, party i
 * generates one fresh random mask and sends it to j over their
 * already-existing private per-pair channel (piggybacking on the same
 * channel dkg.c's Round 1 uses for V3S share delivery); party i adds
 * that mask to its own b0 contribution, party j subtracts it -- so
 * when every valid party's masked contribution is summed, the masks
 * cancel exactly and only the aggregate b0 (matching precisely what
 * the original single-dealer scheme already published) is ever
 * revealed. This is a simpler, self-contained, one-time mask -- not a
 * reuse of threshold_share.pairwise_seed (whose own dealer-free
 * establishment is a separate, smaller question, not solved here
 * either) -- deliberately, to avoid coupling this one-time setup step
 * to the repeated-per-decapsulation masking machinery.
 *
 * Rounds (layered on top of, not replacing, dkg.c's (s_a,e_a) rounds
 * -- b0's contribution reuses each party's already-sampled local x
 * from dkg_round1_state, no new secret sampling needed):
 * - Round P1: dkg_pubkey_round1 (commit to a0_i/d0_i, generate
 *   pairwise masks to send to every higher-indexed party).
 * - Round P2: dkg_pubkey_verify_commit (per revealer) +
 *   dkg_pubkey_finalize_a0_d0 (sum into a0, d0) -- needs every
 *   party's revealed contribution to have been broadcast/exchanged by
 *   the caller.
 * - Round P3: dkg_pubkey_b0_contribution (per party, using the
 *   now-finalized a0, this project's dkg.c Round-3 valid set, and the
 *   masks exchanged in Round P1) + dkg_pubkey_finalize_b0 (sum,
 *   subtract beta).
 */

#define DKG_PUBKEY_CMT_BYTES 32
#define DKG_PUBKEY_NONCE_BYTES 32

typedef struct
{
    ring_elem a0_contrib;
    ring_elem d0_contrib;
    uint8_t nonce[DKG_PUBKEY_NONCE_BYTES];
    /* mask_to[j], meaningful only for j > this party's own index: a
     * fresh random mask generated to send to party j privately. */
    ring_elem mask_to[TIBE_N];
} dkg_pubkey_round1_state;

void dkg_pubkey_round1_init(dkg_pubkey_round1_state* s);
void dkg_pubkey_round1_free(dkg_pubkey_round1_state* s);

/* Samples this party's a0/d0 candidate contribution and every
 * mask_to[j] (j > my_index), and computes the commitment to
 * broadcast: cmt = H(a0_contrib, d0_contrib, nonce). */
void dkg_pubkey_round1(dkg_pubkey_round1_state* s, int my_index, uint8_t cmt_out[DKG_PUBKEY_CMT_BYTES], BN_CTX* ctx);

/* Verifies a revealed (a0_j,d0_j,nonce_j) against its earlier
 * commitment. Returns 1 if valid, 0 otherwise. */
int dkg_pubkey_verify_commit(const uint8_t cmt[DKG_PUBKEY_CMT_BYTES], const ring_elem* a0_j, const ring_elem* d0_j,
                              const uint8_t nonce_j[DKG_PUBKEY_NONCE_BYTES]);

/* Sums the a0/d0 contributions of every party in `valid` (a
 * verified-commitment set, typically all TIBE_N parties for a0/d0 --
 * independent of the (s_a,e_a) DKG's own valid set) into out_a0/
 * out_d0. Must already be ring_init'd. */
void dkg_pubkey_finalize_a0_d0(ring_elem* out_a0, ring_elem* out_d0, const int valid[TIBE_N],
                                ring_elem* const a0_contribs[TIBE_N], ring_elem* const d0_contribs[TIBE_N],
                                BN_CTX* ctx);

/* Party my_index's masked b0 contribution: b0_i + sum_{j in valid,
 * j>i} mask_to[j] - sum_{j in valid, j<i} received_mask[j], where
 * b0_i = a0*s_a^(i)+e_a^(i) (my_x's first/second TIBE_D coefficients).
 * `my_masks_sent` is this party's own dkg_pubkey_round1_state.mask_to;
 * `received_masks[j]` (for j<my_index) must be the mask party j
 * generated for my_index (i.e. states[j].mask_to[my_index], gathered
 * by the caller the same way dkg.c's v3s_recipient_data is gathered).
 * `valid` here is the (s_a,e_a) DKG's own valid set (dkg.h), not
 * a0/d0's -- b0 must sum over the same set (s_a,e_a) itself did. */
void dkg_pubkey_b0_contribution(ring_elem* out, int my_index, const int valid[TIBE_N], const v3s_secret* my_x,
                                 const ring_elem* a0, const ring_elem mask_to[TIBE_N],
                                 ring_elem* const received_masks[TIBE_N], BN_CTX* ctx);

/* Sums the masked b0 contributions from every party in `valid` and
 * subtracts beta (TIBE_BETA_LOG2), giving the final public b0. */
void dkg_pubkey_finalize_b0(ring_elem* out_b0, const int valid[TIBE_N], ring_elem* const b0_contribs[TIBE_N],
                             BN_CTX* ctx);

#endif /* TIBE_DKG_PUBKEY_H */
