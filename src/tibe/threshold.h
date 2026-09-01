#ifndef TIBE_THRESHOLD_H
#define TIBE_THRESHOLD_H

#include <openssl/bn.h>
#include <stdint.h>

#include "params.h"
#include "ring.h"
#include "tibe.h"

/*
 * The real 3-round threshold-decryption protocol (BCHK_PAPER_SPEC.md
 * Sec 4.5, Algorithms 5-8 / Figure 5), replacing tibe_decrypt_direct's
 * (tibe.c) single-party stand-in: (s_a, e_a) are genuinely
 * Shamir-shared across TIBE_N parties, and any TIBE_T of them jointly
 * recover the message via ShareExtract_{0,1,2}/Combine -- commit/
 * reveal (catching a party that lies about its round-0 value) plus
 * pairwise-PRF masking (hiding each individual z_i from anyone who
 * only sees a strict subset of contributions) -- without any party,
 * including the coordinator, ever reconstructing (s_a, e_a).
 *
 * d0 (from tibe_msk, tibe.h) is NOT secret-shared -- only s_a and e_a
 * are, per Algorithm 1 line 9 ("dk_i := ([[s_a]]_i, [[e_a]]_i)"). Every
 * party (shareholders and whoever runs Combine) needs d0 directly to
 * compute Decomp_beta(d0^-1 * (r-w)) locally; it is effectively public
 * infrastructure distributed once by the trusted dealer (Remark 1),
 * not a value the (s_a,e_a) secrecy guarantee is protecting -- w
 * itself becomes public after round 1, so d0^-1*(r-w) is a publicly
 * computable quantity once every active party's w_i is known.
 *
 * z2 sign: Phase 3 found empirically (and confirmed by hand algebra
 * and an independent symbolic check) that a literal transcription of
 * Algorithm 8 line 3 ("z2 = sum(z_{i,2}) + c0") does not satisfy
 * Algorithm 8's own F_vk*z==r assertion -- the fix, "z2 = sum(z_{i,2})
 * - c0", is what tibe.c's tibe_decrypt_direct uses. That derivation
 * only involved the same A0/b0/beta algebra this real protocol also
 * uses (the extra noise-flooding/masking terms are purely additive on
 * top and don't touch the sign relationship), so this module applies
 * the same fix -- re-verified here independently via this phase's own
 * end-to-end tests, not copied on faith from Phase 3.
 *
 * y_{i,0} correction: an initial reading of Algorithm 5 line 2 as
 * "y_{i,0} = a0*p_{i,0}+p_{i,1}" (raw a0, not the published A0) made
 * the full multi-party correctness algebra NOT close, even with the
 * z2 fix above and real masking/Lagrange reconstruction both verified
 * independently correct in isolation. A symbolic toy-ring check across
 * several hypotheses found the fix: y_{i,0} = A0.p_i, a proper
 * 3-vector dot product with the *published* A0 (from ek), exactly
 * mirroring y_{i,1} = (A1-E(vk)*G).x_{i,0} and y_{i,2} = A2.x_{i,1}'s
 * own pattern -- the transcription slip was almost certainly reading
 * a compact dot-product notation as the scalar formula "a0*p_{i,0}+
 * p_{i,1}" instead. This is why no shareholder needs raw a0 at all --
 * only ek (for A0/A1/A2/G) and d0 (for Decomp_beta) are needed beyond
 * a party's own Shamir share.
 */

/* One shareholder's private state after threshold_setup: its Shamir
 * share of (s_a, e_a), the (not secret-shared) d0 -- needed directly
 * by every party for Decomp_beta(d0^-1*...) in round 2/Combine, see
 * tibe.h's tibe_msk comment for why it lives outside the
 * Shamir-shared secret -- its own x-coordinate (index+1, matching
 * src/kyber/threshold.c's convention), and the pairwise PRF seeds it
 * shares with every other party (pairwise_seed[j] is this party's
 * shared secret with the party at x-coordinate j+1; the entry at its
 * own index is unused). */
typedef struct
{
    int x;
    ring_elem share_s_a;
    ring_elem share_e_a;
    ring_elem d0;
    uint8_t pairwise_seed[TIBE_N][TIBE_SEED_BYTES];
} threshold_share;

/* Round-0 output (broadcast) plus the private state a party must
 * retain through round 2. */
typedef struct
{
    ring_elem x0[3];
    ring_elem x1[3];
    ring_elem p[3];
    ring_elem w;
} threshold_round0_state;

/* Round-2 output ("contrib_{i,2}" in the paper), Algorithm 7 line 9. */
typedef struct
{
    ring_elem z[3];
    ring_elem x0[3];
    ring_elem x1[3];
} threshold_contrib2;

void threshold_share_init(threshold_share* s);
void threshold_share_free(threshold_share* s);
void threshold_round0_state_init(threshold_round0_state* s);
void threshold_round0_state_free(threshold_round0_state* s);
void threshold_contrib2_init(threshold_contrib2* c);
void threshold_contrib2_free(threshold_contrib2* c);

/* Fixed-width serialization (9 ring elements: z[3],x0[3],x1[3]) --
 * Phase 7's round-2 HTTP response. */
size_t threshold_contrib2_serialized_bytes(void);
void threshold_contrib2_serialize(uint8_t* out, const threshold_contrib2* c);
void threshold_contrib2_deserialize(threshold_contrib2* c, const uint8_t* in);

/* Dealer step: Algorithm 1 line 9 (Shamir-share s_a and e_a
 * coefficient-wise as degree-<T polynomials over Z_q, secret at x=0)
 * plus pairwise-seed generation for round 2's masking, packaged into
 * TIBE_N threshold_share structs (shares_out[i] has x-coordinate
 * i+1). `msk` is Phase 3's tibe_setup output -- this function is what
 * turns "one party holds (s_a,e_a,d0) directly" into "N parties each
 * hold an unreconstructable share." */
void threshold_setup(threshold_share shares_out[TIBE_N], const tibe_msk* msk, BN_CTX* ctx);

/* Serialization for the PRIVATE parts of one threshold_share -- what
 * the dealer sends to shareholder i over its own secure channel
 * (Phase 7's Docker wiring): the Shamir shares of (s_a, e_a), d0 (the
 * same value for every party, but naturally travels with each
 * shareholder's own handoff rather than needing a separate channel --
 * see tibe.h's tibe_msk comment for why every party needs it), and the
 * full pairwise-seed table. `x` is a plain small int, sent separately.
 * The coordinator isn't one of the N shareholders but also needs d0
 * for tkem_combine -- the dealer writes it to the shared volume
 * separately for that (see BCHK_TODO.md Phase 7 / src/tibe_dealer.c). */
size_t threshold_share_private_serialized_bytes(void);
void threshold_share_private_serialize(uint8_t* out, const threshold_share* s);
void threshold_share_private_deserialize(threshold_share* s, const uint8_t* in);

/* Algorithm 5: fresh blinding plus `ek` (A0/A1/A2/G) and `id` --
 * doesn't touch a party's Shamir share at all (y_{i,0}=A0.p_i uses
 * only the published A0, see threshold.h's header comment for the
 * y_{i,0} correction). Returns cmt_i (TIBE_CMT_BYTES bytes) and fills
 * `state` for later rounds. */
void threshold_round0(uint8_t cmt_out[TIBE_CMT_BYTES], threshold_round0_state* state, const tibe_ek* ek,
                       const ring_elem* id, BN_CTX* ctx);

/* Algorithm 6: trivial reveal of the w computed in round 0. `w_out`
 * must already be ring_init'd. */
void threshold_round1(ring_elem* w_out, const threshold_round0_state* state);

/* Algorithm 7: given every active party's round-0/1 output (indexed
 * in the same order as `act_x`, which lists the active set's
 * x-coordinates), verify commitments, derive the pairwise mask, and
 * compute this party's contribution. `my_index` is this party's
 * position within `act_x`/`cmts`/`ws` (needed to skip masking against
 * itself and to know which pairwise_seed entries to use). Note:
 * Algorithm 7 itself never references `id`/F_vk (only `ek->r`,
 * `my_share`'s `d0` and pairwise seeds, `ct`, and the collected
 * cmt/w values) -- F_vk only reappears in Combine. Returns 1 on
 * success, 0 if any other active party's revealed w_j doesn't match
 * its round-0 commitment (a caught liar -- Algorithm 7 line 1's
 * assertion). */
int threshold_round2(threshold_contrib2* out, const threshold_round0_state* state, const threshold_share* my_share,
                      const tibe_ek* ek, const tibe_ct* ct, const int* act_x, int act_size, int my_index,
                      const uint8_t (*cmts)[TIBE_CMT_BYTES], const ring_elem* ws, BN_CTX* ctx);

/* Algorithm 8: sums every active party's contrib2, reconstructs
 * (c0,c1) itself from the public w=sum(w_j) (any one active party's
 * already-computed c0/c1 could be reused instead -- they're a
 * deterministic function of public data by this point, not a secret
 * -- but this function recomputes independently for clarity, at the
 * cost of one more ring_inv). Runs Algorithm 8 line 7's own
 * F_vk*z==r assertion; returns 1 and fills msg_out on success, 0 on
 * failure (which, for an honest ciphertext/shares/T-sized act, should
 * not happen -- see threshold_round2's return value for the
 * malicious-party case, which is a different, earlier check). */
int threshold_combine(uint8_t msg_out[TIBE_MSG_BYTES], const tibe_ek* ek, const ring_elem* id, const tibe_ct* ct,
                       const ring_elem* d0, const int* act_x, int act_size, const ring_elem* ws,
                       const threshold_contrib2* contribs, BN_CTX* ctx);

#endif /* TIBE_THRESHOLD_H */
