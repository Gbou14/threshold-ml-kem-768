/*
 * Self-contained regression test for the DKG protocol (Phase 8d, this
 * project's own 3-round tier-1 adaptation -- see dkg.h's header
 * comment and BCHK_TODO.md Phase 8d for why this is not the paper's
 * own V1-V4/K1-K4, which are tier 2).
 *
 * Two things validated:
 * 1. A full TIBE_N-party honest run produces a real (T,N)-Shamir
 *    sharing of a jointly-generated secret that plugs directly into
 *    the *existing*, unmodified threshold_round0/1/2/Combine and
 *    decapsulates correctly. Since a0/d0's own distributed generation
 *    and the b0-reveal step aren't built yet (see BCHK_TODO.md Phase
 *    8d's correction), this is necessarily a hybrid: d0/a0 sampled
 *    the same way tibe_setup already does, and A0/b0 computed
 *    directly from the DKG's true joint secret via a test-only
 *    reconstruction (summing every party's real local x^(j) --
 *    something only this test orchestrator does, never any protocol
 *    participant, mirroring how test_v3s.c already validates its own
 *    correctness this way) purely so ek is internally consistent
 *    enough to run the real protocol against.
 * 2. Tier 1's actual payoff: a party submitting a corrupted local
 *    share to one recipient gets caught by that recipient's
 *    V3S.Verify, and Round 3's unanimous-positive consensus rule then
 *    excludes that dealer's entire contribution for *every* party
 *    (not just the one who caught it) -- the joint secret silently
 *    changes (excluding the malicious contribution) rather than
 *    silently corrupting.
 */
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../dkg.h"
#include "../identity.h"
#include "../threshold.h"
#include "../tibe.h"
#include "../wots.h"

static int failures = 0;

#define CHECK(cond, msg)                                                                                             \
    do                                                                                                                \
    {                                                                                                                 \
        if (!(cond))                                                                                                  \
        {                                                                                                             \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);                                                    \
            failures++;                                                                                               \
        }                                                                                                             \
    } while (0)

/* Runs DKG rounds 1-3 across TIBE_N parties (all locally, this test
 * orchestrating every party -- matching test_threshold.c's own style
 * of driving all parties from one process). `exclude_index`, if >= 0,
 * corrupts the local share dealer `exclude_index` sends to recipient
 * 0 specifically (simulating a malicious dealer), to exercise Round
 * 3's detection/exclusion path; pass -1 for the fully-honest run. */
/* NOTE on allocation: dkg_round1_state/dkg_public_share/
 * v3s_recipient_data are all large (each embeds V3S_DIM_X=8192- or
 * V3S_DIM_Y=256-wide BIGNUM* arrays; v3s_share_output alone is
 * several MB). A TIBE_N-sized array of any of these, or a
 * TIBE_N*TIBE_N array of v3s_recipient_data, overflows the default
 * stack (found the hard way -- an early version of this test
 * segfaulted from exactly this). Every such array below is
 * heap-allocated via malloc, not declared as a local array. */

static void
run_dkg(ring_elem share_s_a[TIBE_N], ring_elem share_e_a[TIBE_N], int valid_out[TIBE_N], int exclude_index,
        BN_CTX* ctx)
{
    dkg_round1_state* states = malloc(sizeof(dkg_round1_state) * TIBE_N);
    dkg_public_share* pubs = malloc(sizeof(dkg_public_share) * TIBE_N);
    for (int i = 0; i < TIBE_N; i++)
    {
        dkg_public_share_init(&pubs[i]);
        dkg_round1(&states[i], ctx);
        dkg_round1_extract_public(&pubs[i], &states[i]);
    }

    /* received[dealer][recipient] -- what recipient privately got from dealer. */
    v3s_recipient_data(*received)[TIBE_N] = malloc(sizeof(v3s_recipient_data) * TIBE_N * TIBE_N);
    for (int dealer = 0; dealer < TIBE_N; dealer++)
    {
        for (int recip = 0; recip < TIBE_N; recip++)
        {
            v3s_recipient_data_init(&received[dealer][recip]);
            dkg_round1_extract_recipient(&received[dealer][recip], &states[dealer], recip);
        }
    }

    if (exclude_index >= 0)
    {
        /* Corrupt what party `exclude_index` (as dealer) sent to
         * recipient 0 -- simulates a dealer lying to exactly one
         * party, the scenario tier 1's soundness property covers. */
        BN_add_word(received[exclude_index][0].x_share[0], 1);
    }

    dkg_round2_verdicts verdicts[TIBE_N];
    v3s_recipient_data* recv_by_i = malloc(sizeof(v3s_recipient_data) * TIBE_N);
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int dealer = 0; dealer < TIBE_N; dealer++)
        {
            recv_by_i[dealer] = received[dealer][i];
        }
        dkg_round2(&verdicts[i], i, pubs, recv_by_i, ctx);
    }

    dkg_compute_valid_set(valid_out, verdicts);

    for (int i = 0; i < TIBE_N; i++)
    {
        for (int dealer = 0; dealer < TIBE_N; dealer++)
        {
            recv_by_i[dealer] = received[dealer][i];
        }
        dkg_aggregate(&share_s_a[i], &share_e_a[i], valid_out, recv_by_i, ctx);
    }
    free(recv_by_i);

    for (int dealer = 0; dealer < TIBE_N; dealer++)
    {
        for (int recip = 0; recip < TIBE_N; recip++)
        {
            v3s_recipient_data_free(&received[dealer][recip]);
        }
        dkg_public_share_free(&pubs[dealer]);
        dkg_round1_state_free(&states[dealer]);
    }
    free(received);
    free(pubs);
    free(states);
}

/* Test-only: sums every party's real local x^(j) directly (int64
 * arithmetic, small values) to get the true joint secret -- never
 * done by any real protocol participant, only by this orchestrator,
 * purely to build a consistent ek for validating that DKG's output
 * plugs into the existing protocol correctly. Re-derives its own
 * dkg_round1_state calls rather than reusing run_dkg's (kept
 * separate/simple; the cost of one extra DKG round-1 pass is
 * negligible next to what follows). */
static void
reconstruct_true_secret(ring_elem* s_a, ring_elem* e_a, dkg_round1_state states[TIBE_N], BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* tmp = BN_new();
    ring_zero(s_a);
    ring_zero(e_a);
    for (int j = 0; j < TIBE_N; j++)
    {
        for (int c = 0; c < TIBE_D; c++)
        {
            int64_t v = states[j].x.coeffs[c];
            uint64_t mag = (uint64_t)(v < 0 ? -v : v);
            BN_set_word(tmp, mag);
            if (v < 0)
            {
                BN_set_negative(tmp, 1);
            }
            BN_nnmod(tmp, tmp, q, ctx);
            BN_mod_add(s_a->coeffs[c], s_a->coeffs[c], tmp, q, ctx);
        }
        for (int c = 0; c < TIBE_D; c++)
        {
            int64_t v = states[j].x.coeffs[TIBE_D + c];
            uint64_t mag = (uint64_t)(v < 0 ? -v : v);
            BN_set_word(tmp, mag);
            if (v < 0)
            {
                BN_set_negative(tmp, 1);
            }
            BN_nnmod(tmp, tmp, q, ctx);
            BN_mod_add(e_a->coeffs[c], e_a->coeffs[c], tmp, q, ctx);
        }
    }
    BN_free(tmp);
}

static void
test_full_dkg_then_decapsulation(BN_CTX* ctx)
{
    /* Template ek/msk for A1/A2/G/r/d0 -- all independent of
     * (s_a,e_a), see BCHK_TODO.md Phase 8d's correction. Its own
     * A0/s_a/e_a are discarded/overwritten below. */
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tibe_setup(&ek, &msk, ctx);

    ring_elem share_s_a[TIBE_N], share_e_a[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        ring_init(&share_s_a[i]);
        ring_init(&share_e_a[i]);
    }
    int valid[TIBE_N];

    /* Not using run_dkg here: it doesn't expose the per-party round-1
     * states, and reconstruct_true_secret (test-only) needs them to
     * build an ek consistent with these exact shares -- so this test
     * runs the DKG protocol's rounds inline instead, capturing
     * `states` alongside. run_dkg itself is exercised by
     * test_malicious_dealer_excluded below. */
    /* Heap-allocated -- see run_dkg's note above on why these can't be
     * local arrays. */
    dkg_round1_state* states = malloc(sizeof(dkg_round1_state) * TIBE_N);
    dkg_public_share* pubs = malloc(sizeof(dkg_public_share) * TIBE_N);
    for (int i = 0; i < TIBE_N; i++)
    {
        dkg_public_share_init(&pubs[i]);
        dkg_round1(&states[i], ctx);
        dkg_round1_extract_public(&pubs[i], &states[i]);
    }
    v3s_recipient_data(*received)[TIBE_N] = malloc(sizeof(v3s_recipient_data) * TIBE_N * TIBE_N);
    for (int dealer = 0; dealer < TIBE_N; dealer++)
    {
        for (int recip = 0; recip < TIBE_N; recip++)
        {
            v3s_recipient_data_init(&received[dealer][recip]);
            dkg_round1_extract_recipient(&received[dealer][recip], &states[dealer], recip);
        }
    }
    dkg_round2_verdicts verdicts[TIBE_N];
    v3s_recipient_data* recv_by_i = malloc(sizeof(v3s_recipient_data) * TIBE_N);
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int dealer = 0; dealer < TIBE_N; dealer++)
        {
            recv_by_i[dealer] = received[dealer][i];
        }
        dkg_round2(&verdicts[i], i, pubs, recv_by_i, ctx);
    }
    dkg_compute_valid_set(valid, verdicts);
    int all_valid = 1;
    for (int i = 0; i < TIBE_N; i++)
    {
        if (!valid[i])
        {
            all_valid = 0;
        }
    }
    CHECK(all_valid, "an honest TIBE_N-party DKG round accepts every dealer's contribution");
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int dealer = 0; dealer < TIBE_N; dealer++)
        {
            recv_by_i[dealer] = received[dealer][i];
        }
        dkg_aggregate(&share_s_a[i], &share_e_a[i], valid, recv_by_i, ctx);
    }
    free(recv_by_i);
    reconstruct_true_secret(&msk.s_a, &msk.e_a, states, ctx);

    for (int dealer = 0; dealer < TIBE_N; dealer++)
    {
        for (int recip = 0; recip < TIBE_N; recip++)
        {
            v3s_recipient_data_free(&received[dealer][recip]);
        }
        dkg_public_share_free(&pubs[dealer]);
        dkg_round1_state_free(&states[dealer]);
    }
    free(received);
    free(pubs);
    free(states);

    /* Rebuild ek.A0 from the true joint secret, matching tibe_setup's
     * own A0 construction exactly (tibe.c): A0 = [1, a0, b0] * d0,
     * b0 = a0*s_a + e_a - beta. */
    const BIGNUM* q = ring_modulus();
    ring_elem a0, b0, tmp, beta_elem, one;
    ring_init(&a0);
    ring_init(&b0);
    ring_init(&tmp);
    ring_init(&beta_elem);
    ring_init(&one);
    ring_random_uniform(&a0, ctx);
    ring_mul(&tmp, &a0, &msk.s_a, ctx);
    ring_add(&b0, &tmp, &msk.e_a, ctx);
    BIGNUM* beta_bn = BN_new();
    BN_lshift(beta_bn, BN_value_one(), TIBE_BETA_LOG2);
    BN_nnmod(beta_bn, beta_bn, q, ctx);
    BN_copy(beta_elem.coeffs[0], beta_bn);
    BN_free(beta_bn);
    ring_sub(&b0, &b0, &beta_elem, ctx);
    ring_zero(&one);
    BN_set_word(one.coeffs[0], 1);
    ring_mul(&ek.A0[0], &one, &msk.d0, ctx);
    ring_mul(&ek.A0[1], &a0, &msk.d0, ctx);
    ring_mul(&ek.A0[2], &b0, &msk.d0, ctx);
    ring_free(&a0);
    ring_free(&b0);
    ring_free(&tmp);
    ring_free(&beta_elem);
    ring_free(&one);

    /* From here, exactly test_threshold.c's own full-protocol test. */
    threshold_share shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_init(&shares[i]);
        shares[i].x = i + 1;
        ring_copy(&shares[i].share_s_a, &share_s_a[i]);
        ring_copy(&shares[i].share_e_a, &share_e_a[i]);
        ring_copy(&shares[i].d0, &msk.d0);
    }
    /* Pairwise seeds: not yet DKG'd (BCHK_TODO.md Phase 8d flags this
     * as separate, smaller, transport-level future work) -- generated
     * directly here as a stand-in, matching threshold_setup's own
     * approach for now. */
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int j = i + 1; j < TIBE_N; j++)
        {
            uint8_t pairseed[TIBE_SEED_BYTES];
            RAND_bytes(pairseed, sizeof(pairseed));
            memcpy(shares[i].pairwise_seed[j], pairseed, TIBE_SEED_BYTES);
            memcpy(shares[j].pairwise_seed[i], pairseed, TIBE_SEED_BYTES);
        }
    }

    wots_sk sk;
    wots_vk vk;
    wots_keygen(&sk, &vk);
    ring_elem id;
    ring_init(&id);
    identity_embed(&id, &vk, ctx);

    uint8_t msg[TIBE_MSG_BYTES];
    RAND_bytes(msg, sizeof(msg));
    tibe_ct ct;
    tibe_ct_init(&ct);
    tibe_encrypt(&ct, &ek, &id, msg, ctx);

    int act_x[TIBE_T] = {1, 3, 5, 7, 9};
    threshold_round0_state r0states[TIBE_T];
    uint8_t cmts[TIBE_T][TIBE_CMT_BYTES];
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_init(&r0states[i]);
        threshold_round0(cmts[i], &r0states[i], &ek, &id, ctx);
    }
    ring_elem ws[TIBE_T];
    for (int i = 0; i < TIBE_T; i++)
    {
        ring_init(&ws[i]);
        threshold_round1(&ws[i], &r0states[i]);
    }
    threshold_contrib2 contribs[TIBE_T];
    int all_ok = 1;
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_contrib2_init(&contribs[i]);
        int ok = threshold_round2(&contribs[i], &r0states[i], &shares[act_x[i] - 1], &ek, &ct, act_x, TIBE_T, i, cmts,
                                   ws, ctx);
        if (!ok)
        {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "every active party's round2 accepts everyone else's honestly-revealed w_j (DKG-issued shares)");

    uint8_t msg_out[TIBE_MSG_BYTES];
    int combine_ok = threshold_combine(msg_out, &ek, &id, &ct, &msk.d0, act_x, TIBE_T, ws, contribs, ctx);
    CHECK(combine_ok, "threshold_combine's own F_vk*z==r correctness assertion holds (DKG-issued shares)");
    if (combine_ok)
    {
        CHECK(memcmp(msg, msg_out, TIBE_MSG_BYTES) == 0,
              "DKG-issued shares decapsulate correctly through the real, unmodified threshold protocol");
    }

    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_free(&shares[i]);
        ring_free(&share_s_a[i]);
        ring_free(&share_e_a[i]);
    }
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_free(&r0states[i]);
        ring_free(&ws[i]);
        threshold_contrib2_free(&contribs[i]);
    }
    ring_free(&id);
    tibe_ct_free(&ct);
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
}

static void
test_malicious_dealer_excluded(BN_CTX* ctx)
{
    ring_elem share_s_a[TIBE_N], share_e_a[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        ring_init(&share_s_a[i]);
        ring_init(&share_e_a[i]);
    }
    int valid[TIBE_N];
    /* Party at index 4 sends a corrupted local share to recipient 0. */
    run_dkg(share_s_a, share_e_a, valid, 4, ctx);

    CHECK(valid[4] == 0, "a dealer that sends a corrupted share to even one recipient is excluded for everyone");
    int others_ok = 1;
    for (int i = 0; i < TIBE_N; i++)
    {
        if (i != 4 && !valid[i])
        {
            others_ok = 0;
        }
    }
    CHECK(others_ok, "every other (honest) dealer is still accepted despite one malicious dealer");

    for (int i = 0; i < TIBE_N; i++)
    {
        ring_free(&share_s_a[i]);
        ring_free(&share_e_a[i]);
    }
}

int
main(void)
{
    BN_CTX* ctx = BN_CTX_new();

    test_full_dkg_then_decapsulation(ctx);
    test_malicious_dealer_excluded(ctx);

    BN_CTX_free(ctx);

    if (failures == 0)
    {
        printf("test_dkg: all tests passed\n");
        return 0;
    }
    printf("test_dkg: %d failure(s)\n", failures);
    return 1;
}
