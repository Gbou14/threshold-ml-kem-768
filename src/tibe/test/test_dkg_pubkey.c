/*
 * Self-contained regression test for dkg_pubkey.c (Phase 8d,
 * completing the fully dealer-free system).
 *
 * Two things validated:
 * 1. The commit-reveal mechanism for a0/d0 itself: a tampered reveal
 *    fails verification, honest reveals combine correctly.
 * 2. The crown-jewel end-to-end check: the *complete* fully
 *    dealer-free pipeline -- dkg.c's (s_a,e_a) DKG, layered with
 *    dkg_pubkey.c's a0/d0/b0 generation -- decapsulates correctly
 *    through the real, unmodified threshold protocol, **without any
 *    test-only reconstruction of the joint secret anywhere**. Unlike
 *    test_dkg.c (which had to reconstruct (s_a,e_a) directly to build
 *    a consistent ek, since b0 wasn't distributed yet), this test
 *    never forms the full (s_a,e_a) at all -- b0 emerges purely from
 *    summing masked per-party contributions. That absence is itself
 *    the thing being tested: if this test needed to reconstruct
 *    anything to make ek consistent, that would mean the dealer-free
 *    claim doesn't actually hold.
 */
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../dkg.h"
#include "../dkg_pubkey.h"
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

static void
test_commit_reveal(BN_CTX* ctx)
{
    dkg_pubkey_round1_state s;
    dkg_pubkey_round1_init(&s);
    uint8_t cmt[DKG_PUBKEY_CMT_BYTES];
    dkg_pubkey_round1(&s, 0, cmt, ctx);

    CHECK(dkg_pubkey_verify_commit(cmt, &s.a0_contrib, &s.d0_contrib, s.nonce) == 1,
          "an honest reveal verifies against its own commitment");

    ring_elem tampered;
    ring_init(&tampered);
    ring_copy(&tampered, &s.a0_contrib);
    BN_add_word(tampered.coeffs[0], 1);
    CHECK(dkg_pubkey_verify_commit(cmt, &tampered, &s.d0_contrib, s.nonce) == 0,
          "a tampered a0 reveal fails verification");
    ring_free(&tampered);

    uint8_t bad_nonce[DKG_PUBKEY_NONCE_BYTES];
    memcpy(bad_nonce, s.nonce, sizeof(bad_nonce));
    bad_nonce[0] ^= 0xFF;
    CHECK(dkg_pubkey_verify_commit(cmt, &s.a0_contrib, &s.d0_contrib, bad_nonce) == 0,
          "a tampered nonce fails verification");

    dkg_pubkey_round1_free(&s);
}

static void
test_full_dealer_free_pipeline(BN_CTX* ctx)
{
    /* --- Layer 1: dkg.c's (s_a,e_a) DKG, exactly as test_dkg.c runs it,
     * but this time we never reconstruct the joint secret from it. --- */
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
    int valid[TIBE_N];
    dkg_compute_valid_set(valid, verdicts);
    int all_valid = 1;
    for (int i = 0; i < TIBE_N; i++)
    {
        if (!valid[i])
        {
            all_valid = 0;
        }
    }
    CHECK(all_valid, "an honest TIBE_N-party (s_a,e_a) DKG round accepts every dealer");

    ring_elem share_s_a[TIBE_N], share_e_a[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        ring_init(&share_s_a[i]);
        ring_init(&share_e_a[i]);
        for (int dealer = 0; dealer < TIBE_N; dealer++)
        {
            recv_by_i[dealer] = received[dealer][i];
        }
        dkg_aggregate(&share_s_a[i], &share_e_a[i], valid, recv_by_i, ctx);
    }
    free(recv_by_i);

    /* --- Layer 2: dkg_pubkey.c's a0/d0 commit-reveal. --- */
    dkg_pubkey_round1_state* pk_states = malloc(sizeof(dkg_pubkey_round1_state) * TIBE_N);
    uint8_t pk_cmts[TIBE_N][DKG_PUBKEY_CMT_BYTES];
    for (int i = 0; i < TIBE_N; i++)
    {
        dkg_pubkey_round1_init(&pk_states[i]);
        dkg_pubkey_round1(&pk_states[i], i, pk_cmts[i], ctx);
    }
    int valid_ab[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        valid_ab[i] = dkg_pubkey_verify_commit(pk_cmts[i], &pk_states[i].a0_contrib, &pk_states[i].d0_contrib,
                                                pk_states[i].nonce);
    }
    int all_ab_valid = 1;
    for (int i = 0; i < TIBE_N; i++)
    {
        if (!valid_ab[i])
        {
            all_ab_valid = 0;
        }
    }
    CHECK(all_ab_valid, "an honest TIBE_N-party a0/d0 commit-reveal round verifies for everyone");

    ring_elem* a0_contribs[TIBE_N];
    ring_elem* d0_contribs[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        a0_contribs[i] = &pk_states[i].a0_contrib;
        d0_contribs[i] = &pk_states[i].d0_contrib;
    }
    ring_elem a0, d0;
    ring_init(&a0);
    ring_init(&d0);
    dkg_pubkey_finalize_a0_d0(&a0, &d0, valid_ab, a0_contribs, d0_contribs, ctx);

    /* --- Layer 3: b0's masked reveal, over the (s_a,e_a) DKG's own
     * valid set (not valid_ab -- b0 must sum over the same
     * contributors s_a/e_a itself did). --- */
    ring_elem* b0_contribs_storage = malloc(sizeof(ring_elem) * TIBE_N);
    ring_elem* b0_contribs[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        ring_init(&b0_contribs_storage[i]);
        b0_contribs[i] = &b0_contribs_storage[i];
        if (!valid[i])
        {
            continue;
        }
        ring_elem* received_masks[TIBE_N];
        ring_elem zero_placeholder;
        ring_init(&zero_placeholder);
        for (int j = 0; j < TIBE_N; j++)
        {
            if (j < i)
            {
                received_masks[j] = &pk_states[j].mask_to[i];
            }
            else
            {
                received_masks[j] = &zero_placeholder; /* unused for j>=i, see dkg_pubkey_b0_contribution */
            }
        }
        dkg_pubkey_b0_contribution(b0_contribs[i], i, valid, &states[i].x, &a0, pk_states[i].mask_to, received_masks,
                                    ctx);
        ring_free(&zero_placeholder);
    }
    ring_elem b0;
    ring_init(&b0);
    dkg_pubkey_finalize_b0(&b0, valid, b0_contribs, ctx);

    /* --- Assemble ek.A0 = [1,a0,b0]*d0, exactly matching tibe_setup's
     * own construction -- but note d0/a0/b0 here came entirely from
     * the distributed protocol above; msk.s_a/msk.e_a are never
     * formed. ek/msk and friends are heap-allocated below (not local
     * structs) -- this function's own locals otherwise add up to
     * several MB even before any callee's own stack use, which
     * segfaulted the first version of this test (stack overflow,
     * found the hard way -- see BCHK_TODO.md Phase 8d). */
    tibe_ek* ek = malloc(sizeof(tibe_ek));
    tibe_msk* msk = malloc(sizeof(tibe_msk));
    tibe_ek_init(ek);
    tibe_msk_init(msk);
    ring_copy(&msk->d0, &d0);
    /* msk->s_a/msk->e_a stay zero-inited/unused -- this test never
     * populates them, on purpose. */

    ring_elem one;
    ring_init(&one);
    ring_zero(&one);
    BN_set_word(one.coeffs[0], 1);
    ring_mul(&ek->A0[0], &one, &d0, ctx);
    ring_mul(&ek->A0[1], &a0, &d0, ctx);
    ring_mul(&ek->A0[2], &b0, &d0, ctx);
    ring_free(&one);

    /* A1/A2/G/r are independent of (s_a,e_a)/a0/d0/b0 (see
     * BCHK_TODO.md Phase 8d's correction) -- sampled directly here the
     * same way tibe_setup does, matching that a fully dealer-free
     * deployment would have some other mechanism for these (e.g. a
     * simple public verifiable-randomness step, since none of them
     * need to stay secret or resist bias the way a0 does -- out of
     * scope for this pass, flagged, not solved here). */
    ring_random_uniform(&ek->A1[0], ctx);
    ring_random_uniform(&ek->A1[1], ctx);
    ring_random_uniform(&ek->A1[2], ctx);
    ring_elem d2, a2, b2;
    ring_init(&d2);
    ring_init(&a2);
    ring_init(&b2);
    ring_random_uniform(&d2, ctx);
    ring_random_uniform(&a2, ctx);
    ring_random_uniform(&b2, ctx);
    ring_elem one2;
    ring_init(&one2);
    ring_zero(&one2);
    BN_set_word(one2.coeffs[0], 1);
    ring_mul(&ek->A2[0], &one2, &d2, ctx);
    ring_mul(&ek->A2[1], &a2, &d2, ctx);
    ring_mul(&ek->A2[2], &b2, &d2, ctx);
    ring_free(&one2);
    ring_free(&d2);
    ring_free(&a2);
    ring_free(&b2);
    /* G := [1, g, g^2]: reuse tibe_setup's own g via a throwaway
     * tibe_setup call and copy just ek->G -- compute_g() itself is
     * static/private to tibe.c, not exposed, and re-deriving it here
     * would duplicate real logic rather than test dkg_pubkey.c. */
    tibe_ek* throwaway_ek = malloc(sizeof(tibe_ek));
    tibe_msk* throwaway_msk = malloc(sizeof(tibe_msk));
    tibe_ek_init(throwaway_ek);
    tibe_msk_init(throwaway_msk);
    tibe_setup(throwaway_ek, throwaway_msk, ctx);
    for (int i = 0; i < 3; i++)
    {
        ring_copy(&ek->G[i], &throwaway_ek->G[i]);
    }
    ring_copy(&ek->r, &throwaway_ek->r);
    tibe_ek_free(throwaway_ek);
    tibe_msk_free(throwaway_msk);
    free(throwaway_ek);
    free(throwaway_msk);

    /* --- From here, exactly the existing full-protocol test. --- */
    threshold_share* shares = malloc(sizeof(threshold_share) * TIBE_N);
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_init(&shares[i]);
        shares[i].x = i + 1;
        ring_copy(&shares[i].share_s_a, &share_s_a[i]);
        ring_copy(&shares[i].share_e_a, &share_e_a[i]);
        ring_copy(&shares[i].d0, &d0);
    }
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
    tibe_ct* ct = malloc(sizeof(tibe_ct));
    tibe_ct_init(ct);
    tibe_encrypt(ct, ek, &id, msg, ctx);

    int act_x[TIBE_T] = {1, 3, 5, 7, 9};
    threshold_round0_state* r0states = malloc(sizeof(threshold_round0_state) * TIBE_T);
    uint8_t cmts[TIBE_T][TIBE_CMT_BYTES];
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_init(&r0states[i]);
        threshold_round0(cmts[i], &r0states[i], ek, &id, ctx);
    }
    ring_elem ws[TIBE_T];
    for (int i = 0; i < TIBE_T; i++)
    {
        ring_init(&ws[i]);
        threshold_round1(&ws[i], &r0states[i]);
    }
    threshold_contrib2* contribs = malloc(sizeof(threshold_contrib2) * TIBE_T);
    int all_ok = 1;
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_contrib2_init(&contribs[i]);
        int ok = threshold_round2(&contribs[i], &r0states[i], &shares[act_x[i] - 1], ek, ct, act_x, TIBE_T, i, cmts,
                                   ws, ctx);
        if (!ok)
        {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "every active party's round2 accepts everyone else's honestly-revealed w_j (fully dealer-free ek)");

    uint8_t msg_out[TIBE_MSG_BYTES];
    int combine_ok = threshold_combine(msg_out, ek, &id, ct, &d0, act_x, TIBE_T, ws, contribs, ctx);
    CHECK(combine_ok, "threshold_combine's own F_vk*z==r correctness assertion holds (fully dealer-free ek)");
    if (combine_ok)
    {
        CHECK(memcmp(msg, msg_out, TIBE_MSG_BYTES) == 0,
              "a FULLY dealer-free keygen (no party ever forms (s_a,e_a)) decapsulates correctly");
    }

    /* Cleanup. */
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_free(&shares[i]);
        ring_free(&share_s_a[i]);
        ring_free(&share_e_a[i]);
        ring_free(&b0_contribs_storage[i]);
        dkg_pubkey_round1_free(&pk_states[i]);
    }
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_free(&r0states[i]);
        ring_free(&ws[i]);
        threshold_contrib2_free(&contribs[i]);
    }
    free(r0states);
    free(contribs);
    free(shares);
    free(b0_contribs_storage);
    free(pk_states);
    ring_free(&a0);
    ring_free(&d0);
    ring_free(&b0);
    ring_free(&id);
    tibe_ct_free(ct);
    tibe_ek_free(ek);
    tibe_msk_free(msk);
    free(ct);
    free(ek);
    free(msk);

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

int
main(void)
{
    BN_CTX* ctx = BN_CTX_new();

    test_commit_reveal(ctx);
    test_full_dealer_free_pipeline(ctx);

    BN_CTX_free(ctx);

    if (failures == 0)
    {
        printf("test_dkg_pubkey: all tests passed\n");
        return 0;
    }
    printf("test_dkg_pubkey: %d failure(s)\n", failures);
    return 1;
}
