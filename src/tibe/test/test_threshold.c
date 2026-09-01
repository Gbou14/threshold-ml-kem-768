/*
 * Self-contained regression test for the real 3-round
 * threshold-decryption protocol (threshold.c). No public reference
 * exists for this scheme, so validation is by internal consistency:
 * a cheap direct check that Shamir-sharing has the right threshold
 * property (reconstructs from T-or-more shares, gives a wrong answer
 * from fewer), and one full, expensive end-to-end run of the real
 * 3-round protocol (Setup -> per-party round0/1/2 -> Combine) that
 * recovers the actual encrypted message using a real WOTS+-embedded
 * identity -- not the tibe_decrypt_direct single-party stand-in
 * Phase 3 used.
 *
 * The full end-to-end test is run exactly once (not repeated): each
 * active party's round 0 alone costs ~10 O(D^2) ring_mul-equivalents,
 * so a single T=5-of-N=10 cycle already takes on the order of 15-20
 * minutes on this development machine (see README.md "Performance").
 */
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

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

/* Direct Lagrange-at-zero reconstruction, independent of (not reusing)
 * threshold.c's internal lagrange_coeff_at_zero -- this test validates
 * threshold_setup's *output* black-box, not by calling back into the
 * module's own private helpers. */
static void
reconstruct(ring_elem* out, const ring_elem* shares, const int* act_x, int act_size, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    ring_zero(out);
    for (int k = 0; k < act_size; k++)
    {
        BIGNUM* num = BN_new();
        BIGNUM* den = BN_new();
        BIGNUM* xi = BN_new();
        BIGNUM* xj = BN_new();
        BIGNUM* tmp = BN_new();
        BIGNUM* zero = BN_new();
        BN_zero(zero);
        BN_one(num);
        BN_one(den);
        BN_set_word(xi, (unsigned long)act_x[k]);

        for (int m = 0; m < act_size; m++)
        {
            if (m == k)
            {
                continue;
            }
            BN_set_word(xj, (unsigned long)act_x[m]);
            BN_mod_sub(tmp, zero, xj, q, ctx);
            BN_mod_mul(num, num, tmp, q, ctx);
            BN_mod_sub(tmp, xi, xj, q, ctx);
            BN_mod_mul(den, den, tmp, q, ctx);
        }
        BIGNUM* den_inv = BN_new();
        BN_mod_inverse(den_inv, den, q, ctx);
        BIGNUM* lambda = BN_new();
        BN_mod_mul(lambda, num, den_inv, q, ctx);

        ring_elem term;
        ring_init(&term);
        ring_scalar_mul(&term, &shares[k], lambda, ctx);
        ring_add(out, out, &term, ctx);
        ring_free(&term);

        BN_free(num);
        BN_free(den);
        BN_free(xi);
        BN_free(xj);
        BN_free(tmp);
        BN_free(zero);
        BN_free(den_inv);
        BN_free(lambda);
    }
}

static void
test_shamir_threshold_property(BN_CTX* ctx)
{
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tibe_setup(&ek, &msk, ctx);

    threshold_share shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_init(&shares[i]);
    }
    threshold_setup(shares, &msk, ctx);

    ring_elem s_a_shares[TIBE_N], e_a_shares[TIBE_N];
    int all_x[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        ring_init(&s_a_shares[i]);
        ring_init(&e_a_shares[i]);
        ring_copy(&s_a_shares[i], &shares[i].share_s_a);
        ring_copy(&e_a_shares[i], &shares[i].share_e_a);
        all_x[i] = shares[i].x;
    }

    /* Any T-sized (here: all N, a superset of any valid T-subset by
     * Shamir's own consistency guarantee) or larger active set
     * reconstructs correctly. */
    ring_elem s_a_reconstructed, e_a_reconstructed;
    ring_init(&s_a_reconstructed);
    ring_init(&e_a_reconstructed);
    reconstruct(&s_a_reconstructed, s_a_shares, all_x, TIBE_N, ctx);
    reconstruct(&e_a_reconstructed, e_a_shares, all_x, TIBE_N, ctx);
    CHECK(ring_eq(&s_a_reconstructed, &msk.s_a), "reconstructing s_a from all N shares matches the original");
    CHECK(ring_eq(&e_a_reconstructed, &msk.e_a), "reconstructing e_a from all N shares matches the original");

    /* Exactly T shares also reconstructs correctly (a non-trivial
     * subset, not just 1..T). */
    int t_subset[TIBE_T] = {2, 4, 6, 8, 10};
    ring_elem s_a_shares_t[TIBE_T], e_a_shares_t[TIBE_T];
    for (int i = 0; i < TIBE_T; i++)
    {
        ring_init(&s_a_shares_t[i]);
        ring_init(&e_a_shares_t[i]);
        ring_copy(&s_a_shares_t[i], &shares[t_subset[i] - 1].share_s_a);
        ring_copy(&e_a_shares_t[i], &shares[t_subset[i] - 1].share_e_a);
    }
    ring_elem s_a_from_t, e_a_from_t;
    ring_init(&s_a_from_t);
    ring_init(&e_a_from_t);
    reconstruct(&s_a_from_t, s_a_shares_t, t_subset, TIBE_T, ctx);
    reconstruct(&e_a_from_t, e_a_shares_t, t_subset, TIBE_T, ctx);
    CHECK(ring_eq(&s_a_from_t, &msk.s_a), "reconstructing s_a from exactly T=5 shares {2,4,6,8,10} matches the original");
    CHECK(ring_eq(&e_a_from_t, &msk.e_a), "reconstructing e_a from exactly T=5 shares {2,4,6,8,10} matches the original");

    /* Fewer than T shares gives a WRONG answer -- the threshold
     * property actually holding, not just "enough shares work." */
    int below_t[TIBE_T - 1] = {2, 4, 6, 8};
    ring_elem s_a_shares_below[TIBE_T - 1];
    for (int i = 0; i < TIBE_T - 1; i++)
    {
        ring_init(&s_a_shares_below[i]);
        ring_copy(&s_a_shares_below[i], &shares[below_t[i] - 1].share_s_a);
    }
    ring_elem s_a_from_below;
    ring_init(&s_a_from_below);
    reconstruct(&s_a_from_below, s_a_shares_below, below_t, TIBE_T - 1, ctx);
    CHECK(!ring_eq(&s_a_from_below, &msk.s_a), "reconstructing s_a from only T-1=4 shares does NOT match the original");

    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_free(&shares[i]);
        ring_free(&s_a_shares[i]);
        ring_free(&e_a_shares[i]);
    }
    for (int i = 0; i < TIBE_T; i++)
    {
        ring_free(&s_a_shares_t[i]);
        ring_free(&e_a_shares_t[i]);
    }
    for (int i = 0; i < TIBE_T - 1; i++)
    {
        ring_free(&s_a_shares_below[i]);
    }
    ring_free(&s_a_reconstructed);
    ring_free(&e_a_reconstructed);
    ring_free(&s_a_from_t);
    ring_free(&e_a_from_t);
    ring_free(&s_a_from_below);
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
}

static void
test_full_threshold_decapsulation(BN_CTX* ctx)
{
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tibe_setup(&ek, &msk, ctx);

    threshold_share shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_init(&shares[i]);
    }
    threshold_setup(shares, &msk, ctx);

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

    /* T=5 of N=10, a non-trivial (not 1..T) active set. */
    int act_x[TIBE_T] = {2, 4, 6, 8, 10};
    threshold_round0_state states[TIBE_T];
    uint8_t cmts[TIBE_T][TIBE_CMT_BYTES];
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_init(&states[i]);
        threshold_round0(cmts[i], &states[i], &ek, &id, ctx);
    }

    ring_elem ws[TIBE_T];
    for (int i = 0; i < TIBE_T; i++)
    {
        ring_init(&ws[i]);
        threshold_round1(&ws[i], &states[i]);
    }

    threshold_contrib2 contribs[TIBE_T];
    int all_ok = 1;
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_contrib2_init(&contribs[i]);
        int ok = threshold_round2(&contribs[i], &states[i], &shares[act_x[i] - 1], &ek, &ct, act_x, TIBE_T, i, cmts,
                                   ws, ctx);
        if (!ok)
        {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "every honest active party's round2 accepts everyone else's honestly-revealed w_j");

    uint8_t msg_out[TIBE_MSG_BYTES];
    int combine_ok = threshold_combine(msg_out, &ek, &id, &ct, &msk.d0, act_x, TIBE_T, ws, contribs, ctx);
    CHECK(combine_ok, "threshold_combine's own F_vk*z==r correctness assertion holds");
    if (combine_ok)
    {
        CHECK(memcmp(msg, msg_out, TIBE_MSG_BYTES) == 0,
              "the real 3-round protocol (T=5 of N=10) recovers the original encrypted message");
    }

    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_free(&shares[i]);
    }
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_free(&states[i]);
        ring_free(&ws[i]);
        threshold_contrib2_free(&contribs[i]);
    }
    ring_free(&id);
    tibe_ct_free(&ct);
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
}

/*
 * Phase 8a: below-threshold and malicious-party (lying about w_i)
 * behavior, tested at the *full protocol* level -- not the cheap
 * Shamir-only check above, which only shows the underlying secret
 * sharing has the right threshold property in isolation, not that the
 * real round0/round1/round2/Combine sequence actually fails closed
 * when it should. Both scenarios share one Setup/threshold_setup/
 * Encrypt (the expensive one-time cost) via test_full_protocol_gaps,
 * below.
 */

/* T-1=4 parties (below TIBE_T=5) run the real protocol honestly --
 * confirms Combine does NOT recover the correct shared secret, not
 * just that Shamir reconstruction alone would be wrong. */
static void
check_below_threshold_fails(BN_CTX* ctx, const tibe_ek* ek, const ring_elem* id, const tibe_ct* ct,
                             const uint8_t msg[TIBE_MSG_BYTES], const threshold_share shares[TIBE_N],
                             const ring_elem* d0)
{
    int act_x[TIBE_T - 1] = {2, 4, 6, 8}; /* T-1 = 4, below threshold */
    int act_size = TIBE_T - 1;

    threshold_round0_state states[TIBE_T - 1];
    uint8_t cmts[TIBE_T - 1][TIBE_CMT_BYTES];
    for (int i = 0; i < act_size; i++)
    {
        threshold_round0_state_init(&states[i]);
        threshold_round0(cmts[i], &states[i], ek, id, ctx);
    }

    ring_elem ws[TIBE_T - 1];
    for (int i = 0; i < act_size; i++)
    {
        ring_init(&ws[i]);
        threshold_round1(&ws[i], &states[i]);
    }

    threshold_contrib2 contribs[TIBE_T - 1];
    int all_ok = 1;
    for (int i = 0; i < act_size; i++)
    {
        threshold_contrib2_init(&contribs[i]);
        int ok = threshold_round2(&contribs[i], &states[i], &shares[act_x[i] - 1], ek, ct, act_x, act_size, i, cmts,
                                   ws, ctx);
        if (!ok)
        {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "below-threshold parties are each individually honest -- round2 doesn't reject any of them "
                  "(this scenario is about insufficient COUNT, not a caught liar)");

    uint8_t msg_out[TIBE_MSG_BYTES];
    int combine_ok = threshold_combine(msg_out, ek, id, ct, d0, act_x, act_size, ws, contribs, ctx);
    int looks_correct = combine_ok && (memcmp(msg, msg_out, TIBE_MSG_BYTES) == 0);
    CHECK(!looks_correct,
          "T-1=4 honest parties (below TIBE_T=5) do NOT recover the correct message via the real protocol "
          "-- either Combine's own F_vk*z==r assertion fails, or (checked explicitly, not assumed) the "
          "decoded message is wrong");

    for (int i = 0; i < act_size; i++)
    {
        threshold_round0_state_free(&states[i]);
        ring_free(&ws[i]);
        threshold_contrib2_free(&contribs[i]);
    }
}

/* All T=5 parties run round0/round1 honestly; the party at act_x[0]
 * then has its revealed w corrupted (simulating it lying in round1 --
 * revealing something other than what it committed to in round0)
 * before an honest party's round2 sees it. Confirms Algorithm 7 line
 * 1's commit-then-reveal check actually catches this over the real
 * protocol, not just that the check exists in the code. */
static void
check_malicious_party_detected(BN_CTX* ctx, const tibe_ek* ek, const ring_elem* id, const tibe_ct* ct,
                                const threshold_share shares[TIBE_N])
{
    int act_x[TIBE_T] = {2, 4, 6, 8, 10};

    threshold_round0_state states[TIBE_T];
    uint8_t cmts[TIBE_T][TIBE_CMT_BYTES];
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_init(&states[i]);
        threshold_round0(cmts[i], &states[i], ek, id, ctx);
    }

    ring_elem ws[TIBE_T];
    for (int i = 0; i < TIBE_T; i++)
    {
        ring_init(&ws[i]);
        threshold_round1(&ws[i], &states[i]);
    }

    /* Corrupt party 0's (x=2) revealed w -- it no longer matches
     * cmts[0] = H_cmt(the value it actually committed to). */
    BN_add_word(ws[0].coeffs[0], 1);

    /* An honest party (index 1, x=4) runs round2 against this
     * corrupted set. threshold_round2's commitment-verification loop
     * runs BEFORE any of the expensive ring_inv/masking work, so a
     * caught liar is cheap to detect even though this test reuses a
     * real, full T=5 round0/round1 (needed so the commitments/reveals
     * are genuine, not synthetic). */
    threshold_contrib2 contrib;
    threshold_contrib2_init(&contrib);
    int ok =
        threshold_round2(&contrib, &states[1], &shares[act_x[1] - 1], ek, ct, act_x, TIBE_T, 1, cmts, ws, ctx);
    CHECK(!ok, "an honest party's round2 detects and rejects another party's corrupted "
               "(lied-about) revealed w -- Algorithm 7 line 1's commit-then-reveal check, over the real protocol");

    threshold_contrib2_free(&contrib);
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_free(&states[i]);
        ring_free(&ws[i]);
    }
}

static void
test_full_protocol_gaps(BN_CTX* ctx)
{
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tibe_setup(&ek, &msk, ctx);

    threshold_share shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_init(&shares[i]);
    }
    threshold_setup(shares, &msk, ctx);

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

    check_below_threshold_fails(ctx, &ek, &id, &ct, msg, shares, &msk.d0);
    check_malicious_party_detected(ctx, &ek, &id, &ct, shares);

    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_free(&shares[i]);
    }
    ring_free(&id);
    tibe_ct_free(&ct);
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
}

int
main(void)
{
    BN_CTX* ctx = BN_CTX_new();

    test_shamir_threshold_property(ctx);
    test_full_threshold_decapsulation(ctx);
    test_full_protocol_gaps(ctx);

    BN_CTX_free(ctx);

    if (failures == 0)
    {
        printf("test_threshold: all tests passed\n");
        return 0;
    }
    printf("test_threshold: %d failure(s)\n", failures);
    return 1;
}
