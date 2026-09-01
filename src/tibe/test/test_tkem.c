/*
 * Self-contained regression test for the BCHK+ TKEM layer (tkem.c).
 * No public reference exists for this scheme, so validation is by
 * internal consistency: a valid Encaps output verifies and a tampered
 * one doesn't (cheap -- dominated by one Encaps call, no threshold
 * protocol involved), and one full, expensive end-to-end run of
 * Keygen -> Encaps -> ShareDecaps (T=5 of N=10) -> Combine that
 * checks the shared secret Combine derives matches what Encaps
 * produced.
 */
#include <stdio.h>
#include <string.h>

#include "../tkem.h"

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
test_encaps_verify_roundtrip(BN_CTX* ctx)
{
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tkem_keygen(&ek, &msk, ctx);

    tkem_ct ct;
    tkem_ct_init(&ct);
    uint8_t ss[TKEM_SSBYTES];
    tkem_encaps(&ct, ss, &ek, ctx);

    CHECK(tkem_verify_ct(&ct), "a freshly-Encaps'd ciphertext verifies");

    tkem_ct_free(&ct);
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
}

static void
test_tampered_ct_rejected(BN_CTX* ctx)
{
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tkem_keygen(&ek, &msk, ctx);

    tkem_ct ct;
    tkem_ct_init(&ct);
    uint8_t ss[TKEM_SSBYTES];
    tkem_encaps(&ct, ss, &ek, ctx);

    /* Flip one coefficient of v -- a modified ciphertext under the
     * same vk/sig should fail SIG.Verify (the message it signed no
     * longer matches). */
    BN_add_word(ct.ct.v.coeffs[0], 1);
    CHECK(!tkem_verify_ct(&ct), "a tampered ciphertext (v coefficient flipped) fails verification");

    threshold_round0_state state;
    threshold_round0_state_init(&state);
    uint8_t cmt[TIBE_CMT_BYTES];
    int ok = tkem_share_decaps_0(cmt, &state, &ct, &ek, ctx);
    CHECK(!ok, "tkem_share_decaps_0 rejects the tampered ciphertext before doing any TIBE-layer work");
    threshold_round0_state_free(&state);

    /* Flip one byte of the signature instead -- same expected outcome. */
    tkem_ct_free(&ct);
    tkem_ct_init(&ct);
    tkem_encaps(&ct, ss, &ek, ctx);
    ct.sig[0] ^= 0x01;
    CHECK(!tkem_verify_ct(&ct), "a tampered signature byte fails verification");

    tkem_ct_free(&ct);
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
}

static void
test_full_tkem_decapsulation(BN_CTX* ctx)
{
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tkem_keygen(&ek, &msk, ctx);

    threshold_share shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_init(&shares[i]);
    }
    threshold_setup(shares, &msk, ctx);

    tkem_ct ct;
    tkem_ct_init(&ct);
    uint8_t ss_encaps[TKEM_SSBYTES];
    tkem_encaps(&ct, ss_encaps, &ek, ctx);

    int act_x[TIBE_T] = {2, 4, 6, 8, 10};
    threshold_round0_state states[TIBE_T];
    uint8_t cmts[TIBE_T][TIBE_CMT_BYTES];
    int all_ok = 1;
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_round0_state_init(&states[i]);
        if (!tkem_share_decaps_0(cmts[i], &states[i], &ct, &ek, ctx))
        {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "every party's tkem_share_decaps_0 accepts the honestly-Encaps'd ciphertext");

    ring_elem ws[TIBE_T];
    for (int i = 0; i < TIBE_T; i++)
    {
        ring_init(&ws[i]);
        if (!tkem_share_decaps_1(&ws[i], &states[i], &ct))
        {
            all_ok = 0;
        }
    }

    threshold_contrib2 contribs[TIBE_T];
    for (int i = 0; i < TIBE_T; i++)
    {
        threshold_contrib2_init(&contribs[i]);
        if (!tkem_share_decaps_2(&contribs[i], &states[i], &shares[act_x[i] - 1], &ct, &ek, act_x, TIBE_T, i, cmts,
                                  ws, ctx))
        {
            all_ok = 0;
        }
    }
    CHECK(all_ok, "every party's round0/1/2 succeeds for the honest ciphertext");

    uint8_t ss_combine[TKEM_SSBYTES];
    int combine_ok = tkem_combine(ss_combine, &ek, &msk.d0, &ct, act_x, TIBE_T, ws, contribs, ctx);
    CHECK(combine_ok, "tkem_combine succeeds (SIG.Verify, threshold_combine's F_vk*z==r, and the FO "
                       "re-encryption check all pass)");
    if (combine_ok)
    {
        CHECK(memcmp(ss_encaps, ss_combine, TKEM_SSBYTES) == 0,
              "the shared secret Combine derives matches what Encaps produced");
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
    tkem_ct_free(&ct);
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
}

int
main(void)
{
    BN_CTX* ctx = BN_CTX_new();

    test_encaps_verify_roundtrip(ctx);
    test_tampered_ct_rejected(ctx);
    test_full_tkem_decapsulation(ctx);

    BN_CTX_free(ctx);

    if (failures == 0)
    {
        printf("test_tkem: all tests passed\n");
        return 0;
    }
    printf("test_tkem: %d failure(s)\n", failures);
    return 1;
}
