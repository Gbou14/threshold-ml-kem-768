/*
 * Self-contained regression test for the V3S module (Phase 8d, "VSSS
 * with detection" tier -- Espitau-Niot-Prest eprint 2024/959, Figure
 * 4). No public reference implementation exists (same situation as
 * everywhere else in this project), so validated by internal
 * consistency: an honest V3S.Share's shares all verify and
 * reconstruct to the original secret; tampering with a share, a
 * proof, or an oversized secret all get caught.
 *
 * This runs at this project's real dimensions (V3S_DIM_X=8192,
 * V3S_DIM_Y=256) -- unlike the ring-algebra bugs Phase 3/5 caught,
 * there's no O(d^2) BIGNUM ring_mul in this module's hot path (R*x is
 * cheap conditional BIGNUM mod-add/sub, not full polynomial
 * multiplication), so a toy/reduced-dimension version isn't needed to
 * iterate quickly -- this is already fast enough to validate directly.
 */
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../gauss.h"
#include "../ring.h"
#include "../v3s.h"

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
make_honest_secret(v3s_secret* x)
{
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        x->coeffs[c] = gauss_sample_coeff(TIBE_DKG_LOCAL_SIGMA);
    }
}

static void
test_honest_share_verify_reconstruct(void)
{
    BN_CTX* ctx = BN_CTX_new();

    v3s_secret x;
    make_honest_secret(&x);

    v3s_share_output out;
    v3s_share(&out, &x, ctx);

    /* Every party's own share verifies. */
    for (int i = 0; i < TIBE_N; i++)
    {
        v3s_recipient_data rd;
        v3s_recipient_data_init(&rd);
        v3s_share_extract_recipient(&rd, &out, i);

        char msg[64];
        snprintf(msg, sizeof(msg), "party %d's honest share verifies", i);
        CHECK(v3s_verify(i, out.v_shares, out.root, &out.R, &rd, ctx) == 1, msg);

        v3s_recipient_data_free(&rd);
    }

    /* Reconstruction from exactly TIBE_T shares recovers x. */
    int act_x[TIBE_T];
    BIGNUM** x_shares_subset = malloc(sizeof(BIGNUM*) * TIBE_T * V3S_DIM_X);
    for (int k = 0; k < TIBE_T; k++)
    {
        act_x[k] = k + 1;
    }
    v3s_secret recovered;
    int ok = v3s_reconstruct(&recovered, (BIGNUM* const(*)[V3S_DIM_X])out.x_shares, act_x, TIBE_T, ctx);
    CHECK(ok == 1, "reconstruction from T shares succeeds");
    int mismatch = 0;
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        if (recovered.coeffs[c] != x.coeffs[c])
        {
            mismatch++;
        }
    }
    CHECK(mismatch == 0, "reconstructed secret matches the original exactly, every coordinate");
    free(x_shares_subset);

    /* Reconstruction using more than T shares (with the extra ones
     * genuinely consistent) also succeeds. */
    int act_x_more[TIBE_N];
    for (int k = 0; k < TIBE_N; k++)
    {
        act_x_more[k] = k + 1;
    }
    v3s_secret recovered2;
    ok = v3s_reconstruct(&recovered2, (BIGNUM* const(*)[V3S_DIM_X])out.x_shares, act_x_more, TIBE_N, ctx);
    CHECK(ok == 1, "reconstruction from all N (consistent) shares succeeds");
    mismatch = 0;
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        if (recovered2.coeffs[c] != x.coeffs[c])
        {
            mismatch++;
        }
    }
    CHECK(mismatch == 0, "N-share reconstruction also matches the original exactly");

    v3s_share_free(&out);
    BN_CTX_free(ctx);
}

static void
test_tampered_share_detected(void)
{
    BN_CTX* ctx = BN_CTX_new();
    v3s_secret x;
    make_honest_secret(&x);
    v3s_share_output out;
    v3s_share(&out, &x, ctx);

    /* Corrupting the x_share sent to party 3 (without touching its
     * Merkle leaf/proof, simulating a dealer who tries to swap in a
     * different value post-commitment) must be caught by the local
     * linear-consistency check (v_i != R*x_i+y_i anymore) -- this is
     * the actual thing V3S buys over the plain commit-reveal scheme
     * already used elsewhere in this project. */
    v3s_recipient_data rd;
    v3s_recipient_data_init(&rd);
    v3s_share_extract_recipient(&rd, &out, 3);
    BN_add_word(rd.x_share[0], 1);
    CHECK(v3s_verify(3, out.v_shares, out.root, &out.R, &rd, ctx) == 0,
          "a share tampered after commitment fails V3S.Verify");
    v3s_recipient_data_free(&rd);

    /* Corrupting the Merkle proof itself (simulating a dealer lying
     * about a leaf's siblings) is also caught. */
    v3s_recipient_data rd2;
    v3s_recipient_data_init(&rd2);
    v3s_share_extract_recipient(&rd2, &out, 5);
    rd2.proof.siblings[0][0] ^= 0xFF;
    CHECK(v3s_verify(5, out.v_shares, out.root, &out.R, &rd2, ctx) == 0, "a tampered Merkle proof fails V3S.Verify");
    v3s_recipient_data_free(&rd2);

    /* Corrupting the nonce (breaks the Merkle leaf hash) is caught. */
    v3s_recipient_data rd3;
    v3s_recipient_data_init(&rd3);
    v3s_share_extract_recipient(&rd3, &out, 7);
    rd3.nonce[0] ^= 0xFF;
    CHECK(v3s_verify(7, out.v_shares, out.root, &out.R, &rd3, ctx) == 0, "a tampered nonce fails V3S.Verify");
    v3s_recipient_data_free(&rd3);

    v3s_share_free(&out);
    BN_CTX_free(ctx);
}

static void
test_oversized_secret_rejected(void)
{
    BN_CTX* ctx = BN_CTX_new();

    /* An honest-looking share structure, but the underlying secret is
     * far beyond any honest TIBE_DKG_LOCAL_SIGMA=16 draw -- simulates
     * a malicious dealer directly injecting an oversized x rather
     * than sampling honestly. Every coordinate set to
     * TIBE_DKG_B_REJECT's own scale (see gen_dkg_params.py) so the
     * whole vector's norm is unambiguously over TIBE_DKG_B_ACCEPT. */
    v3s_secret x;
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        x.coeffs[c] = 5000; /* per-coordinate; norm ~= 5000*sqrt(8192) ~= 452,548 >> B_accept region once combined with R,y */
    }
    v3s_share_output out;
    v3s_share(&out, &x, ctx);

    int rejected_count = 0;
    for (int i = 0; i < TIBE_N; i++)
    {
        v3s_recipient_data rd;
        v3s_recipient_data_init(&rd);
        v3s_share_extract_recipient(&rd, &out, i);
        if (v3s_verify(i, out.v_shares, out.root, &out.R, &rd, ctx) == 0)
        {
            rejected_count++;
        }
        v3s_recipient_data_free(&rd);
    }
    printf("  oversized-secret test: %d/%d parties rejected the share\n", rejected_count, TIBE_N);
    CHECK(rejected_count == TIBE_N, "an oversized secret is rejected by every honest party's V3S.Verify");

    v3s_share_free(&out);
    BN_CTX_free(ctx);
}

int
main(void)
{
    test_honest_share_verify_reconstruct();
    test_tampered_share_detected();
    test_oversized_secret_rejected();

    if (failures == 0)
    {
        printf("test_v3s: all tests passed\n");
        return 0;
    }
    printf("test_v3s: %d failure(s)\n", failures);
    return 1;
}
