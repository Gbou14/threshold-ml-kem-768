/*
 * Self-contained regression test for the identity-embedding map E
 * (identity.c). No public reference exists for this exact
 * instantiation, so validation is by internal consistency and by the
 * paper's own required security property: for distinct WOTS+
 * verification keys vk0 != vk1, E(vk0)-E(vk1) must be a unit in R_q --
 * checked directly (not just assumed from the derivation in
 * README.md "Phase 4") via ring_inv succeeding and the product with
 * its inverse being 1.
 */
#include <stdio.h>
#include <string.h>

#include "../identity.h"
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
test_embed_field_nonzero(BN_CTX* ctx)
{
    wots_sk sk;
    wots_vk vk;
    wots_keygen(&sk, &vk);

    field_elem y;
    field_init(&y);
    identity_embed_field(&y, &vk, ctx);
    CHECK(!field_is_zero(&y), "E_F(vk) is nonzero for a fresh vk");

    field_free(&y);
}

static void
test_embed_matches_split(BN_CTX* ctx)
{
    /* E(vk) := f^-1(E_F(vk), E_F(vk)) -- check the implementation
     * actually satisfies its own definition: splitting E(vk) back
     * apart must reproduce (E_F(vk), E_F(vk)) exactly. This is the
     * direct check that identity_embed calls ring_unsplit correctly,
     * complementing test_ring.c's independent validation that
     * ring_split/ring_unsplit are mutual inverses in general. */
    wots_sk sk;
    wots_vk vk;
    wots_keygen(&sk, &vk);

    field_elem expected;
    field_init(&expected);
    identity_embed_field(&expected, &vk, ctx);

    ring_elem id;
    ring_init(&id);
    identity_embed(&id, &vk, ctx);

    field_elem y1, y2;
    field_init(&y1);
    field_init(&y2);
    ring_split(&y1, &y2, &id, ctx);

    CHECK(field_eq(&y1, &expected) && field_eq(&y2, &expected),
          "split(E(vk)) == (E_F(vk), E_F(vk)) in both factors");

    field_free(&expected);
    ring_free(&id);
    field_free(&y1);
    field_free(&y2);
}

static void
test_distinct_vks_give_distinct_embeddings(BN_CTX* ctx)
{
    wots_sk sk1, sk2, sk3;
    wots_vk vk1, vk2, vk3;
    wots_keygen(&sk1, &vk1);
    wots_keygen(&sk2, &vk2);
    wots_keygen(&sk3, &vk3);

    ring_elem id1, id2, id3;
    ring_init(&id1);
    ring_init(&id2);
    ring_init(&id3);
    identity_embed(&id1, &vk1, ctx);
    identity_embed(&id2, &vk2, ctx);
    identity_embed(&id3, &vk3, ctx);

    CHECK(!ring_eq(&id1, &id2) && !ring_eq(&id1, &id3) && !ring_eq(&id2, &id3),
          "3 distinct vks give 3 pairwise-distinct E(vk) values");

    ring_free(&id1);
    ring_free(&id2);
    ring_free(&id3);
}

static void
test_difference_is_a_unit(BN_CTX* ctx)
{
    /* The actual security property the paper requires (Sec 4.2,
     * "Identity Embedding"): for vk0 != vk1, E(vk0)-E(vk1) must be a
     * unit in R_q. Checked directly by inverting the difference and
     * confirming diff * inv(diff) == 1, not by trusting the
     * derivation alone. */
    wots_sk sk0, sk1;
    wots_vk vk0, vk1;
    wots_keygen(&sk0, &vk0);
    wots_keygen(&sk1, &vk1);

    ring_elem id0, id1, diff, inv_diff, product, one;
    ring_init(&id0);
    ring_init(&id1);
    ring_init(&diff);
    ring_init(&inv_diff);
    ring_init(&product);
    ring_init(&one);
    identity_embed(&id0, &vk0, ctx);
    identity_embed(&id1, &vk1, ctx);
    ring_sub(&diff, &id0, &id1, ctx);

    BN_one(one.coeffs[0]);
    ring_inv(&inv_diff, &diff, ctx);
    ring_mul(&product, &diff, &inv_diff, ctx);

    CHECK(ring_eq(&product, &one), "E(vk0) - E(vk1) is a unit in R_q for distinct vk0, vk1");

    ring_free(&id0);
    ring_free(&id1);
    ring_free(&diff);
    ring_free(&inv_diff);
    ring_free(&product);
    ring_free(&one);
}

int
main(void)
{
    BN_CTX* ctx = BN_CTX_new();

    test_embed_field_nonzero(ctx);
    test_embed_matches_split(ctx);
    test_distinct_vks_give_distinct_embeddings(ctx);
    test_difference_is_a_unit(ctx);

    BN_CTX_free(ctx);

    if (failures == 0)
    {
        printf("test_identity: all tests passed\n");
        return 0;
    }
    printf("test_identity: %d failure(s)\n", failures);
    return 1;
}
