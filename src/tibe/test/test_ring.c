/*
 * Self-contained regression test for the TIBE ring-arithmetic module
 * (R_q = Z[X]/(X^D+1), BIGNUM-backed). No external reference exists for
 * this ring's parameters (d=4096, q~2^101 is specific to this project's
 * BCHK+ instantiation), so this validates by internal consistency: ring
 * axioms (additive inverse, distributivity), known identity/zero
 * elements, and an explicit negacyclic-wraparound check
 * (X^(D-1) * X == -1, the defining relation X^D == -1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../ring.h"

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
set_monomial(ring_elem* r, int exponent, long coeff, BN_CTX* ctx)
{
    ring_zero(r);
    BN_set_word(r->coeffs[exponent], coeff < 0 ? (unsigned long)(-coeff) : (unsigned long)coeff);
    if (coeff < 0)
    {
        BN_set_negative(r->coeffs[exponent], 1);
    }
    BN_nnmod(r->coeffs[exponent], r->coeffs[exponent], ring_modulus(), ctx);
}

static void
test_zero_and_eq(BN_CTX* ctx)
{
    (void)ctx;
    ring_elem a, b;
    ring_init(&a);
    ring_init(&b);
    CHECK(ring_eq(&a, &b), "two freshly-inited (zero) elements are equal");
    BN_set_word(a.coeffs[3], 5);
    CHECK(!ring_eq(&a, &b), "differing coefficient makes elements unequal");
    ring_free(&a);
    ring_free(&b);
}

static void
test_add_sub_inverse(BN_CTX* ctx)
{
    ring_elem a, b, sum, back;
    ring_init(&a);
    ring_init(&b);
    ring_init(&sum);
    ring_init(&back);
    ring_random_uniform(&a, ctx);
    ring_random_uniform(&b, ctx);
    ring_add(&sum, &a, &b, ctx);
    ring_sub(&back, &sum, &b, ctx);
    CHECK(ring_eq(&back, &a), "(a + b) - b == a for random a, b");
    ring_free(&a);
    ring_free(&b);
    ring_free(&sum);
    ring_free(&back);
}

static void
test_negation(BN_CTX* ctx)
{
    ring_elem a, neg_a, sum, zero;
    ring_init(&a);
    ring_init(&neg_a);
    ring_init(&sum);
    ring_init(&zero);
    ring_random_uniform(&a, ctx);
    ring_neg(&neg_a, &a, ctx);
    ring_add(&sum, &a, &neg_a, ctx);
    CHECK(ring_eq(&sum, &zero), "a + (-a) == 0");
    ring_free(&a);
    ring_free(&neg_a);
    ring_free(&sum);
    ring_free(&zero);
}

static void
test_scalar_mul(BN_CTX* ctx)
{
    ring_elem a, out;
    ring_init(&a);
    ring_init(&out);
    ring_random_uniform(&a, ctx);

    BIGNUM* one = BN_new();
    BN_one(one);
    ring_scalar_mul(&out, &a, one, ctx);
    CHECK(ring_eq(&out, &a), "scalar_mul by 1 is identity");

    BIGNUM* zero_scalar = BN_new();
    BN_zero(zero_scalar);
    ring_elem zero;
    ring_init(&zero);
    ring_scalar_mul(&out, &a, zero_scalar, ctx);
    CHECK(ring_eq(&out, &zero), "scalar_mul by 0 gives 0");

    BN_free(one);
    BN_free(zero_scalar);
    ring_free(&a);
    ring_free(&out);
    ring_free(&zero);
}

static void
test_serialize_roundtrip(BN_CTX* ctx)
{
    ring_elem a, back;
    ring_init(&a);
    ring_init(&back);
    ring_random_uniform(&a, ctx);

    size_t n = ring_serialized_bytes();
    uint8_t* buf = malloc(n);
    ring_serialize(buf, &a);
    ring_deserialize(&back, buf);
    CHECK(ring_eq(&a, &back), "serialize/deserialize round trip preserves a random element");

    free(buf);
    ring_free(&a);
    ring_free(&back);
}

static void
test_mul_identity_and_zero(BN_CTX* ctx)
{
    ring_elem a, one, zero, out;
    ring_init(&a);
    ring_init(&one);
    ring_init(&zero);
    ring_init(&out);
    ring_random_uniform(&a, ctx);
    set_monomial(&one, 0, 1, ctx);

    ring_mul(&out, &a, &one, ctx);
    CHECK(ring_eq(&out, &a), "a * 1 == a");

    ring_mul(&out, &a, &zero, ctx);
    CHECK(ring_eq(&out, &zero), "a * 0 == 0");

    ring_free(&a);
    ring_free(&one);
    ring_free(&zero);
    ring_free(&out);
}

static void
test_negacyclic_wraparound(BN_CTX* ctx)
{
    /* X^(D-1) * X should equal -1, the defining relation X^D == -1 mod
     * (X^D + 1) -- the one property that makes this ring different
     * from plain polynomial multiplication mod X^D - 1. */
    ring_elem x_pow_dminus1, x, out, neg_one;
    ring_init(&x_pow_dminus1);
    ring_init(&x);
    ring_init(&out);
    ring_init(&neg_one);
    set_monomial(&x_pow_dminus1, TIBE_D - 1, 1, ctx);
    set_monomial(&x, 1, 1, ctx);
    set_monomial(&neg_one, 0, -1, ctx);

    ring_mul(&out, &x_pow_dminus1, &x, ctx);
    CHECK(ring_eq(&out, &neg_one), "X^(D-1) * X == -1 (negacyclic wraparound)");

    ring_free(&x_pow_dminus1);
    ring_free(&x);
    ring_free(&out);
    ring_free(&neg_one);
}

static void
test_distributivity(BN_CTX* ctx)
{
    /* a*(b+c) == a*b + a*c, for random (dense) a, b, c -- the one check
     * here that exercises ring_mul on fully random operands rather than
     * sparse monomials, so it's the real stress test of the negacyclic
     * convolution + mod-q reduction together. Only one trial: each
     * dense ring_mul is O(D^2) BIGNUM multiplications and this test
     * does three of them. */
    ring_elem a, b, c, b_plus_c, lhs, ab, ac, rhs;
    ring_init(&a);
    ring_init(&b);
    ring_init(&c);
    ring_init(&b_plus_c);
    ring_init(&lhs);
    ring_init(&ab);
    ring_init(&ac);
    ring_init(&rhs);

    ring_random_uniform(&a, ctx);
    ring_random_uniform(&b, ctx);
    ring_random_uniform(&c, ctx);

    ring_add(&b_plus_c, &b, &c, ctx);
    ring_mul(&lhs, &a, &b_plus_c, ctx);

    ring_mul(&ab, &a, &b, ctx);
    ring_mul(&ac, &a, &c, ctx);
    ring_add(&rhs, &ab, &ac, ctx);

    CHECK(ring_eq(&lhs, &rhs), "a*(b+c) == a*b + a*c for random dense a, b, c");

    ring_free(&a);
    ring_free(&b);
    ring_free(&c);
    ring_free(&b_plus_c);
    ring_free(&lhs);
    ring_free(&ab);
    ring_free(&ac);
    ring_free(&rhs);
}

static void
test_inverse(BN_CTX* ctx)
{
    /* A uniformly random ring element is a unit with overwhelming
     * probability: R_q ~ F_{d/2} x F_{d/2} (two fields of order
     * q^2048), so a random element fails to be a unit only if one of
     * its two CRT components is exactly zero -- probability roughly
     * 2/q^2048, negligible enough to not special-case here. */
    ring_elem a, inv_a, product, one;
    ring_init(&a);
    ring_init(&inv_a);
    ring_init(&product);
    ring_init(&one);
    ring_random_uniform(&a, ctx);
    BN_one(one.coeffs[0]);

    ring_inv(&inv_a, &a, ctx);
    ring_mul(&product, &a, &inv_a, ctx);
    CHECK(ring_eq(&product, &one), "a * ring_inv(a) == 1 for a random (overwhelmingly-likely-unit) a");

    ring_free(&a);
    ring_free(&inv_a);
    ring_free(&product);
    ring_free(&one);
}

static void
test_decomp_beta(BN_CTX* ctx)
{
    ring_elem x, c0, c1, beta_times_c0, reconstructed;
    ring_init(&x);
    ring_init(&c0);
    ring_init(&c1);
    ring_init(&beta_times_c0);
    ring_init(&reconstructed);
    ring_random_uniform(&x, ctx);

    ring_decomp_beta(&c0, &c1, &x, ctx);

    BIGNUM* beta = BN_new();
    BN_lshift(beta, BN_value_one(), TIBE_BETA_LOG2);
    BIGNUM* half_beta = BN_new();
    BN_rshift1(half_beta, beta);
    const BIGNUM* q = ring_modulus();

    int reconstructs = 1;
    int bounded = 1;
    for (int i = 0; i < TIBE_D; i++)
    {
        BIGNUM* term = BN_new();
        BN_mod_mul(term, c0.coeffs[i], beta, q, ctx);
        BN_mod_add(term, term, c1.coeffs[i], q, ctx);
        if (BN_cmp(term, x.coeffs[i]) != 0)
        {
            reconstructs = 0;
        }
        BN_free(term);

        /* |c1_i| <= beta/2, checked against c1's centered representative */
        BIGNUM* half_q = BN_new();
        BN_rshift1(half_q, q);
        BIGNUM* centered_c1 = BN_new();
        if (BN_cmp(c1.coeffs[i], half_q) > 0)
        {
            BN_sub(centered_c1, c1.coeffs[i], q);
        }
        else
        {
            BN_copy(centered_c1, c1.coeffs[i]);
        }
        BN_set_negative(centered_c1, 0); /* abs value */
        if (BN_cmp(centered_c1, half_beta) > 0)
        {
            bounded = 0;
        }
        BN_free(half_q);
        BN_free(centered_c1);
    }
    CHECK(reconstructs, "c0*beta + c1 == x (mod q) for every coefficient");
    CHECK(bounded, "|c1_i| <= beta/2 for every coefficient");

    BN_free(beta);
    BN_free(half_beta);
    ring_free(&x);
    ring_free(&c0);
    ring_free(&c1);
    ring_free(&beta_times_c0);
    ring_free(&reconstructed);
}

int
main(void)
{
    BN_CTX* ctx = BN_CTX_new();

    test_zero_and_eq(ctx);
    test_add_sub_inverse(ctx);
    test_negation(ctx);
    test_scalar_mul(ctx);
    test_serialize_roundtrip(ctx);
    test_mul_identity_and_zero(ctx);
    test_negacyclic_wraparound(ctx);
    test_decomp_beta(ctx);

    clock_t start = clock();
    test_distributivity(ctx);
    double secs = (double)(clock() - start) / CLOCKS_PER_SEC;
    printf("(distributivity dense-multiply check took %.1fs)\n", secs);

    start = clock();
    test_inverse(ctx);
    secs = (double)(clock() - start) / CLOCKS_PER_SEC;
    printf("(ring_inv check took %.1fs)\n", secs);

    BN_CTX_free(ctx);

    if (failures == 0)
    {
        printf("test_ring: all tests passed\n");
        return 0;
    }
    printf("test_ring: %d failure(s)\n", failures);
    return 1;
}
