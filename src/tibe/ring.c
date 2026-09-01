#include "ring.h"

#include <stdlib.h>
#include <string.h>

static BIGNUM* g_q = NULL;
static BIGNUM* g_r1 = NULL;
static BIGNUM* g_r2 = NULL;

const BIGNUM*
ring_modulus(void)
{
    if (g_q == NULL)
    {
        if (BN_hex2bn(&g_q, TIBE_Q_HEX) == 0)
        {
            abort(); /* malformed TIBE_Q_HEX -- a build-time constant, not runtime input */
        }
    }
    return g_q;
}

static const BIGNUM*
ring_r1(void)
{
    if (g_r1 == NULL)
    {
        if (BN_hex2bn(&g_r1, TIBE_R1_HEX) == 0)
        {
            abort();
        }
    }
    return g_r1;
}

static const BIGNUM*
ring_r2(void)
{
    if (g_r2 == NULL)
    {
        if (BN_hex2bn(&g_r2, TIBE_R2_HEX) == 0)
        {
            abort();
        }
    }
    return g_r2;
}

void
ring_init(ring_elem* r)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        r->coeffs[i] = BN_new();
        BN_zero(r->coeffs[i]);
    }
}

void
ring_free(ring_elem* r)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_free(r->coeffs[i]);
        r->coeffs[i] = NULL;
    }
}

void
ring_zero(ring_elem* r)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_zero(r->coeffs[i]);
    }
}

void
ring_copy(ring_elem* dst, const ring_elem* src)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_copy(dst->coeffs[i], src->coeffs[i]);
    }
}

void
ring_add(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_add(out->coeffs[i], a->coeffs[i], b->coeffs[i], q, ctx);
    }
}

void
ring_sub(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_sub(out->coeffs[i], a->coeffs[i], b->coeffs[i], q, ctx);
    }
}

void
ring_neg(ring_elem* out, const ring_elem* a, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_sub(out->coeffs[i], zero, a->coeffs[i], q, ctx);
    }
    BN_free(zero);
}

void
ring_scalar_mul(ring_elem* out, const ring_elem* a, const BIGNUM* scalar, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_mul(out->coeffs[i], a->coeffs[i], scalar, q, ctx);
    }
}

void
ring_mul(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx)
{
    /* Negacyclic convolution mod X^D+1: out[k] = sum_{i+j=k} a_i b_j -
     * sum_{i+j=k+D} a_i b_j, all mod q. `out` must not alias a or b. */
    const BIGNUM* q = ring_modulus();
    BIGNUM* prod = BN_new();

    ring_zero(out);
    for (int i = 0; i < TIBE_D; i++)
    {
        for (int j = 0; j < TIBE_D; j++)
        {
            int k = i + j;
            BN_mod_mul(prod, a->coeffs[i], b->coeffs[j], q, ctx);
            if (k < TIBE_D)
            {
                BN_mod_add(out->coeffs[k], out->coeffs[k], prod, q, ctx);
            }
            else
            {
                BN_mod_sub(out->coeffs[k - TIBE_D], out->coeffs[k - TIBE_D], prod, q, ctx);
            }
        }
    }
    BN_free(prod);
}

int
ring_eq(const ring_elem* a, const ring_elem* b)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        if (BN_cmp(a->coeffs[i], b->coeffs[i]) != 0)
        {
            return 0;
        }
    }
    return 1;
}

void
ring_random_uniform(ring_elem* out, BN_CTX* ctx)
{
    (void)ctx;
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_rand_range(out->coeffs[i], q);
    }
}

size_t
ring_serialized_bytes(void)
{
    return (size_t)TIBE_D * (size_t)TIBE_Q_BYTES;
}

void
ring_serialize(uint8_t* out, const ring_elem* a)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_bn2binpad(a->coeffs[i], out + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES);
    }
}

void
ring_deserialize(ring_elem* out, const uint8_t* in)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_bin2bn(in + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES, out->coeffs[i]);
    }
}

/*
 * ring_inv: polynomial extended Euclidean algorithm over the field
 * Z_q, computing a^-1 mod (X^D+1). Working polynomials here are NOT
 * ring_elem (fixed at degree < D, silently wrapping mod X^D+1) --
 * intermediate remainders and Bezout coefficients in the Euclidean
 * algorithm are plain polynomials that must NOT be reduced mod X^D+1
 * mid-computation, so this uses a separate, generously-oversized
 * buffer type (xpoly) local to this file. Classical result (see e.g.
 * von zur Gathen & Gerhard, "Modern Computer Algebra"): both the
 * degree of every intermediate value and the total field-operation
 * count across the whole algorithm stay O(D) / O(D^2) respectively --
 * the same complexity class as a single ring_mul -- despite the
 * generous buffer sizing below, which exists only as a safety margin
 * against an off-by-one, not because degrees are expected to
 * approach it.
 */
#define XPOLY_CAP (2 * TIBE_D + 2)

typedef struct
{
    BIGNUM* c[XPOLY_CAP];
    int deg; /* -1 = the zero polynomial */
} xpoly;

static void
xpoly_init(xpoly* p)
{
    for (int i = 0; i < XPOLY_CAP; i++)
    {
        p->c[i] = BN_new();
        BN_zero(p->c[i]);
    }
    p->deg = -1;
}

static void
xpoly_free(xpoly* p)
{
    for (int i = 0; i < XPOLY_CAP; i++)
    {
        BN_free(p->c[i]);
        p->c[i] = NULL;
    }
}

static void
xpoly_recompute_degree(xpoly* p)
{
    p->deg = -1;
    for (int i = XPOLY_CAP - 1; i >= 0; i--)
    {
        if (!BN_is_zero(p->c[i]))
        {
            p->deg = i;
            break;
        }
    }
}

static void
xpoly_zero(xpoly* p)
{
    for (int i = 0; i < XPOLY_CAP; i++)
    {
        BN_zero(p->c[i]);
    }
    p->deg = -1;
}

static void
xpoly_copy(xpoly* dst, const xpoly* src)
{
    for (int i = 0; i < XPOLY_CAP; i++)
    {
        BN_copy(dst->c[i], src->c[i]);
    }
    dst->deg = src->deg;
}

static void
xpoly_set_one(xpoly* p)
{
    xpoly_zero(p);
    BN_one(p->c[0]);
    p->deg = 0;
}

static void
xpoly_set_modulus(xpoly* p)
{
    /* X^D + 1 */
    xpoly_zero(p);
    BN_one(p->c[0]);
    BN_one(p->c[TIBE_D]);
    p->deg = TIBE_D;
}

/* quot, rem := dividend / divisor over Z_q[X]. divisor must be nonzero. */
static void
xpoly_divmod(xpoly* quot, xpoly* rem, const xpoly* dividend, const xpoly* divisor, const BIGNUM* q, BN_CTX* ctx)
{
    xpoly_copy(rem, dividend);
    xpoly_zero(quot);

    BIGNUM* lead_inv = BN_new();
    BN_mod_inverse(lead_inv, divisor->c[divisor->deg], q, ctx);
    BIGNUM* coef = BN_new();
    BIGNUM* term = BN_new();

    while (rem->deg >= divisor->deg)
    {
        int shift = rem->deg - divisor->deg;
        BN_mod_mul(coef, rem->c[rem->deg], lead_inv, q, ctx);
        BN_mod_add(quot->c[shift], quot->c[shift], coef, q, ctx);
        for (int i = 0; i <= divisor->deg; i++)
        {
            BN_mod_mul(term, coef, divisor->c[i], q, ctx);
            BN_mod_sub(rem->c[i + shift], rem->c[i + shift], term, q, ctx);
        }
        xpoly_recompute_degree(rem);
    }
    xpoly_recompute_degree(quot);

    BN_free(lead_inv);
    BN_free(coef);
    BN_free(term);
}

/* out := a*b, plain convolution -- NOT reduced mod X^D+1 (that
 * reduction is exactly what this helper must NOT do; ring_mul is the
 * function that does, and is unrelated to this one). */
static void
xpoly_mul_plain(xpoly* out, const xpoly* a, const xpoly* b, const BIGNUM* q, BN_CTX* ctx)
{
    xpoly_zero(out);
    if (a->deg < 0 || b->deg < 0)
    {
        return;
    }
    BIGNUM* term = BN_new();
    for (int i = 0; i <= a->deg; i++)
    {
        if (BN_is_zero(a->c[i]))
        {
            continue;
        }
        for (int j = 0; j <= b->deg; j++)
        {
            BN_mod_mul(term, a->c[i], b->c[j], q, ctx);
            BN_mod_add(out->c[i + j], out->c[i + j], term, q, ctx);
        }
    }
    xpoly_recompute_degree(out);
    BN_free(term);
}

static void
xpoly_sub(xpoly* out, const xpoly* a, const xpoly* b, const BIGNUM* q, BN_CTX* ctx)
{
    int maxdeg = a->deg > b->deg ? a->deg : b->deg;
    for (int i = 0; i <= maxdeg; i++)
    {
        BN_mod_sub(out->c[i], a->c[i], b->c[i], q, ctx);
    }
    for (int i = maxdeg + 1; i < XPOLY_CAP; i++)
    {
        BN_zero(out->c[i]);
    }
    xpoly_recompute_degree(out);
}

void
ring_inv(ring_elem* out, const ring_elem* a, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();

    xpoly old_r, r, old_t, t, quot, rem, tmp_mul, new_t;
    xpoly_init(&old_r);
    xpoly_init(&r);
    xpoly_init(&old_t);
    xpoly_init(&t);
    xpoly_init(&quot);
    xpoly_init(&rem);
    xpoly_init(&tmp_mul);
    xpoly_init(&new_t);

    for (int i = 0; i < TIBE_D; i++)
    {
        BN_copy(old_r.c[i], a->coeffs[i]);
    }
    xpoly_recompute_degree(&old_r);
    xpoly_set_modulus(&r);
    xpoly_set_one(&old_t);
    /* t starts at the zero polynomial, already true after xpoly_init */

    while (r.deg >= 0)
    {
        xpoly_divmod(&quot, &rem, &old_r, &r, q, ctx);

        /* new_t := old_t - quot*t */
        xpoly_mul_plain(&tmp_mul, &quot, &t, q, ctx);
        xpoly_sub(&new_t, &old_t, &tmp_mul, q, ctx);

        /* (old_r, r) := (r, rem); (old_t, t) := (t, new_t) */
        xpoly_copy(&old_r, &r);
        xpoly_copy(&r, &rem);
        xpoly_copy(&old_t, &t);
        xpoly_copy(&t, &new_t);
    }

    /* old_r is now gcd(a, X^D+1) in Z_q[X] -- a nonzero constant
     * (degree 0) exactly when `a` is a unit in R_q, which is the only
     * case this function is meant to be called for. a*old_t == old_r
     * (mod X^D+1), so a^-1 = old_t * old_r^-1 (old_r's inverse is a
     * plain scalar inverse in the field Z_q). */
    BIGNUM* gcd_inv = BN_new();
    BN_mod_inverse(gcd_inv, old_r.c[0], q, ctx);
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_mul(out->coeffs[i], old_t.c[i], gcd_inv, q, ctx);
    }
    BN_free(gcd_inv);

    xpoly_free(&old_r);
    xpoly_free(&r);
    xpoly_free(&old_t);
    xpoly_free(&t);
    xpoly_free(&quot);
    xpoly_free(&rem);
    xpoly_free(&tmp_mul);
    xpoly_free(&new_t);
}

/* Coefficient's centered-signed representative in (-q/2, q/2] rather
 * than the canonical [0, q). */
static void
centered_coeff(BIGNUM* out, const BIGNUM* raw, const BIGNUM* q, BN_CTX* ctx)
{
    BIGNUM* half_q = BN_new();
    BN_rshift1(half_q, q); /* floor(q/2) */
    if (BN_cmp(raw, half_q) > 0)
    {
        BN_sub(out, raw, q); /* raw - q, now negative -- equivalent mod q, but in (-q/2, q/2] */
    }
    else
    {
        BN_copy(out, raw);
    }
    BN_free(half_q);
    (void)ctx;
}

/* Decompose one centered coefficient x = c0*beta + c1, |c1| <= beta/2,
 * beta = 2^TIBE_BETA_LOG2. BN_div truncates toward zero (remainder's
 * sign matches the dividend's, |rem| < beta) -- adjusted below to land
 * in the symmetric range Decomp_beta requires. */
static void
decomp_beta_scalar(BIGNUM* c0, BIGNUM* c1, const BIGNUM* x_centered, BN_CTX* ctx)
{
    BIGNUM* beta = BN_new();
    BN_lshift(beta, BN_value_one(), TIBE_BETA_LOG2);
    BIGNUM* half_beta = BN_new();
    BN_rshift1(half_beta, beta);
    BIGNUM* neg_half_beta = BN_new();
    BN_copy(neg_half_beta, half_beta);
    BN_set_negative(neg_half_beta, 1);

    BN_div(c0, c1, x_centered, beta, ctx);

    if (BN_cmp(c1, half_beta) > 0)
    {
        BN_add(c0, c0, BN_value_one());
        BN_sub(c1, c1, beta);
    }
    else if (BN_cmp(c1, neg_half_beta) < 0)
    {
        BN_sub(c0, c0, BN_value_one());
        BN_add(c1, c1, beta);
    }

    BN_free(beta);
    BN_free(half_beta);
    BN_free(neg_half_beta);
}

void
ring_decomp_beta(ring_elem* c0, ring_elem* c1, const ring_elem* x, BN_CTX* ctx)
{
    /* c0/c1 are mathematically small (|c1| <= beta/2, c0 correspondingly
     * bounded) regardless of which representative is stored -- that's a
     * fact about the value, not the storage form. Normalized into the
     * canonical [0,q) range here purely to keep every ring_elem's
     * invariant consistent for later ring_add/ring_mul/serialize calls;
     * BN_mod_* would produce the same downstream results either way. */
    const BIGNUM* q = ring_modulus();
    BIGNUM* centered = BN_new();
    for (int i = 0; i < TIBE_D; i++)
    {
        centered_coeff(centered, x->coeffs[i], q, ctx);
        decomp_beta_scalar(c0->coeffs[i], c1->coeffs[i], centered, ctx);
        BN_nnmod(c0->coeffs[i], c0->coeffs[i], q, ctx);
        BN_nnmod(c1->coeffs[i], c1->coeffs[i], q, ctx);
    }
    BN_free(centered);
}

void
field_init(field_elem* f)
{
    for (int i = 0; i < TIBE_D / 2; i++)
    {
        f->c[i] = BN_new();
        BN_zero(f->c[i]);
    }
}

void
field_free(field_elem* f)
{
    for (int i = 0; i < TIBE_D / 2; i++)
    {
        BN_free(f->c[i]);
        f->c[i] = NULL;
    }
}

void
field_zero(field_elem* f)
{
    for (int i = 0; i < TIBE_D / 2; i++)
    {
        BN_zero(f->c[i]);
    }
}

void
field_copy(field_elem* dst, const field_elem* src)
{
    for (int i = 0; i < TIBE_D / 2; i++)
    {
        BN_copy(dst->c[i], src->c[i]);
    }
}

void
field_add(field_elem* out, const field_elem* a, const field_elem* b, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D / 2; i++)
    {
        BN_mod_add(out->c[i], a->c[i], b->c[i], q, ctx);
    }
}

int
field_eq(const field_elem* a, const field_elem* b)
{
    for (int i = 0; i < TIBE_D / 2; i++)
    {
        if (BN_cmp(a->c[i], b->c[i]) != 0)
        {
            return 0;
        }
    }
    return 1;
}

int
field_is_zero(const field_elem* f)
{
    for (int i = 0; i < TIBE_D / 2; i++)
    {
        if (!BN_is_zero(f->c[i]))
        {
            return 0;
        }
    }
    return 1;
}

void
field_mul(field_elem* out, const field_elem* a, const field_elem* b, const BIGNUM* root, BN_CTX* ctx)
{
    /* Same shape as ring_mul, but wraparound multiplies by `root`
     * (since X^{D/2} == root here) instead of negating (X^D == -1 in
     * ring_mul's full ring). `out` must not alias `a` or `b`. */
    const BIGNUM* q = ring_modulus();
    const int half = TIBE_D / 2;
    BIGNUM* prod = BN_new();
    BIGNUM* wrapped = BN_new();

    field_zero(out);
    for (int i = 0; i < half; i++)
    {
        for (int j = 0; j < half; j++)
        {
            int k = i + j;
            BN_mod_mul(prod, a->c[i], b->c[j], q, ctx);
            if (k < half)
            {
                BN_mod_add(out->c[k], out->c[k], prod, q, ctx);
            }
            else
            {
                BN_mod_mul(wrapped, prod, root, q, ctx);
                BN_mod_add(out->c[k - half], out->c[k - half], wrapped, q, ctx);
            }
        }
    }
    BN_free(prod);
    BN_free(wrapped);
}

void
ring_split(field_elem* y1, field_elem* y2, const ring_elem* m, BN_CTX* ctx)
{
    /* m = m_low + X^{D/2}*m_high; y_i = m_low + r_i*m_high, i.e.
     * reduction mod (X^{D/2}-r_i) -- X^{D/2} is replaced by the
     * scalar r_i, leaving a degree-<D/2 polynomial in each factor. */
    const BIGNUM* q = ring_modulus();
    const BIGNUM* r1 = ring_r1();
    const BIGNUM* r2 = ring_r2();
    const int half = TIBE_D / 2;
    BIGNUM* term = BN_new();

    for (int j = 0; j < half; j++)
    {
        BN_mod_mul(term, m->coeffs[half + j], r1, q, ctx);
        BN_mod_add(y1->c[j], m->coeffs[j], term, q, ctx);

        BN_mod_mul(term, m->coeffs[half + j], r2, q, ctx);
        BN_mod_add(y2->c[j], m->coeffs[j], term, q, ctx);
    }
    BN_free(term);
}

void
ring_unsplit(ring_elem* m, const field_elem* y1, const field_elem* y2, BN_CTX* ctx)
{
    /* CRT reconstruction: y1-y2 = (r1-r2)*m_high, so m_high =
     * (y1-y2)*(r1-r2)^-1, then m_low = y1 - r1*m_high. (r1-r2) is a
     * fixed nonzero scalar (r1 != r2 since r2 = -r1 and r1 != 0), so
     * its inverse is a cheap one-off scalar computation, not cached. */
    const BIGNUM* q = ring_modulus();
    const BIGNUM* r1 = ring_r1();
    const BIGNUM* r2 = ring_r2();
    const int half = TIBE_D / 2;

    BIGNUM* r1_minus_r2 = BN_new();
    BN_mod_sub(r1_minus_r2, r1, r2, q, ctx);
    BIGNUM* inv_r1_minus_r2 = BN_new();
    BN_mod_inverse(inv_r1_minus_r2, r1_minus_r2, q, ctx);

    BIGNUM* diff = BN_new();
    BIGNUM* m_high = BN_new();
    BIGNUM* term = BN_new();
    for (int j = 0; j < half; j++)
    {
        BN_mod_sub(diff, y1->c[j], y2->c[j], q, ctx);
        BN_mod_mul(m_high, diff, inv_r1_minus_r2, q, ctx);
        BN_copy(m->coeffs[half + j], m_high);

        BN_mod_mul(term, r1, m_high, q, ctx);
        BN_mod_sub(m->coeffs[j], y1->c[j], term, q, ctx);
    }

    BN_free(r1_minus_r2);
    BN_free(inv_r1_minus_r2);
    BN_free(diff);
    BN_free(m_high);
    BN_free(term);
}
