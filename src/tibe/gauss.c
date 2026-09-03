#include "gauss.h"

#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Phase 8b: exact CDT-based sampling for the small widths, plus
 * Micciancio-Walter convolution (eprint 2017/259, Theorem 2.1) for the
 * two huge "noise flooding" widths, replacing the earlier Box-Muller
 * approximation. See gauss.h and README.md "Gaussian sampling" for the
 * design writeup and precision/statistical-distance bounds.
 *
 * All fixed-point values below are unsigned BIGNUMs representing a
 * real number x in [0,1) (or, for the two "y" quantities inside
 * fxp_exp_neg, a small nonnegative real) as round(x * 2^FXP_BITS).
 * Since the scale is a power of two, "multiply by scale" / "divide by
 * scale" are exact bit shifts (BN_lshift/BN_rshift), not BN_mul/BN_div
 * -- the only genuine (rounding) BN_div calls are the ones dividing by
 * a non-power-of-two (2*sigma^2, a normalization total, k*2^k for
 * ln(2)'s series, n = floor(y/ln2) for range reduction).
 */

#define FXP_BITS 256
#define FXP_BYTES (FXP_BITS / 8)

/* Tail cutoff: table covers k in [-tau*sigma, tau*sigma]. Truncating
 * the discrete Gaussian there loses probability mass
 * ~2*exp(-tau^2/2) per coefficient (standard Gaussian tail bound);
 * with tau=15 that's ~1.9e-49 per coefficient, ~7.8e-46 (~2^-150) even
 * after a union bound over all TIBE_D=4096 coefficients of one ring
 * element -- comfortably negligible. See README.md for the full
 * accounting, including the (larger, but still negligible, ~2^-140ish)
 * bound for the convolution-based huge widths, whose per-coefficient
 * cost is many leaf draws off this same table. */
#define GAUSS_TAU 15

/* Internal base width the two huge widths (TIBE_SIGMA_PRIME,
 * TIBE_SIGMA_P) are built from via convolution. Must exceed
 * GAUSS_CONV_MARGIN (below) with comfortable room -- see README.md
 * "Gaussian sampling" for the derivation. Any sigma <= this threshold
 * (i.e. TIBE_SIGMA=4, TIBE_SIGMA_A=8, and this base itself) is sampled
 * directly off its own CDT table instead. */
#define GAUSS_CONV_BASE_SIGMA 16.0
#define GAUSS_DIRECT_MAX_SIGMA 20.0

/* sqrt(2) * eta_eps(Z), the per-level minimum width the
 * Micciancio-Walter convolution theorem requires (Theorem 2.1: each
 * s_i >= sqrt(2)*|z|_inf*eta_eps(Z)). eta_eps(Z) < 6 for eps <= 2^-160
 * (eprint 2017/259, Sec 2, "eta_eps(Z) is a relatively small constant
 * even for very small values of eps < 2^-160") -- 6.0 here is that
 * bound, not a fitted/approximate value. */
#define GAUSS_ETA_BOUND 6.0
#define GAUSS_CONV_MARGIN (1.4142135623730951 * GAUSS_ETA_BOUND)

#define GAUSS_MAX_LEVELS 30

/* ---- fixed-point helpers (used only for one-time table construction,
 * never per-sample -- see README.md for why table-build time doesn't
 * need to be constant-time: every input is a public sigma). ---- */

static BIGNUM*
fxp_scale(void)
{
    static BIGNUM* s = NULL;
    if (!s)
    {
        s = BN_new();
        BN_set_bit(s, FXP_BITS);
    }
    return s;
}

/* ln(2) * 2^FXP_BITS, via the series ln(2) = sum_{n=1}^inf 1/(n*2^n)
 * (geometric-like convergence; terms underflow past n ~ FXP_BITS, so
 * the loop below self-terminates with ~2^-FXP_BITS accuracy). */
static BIGNUM*
fxp_ln2(BN_CTX* ctx)
{
    static BIGNUM* cached = NULL;
    if (cached)
    {
        return cached;
    }
    BIGNUM* sum = BN_new();
    BN_zero(sum);
    BIGNUM* denom = BN_new();
    BIGNUM* term = BN_new();
    const BIGNUM* scale = fxp_scale();
    for (int n = 1; n <= FXP_BITS + 20; n++)
    {
        BN_set_word(denom, (BN_ULONG)n);
        BN_lshift(denom, denom, n); /* denom = n * 2^n */
        if (BN_ucmp(denom, scale) >= 0)
        {
            break; /* term would round to 0 */
        }
        BN_div(term, NULL, scale, denom, ctx); /* term = floor(scale / (n*2^n)) */
        BN_add(sum, sum, term);
    }
    BN_free(denom);
    BN_free(term);
    cached = sum;
    return cached;
}

/* result := exp(-y), where y_fxp represents y (a nonnegative real, in
 * practice at most ~GAUSS_TAU^2/2 ~ 112.5 for this module's tables) in
 * fixed point. Range-reduces y = n*ln2 + r (0 <= r < ln2), computes
 * exp(-r) via its (fast-converging, since r < ln2 < 1) Taylor series,
 * then scales by 2^-n via a bit shift -- standard, numerically robust
 * (no cancellation, unlike e.g. erf's alternating series at large
 * arguments) construction. */
static void
fxp_exp_neg(BIGNUM* result, const BIGNUM* y_fxp, BN_CTX* ctx)
{
    const BIGNUM* scale = fxp_scale();
    BIGNUM* ln2 = fxp_ln2(ctx);

    BIGNUM* n = BN_new();
    BIGNUM* r = BN_new();
    BN_div(n, r, y_fxp, ln2, ctx); /* y_fxp = n*ln2 + r (both fixed-point, so n falls out as a plain small integer) */
    unsigned long n_word = BN_get_word(n);

    BIGNUM* term = BN_new();
    BN_copy(term, scale); /* term_0 = 1.0 */
    BIGNUM* sum = BN_new();
    BN_copy(sum, scale); /* sum starts at term_0 */
    BIGNUM* prod = BN_new();
    BIGNUM* k_bn = BN_new();
    int sign_negative = 1; /* k=1 term (-r)^1/1! is negative */
    for (int k = 1; k <= 100; k++)
    {
        BN_mul(prod, term, r, ctx);
        BN_rshift(prod, prod, FXP_BITS); /* prod = term_{k-1} * r, back in fixed point */
        BN_set_word(k_bn, (BN_ULONG)k);
        BN_div(term, NULL, prod, k_bn, ctx); /* term_k = term_{k-1} * r / k */
        if (BN_is_zero(term))
        {
            break; /* remaining terms underflow to 0 at this precision */
        }
        if (sign_negative)
        {
            BN_sub(sum, sum, term);
        }
        else
        {
            BN_add(sum, sum, term);
        }
        sign_negative = !sign_negative;
    }
    BN_free(prod);
    BN_free(k_bn);
    BN_free(n);
    BN_free(r);
    BN_free(term);

    BN_rshift(result, sum, (int)n_word); /* * 2^-n */
    BN_free(sum);
}

/* ---- exact CDT table for a small (direct-sampled) sigma ---- */

typedef struct
{
    double sigma;
    int64_t tau_sigma; /* table covers k in [-tau_sigma, tau_sigma] */
    int n;              /* = 2*tau_sigma + 1 */
    BIGNUM** cum;        /* n entries, fixed-point cumulative P(X <= k); cum[n-1] == 2^FXP_BITS exactly */
} gauss_cdt;

static gauss_cdt*
gauss_cdt_build(double sigma, BN_CTX* ctx)
{
    gauss_cdt* t = malloc(sizeof(gauss_cdt));
    t->sigma = sigma;
    t->tau_sigma = (int64_t)ceil(GAUSS_TAU * sigma);
    t->n = (int)(2 * t->tau_sigma + 1);
    t->cum = malloc(sizeof(BIGNUM*) * (size_t)t->n);

    const BIGNUM* scale = fxp_scale();
    long sigma_int = lround(sigma); /* every sigma this function is ever called with (4, 8, 16) is an exact integer */
    BIGNUM* two_sigma2 = BN_new();
    BN_set_word(two_sigma2, (BN_ULONG)(2 * sigma_int * sigma_int));

    BIGNUM** rho = malloc(sizeof(BIGNUM*) * (size_t)t->n);
    BIGNUM* k2 = BN_new();
    BIGNUM* y_fxp = BN_new();
    BIGNUM* total = BN_new();
    BN_zero(total);
    for (int i = 0; i < t->n; i++)
    {
        int64_t k = (int64_t)i - t->tau_sigma;
        BN_set_word(k2, (BN_ULONG)(k * k));
        BN_mul(y_fxp, k2, scale, ctx);
        BN_div(y_fxp, NULL, y_fxp, two_sigma2, ctx); /* y_fxp = (k^2 / (2*sigma^2)) in fixed point */
        rho[i] = BN_new();
        fxp_exp_neg(rho[i], y_fxp, ctx);
        BN_add(total, total, rho[i]);
    }

    BIGNUM* running = BN_new();
    BN_zero(running);
    BIGNUM* scaled = BN_new();
    for (int i = 0; i < t->n; i++)
    {
        BN_add(running, running, rho[i]);
        BN_mul(scaled, running, scale, ctx);
        t->cum[i] = BN_new();
        BN_div(t->cum[i], NULL, scaled, total, ctx);
        BN_free(rho[i]);
    }
    BN_copy(t->cum[t->n - 1], scale); /* force the exact boundary, closing any floor-rounding gap */

    free(rho);
    BN_free(two_sigma2);
    BN_free(k2);
    BN_free(y_fxp);
    BN_free(total);
    BN_free(running);
    BN_free(scaled);
    return t;
}

#define GAUSS_MAX_CACHED_CDT 8
static struct
{
    double sigma;
    gauss_cdt* t;
} g_cdt_cache[GAUSS_MAX_CACHED_CDT];
static int g_cdt_cache_n = 0;

static const gauss_cdt*
get_cdt(double sigma, BN_CTX* ctx)
{
    for (int i = 0; i < g_cdt_cache_n; i++)
    {
        if (g_cdt_cache[i].sigma == sigma)
        {
            return g_cdt_cache[i].t;
        }
    }
    gauss_cdt* t = gauss_cdt_build(sigma, ctx);
    if (g_cdt_cache_n < GAUSS_MAX_CACHED_CDT)
    {
        g_cdt_cache[g_cdt_cache_n].sigma = sigma;
        g_cdt_cache[g_cdt_cache_n].t = t;
        g_cdt_cache_n++;
    }
    return t;
}

/* ---- convolution schedule for a huge (>GAUSS_DIRECT_MAX_SIGMA) sigma ---- */

typedef struct
{
    double sigma_target;
    int levels;
    int64_t k[GAUSS_MAX_LEVELS];
    double achieved_sigma;
} gauss_conv_schedule;

/* Builds the coefficient sequence k[0..levels) such that recursively
 * combining GAUSS_CONV_BASE_SIGMA-width samples as
 * x_{i+1} = k[i]*x1 + x2  (x1, x2 independent draws of width s_i)
 * reaches a width >= sigma_target, per Theorem 2.1's convolution
 * (each level's width becomes s_i*sqrt(k[i]^2+1)). k[i] is capped at
 * s_i/GAUSS_CONV_MARGIN so every level respects the theorem's
 * precondition; that cap grows with s_i, so achievable width grows
 * roughly quadratically per level -- reaching TIBE_SIGMA_P=2^47 from
 * a width-16 base takes only ~7 levels (~2^7=128 base draws total),
 * not the ~(2^47/16)^2 draws a naive fixed-coefficient sum would need.
 * See README.md for the concrete derived schedules and their citation. */
static void
gauss_build_schedule(gauss_conv_schedule* sched, double sigma_target)
{
    sched->sigma_target = sigma_target;
    double s = GAUSS_CONV_BASE_SIGMA;
    int levels = 0;
    while (s < sigma_target && levels < GAUSS_MAX_LEVELS)
    {
        double k_max = floor(s / GAUSS_CONV_MARGIN);
        if (k_max < 1.0)
        {
            k_max = 1.0;
        }
        double k_want = ceil(sigma_target / s);
        double k = (k_want < k_max) ? k_want : k_max;
        if (k < 1.0)
        {
            k = 1.0;
        }
        sched->k[levels] = (int64_t)k;
        s = s * sqrt(k * k + 1.0);
        levels++;
    }
    sched->levels = levels;
    sched->achieved_sigma = s;
}

#define GAUSS_MAX_CACHED_SCHED 4
static struct
{
    double sigma;
    gauss_conv_schedule sched;
} g_sched_cache[GAUSS_MAX_CACHED_SCHED];
static int g_sched_cache_n = 0;

static const gauss_conv_schedule*
get_schedule(double sigma_target)
{
    for (int i = 0; i < g_sched_cache_n; i++)
    {
        if (g_sched_cache[i].sigma == sigma_target)
        {
            return &g_sched_cache[i].sched;
        }
    }
    if (g_sched_cache_n >= GAUSS_MAX_CACHED_SCHED)
    {
        fprintf(stderr, "tibe/gauss: convolution schedule cache exhausted\n");
        abort();
    }
    g_sched_cache[g_sched_cache_n].sigma = sigma_target;
    gauss_build_schedule(&g_sched_cache[g_sched_cache_n].sched, sigma_target);
    g_sched_cache_n++;
    return &g_sched_cache[g_sched_cache_n - 1].sched;
}

/* ---- randomness source: RAND_bytes or a gauss_prg byte stream ---- */

typedef struct
{
    gauss_prg* prg; /* NULL => draw from RAND_bytes instead */
} gauss_rng;

static void
gauss_prg_next(gauss_prg* prg, uint8_t* out, size_t n)
{
    if (prg->pos + n > prg->len)
    {
        fprintf(stderr, "tibe/gauss: gauss_prg exhausted (need more out_len at init)\n");
        abort();
    }
    memcpy(out, prg->buf + prg->pos, n);
    prg->pos += n;
}

static void
rng_bytes(gauss_rng* rng, uint8_t* out, size_t n)
{
    if (rng->prg)
    {
        gauss_prg_next(rng->prg, out, n);
    }
    else
    {
        RAND_bytes(out, n);
    }
}

/* One CDT lookup: draws FXP_BYTES bytes, interprets them as a uniform
 * fixed-point r in [0, 2^FXP_BITS), and returns the k such that
 * cum[k's index - 1] <= r < cum[k's index]. Always scans all t->n
 * entries (never breaks out early) so the number of iterations and
 * memory locations touched depends only on t->sigma (public), not on
 * r or the result -- see gauss.h's constant-time caveat. */
static int64_t
gauss_cdt_sample(const gauss_cdt* t, gauss_rng* rng)
{
    uint8_t buf[FXP_BYTES];
    rng_bytes(rng, buf, FXP_BYTES);
    BIGNUM* r = BN_bin2bn(buf, FXP_BYTES, NULL);

    int64_t result = t->tau_sigma; /* unreachable in practice: cum[n-1] == scale > any r < scale */
    int found = 0;
    for (int i = 0; i < t->n; i++)
    {
        int lt = (BN_ucmp(r, t->cum[i]) < 0);
        if (lt && !found)
        {
            result = (int64_t)i - t->tau_sigma;
        }
        found = found || lt;
    }
    BN_free(r);
    return result;
}

static int64_t
gauss_conv_sample_rec(const gauss_cdt* base, const gauss_conv_schedule* sched, int level, gauss_rng* rng)
{
    if (level == 0)
    {
        return gauss_cdt_sample(base, rng);
    }
    int64_t x1 = gauss_conv_sample_rec(base, sched, level - 1, rng);
    int64_t x2 = gauss_conv_sample_rec(base, sched, level - 1, rng);
    return sched->k[level - 1] * x1 + x2;
}

static int64_t
gauss_sample_coeff_rng(double sigma, gauss_rng* rng, BN_CTX* ctx)
{
    if (sigma <= GAUSS_DIRECT_MAX_SIGMA)
    {
        return gauss_cdt_sample(get_cdt(sigma, ctx), rng);
    }
    const gauss_cdt* base = get_cdt(GAUSS_CONV_BASE_SIGMA, ctx);
    const gauss_conv_schedule* sched = get_schedule(sigma);
    return gauss_conv_sample_rec(base, sched, sched->levels, rng);
}

/* ---- public API (signatures unchanged from the Box-Muller version) ---- */

int64_t
gauss_sample_coeff(double sigma)
{
    BN_CTX* ctx = BN_CTX_new();
    gauss_rng rng = {.prg = NULL};
    int64_t v = gauss_sample_coeff_rng(sigma, &rng, ctx);
    BN_CTX_free(ctx);
    return v;
}

void
gauss_sample(ring_elem* out, double sigma, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* tmp = BN_new();
    for (int i = 0; i < TIBE_D; i++)
    {
        int64_t v = gauss_sample_coeff(sigma);
        uint64_t mag = (uint64_t)(v < 0 ? -v : v);
        BN_set_word(tmp, mag);
        if (v < 0)
        {
            BN_set_negative(tmp, 1);
        }
        BN_nnmod(out->coeffs[i], tmp, q, ctx);
    }
    BN_free(tmp);
}

void
gauss_prg_init(gauss_prg* prg, const uint8_t* seed, size_t seed_len, size_t out_len)
{
    prg->buf = malloc(out_len);
    prg->len = out_len;
    prg->pos = 0;

    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!md || !mctx || !EVP_DigestInit_ex2(mctx, md, NULL) || !EVP_DigestUpdate(mctx, seed, seed_len) ||
        !EVP_DigestFinalXOF(mctx, prg->buf, out_len))
    {
        fprintf(stderr, "tibe/gauss: OpenSSL SHAKE256 XOF failed\n");
        abort();
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
}

void
gauss_prg_free(gauss_prg* prg)
{
    free(prg->buf);
    prg->buf = NULL;
    prg->len = 0;
    prg->pos = 0;
}

int64_t
gauss_sample_coeff_from_prg(gauss_prg* prg, double sigma)
{
    BN_CTX* ctx = BN_CTX_new();
    gauss_rng rng = {.prg = prg};
    int64_t v = gauss_sample_coeff_rng(sigma, &rng, ctx);
    BN_CTX_free(ctx);
    return v;
}

void
gauss_sample_from_prg(ring_elem* out, double sigma, gauss_prg* prg, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* tmp = BN_new();
    for (int i = 0; i < TIBE_D; i++)
    {
        int64_t v = gauss_sample_coeff_from_prg(prg, sigma);
        uint64_t mag = (uint64_t)(v < 0 ? -v : v);
        BN_set_word(tmp, mag);
        if (v < 0)
        {
            BN_set_negative(tmp, 1);
        }
        BN_nnmod(out->coeffs[i], tmp, q, ctx);
    }
    BN_free(tmp);
}

size_t
gauss_bytes_per_coeff(double sigma)
{
    if (sigma <= GAUSS_DIRECT_MAX_SIGMA)
    {
        return FXP_BYTES;
    }
    const gauss_conv_schedule* sched = get_schedule(sigma);
    return FXP_BYTES * ((size_t)1 << sched->levels);
}
