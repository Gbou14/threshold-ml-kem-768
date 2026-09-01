#include "gauss.h"

#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -std=c11 (strict ISO C, no POSIX extensions) doesn't guarantee M_PI
 * from <math.h>; define it directly rather than relying on a feature
 * test macro. */
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Uniform double in (0, 1], from 53 bits. The "+1" numerator avoids
 * log(0) in the Box-Muller step below without measurably biasing the
 * distribution (53 bits of resolution). Shared by both the
 * RAND_bytes-driven and gauss_prg-driven paths below. */
static double
uniform01_from_bytes(const uint8_t b[8])
{
    uint64_t r;
    memcpy(&r, b, sizeof(r));
    r >>= 11; /* keep the top 53 bits */
    return (double)(r + 1) / (double)(1ULL << 53);
}

static int64_t
box_muller_sample(double u1, double u2, double sigma)
{
    double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    return (int64_t)llround(z * sigma);
}

int64_t
gauss_sample_coeff(double sigma)
{
    uint8_t b1[8], b2[8];
    RAND_bytes(b1, sizeof(b1));
    RAND_bytes(b2, sizeof(b2));
    return box_muller_sample(uniform01_from_bytes(b1), uniform01_from_bytes(b2), sigma);
}

void
gauss_sample(ring_elem* out, double sigma, BN_CTX* ctx)
{
    (void)ctx;
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

static void
gauss_prg_next8(gauss_prg* prg, uint8_t out[8])
{
    if (prg->pos + 8 > prg->len)
    {
        fprintf(stderr, "tibe/gauss: gauss_prg exhausted (need more out_len at init)\n");
        abort();
    }
    memcpy(out, prg->buf + prg->pos, 8);
    prg->pos += 8;
}

int64_t
gauss_sample_coeff_from_prg(gauss_prg* prg, double sigma)
{
    uint8_t b1[8], b2[8];
    gauss_prg_next8(prg, b1);
    gauss_prg_next8(prg, b2);
    return box_muller_sample(uniform01_from_bytes(b1), uniform01_from_bytes(b2), sigma);
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
