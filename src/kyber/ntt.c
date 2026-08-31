#include "ntt.h"
#include "params.h"
#include "reduce.h"

int16_t zetas[128];
static int zetas_ready = 0;

/* Reverse the low 7 bits of i. */
static uint8_t
bitrev7(uint8_t i)
{
    uint8_t r = 0;
    for (int b = 0; b < 7; b++)
    {
        r |= ((i >> b) & 1u) << (6 - b);
    }
    return r;
}

static int16_t
center(int32_t x)
{
    if (x > KYBER_Q / 2)
    {
        x -= KYBER_Q;
    }
    if (x < -KYBER_Q / 2)
    {
        x += KYBER_Q;
    }
    return (int16_t)x;
}

void
kyber_ntt_init(void)
{
    if (zetas_ready)
    {
        return;
    }

    /* zeta = 17 is the standard primitive 256th root of unity mod q for
     * ML-KEM. tmp[i] = zeta^i in Montgomery domain, built iteratively:
     * tmp[0] = R (Montgomery representation of 1), and each step
     * multiplies by zeta (also lifted into Montgomery domain, hence the
     * extra factor of R folded into the constant below). */
    int16_t tmp[128];
    tmp[0] = KYBER_MONT;
    int32_t mont_zeta = (KYBER_MONT * 17) % KYBER_Q;
    for (int i = 1; i < 128; i++)
    {
        tmp[i] = fq_mul(tmp[i - 1], (int16_t)mont_zeta);
    }

    /* The NTT butterfly network consumes twiddle factors in
     * bit-reversed order. */
    for (int i = 0; i < 128; i++)
    {
        zetas[i] = center(tmp[bitrev7((uint8_t)i)]);
    }

    zetas_ready = 1;
}

void
ntt(int16_t r[256])
{
    kyber_ntt_init();

    unsigned int k = 1;
    for (unsigned int len = 128; len >= 2; len >>= 1)
    {
        for (unsigned int start = 0; start < 256; start += 2 * len)
        {
            int16_t zeta = zetas[k++];
            for (unsigned int j = start; j < start + len; j++)
            {
                int16_t t = fq_mul(zeta, r[j + len]);
                r[j + len] = (int16_t)(r[j] - t);
                r[j] = (int16_t)(r[j] + t);
            }
        }
    }
}

void
invntt(int16_t r[256])
{
    kyber_ntt_init();

    /* mont^2 / 128 mod q, folds the final Montgomery-domain rescale and
     * the 1/128 factor of the inverse transform into one constant. */
    const int16_t f = 1441;

    unsigned int k = 127;
    for (unsigned int len = 2; len <= 128; len <<= 1)
    {
        for (unsigned int start = 0; start < 256; start += 2 * len)
        {
            int16_t zeta = zetas[k--];
            for (unsigned int j = start; j < start + len; j++)
            {
                int16_t t = r[j];
                r[j] = barrett_reduce((int16_t)(t + r[j + len]));
                r[j + len] = (int16_t)(r[j + len] - t);
                r[j + len] = fq_mul(zeta, r[j + len]);
            }
        }
    }

    for (unsigned int j = 0; j < 256; j++)
    {
        r[j] = fq_mul(r[j], f);
    }
}

void
basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
    r[0] = fq_mul(a[1], b[1]);
    r[0] = fq_mul(r[0], zeta);
    r[0] = (int16_t)(r[0] + fq_mul(a[0], b[0]));
    r[1] = fq_mul(a[0], b[1]);
    r[1] = (int16_t)(r[1] + fq_mul(a[1], b[0]));
}
