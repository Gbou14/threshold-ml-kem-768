#include "gauss.h"

#include <math.h>
#include <openssl/rand.h>
#include <stdint.h>

/* -std=c11 (strict ISO C, no POSIX extensions) doesn't guarantee M_PI
 * from <math.h>; define it directly rather than relying on a feature
 * test macro. */
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Uniform double in (0, 1], from 53 bits of OpenSSL RAND_bytes output.
 * The "+1" numerator avoids log(0) in the Box-Muller step below without
 * measurably biasing the distribution (53 bits of resolution). */
static double
uniform01(void)
{
    uint64_t r;
    RAND_bytes((unsigned char*)&r, sizeof(r));
    r >>= 11; /* keep the top 53 bits */
    return (double)(r + 1) / (double)(1ULL << 53);
}

int64_t
gauss_sample_coeff(double sigma)
{
    double u1 = uniform01();
    double u2 = uniform01();
    double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    return (int64_t)llround(z * sigma);
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
