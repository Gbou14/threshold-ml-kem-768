#include "threshold.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

static int32_t
mod_q(int32_t a)
{
    int32_t r = a % KYBER_Q;
    return (r < 0) ? r + KYBER_Q : r;
}

static int16_t
center_q(int32_t a)
{
    int32_t r = mod_q(a);
    if (r > KYBER_Q / 2)
    {
        r -= KYBER_Q;
    }
    return (int16_t)r;
}

/* q^{-1} mod q doesn't exist for a=0, but every denominator that shows
 * up here is a product of distinct nonzero (x_i - x_j) values, so this
 * is only ever called on a nonzero input. */
static int32_t
mod_inverse_q(int32_t a)
{
    int32_t t = 0, newt = 1;
    int32_t r = KYBER_Q, newr = mod_q(a);

    while (newr != 0)
    {
        int32_t quot = r / newr;

        int32_t tmp = t;
        t = newt;
        newt = tmp - quot * newt;

        tmp = r;
        r = newr;
        newr = tmp - quot * newr;
    }

    return mod_q(t);
}

/* Uniform random value in [0, KYBER_Q) via rejection sampling on
 * OpenSSL's CSPRNG -- the Shamir polynomial's random coefficients must
 * not be predictable, unlike the original toy prototype's rand(). */
static int16_t
rand_mod_q(void)
{
    for (;;)
    {
        uint8_t b[2];
        if (!RAND_bytes(b, sizeof(b)))
        {
            fprintf(stderr, "kyber: RAND_bytes failed\n");
            abort();
        }
        uint16_t v = (uint16_t)(b[0] | (b[1] << 8));
        v = (uint16_t)(v & 0x0FFF); /* 12 bits, same rejection range as rej_uniform */
        if (v < KYBER_Q)
        {
            return (int16_t)v;
        }
    }
}

void
threshold_split_secret(const polyvec *secret, polyvec *shares_out, int k, int n)
{
    int32_t coeffs[k];

    for (int p = 0; p < KYBER_K; p++)
    {
        for (int c = 0; c < KYBER_N; c++)
        {
            coeffs[0] = mod_q(secret->vec[p].coeffs[c]);
            for (int j = 1; j < k; j++)
            {
                coeffs[j] = rand_mod_q();
            }

            for (int i = 0; i < n; i++)
            {
                int32_t x = i + 1;
                int32_t y = 0;
                int32_t power = 1;
                for (int j = 0; j < k; j++)
                {
                    y = mod_q(y + coeffs[j] * power);
                    power = mod_q(power * x);
                }
                shares_out[i].vec[p].coeffs[c] = center_q(y);
            }
        }
    }
}

void
threshold_partial_decrypt(poly *partial_out, const polyvec *share, const polyvec *b)
{
    polyvec_basemul_acc_montgomery(partial_out, share, b);
}

void
threshold_combine(poly *mp_out, const poly *partials, const int *xs, int k)
{
    for (int c = 0; c < KYBER_N; c++)
    {
        int32_t result = 0;

        for (int i = 0; i < k; i++)
        {
            int32_t xi = xs[i];
            int32_t yi = partials[i].coeffs[c];

            int32_t num = 1;
            int32_t den = 1;
            for (int j = 0; j < k; j++)
            {
                if (j == i)
                {
                    continue;
                }
                int32_t xj = xs[j];
                num = mod_q(num * (-xj));
                den = mod_q(den * (xi - xj));
            }

            int32_t term = mod_q(yi * num);
            term = mod_q(term * mod_inverse_q(den));
            result = mod_q(result + term);
        }

        mp_out->coeffs[c] = center_q(result);
    }
}

void
threshold_finish_decrypt(uint8_t msg_out[KYBER_MSGBYTES], const poly *partials, const int *xs, int k, const poly *v)
{
    poly mp;
    threshold_combine(&mp, partials, xs, k);
    poly_invntt_tomont(&mp);

    poly diff;
    poly_sub(&diff, v, &mp);
    poly_reduce(&diff);
    poly_tomsg(msg_out, &diff);
}
