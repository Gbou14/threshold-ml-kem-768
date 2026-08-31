#include "polyvec.h"

void
polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

void
polyvec_reduce(polyvec *r)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_reduce(&r->vec[i]);
    }
}

void
polyvec_ntt(polyvec *r)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_ntt(&r->vec[i]);
    }
}

void
polyvec_invntt_tomont(polyvec *r)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_invntt_tomont(&r->vec[i]);
    }
}

void
polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b)
{
    poly t;
    poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < KYBER_K; i++)
    {
        poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

void
polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
    }
}

void
polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
    }
}

/* KYBER_DU=10-bit compression: same fixed-point rounded-division-by-q
 * technique as poly_compress, just with an 11-bit-wide intermediate
 * (2^42-ish) since the 10-bit scale factor no longer fits a 32-bit
 * multiply-shift as cleanly. */
void
polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a)
{
    uint16_t t[4];
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N / 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                uint16_t c = (uint16_t)a->vec[i].coeffs[4 * j + k];
                c = (uint16_t)(c + (((int16_t)c >> 15) & KYBER_Q)); /* map to [0, q) */
                uint64_t d0 = c;
                d0 <<= 10;
                d0 += 1665;
                d0 *= 1290167;
                d0 >>= 32;
                t[k] = (uint16_t)(d0 & 0x3FF);
            }
            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[4] = (uint8_t)(t[3] >> 2);
            r += 5;
        }
    }
}

void
polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
    uint16_t t[4];
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N / 4; j++)
        {
            t[0] = (uint16_t)((a[0] >> 0) | ((uint16_t)a[1] << 8));
            t[1] = (uint16_t)((a[1] >> 2) | ((uint16_t)a[2] << 6));
            t[2] = (uint16_t)((a[2] >> 4) | ((uint16_t)a[3] << 4));
            t[3] = (uint16_t)((a[3] >> 6) | ((uint16_t)a[4] << 2));
            a += 5;

            for (int k = 0; k < 4; k++)
            {
                r->vec[i].coeffs[4 * j + k] =
                    (int16_t)((((uint32_t)(t[k] & 0x3FF)) * KYBER_Q + 512) >> 10);
            }
        }
    }
}
