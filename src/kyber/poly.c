#include "poly.h"

#include "cbd.h"
#include "ntt.h"
#include "reduce.h"
#include "shake.h"

void
poly_add(poly *r, const poly *a, const poly *b)
{
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = (int16_t)(a->coeffs[i] + b->coeffs[i]);
    }
}

void
poly_sub(poly *r, const poly *a, const poly *b)
{
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = (int16_t)(a->coeffs[i] - b->coeffs[i]);
    }
}

void
poly_reduce(poly *r)
{
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

void
poly_ntt(poly *r)
{
    ntt(r->coeffs);
    poly_reduce(r);
}

void
poly_invntt_tomont(poly *r)
{
    invntt(r->coeffs);
}

void
poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
    /* Each NTT "slot" i represents an element of Z_q[X]/(X^2 - zetas[64+i])
     * (or its negation for the odd-indexed slot); zetas[64..127] are
     * exactly the twiddle factors for that top layer of the transform. */
    for (int i = 0; i < KYBER_N / 4; i++)
    {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i]);
        basemul(&r->coeffs[4 * i + 2],
                &a->coeffs[4 * i + 2],
                &b->coeffs[4 * i + 2],
                (int16_t)(-zetas[64 + i]));
    }
}

void
poly_tomont(poly *r)
{
    /* Lift plain coefficients into Montgomery domain: multiply by
     * R^2 mod q so that a subsequent montgomery_reduce leaves a*R. */
    const int16_t r2_mod_q = (int16_t)(((uint64_t)1 << 32) % KYBER_Q);
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * r2_mod_q);
    }
}

void
poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[2 * KYBER_N / 4];
    kyber_prf(buf, sizeof(buf), seed, nonce);
    cbd_eta2(r->coeffs, buf);
}

void
poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[2 * KYBER_N / 4];
    kyber_prf(buf, sizeof(buf), seed, nonce);
    cbd_eta2(r->coeffs, buf);
}

/* Fixed-point rounded division by q, used to avoid a variable-time
 * division instruction: round(u * 2^bits / q) computed as
 * (u*2^bits + q/2) * ceil(2^(bits+shift)/q) >> shift, with shift chosen
 * so the multiply stays within 32 bits and the rounding error from
 * approximating 1/q is smaller than half a unit in the last place. */
static uint32_t
round_div_q(uint32_t scaled_plus_half, uint32_t recip, unsigned shift)
{
    return (scaled_plus_half * recip) >> shift;
}

void
poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a)
{
    uint8_t t[8];
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            int16_t u = a->coeffs[8 * i + j];
            u = (int16_t)(u + ((u >> 15) & KYBER_Q)); /* map to [0, q) */
            t[j] = (uint8_t)(round_div_q((uint32_t)u * 16 + 1665, 80635, 28) & 0xF);
        }
        r[0] = (uint8_t)(t[0] | (t[1] << 4));
        r[1] = (uint8_t)(t[2] | (t[3] << 4));
        r[2] = (uint8_t)(t[4] | (t[5] << 4));
        r[3] = (uint8_t)(t[6] | (t[7] << 4));
        r += 4;
    }
}

void
poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES])
{
    for (int i = 0; i < KYBER_N / 2; i++)
    {
        r->coeffs[2 * i + 0] = (int16_t)((((uint16_t)(a[0] & 0xF)) * KYBER_Q + 8) >> 4);
        r->coeffs[2 * i + 1] = (int16_t)((((uint16_t)(a[0] >> 4)) * KYBER_Q + 8) >> 4);
        a += 1;
    }
}

void
poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a)
{
    for (int i = 0; i < KYBER_N / 2; i++)
    {
        uint16_t t0 = (uint16_t)a->coeffs[2 * i];
        t0 = (uint16_t)(t0 + (((int16_t)t0 >> 15) & KYBER_Q)); /* map to [0, q) */
        uint16_t t1 = (uint16_t)a->coeffs[2 * i + 1];
        t1 = (uint16_t)(t1 + (((int16_t)t1 >> 15) & KYBER_Q));
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

void
poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES])
{
    for (int i = 0; i < KYBER_N / 2; i++)
    {
        r->coeffs[2 * i] = (int16_t)(((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF);
        r->coeffs[2 * i + 1] = (int16_t)(((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF);
    }
}

void
poly_frommsg(poly *r, const uint8_t msg[KYBER_MSGBYTES])
{
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            int16_t bit = (int16_t)((msg[i] >> j) & 1);
            /* Branchless select, matching a constant-time cmov: bit=0
             * keeps 0, bit=1 selects round(q/2). Written with an
             * arithmetic mask to avoid a data-dependent branch. */
            int16_t mask = (int16_t)(-bit);
            r->coeffs[8 * i + j] = (int16_t)(mask & ((KYBER_Q + 1) / 2));
        }
    }
}

void
poly_tomsg(uint8_t msg[KYBER_MSGBYTES], const poly *a)
{
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        msg[i] = 0;
        for (int j = 0; j < 8; j++)
        {
            uint32_t t = (uint32_t)a->coeffs[8 * i + j];
            uint32_t bit = round_div_q(t * 2 + 1665, 80635, 28) & 1u;
            msg[i] = (uint8_t)(msg[i] | (bit << j));
        }
    }
}
