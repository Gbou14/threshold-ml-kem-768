#include "indcpa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntt.h"
#include "shake.h"

#define SHAKE128_RATE 168
#define GEN_MATRIX_MAX_BLOCKS 16 /* 2688 bytes; 3 blocks succeeds with overwhelming probability */

static unsigned int
rej_uniform(int16_t *r, unsigned int len, const uint8_t *buf, unsigned int buflen)
{
    unsigned int ctr = 0, pos = 0;
    while (ctr < len && pos + 3 <= buflen)
    {
        uint16_t val0 = (uint16_t)(((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF);
        uint16_t val1 = (uint16_t)(((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF);
        pos += 3;

        if (val0 < KYBER_Q)
        {
            r[ctr++] = (int16_t)val0;
        }
        if (ctr < len && val1 < KYBER_Q)
        {
            r[ctr++] = (int16_t)val1;
        }
    }
    return ctr;
}

void
kyber_gen_matrix(polyvec a[KYBER_K], const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_K; j++)
        {
            uint8_t extseed[KYBER_SYMBYTES + 2];
            memcpy(extseed, seed, KYBER_SYMBYTES);
            if (transposed)
            {
                extseed[KYBER_SYMBYTES] = (uint8_t)i;
                extseed[KYBER_SYMBYTES + 1] = (uint8_t)j;
            }
            else
            {
                extseed[KYBER_SYMBYTES] = (uint8_t)j;
                extseed[KYBER_SYMBYTES + 1] = (uint8_t)i;
            }

            /* Squeeze a growing buffer until rejection sampling yields
             * KYBER_N valid coefficients. 3 blocks (504 bytes) succeeds
             * with overwhelming probability on the first try; the loop
             * only exists for the astronomically unlikely case it
             * doesn't. Recomputing the XOF from scratch at a larger
             * output length is safe and gives the identical prefix,
             * since a XOF's output is a single fixed stream indexed by
             * length, not a fresh squeeze each call. */
            uint8_t buf[GEN_MATRIX_MAX_BLOCKS * SHAKE128_RATE];
            int16_t coeffs[KYBER_N];
            unsigned int ctr = 0;
            unsigned int blocks = 3;
            while (ctr < KYBER_N)
            {
                if (blocks > GEN_MATRIX_MAX_BLOCKS)
                {
                    fprintf(stderr, "kyber: gen_matrix rejection sampling did not converge\n");
                    abort();
                }
                unsigned int buflen = blocks * SHAKE128_RATE;
                shake128_xof(buf, buflen, extseed, sizeof(extseed));
                ctr = rej_uniform(coeffs, KYBER_N, buf, buflen);
                blocks++;
            }
            memcpy(a[i].vec[j].coeffs, coeffs, sizeof(coeffs));
        }
    }
}

static void
pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES], const polyvec *pk, const uint8_t seed[KYBER_SYMBYTES])
{
    polyvec_tobytes(r, pk);
    memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

static void
unpack_pk(polyvec *pk, uint8_t seed[KYBER_SYMBYTES], const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
    polyvec_frombytes(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

static void
pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], const polyvec *b, const poly *v)
{
    polyvec_compress(r, b);
    poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void
unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
    polyvec_decompress(b, c);
    poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

void
indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                       uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                       const uint8_t coins[KYBER_SYMBYTES])
{
    uint8_t buf[2 * KYBER_SYMBYTES];
    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = KYBER_K;
    sha3_512(buf, buf, KYBER_SYMBYTES + 1);
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;

    polyvec a[KYBER_K];
    kyber_gen_matrix(a, publicseed, 0);

    polyvec skpv, e, pkpv;
    uint8_t nonce = 0;
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    }
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    }

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    for (int i = 0; i < KYBER_K; i++)
    {
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    polyvec_tobytes(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

void
indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
           const uint8_t m[KYBER_INDCPA_MSGBYTES],
           const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
           const uint8_t coins[KYBER_SYMBYTES])
{
    uint8_t seed[KYBER_SYMBYTES];
    polyvec pkpv;
    unpack_pk(&pkpv, seed, pk);

    poly k;
    poly_frommsg(&k, m);

    polyvec at[KYBER_K];
    kyber_gen_matrix(at, seed, 1);

    polyvec sp, ep;
    poly epp;
    uint8_t nonce = 0;
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_getnoise_eta1(&sp.vec[i], coins, nonce++);
    }
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_getnoise_eta2(&ep.vec[i], coins, nonce++);
    }
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    polyvec b;
    for (int i = 0; i < KYBER_K; i++)
    {
        polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    }
    poly v;
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

    polyvec_invntt_tomont(&b);
    poly_invntt_tomont(&v);

    polyvec_add(&b, &b, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(&b);
    poly_reduce(&v);

    pack_ciphertext(c, &b, &v);
}

void
indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t c[KYBER_INDCPA_BYTES], const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
    polyvec b, skpv;
    poly v;
    unpack_ciphertext(&b, &v, c);
    polyvec_frombytes(&skpv, sk);

    polyvec_ntt(&b);
    poly mp;
    polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}
