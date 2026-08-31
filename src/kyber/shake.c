#include "shake.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

static void
xof(const char *alg, uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    EVP_MD *md = EVP_MD_fetch(NULL, alg, NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!md || !ctx || !EVP_DigestInit_ex2(ctx, md, NULL) || !EVP_DigestUpdate(ctx, in, inlen) ||
        !EVP_DigestFinalXOF(ctx, out, outlen))
    {
        fprintf(stderr, "kyber: OpenSSL %s XOF failed\n", alg);
        abort();
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
}

void
shake128_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    xof("SHAKE128", out, outlen, in, inlen);
}

void
shake256_xof(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    xof("SHAKE256", out, outlen, in, inlen);
}

void
kyber_prf(uint8_t *out, size_t outlen, const uint8_t seed[32], uint8_t nonce)
{
    uint8_t in[33];
    for (int i = 0; i < 32; i++)
    {
        in[i] = seed[i];
    }
    in[32] = nonce;
    shake256_xof(out, outlen, in, sizeof(in));
}

static void
fixed_digest(const char *alg, uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    size_t got = 0;
    if (!EVP_Q_digest(NULL, alg, NULL, in, inlen, out, &got) || got != outlen)
    {
        fprintf(stderr, "kyber: OpenSSL %s failed\n", alg);
        abort();
    }
}

void
sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    fixed_digest("SHA3-256", out, 32, in, inlen);
}

void
sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    fixed_digest("SHA3-512", out, 64, in, inlen);
}
