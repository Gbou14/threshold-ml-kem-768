#include "identity.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Self-contained SHAKE-256 XOF (not shared with src/kyber/shake.c --
 * this module is deliberately independent of src/kyber/, matching how
 * wots.c has its own sha256() rather than depending on the other
 * trust implementation's code). */
static void
shake256_xof(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!md || !mctx || !EVP_DigestInit_ex2(mctx, md, NULL) || !EVP_DigestUpdate(mctx, in, inlen) ||
        !EVP_DigestFinalXOF(mctx, out, outlen))
    {
        fprintf(stderr, "tibe/identity: OpenSSL SHAKE256 XOF failed\n");
        abort();
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
}

void
identity_embed_field(field_elem* out, const wots_vk* vk, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    const int half = TIBE_D / 2;
    size_t xof_len = (size_t)half * TIBE_Q_BYTES;
    uint8_t* buf = malloc(xof_len);

    /* Retry on an all-zero result, domain-separated by a trailing
     * counter byte -- astronomically unlikely to ever fire (roughly
     * 1/q^2048 per attempt), handled rather than assumed impossible. */
    for (uint8_t attempt = 0;; attempt++)
    {
        uint8_t input[WOTS_SEEDBYTES + WOTS_VK1BYTES + 1];
        memcpy(input, vk->seed, WOTS_SEEDBYTES);
        memcpy(input + WOTS_SEEDBYTES, vk->vk1, WOTS_VK1BYTES);
        input[WOTS_SEEDBYTES + WOTS_VK1BYTES] = attempt;

        shake256_xof(buf, xof_len, input, sizeof(input));
        for (int i = 0; i < half; i++)
        {
            BN_bin2bn(buf + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES, out->c[i]);
            BN_nnmod(out->c[i], out->c[i], q, ctx);
        }
        if (!field_is_zero(out))
        {
            break;
        }
    }

    free(buf);
}

void
identity_embed(ring_elem* out, const wots_vk* vk, BN_CTX* ctx)
{
    field_elem y;
    field_init(&y);
    identity_embed_field(&y, vk, ctx);
    ring_unsplit(out, &y, &y, ctx);
    field_free(&y);
}
