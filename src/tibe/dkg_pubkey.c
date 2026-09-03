#include "dkg_pubkey.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ring.h" /* ring_modulus() */

/* Self-contained SHAKE-256 XOF, matching the pattern already used
 * throughout this module. */
static void
shake256_xof(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!md || !mctx || !EVP_DigestInit_ex2(mctx, md, NULL) || !EVP_DigestUpdate(mctx, in, inlen) ||
        !EVP_DigestFinalXOF(mctx, out, outlen))
    {
        fprintf(stderr, "tibe/dkg_pubkey: OpenSSL SHAKE256 XOF failed\n");
        abort();
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
}

static void
compute_commit(uint8_t out[DKG_PUBKEY_CMT_BYTES], const ring_elem* a0_contrib, const ring_elem* d0_contrib,
                const uint8_t nonce[DKG_PUBKEY_NONCE_BYTES])
{
    size_t rb = ring_serialized_bytes();
    size_t total = 1 + 2 * rb + DKG_PUBKEY_NONCE_BYTES;
    uint8_t* buf = malloc(total);
    buf[0] = 0x03; /* domain byte, distinct from threshold.c's (0,1,2) and v3s.c's (2) conventions */
    ring_serialize(buf + 1, a0_contrib);
    ring_serialize(buf + 1 + rb, d0_contrib);
    memcpy(buf + 1 + 2 * rb, nonce, DKG_PUBKEY_NONCE_BYTES);
    shake256_xof(out, DKG_PUBKEY_CMT_BYTES, buf, total);
    free(buf);
}

void
dkg_pubkey_round1_init(dkg_pubkey_round1_state* s)
{
    ring_init(&s->a0_contrib);
    ring_init(&s->d0_contrib);
    for (int j = 0; j < TIBE_N; j++)
    {
        ring_init(&s->mask_to[j]);
    }
}

void
dkg_pubkey_round1_free(dkg_pubkey_round1_state* s)
{
    ring_free(&s->a0_contrib);
    ring_free(&s->d0_contrib);
    for (int j = 0; j < TIBE_N; j++)
    {
        ring_free(&s->mask_to[j]);
    }
}

void
dkg_pubkey_round1(dkg_pubkey_round1_state* s, int my_index, uint8_t cmt_out[DKG_PUBKEY_CMT_BYTES], BN_CTX* ctx)
{
    ring_random_uniform(&s->a0_contrib, ctx);
    ring_random_uniform(&s->d0_contrib, ctx);
    RAND_bytes(s->nonce, DKG_PUBKEY_NONCE_BYTES);
    for (int j = my_index + 1; j < TIBE_N; j++)
    {
        ring_random_uniform(&s->mask_to[j], ctx);
    }
    compute_commit(cmt_out, &s->a0_contrib, &s->d0_contrib, s->nonce);
}

int
dkg_pubkey_verify_commit(const uint8_t cmt[DKG_PUBKEY_CMT_BYTES], const ring_elem* a0_j, const ring_elem* d0_j,
                          const uint8_t nonce_j[DKG_PUBKEY_NONCE_BYTES])
{
    uint8_t recomputed[DKG_PUBKEY_CMT_BYTES];
    compute_commit(recomputed, a0_j, d0_j, nonce_j);
    return memcmp(recomputed, cmt, DKG_PUBKEY_CMT_BYTES) == 0;
}

void
dkg_pubkey_finalize_a0_d0(ring_elem* out_a0, ring_elem* out_d0, const int valid[TIBE_N],
                           ring_elem* const a0_contribs[TIBE_N], ring_elem* const d0_contribs[TIBE_N], BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    ring_zero(out_a0);
    ring_zero(out_d0);
    for (int j = 0; j < TIBE_N; j++)
    {
        if (!valid[j])
        {
            continue;
        }
        for (int c = 0; c < TIBE_D; c++)
        {
            BN_mod_add(out_a0->coeffs[c], out_a0->coeffs[c], a0_contribs[j]->coeffs[c], q, ctx);
        }
        for (int c = 0; c < TIBE_D; c++)
        {
            BN_mod_add(out_d0->coeffs[c], out_d0->coeffs[c], d0_contribs[j]->coeffs[c], q, ctx);
        }
    }
}

void
dkg_pubkey_b0_contribution(ring_elem* out, int my_index, const int valid[TIBE_N], const v3s_secret* my_x,
                            const ring_elem* a0, const ring_elem mask_to[TIBE_N],
                            ring_elem* const received_masks[TIBE_N], BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();

    /* b0_i = a0*s_a^(i) + e_a^(i), s_a^(i)/e_a^(i) = my_x's first/
     * second TIBE_D coefficients (same flattening convention as
     * v3s.h/dkg.c). */
    ring_elem s_a_i, e_a_i, tmp;
    ring_init(&s_a_i);
    ring_init(&e_a_i);
    ring_init(&tmp);
    for (int c = 0; c < TIBE_D; c++)
    {
        int64_t v = my_x->coeffs[c];
        uint64_t mag = (uint64_t)(v < 0 ? -v : v);
        BN_set_word(tmp.coeffs[c], mag);
        if (v < 0)
        {
            BN_set_negative(tmp.coeffs[c], 1);
        }
        BN_nnmod(s_a_i.coeffs[c], tmp.coeffs[c], q, ctx);
    }
    for (int c = 0; c < TIBE_D; c++)
    {
        int64_t v = my_x->coeffs[TIBE_D + c];
        uint64_t mag = (uint64_t)(v < 0 ? -v : v);
        BN_set_word(tmp.coeffs[c], mag);
        if (v < 0)
        {
            BN_set_negative(tmp.coeffs[c], 1);
        }
        BN_nnmod(e_a_i.coeffs[c], tmp.coeffs[c], q, ctx);
    }

    ring_mul(out, a0, &s_a_i, ctx);
    ring_add(out, out, &e_a_i, ctx);

    for (int j = 0; j < TIBE_N; j++)
    {
        if (j == my_index || !valid[j])
        {
            continue;
        }
        if (j > my_index)
        {
            ring_add(out, out, &mask_to[j], ctx);
        }
        else
        {
            ring_sub(out, out, received_masks[j], ctx);
        }
    }

    ring_free(&s_a_i);
    ring_free(&e_a_i);
    ring_free(&tmp);
}

void
dkg_pubkey_finalize_b0(ring_elem* out_b0, const int valid[TIBE_N], ring_elem* const b0_contribs[TIBE_N], BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    ring_zero(out_b0);
    for (int j = 0; j < TIBE_N; j++)
    {
        if (!valid[j])
        {
            continue;
        }
        for (int c = 0; c < TIBE_D; c++)
        {
            BN_mod_add(out_b0->coeffs[c], out_b0->coeffs[c], b0_contribs[j]->coeffs[c], q, ctx);
        }
    }

    ring_elem beta_elem;
    ring_init(&beta_elem);
    BIGNUM* beta_bn = BN_new();
    BN_lshift(beta_bn, BN_value_one(), TIBE_BETA_LOG2);
    BN_nnmod(beta_bn, beta_bn, q, ctx);
    BN_copy(beta_elem.coeffs[0], beta_bn);
    BN_free(beta_bn);
    ring_sub(out_b0, out_b0, &beta_elem, ctx);
    ring_free(&beta_elem);
}
