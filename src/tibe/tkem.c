#include "tkem.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Self-contained SHAKE-256 XOF, matching the pattern already used in
 * identity.c/threshold.c/wots.c. */
static void
shake256_xof(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!md || !mctx || !EVP_DigestInit_ex2(mctx, md, NULL) || !EVP_DigestUpdate(mctx, in, inlen) ||
        !EVP_DigestFinalXOF(mctx, out, outlen))
    {
        fprintf(stderr, "tibe/tkem: OpenSSL SHAKE256 XOF failed\n");
        abort();
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
}

static void
domain_prefix(uint8_t out[32], uint8_t constant)
{
    memset(out, 0, 32);
    out[31] = constant;
}

/* ct serialized as u[0..8] || v -- the exact bytes WOTS+ signs/
 * verifies, and part of what H_fo hashes. Caller frees. */
static uint8_t*
serialize_ct(size_t* len_out, const tibe_ct* ct)
{
    size_t ring_bytes = ring_serialized_bytes();
    size_t total = 10 * ring_bytes;
    uint8_t* buf = malloc(total);
    uint8_t* p = buf;
    for (int i = 0; i < 9; i++)
    {
        ring_serialize(p, &ct->u[i]);
        p += ring_bytes;
    }
    ring_serialize(p, &ct->v);
    *len_out = total;
    return buf;
}

/* G_fo(msg) -> TIBE_ENCRYPT_SEED_BYTES bytes, the derandomization
 * seed for TIBE.Encrypt. */
static void
g_fo(uint8_t out[TIBE_ENCRYPT_SEED_BYTES], const uint8_t msg[TIBE_MSG_BYTES])
{
    uint8_t in[32 + TIBE_MSG_BYTES];
    domain_prefix(in, 0);
    memcpy(in + 32, msg, TIBE_MSG_BYTES);
    shake256_xof(out, TIBE_ENCRYPT_SEED_BYTES, in, sizeof(in));
}

/* H_fo(msg||ct) -> TKEM_SSBYTES bytes, the final shared secret. */
static void
h_fo(uint8_t out[TKEM_SSBYTES], const uint8_t msg[TIBE_MSG_BYTES], const tibe_ct* ct)
{
    size_t ct_len;
    uint8_t* ct_bytes = serialize_ct(&ct_len, ct);
    size_t inlen = 32 + TIBE_MSG_BYTES + ct_len;
    uint8_t* in = malloc(inlen);
    domain_prefix(in, 1);
    memcpy(in + 32, msg, TIBE_MSG_BYTES);
    memcpy(in + 32 + TIBE_MSG_BYTES, ct_bytes, ct_len);
    shake256_xof(out, TKEM_SSBYTES, in, inlen);
    free(ct_bytes);
    free(in);
}

void
tkem_ct_init(tkem_ct* ct)
{
    tibe_ct_init(&ct->ct);
}

void
tkem_ct_free(tkem_ct* ct)
{
    tibe_ct_free(&ct->ct);
}

void
tkem_keygen(tibe_ek* ek, tibe_msk* msk, BN_CTX* ctx)
{
    tibe_setup(ek, msk, ctx);
}

void
tkem_encaps_derand(tkem_ct* ct, uint8_t ss[TKEM_SSBYTES], const tibe_ek* ek, const uint8_t msg[TIBE_MSG_BYTES],
                    BN_CTX* ctx)
{
    uint8_t rand_seed[TIBE_ENCRYPT_SEED_BYTES];
    g_fo(rand_seed, msg);

    wots_sk sk;
    wots_keygen(&sk, &ct->vk); /* fresh keypair every call -- WOTS+ is one-time, see tkem.h */

    ring_elem id;
    ring_init(&id);
    identity_embed(&id, &ct->vk, ctx);

    tibe_encrypt_derand(&ct->ct, ek, &id, msg, rand_seed, ctx);

    size_t ct_len;
    uint8_t* ct_bytes = serialize_ct(&ct_len, &ct->ct);
    wots_sign(ct->sig, &sk, &ct->vk, ct_bytes, ct_len);
    free(ct_bytes);

    h_fo(ss, msg, &ct->ct);

    ring_free(&id);
}

void
tkem_encaps(tkem_ct* ct, uint8_t ss[TKEM_SSBYTES], const tibe_ek* ek, BN_CTX* ctx)
{
    uint8_t msg[TIBE_MSG_BYTES];
    if (RAND_bytes(msg, sizeof(msg)) != 1)
    {
        fprintf(stderr, "tibe/tkem: RAND_bytes (msg) failed\n");
        abort();
    }
    tkem_encaps_derand(ct, ss, ek, msg, ctx);
}

int
tkem_verify_ct(const tkem_ct* ct)
{
    size_t ct_len;
    uint8_t* ct_bytes = serialize_ct(&ct_len, &ct->ct);
    int ok = wots_verify(&ct->vk, ct_bytes, ct_len, ct->sig);
    free(ct_bytes);
    return ok;
}

int
tkem_share_decaps_0(uint8_t cmt_out[TIBE_CMT_BYTES], threshold_round0_state* state, const tkem_ct* ct,
                     const tibe_ek* ek, BN_CTX* ctx)
{
    if (!tkem_verify_ct(ct))
    {
        return 0;
    }
    ring_elem id;
    ring_init(&id);
    identity_embed(&id, &ct->vk, ctx);
    threshold_round0(cmt_out, state, ek, &id, ctx);
    ring_free(&id);
    return 1;
}

int
tkem_share_decaps_1(ring_elem* w_out, const threshold_round0_state* state, const tkem_ct* ct)
{
    if (!tkem_verify_ct(ct))
    {
        return 0;
    }
    threshold_round1(w_out, state);
    return 1;
}

int
tkem_share_decaps_2(threshold_contrib2* out, const threshold_round0_state* state, const threshold_share* my_share,
                     const tkem_ct* ct, const tibe_ek* ek, const int* act_x, int act_size, int my_index,
                     const uint8_t (*cmts)[TIBE_CMT_BYTES], const ring_elem* ws, BN_CTX* ctx)
{
    if (!tkem_verify_ct(ct))
    {
        return 0;
    }
    return threshold_round2(out, state, my_share, ek, &ct->ct, act_x, act_size, my_index, cmts, ws, ctx);
}

int
tkem_combine(uint8_t ss_out[TKEM_SSBYTES], const tibe_ek* ek, const ring_elem* d0, const tkem_ct* ct,
             const int* act_x, int act_size, const ring_elem* ws, const threshold_contrib2* contribs, BN_CTX* ctx)
{
    if (!tkem_verify_ct(ct))
    {
        return 0;
    }

    ring_elem id;
    ring_init(&id);
    identity_embed(&id, &ct->vk, ctx);

    uint8_t msg[TIBE_MSG_BYTES];
    int combine_ok = threshold_combine(msg, ek, &id, &ct->ct, d0, act_x, act_size, ws, contribs, ctx);
    if (!combine_ok)
    {
        ring_free(&id);
        return 0;
    }

    /* FO-style decapsulation-consistency check: re-derive the same
     * randomness from the now-public msg and confirm re-encrypting
     * reproduces the exact ciphertext -- see tkem.h's header comment
     * for why this is safe to run here rather than needing to be
     * thresholdized. */
    uint8_t rand_seed[TIBE_ENCRYPT_SEED_BYTES];
    g_fo(rand_seed, msg);

    tibe_ct recomputed;
    tibe_ct_init(&recomputed);
    tibe_encrypt_derand(&recomputed, ek, &id, msg, rand_seed, ctx);
    int fo_ok = tibe_ct_eq(&recomputed, &ct->ct);
    tibe_ct_free(&recomputed);
    ring_free(&id);

    if (!fo_ok)
    {
        return 0;
    }

    h_fo(ss_out, msg, &ct->ct);
    return 1;
}
