#include "wots.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The paper's four hash functions (BCHK_PAPER_SPEC.md Sec 3.3):
 *
 *   f_k(x)      = SHA2-256( toByte(0,32) || k || x )
 *   PRF_seed(y) = SHA2-256( toByte(1,32) || seed || y )
 *   H_msg(m)    = SHA2-256( toByte(2,32) || m )
 *   H_key(k)    = SHA2-256( toByte(3,32) || k )
 *
 * toByte(X,32) is the standard XMSS/WOTS+ notation for "X encoded as a
 * big-endian 32-byte string" -- for the small constants 0..3 used here
 * that's just 31 zero bytes followed by the constant. PRF_seed's `y`
 * argument (the paper doesn't pin its byte-width) is encoded as a
 * 4-byte big-endian integer, a concrete choice made here (documented,
 * not specified by the paper).
 */

static void
sha256(uint8_t out[32], const uint8_t* in, size_t inlen)
{
    size_t got = 0;
    if (!EVP_Q_digest(NULL, "SHA256", NULL, in, inlen, out, &got) || got != 32)
    {
        fprintf(stderr, "tibe/wots: OpenSSL SHA256 failed\n");
        abort();
    }
}

static void
domain_prefix(uint8_t out[32], uint8_t constant)
{
    memset(out, 0, 32);
    out[31] = constant;
}

static void
f_hash(uint8_t out[WOTS_N], const uint8_t key[WOTS_N], const uint8_t x[WOTS_N])
{
    uint8_t buf[32 + WOTS_N + WOTS_N];
    domain_prefix(buf, 0);
    memcpy(buf + 32, key, WOTS_N);
    memcpy(buf + 32 + WOTS_N, x, WOTS_N);
    sha256(out, buf, sizeof(buf));
}

static void
prf_seed(uint8_t out[WOTS_N], const uint8_t seed[WOTS_SEEDBYTES], uint32_t y)
{
    uint8_t buf[32 + WOTS_SEEDBYTES + 4];
    domain_prefix(buf, 1);
    memcpy(buf + 32, seed, WOTS_SEEDBYTES);
    buf[32 + WOTS_SEEDBYTES + 0] = (uint8_t)(y >> 24);
    buf[32 + WOTS_SEEDBYTES + 1] = (uint8_t)(y >> 16);
    buf[32 + WOTS_SEEDBYTES + 2] = (uint8_t)(y >> 8);
    buf[32 + WOTS_SEEDBYTES + 3] = (uint8_t)(y);
    sha256(out, buf, sizeof(buf));
}

static void
h_msg(uint8_t out[WOTS_N], const uint8_t* m, size_t mlen)
{
    uint8_t* buf = malloc(32 + mlen);
    domain_prefix(buf, 2);
    memcpy(buf + 32, m, mlen);
    sha256(out, buf, 32 + mlen);
    free(buf);
}

static void
h_key(uint8_t out[WOTS_N], const uint8_t* concatenated_tops, size_t len)
{
    uint8_t* buf = malloc(32 + len);
    domain_prefix(buf, 3);
    memcpy(buf + 32, concatenated_tops, len);
    sha256(out, buf, 32 + len);
    free(buf);
}

/* Derive the w-1=15 (key,mask) pairs shared across all l chains,
 * deterministically from the public seed -- so Verify (which only has
 * the public vk, never sk) can reconstruct exactly the same pairs Sign
 * used. i = 1..2*(w-1): the first w-1 outputs are the bitmasks r, the
 * next w-1 are the keys k (BCHK_PAPER_SPEC.md Sec 3.3: "(r,k) <-
 * {PRF_seed(i)}_{i=1}^{2(w-1)}"). */
static void
derive_r_k(const uint8_t seed[WOTS_SEEDBYTES], uint8_t r[WOTS_W1][WOTS_N], uint8_t k[WOTS_W1][WOTS_N])
{
    for (int j = 0; j < WOTS_W1; j++)
    {
        prf_seed(r[j], seed, (uint32_t)(j + 1));
    }
    for (int j = 0; j < WOTS_W1; j++)
    {
        prf_seed(k[j], seed, (uint32_t)(WOTS_W1 + j + 1));
    }
}

/* Walk one chain from value `x` through steps [from, from+steps), i.e.
 * c^{from+steps}_k(sk_i, r) given c^{from}_k(sk_i, r) = x already. Step
 * j applies f_{k[j]}(value XOR r[j]). */
static void
chain_walk(uint8_t out[WOTS_N], const uint8_t x[WOTS_N], int from, int steps, const uint8_t r[WOTS_W1][WOTS_N],
           const uint8_t k[WOTS_W1][WOTS_N])
{
    uint8_t value[WOTS_N];
    uint8_t masked[WOTS_N];
    memcpy(value, x, WOTS_N);
    for (int s = 0; s < steps; s++)
    {
        int j = from + s;
        for (int b = 0; b < WOTS_N; b++)
        {
            masked[b] = value[b] ^ r[j][b];
        }
        f_hash(value, k[j], masked);
    }
    memcpy(out, value, WOTS_N);
}

/* The l=67 base-16 digits (b_1..b_l1 from H_msg(msg), b_{l1+1}..b_l
 * from the checksum of those digits) that select how far each of the
 * l chains gets walked. Standard WOTS+ checksum: chk = sum_i (w-1 -
 * m_i), which is large when the message digits are small and vice
 * versa -- so an adversary who wants to forge by walking any digit
 * *forward* (the only direction the one-way chain allows) would need
 * the checksum to also move forward to stay consistent, which requires
 * walking a checksum-chain forward too, which needs the corresponding
 * secret value -- exactly what a one-time signature doesn't reveal for
 * chains not touched by the real signature. */
static void
message_digits(uint8_t digits[WOTS_L], const uint8_t* msg, size_t msglen)
{
    uint8_t h[WOTS_N];
    h_msg(h, msg, msglen);

    for (int i = 0; i < WOTS_N; i++)
    {
        digits[2 * i] = h[i] >> 4;
        digits[2 * i + 1] = h[i] & 0xF;
    }

    uint32_t chk = 0;
    for (int i = 0; i < WOTS_L1; i++)
    {
        chk += (uint32_t)(WOTS_W1 - digits[i]);
    }
    digits[WOTS_L1 + 0] = (uint8_t)((chk >> 8) & 0xF);
    digits[WOTS_L1 + 1] = (uint8_t)((chk >> 4) & 0xF);
    digits[WOTS_L1 + 2] = (uint8_t)(chk & 0xF);
}

void
wots_keygen(wots_sk* sk, wots_vk* vk)
{
    if (RAND_bytes(vk->seed, WOTS_SEEDBYTES) != 1)
    {
        fprintf(stderr, "tibe/wots: RAND_bytes (seed) failed\n");
        abort();
    }
    for (int i = 0; i < WOTS_L; i++)
    {
        if (RAND_bytes(sk->sk[i], WOTS_N) != 1)
        {
            fprintf(stderr, "tibe/wots: RAND_bytes (sk) failed\n");
            abort();
        }
    }

    uint8_t r[WOTS_W1][WOTS_N];
    uint8_t k[WOTS_W1][WOTS_N];
    derive_r_k(vk->seed, r, k);

    uint8_t tops[WOTS_L][WOTS_N];
    for (int i = 0; i < WOTS_L; i++)
    {
        chain_walk(tops[i], sk->sk[i], 0, WOTS_W1, r, k);
    }
    h_key(vk->vk1, (const uint8_t*)tops, sizeof(tops));
}

void
wots_sign(uint8_t sig[WOTS_SIGBYTES], const wots_sk* sk, const wots_vk* vk, const uint8_t* msg, size_t msglen)
{
    uint8_t digits[WOTS_L];
    message_digits(digits, msg, msglen);

    uint8_t r[WOTS_W1][WOTS_N];
    uint8_t k[WOTS_W1][WOTS_N];
    derive_r_k(vk->seed, r, k);

    for (int i = 0; i < WOTS_L; i++)
    {
        chain_walk(sig + (size_t)i * WOTS_N, sk->sk[i], 0, digits[i], r, k);
    }
}

int
wots_verify(const wots_vk* vk, const uint8_t* msg, size_t msglen, const uint8_t sig[WOTS_SIGBYTES])
{
    uint8_t digits[WOTS_L];
    message_digits(digits, msg, msglen);

    uint8_t r[WOTS_W1][WOTS_N];
    uint8_t k[WOTS_W1][WOTS_N];
    derive_r_k(vk->seed, r, k);

    uint8_t tops[WOTS_L][WOTS_N];
    for (int i = 0; i < WOTS_L; i++)
    {
        int remaining = WOTS_W1 - digits[i];
        chain_walk(tops[i], sig + (size_t)i * WOTS_N, digits[i], remaining, r, k);
    }

    uint8_t vk1_check[WOTS_N];
    h_key(vk1_check, (const uint8_t*)tops, sizeof(tops));
    return memcmp(vk1_check, vk->vk1, WOTS_N) == 0;
}
