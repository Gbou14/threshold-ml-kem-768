#ifndef TIBE_WOTS_H
#define TIBE_WOTS_H

#include <stddef.h>
#include <stdint.h>

/*
 * WOTS+ (Hulsing, Africacrypt 2013), instantiated exactly as
 * BCHK_PAPER_SPEC.md Sec 3.3 / Theorem 6 pins it: n=256 bits (32
 * bytes), Winternitz parameter w=16, hash functions f/PRF/H_msg/H_key
 * all SHA2-256 with a one-byte-repeated-32-times domain-separation
 * prefix (toByte(0..3, 32)). This is the one-time signature the BCHK+
 * transform binds to each fresh TIBE ciphertext (see
 * BCHK_PAPER_SPEC.md Sec 3.4) -- not a threshold primitive itself: one
 * party (whoever runs Encaps) generates a fresh keypair and signs,
 * every shareholder just verifies (a public-value check, per BCHK).
 *
 * Parameter derivation (RFC 8391's standard WOTS+ formula, n=32
 * bytes, w=16): l1 = ceil(n*8 / log2(w)) = 64, l2 = floor(log2(l1*(w-1))
 * / log2(w)) + 1 = 3, l = l1+l2 = 67. Signature length l*n = 2144
 * bytes, matching the paper's stated figure exactly.
 */

#define WOTS_N 32   /* hash output size, bytes (n=256 bits) */
#define WOTS_W 16   /* Winternitz parameter */
#define WOTS_W1 (WOTS_W - 1) /* number of chain steps / (key,mask) pairs per chain: 15 */
#define WOTS_L1 64  /* base-w digits needed to represent an n-byte message */
#define WOTS_L2 3   /* base-w digits needed for the checksum */
#define WOTS_L (WOTS_L1 + WOTS_L2) /* 67: number of parallel hash chains */

#define WOTS_SEEDBYTES 32 /* 2*kappa, kappa=128 */
#define WOTS_SIGBYTES (WOTS_L * WOTS_N)               /* 2144 */
#define WOTS_SKBYTES (WOTS_L * WOTS_N)                /* 2144 */
#define WOTS_VK1BYTES WOTS_N                          /* 32 */

typedef struct
{
    uint8_t sk[WOTS_L][WOTS_N];
} wots_sk;

typedef struct
{
    uint8_t seed[WOTS_SEEDBYTES]; /* public: also doubles as the per-call randomness for r/k derivation */
    uint8_t vk1[WOTS_VK1BYTES];   /* public: H_key-compressed top-of-chain values */
} wots_vk;

/* Fresh keypair: sk <- random, seed <- random, vk1 computed by walking
 * every chain to the top and compressing with H_key. Uses OpenSSL
 * RAND_bytes (same RNG source as the rest of this project). */
void wots_keygen(wots_sk* sk, wots_vk* vk);

/* Sign an arbitrary-length message: sig[i] = the i-th chain walked to
 * position b_i, where (b_1..b_l1) are msg's H_msg digest's base-16
 * digits and (b_{l1+1}..b_l) are the checksum's base-16 digits (WOTS+'s
 * standard forgery-prevention checksum -- flipping any signed digit
 * upward, which is easy since chain steps only go one direction, is
 * caught because it would require flipping the checksum digits
 * downward, which needs the missing chain steps in the other
 * direction). This is a ONE-TIME signature scheme: signing twice with
 * the same sk leaks enough chain values to forge -- see
 * BCHK_PAPER_SPEC.md Sec 3.4 ("a fresh (sk,vk) pair per Encaps call"). */
void wots_sign(uint8_t sig[WOTS_SIGBYTES], const wots_sk* sk, const wots_vk* vk, const uint8_t* msg, size_t msglen);

/* Recompute each chain's top value from sig[i] (walking the remaining
 * w-1-b_i steps) and check the H_key-compression matches vk->vk1.
 * Returns 1 if valid, 0 otherwise. */
int wots_verify(const wots_vk* vk, const uint8_t* msg, size_t msglen, const uint8_t sig[WOTS_SIGBYTES]);

#endif /* TIBE_WOTS_H */
