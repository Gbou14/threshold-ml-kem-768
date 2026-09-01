#ifndef TIBE_TIBE_H
#define TIBE_TIBE_H

#include <openssl/bn.h>
#include <stdint.h>

#include "params.h"
#include "ring.h"

/*
 * Threshold IBE core algebra (BCHK_PAPER_SPEC.md Sec 4, Figures 4-5;
 * transcribed directly from the paper's Algorithm boxes 1-4 and 8,
 * re-verified against the paper's PDF page images directly rather than
 * the initial secondhand extraction -- see README.md "Phase 3" for the
 * one real ambiguity that re-read resolved: the encryption randomness
 * `s` is a single ring element (not 3-dimensional), forced by
 * `v := r*s + e' + Encode(msg)` needing to type-check as a scalar
 * equation.
 *
 * Phase 3 scope: non-threshold only. tibe_setup produces the full
 * master secret (s_a, e_a, d0) in one place, and tibe_decrypt_direct
 * is the single-party special case of Algorithms 5-8 (Figure 5) with
 * one "virtual party" holding the whole secret and zero blinding --
 * this validates the core algebra (F_vk, Decomp_beta, the
 * v - z^T*u correctness relation) before Phase 5 adds real
 * Shamir-sharing and the 3-round threshold protocol on top of the
 * exact same equations.
 *
 * Identity handling: `id` throughout this module is an
 * *already-embedded* identity -- a unit ring element, matching what
 * E(vk) is defined to produce (BCHK_PAPER_SPEC.md Sec 3.5). Phase 4
 * builds the real map from WOTS+ verification keys to such a unit;
 * this module's own algebra doesn't care how `id` was produced, only
 * that F_vk = [A0 | A1 - id*G | A2] uses a genuine unit.
 */

#define TIBE_MSG_BITS TIBE_D
#define TIBE_MSG_BYTES (TIBE_D / 8) /* 512 bytes for D=4096 */

/* Public parameters, Algorithm 1 line 8 ("ek := (A0,A1,A2,G,r)"). Each
 * of A0/A1/A2/G is 3 ring elements (a 1x3 row, per the paper's
 * notation); F_vk = [A0 | A1-id*G | A2] concatenates these into the
 * 1x9 row an encryption/decryption identity's ciphertext is built
 * against. */
typedef struct
{
    ring_elem A0[3];
    ring_elem A1[3];
    ring_elem A2[3];
    ring_elem G[3];
    ring_elem r;
} tibe_ek;

/* The full (non-threshold) master secret + the private setup state
 * needed to decrypt. Phase 3 scope only: d0 is not published in ek
 * (Algorithm 1 line 8 has no d0), but a party holding the raw secret
 * privately needs it for Decomp_beta(d0^-1 * ...) in Decrypt/Combine
 * (Algorithm 7 line 5). Phase 5 replaces whole possession of this
 * struct with Shamir shares of s_a/e_a distributed across
 * shareholders -- see BCHK_TODO.md.
 *
 * `a0` (Setup's other unpublished value alongside d0) is deliberately
 * NOT retained here: Phase 5 briefly added it under the assumption
 * that Algorithm 5's y_{i,0} needed raw a0 directly, but that reading
 * turned out to be a transcription slip -- the correctness algebra
 * (verified via a symbolic toy-ring check across the real multi-party
 * protocol, not just Phase 3's single-party collapse) only closes
 * when y_{i,0} = A0.p_i, a proper 3-vector dot product matching
 * y_{i,1}/y_{i,2}'s own pattern, needing only the already-public A0
 * (part of ek), not a0 itself. See src/tibe/README.md "Phase 5" and
 * threshold.c's round0 for the corrected formula. */
typedef struct
{
    ring_elem s_a;
    ring_elem e_a;
    ring_elem d0;
} tibe_msk;

/* A TIBE ciphertext, Algorithm 4 line 7: ct := (u, v). u is 9 ring
 * elements ("F_vk^T * s + e"), v is 1 ring element carrying the
 * encoded message. */
typedef struct
{
    ring_elem u[9];
    ring_elem v;
} tibe_ct;

void tibe_ek_init(tibe_ek* ek);
void tibe_ek_free(tibe_ek* ek);
void tibe_msk_init(tibe_msk* msk);
void tibe_msk_free(tibe_msk* msk);
void tibe_ct_init(tibe_ct* ct);
void tibe_ct_free(tibe_ct* ct);

/* Algorithm 2: msg (TIBE_MSG_BYTES bytes, bit i = (msg[i/8] >> (i%8))
 * & 1, LSB-first within each byte -- a concrete convention the paper's
 * abstract msg=(b_0,...,b_{d-1}) notation leaves open, documented here
 * rather than in the paper) -> a ring element with each bit scaled by
 * floor(q/2). `out` must already be ring_init'd. */
void tibe_encode(ring_elem* out, const uint8_t msg[TIBE_MSG_BYTES], BN_CTX* ctx);

/* Algorithm 3: round each coefficient to the nearer of {0, floor(q/2)}
 * and emit the corresponding bit, inverse of tibe_encode for a
 * sufficiently-low-noise input (which is exactly the correctness
 * property Theorem 5 establishes for honestly-generated ciphertexts). */
void tibe_decode(uint8_t msg_out[TIBE_MSG_BYTES], const ring_elem* m, BN_CTX* ctx);

/* Algorithm 1, non-threshold: produces ek and the full master secret
 * in one place (no Shamir-sharing -- Phase 5). `ek` and `msk` must
 * already be inited via tibe_ek_init/tibe_msk_init. */
void tibe_setup(tibe_ek* ek, tibe_msk* msk, BN_CTX* ctx);

/* Algorithm 4. `ct` must already be inited via tibe_ct_init. */
void tibe_encrypt(tibe_ct* ct, const tibe_ek* ek, const ring_elem* id, const uint8_t msg[TIBE_MSG_BYTES],
                   BN_CTX* ctx);

/* The single-party special case of Algorithms 5-8 (Figure 5): the
 * "active set" is one virtual party holding the whole unshared secret
 * directly, with zero per-shareholder blinding (p_i = x_{i,0} =
 * x_{i,1} = 0, Lagrange coefficient trivially 1) -- see README.md
 * "Phase 3" for the derivation of what that collapses Algorithms 7-8
 * down to. Runs Algorithm 8 line 7's own assertion (F_vk*z == r,
 * ||z||_inf < B) as a correctness self-check. Returns 1 and fills
 * msg_out on success, 0 if the assertion fails (which should not
 * happen for an honestly-generated ciphertext under this ek/msk/id --
 * a 0 return here during testing means a real implementation bug, not
 * expected adversarial behavior, since Phase 3 has no adversary
 * model yet). */
int tibe_decrypt_direct(uint8_t msg_out[TIBE_MSG_BYTES], const tibe_ek* ek, const tibe_msk* msk, const ring_elem* id,
                         const tibe_ct* ct, BN_CTX* ctx);

#endif /* TIBE_TIBE_H */
