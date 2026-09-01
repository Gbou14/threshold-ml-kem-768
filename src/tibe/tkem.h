#ifndef TIBE_TKEM_H
#define TIBE_TKEM_H

#include <openssl/bn.h>
#include <stdint.h>

#include "identity.h"
#include "params.h"
#include "threshold.h"
#include "tibe.h"
#include "wots.h"

/*
 * The BCHK+ TKEM layer (BCHK_PAPER_SPEC.md Sec 4.6, Figure 3),
 * binding a fresh WOTS+ one-time signature to each TIBE ciphertext so
 * that ciphertext validity becomes a public check every shareholder
 * runs independently (see src/tibe/README.md "The actual trust-model
 * delta" -- this is the whole point of BCHK over plain FO), plus the
 * FO-style decapsulation-consistency check on the now-public message.
 *
 * TKEM.Keygen == TIBE.Setup (tkem_keygen is a thin wrapper for
 * naming parity with the paper). TKEM.Encaps generates a fresh WOTS+
 * keypair per call and signs the ciphertext with it; the one-time
 * signature is a genuine one-time signature (wots.h), so this reuse
 * pattern -- fresh keypair every Encaps, never reused -- is not
 * optional. TKEM.ShareDecaps_j/Combine each run the SIG.Verify check
 * (`tkem_verify_ct`) *before* doing any TIBE-layer work, wrapping
 * threshold_round0/1/2/combine (threshold.h) rather than
 * reimplementing them.
 */

#define TKEM_SSBYTES 32 /* the final shared secret K's size */

typedef struct
{
    tibe_ct ct;
    wots_vk vk;
    uint8_t sig[WOTS_SIGBYTES];
} tkem_ct;

void tkem_ct_init(tkem_ct* ct);
void tkem_ct_free(tkem_ct* ct);

/* TKEM.Keygen == TIBE.Setup. `ek`/`msk` must already be inited via
 * tibe_ek_init/tibe_msk_init. */
void tkem_keygen(tibe_ek* ek, tibe_msk* msk, BN_CTX* ctx);

/* TKEM.Encaps, explicit-message form: fresh WOTS+ keypair, TIBE.Encrypt
 * derandomized via rand=G_fo(msg), sign, K=H_fo(msg||ct). Needed by
 * tkem_combine's own re-encryption check (which must reproduce a
 * ciphertext for a *specific*, already-recovered msg, not a random
 * one) and useful for deterministic testing. `ct` must already be
 * inited via tkem_ct_init. */
void tkem_encaps_derand(tkem_ct* ct, uint8_t ss[TKEM_SSBYTES], const tibe_ek* ek, const uint8_t msg[TIBE_MSG_BYTES],
                         BN_CTX* ctx);

/* TKEM.Encaps: tkem_encaps_derand with a fresh random msg. `ct` must
 * already be inited via tkem_ct_init. */
void tkem_encaps(tkem_ct* ct, uint8_t ss[TKEM_SSBYTES], const tibe_ek* ek, BN_CTX* ctx);

/* The BCHK check every ShareDecaps_j/Combine call runs first --
 * SIG.Verify((vk,ct,sig)), a check on entirely public values needing
 * no secret material. Exposed standalone since threshold_round0/1/2/
 * combine (threshold.h) don't know about vk/sig at all; every
 * tkem_share_decaps_0/1/2 and tkem_combine call below run this
 * internally, so callers don't normally need to call it directly
 * except to reject an obviously-invalid ciphertext before starting
 * the protocol. */
int tkem_verify_ct(const tkem_ct* ct);

/* TKEM.ShareDecaps_0/1/2: tkem_verify_ct, then threshold_round0/1/2.
 * Return 0 if verification fails (before any TIBE-layer work runs) or
 * -- round 2 only -- if threshold_round2 itself returns 0 (a caught
 * liar in the commit-then-reveal check, a different, later failure
 * mode from ciphertext-validity failure). */
int tkem_share_decaps_0(uint8_t cmt_out[TIBE_CMT_BYTES], threshold_round0_state* state, const tkem_ct* ct,
                         const tibe_ek* ek, BN_CTX* ctx);
int tkem_share_decaps_1(ring_elem* w_out, const threshold_round0_state* state, const tkem_ct* ct);
int tkem_share_decaps_2(threshold_contrib2* out, const threshold_round0_state* state, const threshold_share* my_share,
                         const tkem_ct* ct, const tibe_ek* ek, const int* act_x, int act_size, int my_index,
                         const uint8_t (*cmts)[TIBE_CMT_BYTES], const ring_elem* ws, BN_CTX* ctx);

/* TKEM.Combine: tkem_verify_ct, TIBE.Combine (recovers msg via
 * threshold_combine), rand=G_fo(msg), assert
 * ct==TIBE.Encrypt(ek,vk,msg;rand) (the FO-style decapsulation-
 * consistency check -- safe to run on msg here because it's already
 * public/non-sensitive by this point, see src/tibe/README.md "The
 * actual trust-model delta"), K=H_fo(msg||ct). Returns 1 and fills
 * ss_out on success, 0 on any failure (verify, threshold_combine's
 * own F_vk*z==r assertion, or the re-encryption check). */
int tkem_combine(uint8_t ss_out[TKEM_SSBYTES], const tibe_ek* ek, const ring_elem* d0, const tkem_ct* ct,
                  const int* act_x, int act_size, const ring_elem* ws, const threshold_contrib2* contribs,
                  BN_CTX* ctx);

#endif /* TIBE_TKEM_H */
