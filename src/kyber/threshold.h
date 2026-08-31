#ifndef KYBER_THRESHOLD_H
#define KYBER_THRESHOLD_H

#include <stdint.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"

/*
 * Threshold decryption for ML-KEM-768's IND-CPA PKE.
 *
 * The trick (same one the original toy-LWE prototype used, just applied
 * to real Kyber's math): indcpa_dec's core step,
 *
 *     mp = polyvec_basemul_acc_montgomery(skpv, b)
 *
 * is linear in skpv for a fixed ciphertext b. So if skpv's K*N=768
 * coefficients are each independently Shamir-shared over Z_q as
 * degree-(k-1) polynomials with the true coefficient at x=0, then each
 * shareholder's LOCAL computation of that same step on their share
 * (instead of the real skpv) produces a poly whose coefficients are
 * themselves points on degree-(k-1) polynomials passing through the
 * true mp's coefficients at x=0 -- because a linear combination of
 * degree-(k-1) polynomials is still degree (k-1). No shareholder ever
 * sees skpv, and the coordinator only ever combines already-linear
 * partial results, never skpv itself.
 */

/* Split a secret-key polyvec into n shares (x = 1..n), each of which is
 * a polyvec of the same shape, holding poly(x_i) for every one of the
 * K*KYBER_N coefficients independently. Any k of the n shares suffice
 * to reconstruct partial decryptions (see threshold_combine below);
 * fewer than k do not. */
void threshold_split_secret(const polyvec *secret, polyvec *shares_out, int k, int n);

/* Each shareholder runs this locally on their share of skpv -- exactly
 * indcpa_dec's mp computation, but on a share instead of the real key. */
void threshold_partial_decrypt(poly *partial_out, const polyvec *share, const polyvec *b);

/* Coordinator step: given k parties' partial results and their x
 * coordinates (matching the x_i used at split time, i.e. party index +
 * 1), reconstruct the true (still NTT-domain) mp polynomial via 256
 * independent Lagrange-interpolate-at-zero operations, one per
 * coefficient. Exposed mainly for testing; threshold_finish_decrypt
 * below is the function real callers should use. */
void threshold_combine(poly *mp_out, const poly *partials, const int *xs, int k);

/* Coordinator step, end to end: combine k partial decryptions and
 * finish indcpa_dec's tail (invntt, subtract from v, reduce, decode)
 * to recover the message. This mirrors indcpa_dec exactly except that
 * mp comes from Lagrange-combining shares instead of a direct
 * computation on the real secret key -- getting that tail sequence
 * exactly right (in particular, poly_invntt_tomont has to run on mp
 * *before* the subtraction) is easy to get wrong by hand, so it lives
 * here once instead of being re-derived at each call site. */
void threshold_finish_decrypt(uint8_t msg_out[KYBER_MSGBYTES],
                               const poly *partials,
                               const int *xs,
                               int k,
                               const poly *v);

/*
 * Full CCA-secure threshold Decaps, under an explicit, narrower trust
 * assumption than the PKE-level functions above: this combiner
 * momentarily reconstructs m' (the PKE-decrypted message) in order to
 * complete the Fujisaki-Okamoto re-encryption check, so it must be
 * trusted not to leak it. No shareholder's share and no party's view
 * of the private key changes -- only this one combining step is
 * weaker than a full generic-MPC threshold KEM. See
 * src/kyber/README.md for why that check can't be done any other way
 * with the tools built so far.
 *
 * z is the secret key's implicit-rejection value (not the private
 * key itself) -- the combiner needs it for the same reason any party
 * running ordinary (non-threshold) Decaps needs it: J(z, ct) is part
 * of Decaps's own logic, not something being newly exposed by
 * thresholding it.
 */
void threshold_decaps(uint8_t ss[KYBER_SSBYTES],
                       const poly *partials,
                       const int *xs,
                       int k,
                       const uint8_t ct[KYBER_CIPHERTEXTBYTES],
                       const uint8_t ek[KYBER_PUBLICKEYBYTES],
                       const uint8_t z[KYBER_SYMBYTES]);

#endif /* KYBER_THRESHOLD_H */
