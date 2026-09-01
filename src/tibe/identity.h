#ifndef TIBE_IDENTITY_H
#define TIBE_IDENTITY_H

#include <openssl/bn.h>

#include "ring.h"
#include "wots.h"

/*
 * The identity-embedding map E : S_vk -> R_q (BCHK_PAPER_SPEC.md Sec
 * 3.5 / the paper's Sec 4.2 "Identity Embedding"), needed so a fresh
 * WOTS+ verification key can play the role of a TIBE identity in
 * F_vk = [A0 | A1 - E(vk)*G | A2]. Built from two pieces:
 *
 *   E_F : S_vk -> F_{D/2} \ {0}       (identity_embed_field)
 *   E(vk) := f^-1(E_F(vk), E_F(vk))   (identity_embed)
 *
 * where f is ring_split/ring_unsplit's isomorphism (ring.h, Phase 4's
 * other half). Per the paper's own security requirement, E must
 * satisfy: for vk0 != vk1, E(vk0)-E(vk1) is a unit in R_q. Embedding
 * the *same* field value into both factors makes this automatic
 * whenever E_F(vk0) != E_F(vk1): f(E(vk0)-E(vk1)) = (d, d) for
 * d = E_F(vk0)-E_F(vk1), a nonzero element of BOTH factor fields (a
 * nonzero coefficient vector is nonzero in either field's
 * representation, regardless of which of the two different
 * multiplication rules is imposed on it), hence a unit by CRT. See
 * src/tibe/README.md "Phase 4" for the full derivation, including why
 * this collapses to "E(vk)'s low D/2 coefficients are E_F(vk), high
 * D/2 coefficients are 0" -- a fact this module relies on ring_unsplit
 * itself to produce, rather than special-casing.
 */

/* E_F: hash-based (SHAKE-256, domain-separated) embedding of a WOTS+
 * vk into a nonzero field_elem. `out` must already be field_init'd.
 * Collision-resistant, not a formally injective map -- see
 * README.md "Phase 4" for why that suffices here (|S_vk| = 2^512 is
 * astronomically smaller than |F_{D/2}| ~ q^2048, the space this
 * hashes into). */
void identity_embed_field(field_elem* out, const wots_vk* vk, BN_CTX* ctx);

/* E(vk) := f^-1(E_F(vk), E_F(vk)). `out` must already be ring_init'd. */
void identity_embed(ring_elem* out, const wots_vk* vk, BN_CTX* ctx);

#endif /* TIBE_IDENTITY_H */
