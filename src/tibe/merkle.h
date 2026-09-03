#ifndef TIBE_MERKLE_H
#define TIBE_MERKLE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Generic Merkle tree over pre-hashed 32-byte leaves, used by v3s.c
 * (Phase 8d) so V3S.Share can commit to all TIBE_N parties' (share,
 * blinding-share, nonce) leaves with one root, and each party can get
 * an O(log N) inclusion proof instead of the dealer broadcasting every
 * other party's raw share data. Not TIBE-specific -- callers own leaf
 * hashing (their own domain separation), this module only owns
 * combining pairs into parents and generating/verifying inclusion
 * proofs.
 *
 * Internal-node hashing is domain-separated from leaf hashing (a
 * single 0x01 prefix byte before left||right) specifically so a
 * second-preimage attacker can't present an internal node's hash as
 * if it were a leaf, or vice versa -- the classic Merkle-tree pitfall
 * (RFC 6962 uses the same style of leaf/node domain separation).
 *
 * Non-power-of-two leaf counts are padded up to the next power of two
 * with a fixed, public, deterministic padding leaf (MERKLE_PAD_LEAF,
 * itself just a domain-separated hash of nothing) -- every party
 * computes the same padding value, so proofs for real leaves work
 * identically whether the tree's "far" siblings are real leaves or
 * padding.
 */

#define MERKLE_HASH_BYTES 32
#define MERKLE_MAX_DEPTH 8 /* supports up to 2^8 = 256 leaves -- far beyond any TIBE_N this project uses */

typedef struct
{
    int n_leaves;                       /* actual (unpadded) leaf count */
    int n_padded;                       /* next power of two >= n_leaves */
    int depth;                          /* log2(n_padded) */
    uint8_t** levels;                   /* levels[0] = leaves (n_padded of them), levels[depth] = {root} */
} merkle_tree;

typedef struct
{
    uint8_t siblings[MERKLE_MAX_DEPTH][MERKLE_HASH_BYTES];
    int depth;
} merkle_proof;

/* Builds a tree over `n_leaves` pre-hashed 32-byte leaves (`leaves` is
 * a flat array of n_leaves*MERKLE_HASH_BYTES bytes). `t` must be
 * zero-initialized (or freshly declared) before calling; caller must
 * merkle_tree_free when done. */
void merkle_build(merkle_tree* t, const uint8_t* leaves, int n_leaves);
void merkle_tree_free(merkle_tree* t);

/* out := the tree's root. */
void merkle_root(uint8_t out[MERKLE_HASH_BYTES], const merkle_tree* t);

/* Generates the co-path proof for leaf index `leaf_index` (0-indexed,
 * must be < t->n_leaves). */
void merkle_proof_generate(merkle_proof* proof, const merkle_tree* t, int leaf_index);

/* Verifies that `leaf` (a pre-hashed 32-byte value) is leaf index
 * `leaf_index` of a tree with `n_leaves` real leaves and the given
 * `root`, using `proof`. Returns 1 if valid, 0 otherwise. Recomputes
 * the padding internally from `n_leaves` -- does not need the full
 * tree, only the root and the proof, matching what a non-dealer party
 * actually has. */
int merkle_proof_verify(const uint8_t root[MERKLE_HASH_BYTES], const uint8_t leaf[MERKLE_HASH_BYTES], int leaf_index,
                         int n_leaves, const merkle_proof* proof);

#endif /* TIBE_MERKLE_H */
