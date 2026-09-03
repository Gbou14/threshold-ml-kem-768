#include "merkle.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Self-contained SHAKE-256 XOF, matching the pattern already used in
 * identity.c/wots.c/threshold.c (each file owns its own small hash
 * wrapper rather than sharing one). */
static void
shake256_xof(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!md || !mctx || !EVP_DigestInit_ex2(mctx, md, NULL) || !EVP_DigestUpdate(mctx, in, inlen) ||
        !EVP_DigestFinalXOF(mctx, out, outlen))
    {
        fprintf(stderr, "tibe/merkle: OpenSSL SHAKE256 XOF failed\n");
        abort();
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
}

static void
hash_node(uint8_t out[MERKLE_HASH_BYTES], const uint8_t left[MERKLE_HASH_BYTES], const uint8_t right[MERKLE_HASH_BYTES])
{
    uint8_t buf[1 + 2 * MERKLE_HASH_BYTES];
    buf[0] = 0x01; /* domain-separates internal nodes from leaves */
    memcpy(buf + 1, left, MERKLE_HASH_BYTES);
    memcpy(buf + 1 + MERKLE_HASH_BYTES, right, MERKLE_HASH_BYTES);
    shake256_xof(out, MERKLE_HASH_BYTES, buf, sizeof(buf));
}

/* Fixed, public, deterministic padding leaf -- every party derives
 * the same value, so co-path proofs work identically whether a "far"
 * sibling is a real leaf or padding. */
static void
padding_leaf(uint8_t out[MERKLE_HASH_BYTES])
{
    uint8_t domain = 0x00;
    shake256_xof(out, MERKLE_HASH_BYTES, &domain, 1);
}

static int
next_pow2(int n)
{
    int p = 1;
    while (p < n)
    {
        p <<= 1;
    }
    return p;
}

static int
ilog2(int p)
{
    int d = 0;
    while (p > 1)
    {
        p >>= 1;
        d++;
    }
    return d;
}

void
merkle_build(merkle_tree* t, const uint8_t* leaves, int n_leaves)
{
    t->n_leaves = n_leaves;
    t->n_padded = next_pow2(n_leaves);
    t->depth = ilog2(t->n_padded);
    t->levels = malloc(sizeof(uint8_t*) * (size_t)(t->depth + 1));

    t->levels[0] = malloc((size_t)t->n_padded * MERKLE_HASH_BYTES);
    memcpy(t->levels[0], leaves, (size_t)n_leaves * MERKLE_HASH_BYTES);
    uint8_t pad[MERKLE_HASH_BYTES];
    padding_leaf(pad);
    for (int i = n_leaves; i < t->n_padded; i++)
    {
        memcpy(t->levels[0] + (size_t)i * MERKLE_HASH_BYTES, pad, MERKLE_HASH_BYTES);
    }

    for (int lvl = 1; lvl <= t->depth; lvl++)
    {
        int count = t->n_padded >> lvl;
        t->levels[lvl] = malloc((size_t)count * MERKLE_HASH_BYTES);
        for (int i = 0; i < count; i++)
        {
            hash_node(t->levels[lvl] + (size_t)i * MERKLE_HASH_BYTES, t->levels[lvl - 1] + (size_t)(2 * i) * MERKLE_HASH_BYTES,
                      t->levels[lvl - 1] + (size_t)(2 * i + 1) * MERKLE_HASH_BYTES);
        }
    }
}

void
merkle_tree_free(merkle_tree* t)
{
    for (int lvl = 0; lvl <= t->depth; lvl++)
    {
        free(t->levels[lvl]);
    }
    free(t->levels);
    t->levels = NULL;
}

void
merkle_root(uint8_t out[MERKLE_HASH_BYTES], const merkle_tree* t)
{
    memcpy(out, t->levels[t->depth], MERKLE_HASH_BYTES);
}

void
merkle_proof_generate(merkle_proof* proof, const merkle_tree* t, int leaf_index)
{
    proof->depth = t->depth;
    int idx = leaf_index;
    for (int lvl = 0; lvl < t->depth; lvl++)
    {
        int sibling_idx = (idx % 2 == 0) ? idx + 1 : idx - 1;
        memcpy(proof->siblings[lvl], t->levels[lvl] + (size_t)sibling_idx * MERKLE_HASH_BYTES, MERKLE_HASH_BYTES);
        idx /= 2;
    }
}

int
merkle_proof_verify(const uint8_t root[MERKLE_HASH_BYTES], const uint8_t leaf[MERKLE_HASH_BYTES], int leaf_index,
                     int n_leaves, const merkle_proof* proof)
{
    if (leaf_index < 0 || leaf_index >= n_leaves)
    {
        return 0;
    }
    uint8_t cur[MERKLE_HASH_BYTES];
    memcpy(cur, leaf, MERKLE_HASH_BYTES);
    int idx = leaf_index;
    for (int lvl = 0; lvl < proof->depth; lvl++)
    {
        uint8_t combined[MERKLE_HASH_BYTES];
        if (idx % 2 == 0)
        {
            hash_node(combined, cur, proof->siblings[lvl]);
        }
        else
        {
            hash_node(combined, proof->siblings[lvl], cur);
        }
        memcpy(cur, combined, MERKLE_HASH_BYTES);
        idx /= 2;
    }
    return memcmp(cur, root, MERKLE_HASH_BYTES) == 0;
}

void
merkle_proof_serialize(uint8_t out[MERKLE_PROOF_SERIALIZED_BYTES], const merkle_proof* proof)
{
    out[0] = (uint8_t)proof->depth;
    memset(out + 1, 0, MERKLE_MAX_DEPTH * MERKLE_HASH_BYTES);
    for (int lvl = 0; lvl < proof->depth; lvl++)
    {
        memcpy(out + 1 + (size_t)lvl * MERKLE_HASH_BYTES, proof->siblings[lvl], MERKLE_HASH_BYTES);
    }
}

void
merkle_proof_deserialize(merkle_proof* proof, const uint8_t in[MERKLE_PROOF_SERIALIZED_BYTES])
{
    proof->depth = in[0];
    for (int lvl = 0; lvl < proof->depth; lvl++)
    {
        memcpy(proof->siblings[lvl], in + 1 + (size_t)lvl * MERKLE_HASH_BYTES, MERKLE_HASH_BYTES);
    }
}
