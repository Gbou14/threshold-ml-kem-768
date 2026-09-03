/*
 * Self-contained regression test for the generic Merkle tree module
 * (Phase 8d groundwork -- v3s.c's commitment structure). No paper
 * pins this exactly (it's a standard, well-understood primitive, not
 * something BCHK+ or Espitau-Niot-Prest specify byte-for-byte), so
 * this validates it by internal consistency: every real leaf's proof
 * verifies against the true root, tampering with any of
 * (leaf, index, root, a sibling in the proof) makes verification
 * fail, and both non-power-of-two and exact-power-of-two leaf counts
 * work.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../merkle.h"

static int failures = 0;

#define CHECK(cond, msg)                                                                                             \
    do                                                                                                                \
    {                                                                                                                 \
        if (!(cond))                                                                                                  \
        {                                                                                                             \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);                                                    \
            failures++;                                                                                               \
        }                                                                                                             \
    } while (0)

static void
make_leaf(uint8_t out[MERKLE_HASH_BYTES], int i)
{
    memset(out, 0, MERKLE_HASH_BYTES);
    out[0] = (uint8_t)i;
    out[1] = (uint8_t)(i * 7 + 3); /* just so leaves aren't all-zero-but-one-byte */
}

static void
check_n_leaves(int n)
{
    uint8_t* leaves = malloc((size_t)n * MERKLE_HASH_BYTES);
    for (int i = 0; i < n; i++)
    {
        make_leaf(leaves + (size_t)i * MERKLE_HASH_BYTES, i);
    }

    merkle_tree t;
    merkle_build(&t, leaves, n);

    uint8_t root[MERKLE_HASH_BYTES];
    merkle_root(root, &t);

    char msg[128];
    for (int i = 0; i < n; i++)
    {
        merkle_proof proof;
        merkle_proof_generate(&proof, &t, i);
        uint8_t leaf[MERKLE_HASH_BYTES];
        make_leaf(leaf, i);

        snprintf(msg, sizeof(msg), "n=%d: leaf %d's proof verifies against the true root", n, i);
        CHECK(merkle_proof_verify(root, leaf, i, n, &proof) == 1, msg);

        /* Tampered leaf */
        uint8_t bad_leaf[MERKLE_HASH_BYTES];
        memcpy(bad_leaf, leaf, MERKLE_HASH_BYTES);
        bad_leaf[0] ^= 0xFF;
        snprintf(msg, sizeof(msg), "n=%d: leaf %d's proof rejects a tampered leaf", n, i);
        CHECK(merkle_proof_verify(root, bad_leaf, i, n, &proof) == 0, msg);

        /* Tampered root */
        uint8_t bad_root[MERKLE_HASH_BYTES];
        memcpy(bad_root, root, MERKLE_HASH_BYTES);
        bad_root[0] ^= 0xFF;
        snprintf(msg, sizeof(msg), "n=%d: leaf %d's proof rejects a tampered root", n, i);
        CHECK(merkle_proof_verify(bad_root, leaf, i, n, &proof) == 0, msg);

        if (proof.depth > 0)
        {
            merkle_proof bad_proof = proof;
            bad_proof.siblings[0][0] ^= 0xFF;
            snprintf(msg, sizeof(msg), "n=%d: leaf %d's proof rejects a tampered sibling", n, i);
            CHECK(merkle_proof_verify(root, leaf, i, n, &bad_proof) == 0, msg);
        }

        /* Wrong index (using another leaf's real proof/leaf pair at
         * this index should fail unless n==1, where there's nothing
         * else to confuse it with) */
        if (n > 1)
        {
            int other = (i + 1) % n;
            snprintf(msg, sizeof(msg), "n=%d: leaf %d's proof rejects being claimed as index %d", n, i, other);
            CHECK(merkle_proof_verify(root, leaf, other, n, &proof) == 0, msg);
        }
    }

    /* Out-of-range index */
    merkle_proof proof0;
    merkle_proof_generate(&proof0, &t, 0);
    uint8_t leaf0[MERKLE_HASH_BYTES];
    make_leaf(leaf0, 0);
    snprintf(msg, sizeof(msg), "n=%d: out-of-range index is rejected", n);
    CHECK(merkle_proof_verify(root, leaf0, n, n, &proof0) == 0, msg);
    CHECK(merkle_proof_verify(root, leaf0, -1, n, &proof0) == 0, msg);

    merkle_tree_free(&t);
    free(leaves);
}

int
main(void)
{
    check_n_leaves(1);
    check_n_leaves(2);
    check_n_leaves(3);
    check_n_leaves(10); /* TIBE_N */
    check_n_leaves(16); /* exact power of two */
    check_n_leaves(17);

    if (failures == 0)
    {
        printf("test_merkle: all tests passed\n");
        return 0;
    }
    printf("test_merkle: %d failure(s)\n", failures);
    return 1;
}
