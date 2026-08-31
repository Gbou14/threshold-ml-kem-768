/*
 * Regression test for threshold (Shamir-shared) decryption of the
 * ML-KEM-768 IND-CPA PKE. No external reference exists for this part
 * (there's no public "threshold Kyber" implementation to diff against)
 * -- validation here is internal consistency: any k-of-n share subset
 * recovers the message without ever reconstructing the secret key, and
 * a below-threshold subset does not.
 */
#include <stdio.h>
#include <string.h>

#include "../indcpa.h"
#include "../threshold.h"
#include "test_vectors.h"

#define N_PARTIES 5
#define THRESHOLD 3

static int failures = 0;

#define CHECK(cond, msg)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);                                                     \
            failures++;                                                                                                \
        }                                                                                                              \
    } while (0)

/* Ciphertext layout is polyvec_compress(b) || poly_compress(v); see
 * indcpa.c's pack_ciphertext. indcpa_dec does this unpacking
 * internally and isn't reusable piecemeal, so we redo the (public)
 * decompress + NTT step here to get at b in the form
 * threshold_partial_decrypt needs. */
static void
unpack_ciphertext_ntt(polyvec *b_ntt, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
    polyvec_decompress(b_ntt, c);
    poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
    polyvec_ntt(b_ntt);
}

/* Reconstruct the message using exactly the k shares named in
 * party_indices (0-based, into an N_PARTIES-sized shares array). */
static void
threshold_decrypt_subset(uint8_t msg_out[32],
                          const polyvec shares[N_PARTIES],
                          const int *party_indices,
                          int k,
                          const uint8_t c[KYBER_INDCPA_BYTES])
{
    polyvec b_ntt;
    poly v;
    unpack_ciphertext_ntt(&b_ntt, &v, c);

    poly partials[THRESHOLD];
    int xs[THRESHOLD];
    for (int i = 0; i < k; i++)
    {
        threshold_partial_decrypt(&partials[i], &shares[party_indices[i]], &b_ntt);
        xs[i] = party_indices[i] + 1;
    }

    threshold_finish_decrypt(msg_out, partials, xs, k, &v);
}

static void
test_any_k_subset_recovers_message(void)
{
    uint8_t keygen_coins[32], enc_coins[32];
    fill_lcg_bytes32(keygen_coins, 42);
    fill_lcg_bytes32(enc_coins, 43);

    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
    indcpa_keypair_derand(pk, sk, keygen_coins);

    polyvec skpv;
    polyvec_frombytes(&skpv, sk);

    polyvec shares[N_PARTIES];
    threshold_split_secret(&skpv, shares, THRESHOLD, N_PARTIES);

    uint8_t c[KYBER_INDCPA_BYTES];
    indcpa_enc(c, test_msg, pk, enc_coins);

    /* Sanity: the ordinary (non-threshold) path still decrypts fine
     * with the un-split secret key. */
    uint8_t direct[32];
    indcpa_dec(direct, c, sk);
    CHECK(memcmp(direct, test_msg, 32) == 0, "ordinary indcpa_dec still recovers the message");

    int subsets[][THRESHOLD] = {
        {0, 1, 2},
        {0, 1, 3},
        {2, 3, 4},
        {0, 2, 4},
        {1, 3, 4},
    };
    for (size_t s = 0; s < sizeof(subsets) / sizeof(subsets[0]); s++)
    {
        uint8_t recovered[32];
        threshold_decrypt_subset(recovered, shares, subsets[s], THRESHOLD, c);
        char label[64];
        snprintf(label,
                 sizeof(label),
                 "subset {%d,%d,%d} recovers the message",
                 subsets[s][0],
                 subsets[s][1],
                 subsets[s][2]);
        CHECK(memcmp(recovered, test_msg, 32) == 0, label);
    }
}

static void
test_below_threshold_fails(void)
{
    uint8_t keygen_coins[32], enc_coins[32];
    fill_lcg_bytes32(keygen_coins, 42);
    fill_lcg_bytes32(enc_coins, 43);

    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
    indcpa_keypair_derand(pk, sk, keygen_coins);

    polyvec skpv;
    polyvec_frombytes(&skpv, sk);

    polyvec shares[N_PARTIES];
    threshold_split_secret(&skpv, shares, THRESHOLD, N_PARTIES);

    uint8_t c[KYBER_INDCPA_BYTES];
    indcpa_enc(c, test_msg, pk, enc_coins);

    /* Only 2 of the 3 required shares: interpolating a degree-2
     * (THRESHOLD-1=2) polynomial from 2 points is under-determined, so
     * this should not recover the message. */
    polyvec b_ntt;
    poly v;
    unpack_ciphertext_ntt(&b_ntt, &v, c);

    poly partials[2];
    int xs[2] = {1, 2};
    threshold_partial_decrypt(&partials[0], &shares[0], &b_ntt);
    threshold_partial_decrypt(&partials[1], &shares[1], &b_ntt);

    uint8_t recovered[32];
    threshold_finish_decrypt(recovered, partials, xs, 2, &v);

    CHECK(memcmp(recovered, test_msg, 32) != 0, "2-of-5 (below THRESHOLD=3) does not recover the message");
}

int
main(void)
{
    test_any_k_subset_recovers_message();
    test_below_threshold_fails();

    if (failures == 0)
    {
        printf("All threshold tests passed.\n");
        return 0;
    }
    printf("%d test(s) failed.\n", failures);
    return 1;
}
