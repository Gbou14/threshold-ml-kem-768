/*
 * Regression test for the full CCA-secure ML-KEM-768 KEM (kem.c) and
 * its threshold counterpart (threshold_decaps). Pinned spot-check
 * values came from a byte-for-byte diff against the pq-crystals/kyber
 * reference implementation's crypto_kem_* functions on the same
 * test_seed-derived inputs used here (see test/dump_kem_ours.c).
 */
#include <stdio.h>
#include <string.h>

#include "../indcpa.h"
#include "../kem.h"
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

static void
test_reference_spot_checks(void)
{
    uint8_t keygen_coins[64];
    fill_lcg_bytes32(keygen_coins, 7);
    fill_lcg_bytes32(keygen_coins + 32, 8);

    uint8_t ek[KYBER_PUBLICKEYBYTES];
    uint8_t dk[KYBER_SECRETKEYBYTES];
    kyber_keypair_derand(ek, dk, keygen_coins);
    CHECK(ek[0] == 178 && ek[1] == 80 && ek[2] == 126 && ek[3] == 60, "EK matches reference spot-check");
    CHECK(dk[0] == 46 && dk[1] == 185 && dk[2] == 1 && dk[3] == 112, "DK matches reference spot-check");

    uint8_t enc_coins[32];
    fill_lcg_bytes32(enc_coins, 9);
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss_enc[KYBER_SSBYTES];
    kyber_encaps_derand(ct, ss_enc, ek, enc_coins);
    CHECK(ct[0] == 42 && ct[1] == 253 && ct[2] == 122 && ct[3] == 201, "CT matches reference spot-check");
    CHECK(ss_enc[0] == 243 && ss_enc[1] == 42 && ss_enc[2] == 239 && ss_enc[3] == 198,
          "SS_ENC matches reference spot-check");

    uint8_t ss_dec[KYBER_SSBYTES];
    kyber_decaps(ss_dec, ct, dk);
    CHECK(memcmp(ss_dec, ss_enc, KYBER_SSBYTES) == 0, "kyber_decaps recovers the encapsulated shared secret exactly");

    uint8_t bad_ct[KYBER_CIPHERTEXTBYTES];
    memcpy(bad_ct, ct, sizeof(bad_ct));
    bad_ct[0] ^= 0xFF;
    uint8_t ss_reject[KYBER_SSBYTES];
    kyber_decaps(ss_reject, bad_ct, dk);
    CHECK(ss_reject[0] == 107 && ss_reject[1] == 44 && ss_reject[2] == 78 && ss_reject[3] == 218,
          "SS_REJECT (implicit rejection) matches reference spot-check");
    CHECK(memcmp(ss_reject, ss_enc, KYBER_SSBYTES) != 0, "a corrupted ciphertext does not decapsulate to the real secret");
}

/* threshold_decaps must agree with plain kyber_decaps on a valid
 * ciphertext (and, since ML-KEM is deterministic given ek/dk/ct, on a
 * rejected one too -- the rejection path doesn't depend on m' at all,
 * so an incorrect m' from a broken combine would only show up on the
 * accept path; both are checked for completeness). */
static void
test_threshold_decaps_matches_plain_decaps(void)
{
    uint8_t keygen_coins[64];
    fill_lcg_bytes32(keygen_coins, 100);
    fill_lcg_bytes32(keygen_coins + 32, 101);

    uint8_t ek[KYBER_PUBLICKEYBYTES];
    uint8_t dk[KYBER_SECRETKEYBYTES];
    kyber_keypair_derand(ek, dk, keygen_coins);
    const uint8_t *z = dk + KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES + KYBER_SYMBYTES;

    polyvec skpv;
    polyvec_frombytes(&skpv, dk); /* dk's first KYBER_INDCPA_SECRETKEYBYTES bytes are dkPKE */

    polyvec shares[N_PARTIES];
    threshold_split_secret(&skpv, shares, THRESHOLD, N_PARTIES);

    uint8_t enc_coins[32];
    fill_lcg_bytes32(enc_coins, 102);
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss_enc[KYBER_SSBYTES];
    kyber_encaps_derand(ct, ss_enc, ek, enc_coins);

    uint8_t ss_plain[KYBER_SSBYTES];
    kyber_decaps(ss_plain, ct, dk);
    CHECK(memcmp(ss_plain, ss_enc, KYBER_SSBYTES) == 0, "sanity: plain kyber_decaps recovers the shared secret");

    polyvec b_ntt;
    polyvec_decompress(&b_ntt, ct);
    polyvec_ntt(&b_ntt);

    int subset[THRESHOLD] = {0, 2, 4};
    poly partials[THRESHOLD];
    int xs[THRESHOLD];
    for (int i = 0; i < THRESHOLD; i++)
    {
        threshold_partial_decrypt(&partials[i], &shares[subset[i]], &b_ntt);
        xs[i] = subset[i] + 1;
    }

    uint8_t ss_threshold[KYBER_SSBYTES];
    threshold_decaps(ss_threshold, partials, xs, THRESHOLD, ct, ek, z);
    CHECK(memcmp(ss_threshold, ss_plain, KYBER_SSBYTES) == 0,
          "threshold_decaps matches plain kyber_decaps on a valid ciphertext");

    /* Rejected ciphertext: threshold_decaps should reject it exactly
     * like kyber_decaps does. */
    uint8_t bad_ct[KYBER_CIPHERTEXTBYTES];
    memcpy(bad_ct, ct, sizeof(bad_ct));
    bad_ct[0] ^= 0xFF;

    uint8_t ss_plain_bad[KYBER_SSBYTES];
    kyber_decaps(ss_plain_bad, bad_ct, dk);

    polyvec b_ntt_bad;
    polyvec_decompress(&b_ntt_bad, bad_ct);
    polyvec_ntt(&b_ntt_bad);
    poly partials_bad[THRESHOLD];
    for (int i = 0; i < THRESHOLD; i++)
    {
        threshold_partial_decrypt(&partials_bad[i], &shares[subset[i]], &b_ntt_bad);
    }
    uint8_t ss_threshold_bad[KYBER_SSBYTES];
    threshold_decaps(ss_threshold_bad, partials_bad, xs, THRESHOLD, bad_ct, ek, z);

    CHECK(memcmp(ss_threshold_bad, ss_plain_bad, KYBER_SSBYTES) == 0,
          "threshold_decaps matches plain kyber_decaps' rejection behavior on a corrupted ciphertext");
    CHECK(memcmp(ss_threshold_bad, ss_enc, KYBER_SSBYTES) != 0,
          "a corrupted ciphertext does not threshold-decapsulate to the real secret");
}

int
main(void)
{
    test_reference_spot_checks();
    test_threshold_decaps_matches_plain_decaps();

    if (failures == 0)
    {
        printf("All kem tests passed.\n");
        return 0;
    }
    printf("%d test(s) failed.\n", failures);
    return 1;
}
