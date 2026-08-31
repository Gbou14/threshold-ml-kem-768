/*
 * Self-contained regression test for the ML-KEM-768 IND-CPA PKE
 * (KeyGen/Enc/Dec). Pinned spot-check values came from a byte-for-byte
 * diff against the pq-crystals/kyber reference implementation on the
 * same test_seed/test_msg inputs used here (see
 * test/dump_indcpa_ours.c for the full dump program).
 */
#include <stdio.h>
#include <string.h>

#include "../indcpa.h"
#include "test_vectors.h"

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
    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
    indcpa_keypair_derand(pk, sk, test_seed);

    CHECK(pk[0] == 41 && pk[1] == 138 && pk[2] == 161 && pk[3] == 13, "PK matches reference spot-check");
    CHECK(sk[0] == 39 && sk[1] == 210 && sk[2] == 167 && sk[3] == 127, "SK matches reference spot-check");

    uint8_t enc_coins[32];
    fill_lcg_bytes32(enc_coins, 123);
    uint8_t c[KYBER_INDCPA_BYTES];
    indcpa_enc(c, test_msg, pk, enc_coins);
    CHECK(c[0] == 253 && c[1] == 22 && c[2] == 187 && c[3] == 218, "CT matches reference spot-check");

    uint8_t recovered[32];
    indcpa_dec(recovered, c, sk);
    CHECK(memcmp(recovered, test_msg, 32) == 0, "Dec(Enc(test_msg)) recovers test_msg exactly");
}

static void
test_roundtrip_fuzz(void)
{
    /* Not cross-validated against the reference -- just checks the
     * scheme is internally consistent (Dec(Enc(m)) == m) across many
     * independent random-looking key/message/coin combinations. */
    int ok = 1;
    for (uint32_t trial = 0; trial < 32 && ok; trial++)
    {
        uint8_t keygen_coins[32], enc_coins[32], msg[32];
        fill_lcg_bytes32(keygen_coins, 1000 + trial);
        fill_lcg_bytes32(enc_coins, 2000 + trial);
        fill_lcg_bytes32(msg, 3000 + trial);

        uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
        indcpa_keypair_derand(pk, sk, keygen_coins);

        uint8_t c[KYBER_INDCPA_BYTES];
        indcpa_enc(c, msg, pk, enc_coins);

        uint8_t recovered[32];
        indcpa_dec(recovered, c, sk);

        if (memcmp(recovered, msg, 32) != 0)
        {
            ok = 0;
        }
    }
    CHECK(ok, "Dec(Enc(m)) == m across 32 random key/message/coin trials");
}

int
main(void)
{
    test_reference_spot_checks();
    test_roundtrip_fuzz();

    if (failures == 0)
    {
        printf("All indcpa tests passed.\n");
        return 0;
    }
    printf("%d test(s) failed.\n", failures);
    return 1;
}
