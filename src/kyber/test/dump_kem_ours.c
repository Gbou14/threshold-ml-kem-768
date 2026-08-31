#include <stdio.h>

#include "../kem.h"
#include "test_vectors.h"

static void
print_bytes(const char *label, const uint8_t *a, int n)
{
    printf("%s\n", label);
    for (int i = 0; i < n; i++)
    {
        printf("%d\n", a[i]);
    }
}

int
main(void)
{
    uint8_t keygen_coins[64];
    fill_lcg_bytes32(keygen_coins, 7);
    fill_lcg_bytes32(keygen_coins + 32, 8);

    uint8_t ek[KYBER_PUBLICKEYBYTES];
    uint8_t dk[KYBER_SECRETKEYBYTES];
    kyber_keypair_derand(ek, dk, keygen_coins);
    print_bytes("EK", ek, KYBER_PUBLICKEYBYTES);
    print_bytes("DK", dk, KYBER_SECRETKEYBYTES);

    uint8_t enc_coins[32];
    fill_lcg_bytes32(enc_coins, 9);
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss_enc[KYBER_SSBYTES];
    kyber_encaps_derand(ct, ss_enc, ek, enc_coins);
    print_bytes("CT", ct, KYBER_CIPHERTEXTBYTES);
    print_bytes("SS_ENC", ss_enc, KYBER_SSBYTES);

    uint8_t ss_dec[KYBER_SSBYTES];
    kyber_decaps(ss_dec, ct, dk);
    print_bytes("SS_DEC", ss_dec, KYBER_SSBYTES);

    /* Also exercise the implicit-rejection path: corrupt one byte of
     * the ciphertext and decapsulate again -- should NOT match ss_enc,
     * and should be a deterministic function of (z, corrupted ct). */
    uint8_t bad_ct[KYBER_CIPHERTEXTBYTES];
    for (int i = 0; i < KYBER_CIPHERTEXTBYTES; i++)
    {
        bad_ct[i] = ct[i];
    }
    bad_ct[0] ^= 0xFF;
    uint8_t ss_reject[KYBER_SSBYTES];
    kyber_decaps(ss_reject, bad_ct, dk);
    print_bytes("SS_REJECT", ss_reject, KYBER_SSBYTES);

    return 0;
}
