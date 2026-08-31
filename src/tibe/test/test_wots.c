/*
 * Self-contained regression test for the WOTS+ one-time signature
 * module. No public test-vector set for this exact instantiation
 * (SHA2-256, w=16, with this project's specific toByte(0..3,32)
 * domain-separation and the PRF_seed 4-byte-index encoding choice) is
 * pinned anywhere -- validated by internal consistency instead:
 * sign-then-verify round trips, and that tampering with the message,
 * the signature, or using the wrong verification key each reliably
 * makes Verify reject.
 */
#include <stdio.h>
#include <string.h>

#include "../wots.h"

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
test_sig_size(void)
{
    CHECK(WOTS_SIGBYTES == 2144, "signature length matches the paper's stated 2144 bytes (Theorem 6)");
    CHECK(WOTS_L == 67 && WOTS_L1 == 64 && WOTS_L2 == 3, "l1=64, l2=3, l=67 match the standard n=32,w=16 derivation");
}

static void
test_valid_roundtrip(void)
{
    wots_sk sk;
    wots_vk vk;
    wots_keygen(&sk, &vk);

    const uint8_t msg[] = "BCHK+ TIBE ciphertext bytes go here, any length works";
    uint8_t sig[WOTS_SIGBYTES];
    wots_sign(sig, &sk, &vk, msg, sizeof(msg));

    CHECK(wots_verify(&vk, msg, sizeof(msg), sig) == 1, "valid signature verifies");
}

static void
test_empty_message(void)
{
    wots_sk sk;
    wots_vk vk;
    wots_keygen(&sk, &vk);

    uint8_t sig[WOTS_SIGBYTES];
    wots_sign(sig, &sk, &vk, NULL, 0);
    CHECK(wots_verify(&vk, NULL, 0, sig) == 1, "empty-message signature verifies");
}

static void
test_tampered_message_rejected(void)
{
    wots_sk sk;
    wots_vk vk;
    wots_keygen(&sk, &vk);

    uint8_t msg[] = "the exact bytes being signed matter";
    uint8_t sig[WOTS_SIGBYTES];
    wots_sign(sig, &sk, &vk, msg, sizeof(msg));

    msg[0] ^= 0x01; /* flip one bit */
    CHECK(wots_verify(&vk, msg, sizeof(msg), sig) == 0, "signature over the original message rejects a tampered message");
}

static void
test_tampered_signature_rejected(void)
{
    wots_sk sk;
    wots_vk vk;
    wots_keygen(&sk, &vk);

    const uint8_t msg[] = "another message";
    uint8_t sig[WOTS_SIGBYTES];
    wots_sign(sig, &sk, &vk, msg, sizeof(msg));

    sig[100] ^= 0x01; /* flip one bit inside one chain value */
    CHECK(wots_verify(&vk, msg, sizeof(msg), sig) == 0, "tampered signature bytes are rejected");
}

static void
test_wrong_vk_rejected(void)
{
    wots_sk sk_a;
    wots_vk vk_a;
    wots_keygen(&sk_a, &vk_a);

    wots_sk sk_b;
    wots_vk vk_b;
    wots_keygen(&sk_b, &vk_b);

    const uint8_t msg[] = "signed under vk_a";
    uint8_t sig[WOTS_SIGBYTES];
    wots_sign(sig, &sk_a, &vk_a, msg, sizeof(msg));

    CHECK(wots_verify(&vk_b, msg, sizeof(msg), sig) == 0, "a valid signature under vk_a is rejected under vk_b");
}

static void
test_fresh_keys_differ(void)
{
    wots_sk sk1, sk2;
    wots_vk vk1, vk2;
    wots_keygen(&sk1, &vk1);
    wots_keygen(&sk2, &vk2);

    CHECK(memcmp(vk1.seed, vk2.seed, WOTS_SEEDBYTES) != 0, "two keygen calls produce different seeds");
    CHECK(memcmp(vk1.vk1, vk2.vk1, WOTS_VK1BYTES) != 0, "two keygen calls produce different vk1 (overwhelmingly likely)");
}

int
main(void)
{
    test_sig_size();
    test_valid_roundtrip();
    test_empty_message();
    test_tampered_message_rejected();
    test_tampered_signature_rejected();
    test_wrong_vk_rejected();
    test_fresh_keys_differ();

    if (failures == 0)
    {
        printf("test_wots: all tests passed\n");
        return 0;
    }
    printf("test_wots: %d failure(s)\n", failures);
    return 1;
}
