/*
 * Self-contained regression test for the TIBE core algebra (Setup /
 * Encode / Decode / Encrypt / direct non-threshold Decrypt). No public
 * reference implementation of this scheme exists anywhere (see
 * BCHK_PAPER_SPEC.md), so this validates by internal consistency:
 * Encode/Decode round trip directly, and full Setup -> Encrypt ->
 * Decrypt round trips recover the original message for random
 * messages and a random (already-embedded) identity.
 */
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#include "../tibe.h"

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
random_msg(uint8_t msg[TIBE_MSG_BYTES])
{
    RAND_bytes(msg, TIBE_MSG_BYTES);
}

static void
test_encode_decode_roundtrip(BN_CTX* ctx)
{
    uint8_t msg[TIBE_MSG_BYTES];
    uint8_t msg_back[TIBE_MSG_BYTES];
    random_msg(msg);

    ring_elem encoded;
    ring_init(&encoded);
    tibe_encode(&encoded, msg, ctx);
    tibe_decode(msg_back, &encoded, ctx);

    CHECK(memcmp(msg, msg_back, TIBE_MSG_BYTES) == 0, "Decode(Encode(msg)) == msg for a random message");
    ring_free(&encoded);
}

static void
test_setup_encrypt_decrypt_roundtrip(BN_CTX* ctx)
{
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tibe_setup(&ek, &msk, ctx);

    /* Phase 3 stub identity: an already-embedded unit ring element.
     * Phase 4 builds the real WOTS+-vk -> unit map E; Encrypt/Decrypt's
     * own algebra doesn't care how `id` was produced. */
    ring_elem id;
    ring_init(&id);
    ring_random_uniform(&id, ctx);

    uint8_t msg[TIBE_MSG_BYTES];
    uint8_t msg_back[TIBE_MSG_BYTES];
    random_msg(msg);

    tibe_ct ct;
    tibe_ct_init(&ct);
    tibe_encrypt(&ct, &ek, &id, msg, ctx);

    int ok = tibe_decrypt_direct(msg_back, &ek, &msk, &id, &ct, ctx);
    CHECK(ok, "tibe_decrypt_direct's own F_vk*z==r correctness assertion holds");
    if (ok)
    {
        CHECK(memcmp(msg, msg_back, TIBE_MSG_BYTES) == 0, "decrypted message matches the encrypted one");
    }

    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
    ring_free(&id);
    tibe_ct_free(&ct);
}

static void
test_multiple_roundtrips(BN_CTX* ctx)
{
    /* Fresh Setup + a couple of messages under the same keys, to catch
     * anything that only shows up statistically rather than on a
     * single lucky/unlucky draw. Kept small (2, not e.g. 5-10): each
     * full Setup+Encrypt+Decrypt cycle costs ~9-10 minutes at this
     * module's d=4096 BIGNUM scale (measured -- see README.md
     * "Performance"), so `make test`'s routine runtime is a real
     * constraint on trial count here, not just belt-and-suspenders
     * caution. */
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    tibe_setup(&ek, &msk, ctx);

    ring_elem id;
    ring_init(&id);
    ring_random_uniform(&id, ctx);

    int all_ok = 1;
    for (int trial = 0; trial < 2; trial++)
    {
        uint8_t msg[TIBE_MSG_BYTES];
        uint8_t msg_back[TIBE_MSG_BYTES];
        random_msg(msg);

        tibe_ct ct;
        tibe_ct_init(&ct);
        tibe_encrypt(&ct, &ek, &id, msg, ctx);
        int ok = tibe_decrypt_direct(msg_back, &ek, &msk, &id, &ct, ctx);
        if (!ok || memcmp(msg, msg_back, TIBE_MSG_BYTES) != 0)
        {
            all_ok = 0;
        }
        tibe_ct_free(&ct);
    }
    CHECK(all_ok, "2 encrypt/decrypt round trips under one Setup all recover the original message");

    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
    ring_free(&id);
}

int
main(void)
{
    BN_CTX* ctx = BN_CTX_new();

    test_encode_decode_roundtrip(ctx);
    test_setup_encrypt_decrypt_roundtrip(ctx);
    test_multiple_roundtrips(ctx);

    BN_CTX_free(ctx);

    if (failures == 0)
    {
        printf("test_tibe: all tests passed\n");
        return 0;
    }
    printf("test_tibe: %d failure(s)\n", failures);
    return 1;
}
