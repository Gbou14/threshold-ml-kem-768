#include <stdio.h>

#include "../indcpa.h"
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
    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
    indcpa_keypair_derand(pk, sk, test_seed);
    print_bytes("PK", pk, KYBER_INDCPA_PUBLICKEYBYTES);
    print_bytes("SK", sk, KYBER_INDCPA_SECRETKEYBYTES);

    uint8_t enc_coins[32];
    fill_lcg_bytes32(enc_coins, 123);
    uint8_t c[KYBER_INDCPA_BYTES];
    indcpa_enc(c, test_msg, pk, enc_coins);
    print_bytes("CT", c, KYBER_INDCPA_BYTES);

    uint8_t recovered[32];
    indcpa_dec(recovered, c, sk);
    print_bytes("RECOVERED_MSG", recovered, 32);

    return 0;
}
