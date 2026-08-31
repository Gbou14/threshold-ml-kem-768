#include "kem.h"

#include <string.h>

#include "indcpa.h"
#include "shake.h"

void
kyber_keypair_derand(uint8_t ek[KYBER_PUBLICKEYBYTES],
                      uint8_t dk[KYBER_SECRETKEYBYTES],
                      const uint8_t coins[2 * KYBER_SYMBYTES])
{
    indcpa_keypair_derand(ek, dk, coins);

    uint8_t *dk_ek = dk + KYBER_INDCPA_SECRETKEYBYTES;
    uint8_t *dk_hek = dk_ek + KYBER_PUBLICKEYBYTES;
    uint8_t *dk_z = dk_hek + KYBER_SYMBYTES;

    memcpy(dk_ek, ek, KYBER_PUBLICKEYBYTES);
    sha3_256(dk_hek, ek, KYBER_PUBLICKEYBYTES);
    memcpy(dk_z, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
}

void
kyber_encaps_derand(uint8_t ct[KYBER_CIPHERTEXTBYTES],
                     uint8_t ss[KYBER_SSBYTES],
                     const uint8_t ek[KYBER_PUBLICKEYBYTES],
                     const uint8_t coins[KYBER_SYMBYTES])
{
    /* buf = m || H(ek); the H(ek) binding is a multi-target
     * countermeasure (ties the derived key to which public key it was
     * encapsulated under), not a secrecy requirement. */
    uint8_t buf[2 * KYBER_SYMBYTES];
    memcpy(buf, coins, KYBER_SYMBYTES);
    sha3_256(buf + KYBER_SYMBYTES, ek, KYBER_PUBLICKEYBYTES);

    uint8_t kr[2 * KYBER_SYMBYTES]; /* K' || r' */
    sha3_512(kr, buf, sizeof(buf));

    indcpa_enc(ct, buf, ek, kr + KYBER_SYMBYTES);
    memcpy(ss, kr, KYBER_SSBYTES);
}

void
kyber_decaps_from_m(uint8_t ss[KYBER_SSBYTES],
                     const uint8_t m[KYBER_MSGBYTES],
                     const uint8_t ct[KYBER_CIPHERTEXTBYTES],
                     const uint8_t ek[KYBER_PUBLICKEYBYTES],
                     const uint8_t z[KYBER_SYMBYTES])
{
    uint8_t buf[2 * KYBER_SYMBYTES];
    memcpy(buf, m, KYBER_MSGBYTES);
    sha3_256(buf + KYBER_SYMBYTES, ek, KYBER_PUBLICKEYBYTES);

    uint8_t kr[2 * KYBER_SYMBYTES]; /* K' || r' */
    sha3_512(kr, buf, sizeof(buf));

    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    indcpa_enc(cmp, buf, ek, kr + KYBER_SYMBYTES);

    int ok = (memcmp(ct, cmp, KYBER_CIPHERTEXTBYTES) == 0);

    /* Implicit-rejection fallback: J(z, ct), indistinguishable from a
     * real key to anyone without z. Always computed, not just on
     * failure, so the two paths take the same shape regardless of ok
     * (this code isn't claiming full constant-time, but there's no
     * reason to skip the cheap half of that discipline). */
    uint8_t rejection_key[KYBER_SSBYTES];
    uint8_t rkprf_in[KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES];
    memcpy(rkprf_in, z, KYBER_SYMBYTES);
    memcpy(rkprf_in + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    shake256_xof(rejection_key, KYBER_SSBYTES, rkprf_in, sizeof(rkprf_in));

    memcpy(ss, ok ? kr : rejection_key, KYBER_SSBYTES);
}

void
kyber_decaps(uint8_t ss[KYBER_SSBYTES], const uint8_t ct[KYBER_CIPHERTEXTBYTES], const uint8_t dk[KYBER_SECRETKEYBYTES])
{
    const uint8_t *dk_pke = dk;
    const uint8_t *ek = dk + KYBER_INDCPA_SECRETKEYBYTES;
    const uint8_t *z = ek + KYBER_PUBLICKEYBYTES + KYBER_SYMBYTES;

    uint8_t m[KYBER_MSGBYTES];
    indcpa_dec(m, ct, dk_pke);

    kyber_decaps_from_m(ss, m, ct, ek, z);
}
