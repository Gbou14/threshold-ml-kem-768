/*
 * Self-contained regression test for the ML-KEM-768 primitives module.
 * Does not depend on any external reference code -- the expected values
 * below were captured once from a byte-for-byte comparison against the
 * public-domain pq-crystals/kyber reference implementation (see the
 * project's dev notes) and are pinned here so this test stays fast and
 * has no external dependency.
 */
#include <stdio.h>
#include <string.h>

#include "../cbd.h"
#include "../ntt.h"
#include "../poly.h"
#include "../reduce.h"
#include "../shake.h"
#include "test_vectors.h"

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

/* The 128 NTT twiddle factors fixed by the ML-KEM standard (zeta=17,
 * bit-reversed order, centered Montgomery domain). */
static const int16_t expected_zetas[128] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,   1577,  182,   962,   -1202,
    -1474, 1468,  573,   -1325, 264,   383,   -829,  1458,  -1602, -130,  -681,  1017,  732,   608,
    -1542, 411,   -205,  -1571, 1223,  652,   -552,  1015,  -1293, 1491,  -282,  -1544, 516,   -8,
    -320,  -666,  -1618, -1162, 126,   1469,  -853,  -90,   -271,  830,   107,   -1421, -247,  -951,
    -398,  961,   -1508, -725,  448,   -1065, 677,   -1275, -1103, 430,   555,   843,   -1251, 871,
    1550,  105,   422,   587,   177,   -235,  -291,  -460,  1574,  1653,  -246,  778,   1159,  -147,
    -777,  1483,  -602,  1119,  -1590, 644,   -872,  349,   418,   329,   -156,  -75,   817,   1097,
    603,   610,   1322,  -1285, -1465, 384,   -1215, -136,  1218,  -1335, -874,  220,   -1187, -1659,
    -1185, -1530, -1278, 794,   -1510, -854,  -870,  478,   -108,  -308,  996,   991,   958,   -1460,
    1522,  1628};

/* NIST FIPS 202 SHAKE256 test vector: SHAKE256(""), first 32 bytes. */
static const uint8_t shake256_empty_32[32] = {0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f,
                                               0xeb, 0x74, 0x3e, 0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8,
                                               0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f};

static void
test_zetas(void)
{
    kyber_ntt_init();
    CHECK(memcmp(zetas, expected_zetas, sizeof(zetas)) == 0, "zetas table matches ML-KEM standard values");
}

static void
test_shake256_kat(void)
{
    uint8_t out[32];
    shake256_xof(out, sizeof(out), NULL, 0);
    CHECK(memcmp(out, shake256_empty_32, sizeof(out)) == 0, "SHAKE256(\"\") matches NIST test vector");
}

/* Spot-checks captured from a byte-exact diff against the reference
 * implementation on the same fill_lcg_poly/fill_lcg_bytes/test_seed
 * inputs used here -- see src/kyber/test/dump_ours.c for the full dump. */
static void
test_reference_spot_checks(void)
{
    int16_t poly_a[256];
    fill_lcg_poly(poly_a, 1);
    ntt(poly_a);
    CHECK(poly_a[0] == -1152 && poly_a[1] == 1542 && poly_a[2] == -3372, "ntt() matches reference spot-check");

    uint8_t cbd_buf[128];
    fill_lcg_bytes(cbd_buf, 7);
    int16_t cbd_out[256];
    cbd_eta2(cbd_out, cbd_buf);
    CHECK(cbd_out[0] == -2 && cbd_out[1] == -2 && cbd_out[2] == 0, "cbd_eta2() matches reference spot-check");

    poly noise1;
    poly_getnoise_eta1(&noise1, test_seed, 0);
    CHECK(noise1.coeffs[0] == -1 && noise1.coeffs[1] == 0 && noise1.coeffs[2] == 1,
          "poly_getnoise_eta1() matches reference spot-check");
}

static void
test_compress_roundtrip_bounded(void)
{
    /* Compression to KYBER_DV=4 bits/coeff is lossy by design; check the
     * round-trip error stays within the guaranteed bound of q/2^(dv+1). */
    poly p;
    fill_lcg_poly(p.coeffs, 99);
    for (int i = 0; i < 256; i++)
    {
        if (p.coeffs[i] < 0)
        {
            p.coeffs[i] = (int16_t)(p.coeffs[i] + KYBER_Q);
        }
    }

    uint8_t compressed[KYBER_POLYCOMPRESSEDBYTES];
    poly_compress(compressed, &p);
    poly decompressed;
    poly_decompress(&decompressed, compressed);

    int max_err = 0;
    for (int i = 0; i < 256; i++)
    {
        int diff = p.coeffs[i] - decompressed.coeffs[i];
        int wrapped = diff > KYBER_Q / 2 ? diff - KYBER_Q : (diff < -KYBER_Q / 2 ? diff + KYBER_Q : diff);
        int abs_err = wrapped < 0 ? -wrapped : wrapped;
        if (abs_err > max_err)
        {
            max_err = abs_err;
        }
    }
    CHECK(max_err <= KYBER_Q / (1 << (KYBER_DV + 1)) + 1, "poly_compress/decompress round-trip error is bounded");
}

static void
test_tobytes_roundtrip_exact(void)
{
    /* Full 12-bit serialization is lossless. */
    poly p;
    fill_lcg_poly(p.coeffs, 42);
    for (int i = 0; i < 256; i++)
    {
        if (p.coeffs[i] < 0)
        {
            p.coeffs[i] = (int16_t)(p.coeffs[i] + KYBER_Q);
        }
    }

    uint8_t bytes[KYBER_POLYBYTES];
    poly_tobytes(bytes, &p);
    poly q;
    poly_frombytes(&q, bytes);
    CHECK(memcmp(p.coeffs, q.coeffs, sizeof(p.coeffs)) == 0, "poly_tobytes/frombytes round-trips exactly");
}

static void
test_msg_roundtrip(void)
{
    poly m;
    poly_frommsg(&m, test_msg);
    uint8_t out[32];
    poly_tomsg(out, &m);
    CHECK(memcmp(out, test_msg, sizeof(out)) == 0, "poly_frommsg/tomsg round-trips exactly");
}

int
main(void)
{
    test_zetas();
    test_shake256_kat();
    test_reference_spot_checks();
    test_compress_roundtrip_bounded();
    test_tobytes_roundtrip_exact();
    test_msg_roundtrip();

    if (failures == 0)
    {
        printf("All primitive tests passed.\n");
        return 0;
    }
    printf("%d test(s) failed.\n", failures);
    return 1;
}
