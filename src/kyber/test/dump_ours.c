#include <stdio.h>

#include "../cbd.h"
#include "../ntt.h"
#include "../poly.h"
#include "../reduce.h"
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

static void
print_arr(const char *label, const int16_t *a, int n)
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
    kyber_ntt_init();

    print_arr("ZETAS", zetas, 128);

    int16_t poly_a[256], poly_b[256];
    fill_lcg_poly(poly_a, 1);
    fill_lcg_poly(poly_b, 2);

    int16_t ntt_a[256], ntt_b[256];
    for (int i = 0; i < 256; i++)
    {
        ntt_a[i] = poly_a[i];
        ntt_b[i] = poly_b[i];
    }
    ntt(ntt_a);
    ntt(ntt_b);
    print_arr("NTT_A", ntt_a, 256);
    print_arr("NTT_B", ntt_b, 256);

    int16_t roundtrip_a[256];
    for (int i = 0; i < 256; i++)
    {
        roundtrip_a[i] = ntt_a[i];
    }
    invntt(roundtrip_a);
    print_arr("INVNTT_A", roundtrip_a, 256);

    printf("BASEMUL\n");
    for (int i = 0; i < 8; i++)
    {
        int16_t r[2];
        int16_t a2[2] = {poly_a[2 * i], poly_a[2 * i + 1]};
        int16_t b2[2] = {poly_b[2 * i], poly_b[2 * i + 1]};
        basemul(r, a2, b2, zetas[64 + i]);
        printf("%d %d\n", r[0], r[1]);
    }

    printf("MONT_EDGE\n");
    int32_t mont_inputs[6] = {0, 1, -1, 3328 * 16384, -3328 * 16384, 12345678};
    for (int i = 0; i < 6; i++)
    {
        printf("%d\n", montgomery_reduce(mont_inputs[i]));
    }

    printf("BARRETT_EDGE\n");
    int16_t bar_inputs[6] = {0, 1, -1, 3328, -3328, 32767};
    for (int i = 0; i < 6; i++)
    {
        printf("%d\n", barrett_reduce(bar_inputs[i]));
    }

    uint8_t cbd_buf[128];
    fill_lcg_bytes(cbd_buf, 7);
    int16_t cbd_out[256];
    cbd_eta2(cbd_out, cbd_buf);
    print_arr("CBD_ETA2", cbd_out, 256);

    poly p;
    fill_lcg_poly(p.coeffs, 3);
    for (int i = 0; i < 256; i++)
    {
        /* map into [0, q) the way tobytes/compress expect a "clean" poly */
        if (p.coeffs[i] < 0)
        {
            p.coeffs[i] = (int16_t)(p.coeffs[i] + 3329);
        }
    }

    uint8_t compressed[KYBER_POLYCOMPRESSEDBYTES];
    poly_compress(compressed, &p);
    print_bytes("POLY_COMPRESS", compressed, KYBER_POLYCOMPRESSEDBYTES);
    poly decompressed;
    poly_decompress(&decompressed, compressed);
    print_arr("POLY_DECOMPRESS", decompressed.coeffs, 256);

    uint8_t serialized[KYBER_POLYBYTES];
    poly_tobytes(serialized, &p);
    print_bytes("POLY_TOBYTES", serialized, KYBER_POLYBYTES);
    poly deserialized;
    poly_frombytes(&deserialized, serialized);
    print_arr("POLY_FROMBYTES", deserialized.coeffs, 256);

    poly msg_poly;
    poly_frommsg(&msg_poly, test_msg);
    print_arr("POLY_FROMMSG", msg_poly.coeffs, 256);
    uint8_t msg_out[32];
    poly_tomsg(msg_out, &msg_poly);
    print_bytes("POLY_TOMSG", msg_out, 32);

    poly noise1, noise2;
    poly_getnoise_eta1(&noise1, test_seed, 0);
    poly_getnoise_eta2(&noise2, test_seed, 1);
    print_arr("GETNOISE_ETA1", noise1.coeffs, 256);
    print_arr("GETNOISE_ETA2", noise2.coeffs, 256);

    return 0;
}
