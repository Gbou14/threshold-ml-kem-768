/*
 * Deterministic pseudo-random test data shared between our own dump
 * program and a dump program linked against the pq-crystals/kyber
 * public-domain reference implementation, so both consume bit-identical
 * inputs when we diff their outputs. Not a cryptographic PRNG -- just a
 * reproducible source of varied test coefficients.
 */
#ifndef KYBER_TEST_VECTORS_H
#define KYBER_TEST_VECTORS_H

#include <stdint.h>

static void
fill_lcg_poly(int16_t out[256], uint32_t seed)
{
    for (int i = 0; i < 256; i++)
    {
        seed = seed * 1103515245u + 12345u;
        out[i] = (int16_t)(((seed >> 16) % 3329) - 1664);
    }
}

static void
fill_lcg_bytes(uint8_t out[128], uint32_t seed)
{
    for (int i = 0; i < 128; i++)
    {
        seed = seed * 1103515245u + 12345u;
        out[i] = (uint8_t)(seed >> 24);
    }
}

static void
fill_lcg_bytes32(uint8_t out[32], uint32_t seed)
{
    for (int i = 0; i < 32; i++)
    {
        seed = seed * 1103515245u + 12345u;
        out[i] = (uint8_t)(seed >> 24);
    }
}

static const uint8_t test_seed[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                       16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static const uint8_t test_msg[32] = {0xAA, 0x55, 0x00, 0xFF, 0x01, 0x80, 0x7F, 0xC3,
                                      0x3C, 0x99, 0x66, 0x18, 0xE7, 0x24, 0xDB, 0x42,
                                      0xAA, 0x55, 0x00, 0xFF, 0x01, 0x80, 0x7F, 0xC3,
                                      0x3C, 0x99, 0x66, 0x18, 0xE7, 0x24, 0xDB, 0x42};

#endif /* KYBER_TEST_VECTORS_H */
