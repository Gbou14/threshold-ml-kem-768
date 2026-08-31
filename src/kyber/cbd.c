#include "cbd.h"
#include "params.h"

static uint32_t
load32_le(const uint8_t x[4])
{
    return (uint32_t)x[0] | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16) | ((uint32_t)x[3] << 24);
}

void
cbd_eta2(int16_t coeffs[256], const uint8_t buf[128])
{
    /* Each 32-bit little-endian word packs 8 coefficients' worth of
     * random bits, 4 bits/coefficient: 2 bits feed the "positive" count,
     * 2 bits feed the "negative" count, and the coefficient is their
     * difference -- a fair sum of +/-1 draws, i.e. binomial(4, 1/2) - 2. */
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        uint32_t t = load32_le(buf + 4 * i);
        uint32_t d = t & 0x55555555u;
        d += (t >> 1) & 0x55555555u;

        for (int j = 0; j < 8; j++)
        {
            int16_t a = (int16_t)((d >> (4 * j + 0)) & 0x3u);
            int16_t b = (int16_t)((d >> (4 * j + 2)) & 0x3u);
            coeffs[8 * i + j] = (int16_t)(a - b);
        }
    }
}
