#include "hexutil.h"

#include <stdio.h>
#include <string.h>

void
hex_encode(char *out, const uint8_t *in, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++)
    {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

static int
hex_val(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

int
hex_decode(uint8_t *out, size_t out_len, const char *hex)
{
    if (strlen(hex) != out_len * 2)
    {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++)
    {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
        {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
