#include "reduce.h"
#include "params.h"

int16_t
montgomery_reduce(int32_t a)
{
    /* t = a * QINV mod 2^16, computed via the natural int16_t wraparound */
    int16_t t = (int16_t)((int32_t)(int16_t)a * KYBER_QINV);
    return (int16_t)((a - (int32_t)t * KYBER_Q) >> 16);
}

int16_t
barrett_reduce(int16_t a)
{
    /* v approximates 2^26 / q; multiplying by v and shifting right by 26
     * computes floor(a/q) without a division instruction. */
    const int32_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    int32_t t = ((int32_t)v * a + (1 << 25)) >> 26;
    return (int16_t)(a - t * KYBER_Q);
}

int16_t
fq_mul(int16_t a, int16_t b)
{
    return montgomery_reduce((int32_t)a * b);
}
