#include "ring.h"

#include <stdlib.h>
#include <string.h>

static BIGNUM* g_q = NULL;

const BIGNUM*
ring_modulus(void)
{
    if (g_q == NULL)
    {
        if (BN_hex2bn(&g_q, TIBE_Q_HEX) == 0)
        {
            abort(); /* malformed TIBE_Q_HEX -- a build-time constant, not runtime input */
        }
    }
    return g_q;
}

void
ring_init(ring_elem* r)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        r->coeffs[i] = BN_new();
        BN_zero(r->coeffs[i]);
    }
}

void
ring_free(ring_elem* r)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_free(r->coeffs[i]);
        r->coeffs[i] = NULL;
    }
}

void
ring_zero(ring_elem* r)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_zero(r->coeffs[i]);
    }
}

void
ring_copy(ring_elem* dst, const ring_elem* src)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_copy(dst->coeffs[i], src->coeffs[i]);
    }
}

void
ring_add(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_add(out->coeffs[i], a->coeffs[i], b->coeffs[i], q, ctx);
    }
}

void
ring_sub(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_sub(out->coeffs[i], a->coeffs[i], b->coeffs[i], q, ctx);
    }
}

void
ring_neg(ring_elem* out, const ring_elem* a, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_sub(out->coeffs[i], zero, a->coeffs[i], q, ctx);
    }
    BN_free(zero);
}

void
ring_scalar_mul(ring_elem* out, const ring_elem* a, const BIGNUM* scalar, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_mod_mul(out->coeffs[i], a->coeffs[i], scalar, q, ctx);
    }
}

void
ring_mul(ring_elem* out, const ring_elem* a, const ring_elem* b, BN_CTX* ctx)
{
    /* Negacyclic convolution mod X^D+1: out[k] = sum_{i+j=k} a_i b_j -
     * sum_{i+j=k+D} a_i b_j, all mod q. `out` must not alias a or b. */
    const BIGNUM* q = ring_modulus();
    BIGNUM* prod = BN_new();

    ring_zero(out);
    for (int i = 0; i < TIBE_D; i++)
    {
        for (int j = 0; j < TIBE_D; j++)
        {
            int k = i + j;
            BN_mod_mul(prod, a->coeffs[i], b->coeffs[j], q, ctx);
            if (k < TIBE_D)
            {
                BN_mod_add(out->coeffs[k], out->coeffs[k], prod, q, ctx);
            }
            else
            {
                BN_mod_sub(out->coeffs[k - TIBE_D], out->coeffs[k - TIBE_D], prod, q, ctx);
            }
        }
    }
    BN_free(prod);
}

int
ring_eq(const ring_elem* a, const ring_elem* b)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        if (BN_cmp(a->coeffs[i], b->coeffs[i]) != 0)
        {
            return 0;
        }
    }
    return 1;
}

void
ring_random_uniform(ring_elem* out, BN_CTX* ctx)
{
    (void)ctx;
    const BIGNUM* q = ring_modulus();
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_rand_range(out->coeffs[i], q);
    }
}

size_t
ring_serialized_bytes(void)
{
    return (size_t)TIBE_D * (size_t)TIBE_Q_BYTES;
}

void
ring_serialize(uint8_t* out, const ring_elem* a)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_bn2binpad(a->coeffs[i], out + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES);
    }
}

void
ring_deserialize(ring_elem* out, const uint8_t* in)
{
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_bin2bn(in + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES, out->coeffs[i]);
    }
}
