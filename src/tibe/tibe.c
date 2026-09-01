#include "tibe.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gauss.h"

static void
ring_set_word_const(ring_elem* out, unsigned long value, BN_CTX* ctx)
{
    ring_zero(out);
    BN_set_word(out->coeffs[0], value);
    BN_nnmod(out->coeffs[0], out->coeffs[0], ring_modulus(), ctx);
}

/* floor(q^{1/3}) via binary search -- q is ~101 bits, so the search
 * space (candidate g values) is only ~34 bits; a handful of BN_sqr/
 * BN_mul calls per iteration is negligible next to this module's
 * O(D^2) ring operations. */
static void
compute_g(BIGNUM* g_out, const BIGNUM* q, BN_CTX* ctx)
{
    BIGNUM* lo = BN_new();
    BIGNUM* hi = BN_new();
    BIGNUM* mid = BN_new();
    BIGNUM* mid_cubed = BN_new();
    BN_zero(lo);
    BN_copy(hi, q); /* generous upper bound: cbrt(q) << q */

    while (BN_cmp(lo, hi) < 0)
    {
        BN_add(mid, lo, hi);
        BN_add_word(mid, 1);
        BN_rshift1(mid, mid); /* mid = ceil((lo+hi)/2) */
        BN_sqr(mid_cubed, mid, ctx);
        BN_mul(mid_cubed, mid_cubed, mid, ctx); /* mid^3 */
        if (BN_cmp(mid_cubed, q) <= 0)
        {
            BN_copy(lo, mid);
        }
        else
        {
            BN_copy(hi, mid);
            BN_sub_word(hi, 1);
        }
    }
    BN_copy(g_out, lo);

    BN_free(lo);
    BN_free(hi);
    BN_free(mid);
    BN_free(mid_cubed);
}

void
tibe_ek_init(tibe_ek* ek)
{
    for (int i = 0; i < 3; i++)
    {
        ring_init(&ek->A0[i]);
        ring_init(&ek->A1[i]);
        ring_init(&ek->A2[i]);
        ring_init(&ek->G[i]);
    }
    ring_init(&ek->r);
}

void
tibe_ek_free(tibe_ek* ek)
{
    for (int i = 0; i < 3; i++)
    {
        ring_free(&ek->A0[i]);
        ring_free(&ek->A1[i]);
        ring_free(&ek->A2[i]);
        ring_free(&ek->G[i]);
    }
    ring_free(&ek->r);
}

void
tibe_msk_init(tibe_msk* msk)
{
    ring_init(&msk->s_a);
    ring_init(&msk->e_a);
    ring_init(&msk->d0);
}

void
tibe_msk_free(tibe_msk* msk)
{
    ring_free(&msk->s_a);
    ring_free(&msk->e_a);
    ring_free(&msk->d0);
}

void
tibe_ct_init(tibe_ct* ct)
{
    for (int i = 0; i < 9; i++)
    {
        ring_init(&ct->u[i]);
    }
    ring_init(&ct->v);
}

void
tibe_ct_free(tibe_ct* ct)
{
    for (int i = 0; i < 9; i++)
    {
        ring_free(&ct->u[i]);
    }
    ring_free(&ct->v);
}

int
tibe_ct_eq(const tibe_ct* a, const tibe_ct* b)
{
    for (int i = 0; i < 9; i++)
    {
        if (!ring_eq(&a->u[i], &b->u[i]))
        {
            return 0;
        }
    }
    return ring_eq(&a->v, &b->v);
}

void
tibe_encode(ring_elem* out, const uint8_t msg[TIBE_MSG_BYTES], BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* half_q = BN_new();
    BN_rshift1(half_q, q); /* floor(q/2) */

    ring_zero(out);
    for (int i = 0; i < TIBE_D; i++)
    {
        int bit = (msg[i / 8] >> (i % 8)) & 1;
        if (bit)
        {
            BN_copy(out->coeffs[i], half_q);
        }
    }

    (void)ctx;
    BN_free(half_q);
}

void
tibe_decode(uint8_t msg_out[TIBE_MSG_BYTES], const ring_elem* m, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* q_quarter = BN_new();
    BIGNUM* q_three_quarter = BN_new();
    BN_rshift(q_quarter, q, 2);              /* floor(q/4) */
    BN_rshift1(q_three_quarter, q);          /* floor(q/2) */
    BN_add(q_three_quarter, q_three_quarter, q_quarter); /* ~ 3q/4 */

    memset(msg_out, 0, TIBE_MSG_BYTES);
    for (int i = 0; i < TIBE_D; i++)
    {
        /* bit=1 if the coefficient lands in (q/4, 3q/4) -- closer to
         * floor(q/2) (Encode's "1" value) than to 0. */
        int bit = (BN_cmp(m->coeffs[i], q_quarter) > 0 && BN_cmp(m->coeffs[i], q_three_quarter) < 0) ? 1 : 0;
        if (bit)
        {
            msg_out[i / 8] |= (uint8_t)(1u << (i % 8));
        }
    }

    (void)ctx;
    BN_free(q_quarter);
    BN_free(q_three_quarter);
}

void
tibe_setup(tibe_ek* ek, tibe_msk* msk, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();

    ring_elem a0, d2, a2, b2, b0, tmp, beta_elem, one, g_elem;
    ring_init(&a0);
    ring_init(&d2);
    ring_init(&a2);
    ring_init(&b2);
    ring_init(&b0);
    ring_init(&tmp);
    ring_init(&beta_elem);
    ring_init(&one);
    ring_init(&g_elem);

    /* d0, a0 <- R_q^x x R_q. Uniform sampling for d0: overwhelming
     * odds it lands in the unit group R_q^x (see test_ring.c's
     * test_inverse comment for why). d0 alone is retained in msk (not
     * freed at the end of this function): it's not published in ek,
     * but Decomp_beta(d0^-1*...) needs it directly in Decrypt/Combine
     * (Algorithm 7 line 5). a0 is only needed locally, to build A0/b0
     * -- Algorithm 5's round-0 blinding uses A0 directly (a proper
     * A0.p_i dot product, see threshold.c), not raw a0. */
    ring_random_uniform(&msk->d0, ctx);
    ring_random_uniform(&a0, ctx);

    /* (s_a, e_a) <- D_{R^2, sigma_a} */
    gauss_sample(&msk->s_a, TIBE_SIGMA_A, ctx);
    gauss_sample(&msk->e_a, TIBE_SIGMA_A, ctx);

    /* b0 = a0*s_a + e_a - beta */
    ring_mul(&tmp, &a0, &msk->s_a, ctx);
    ring_add(&b0, &tmp, &msk->e_a, ctx);
    BIGNUM* beta_bn = BN_new();
    BN_lshift(beta_bn, BN_value_one(), TIBE_BETA_LOG2);
    BN_nnmod(beta_bn, beta_bn, q, ctx);
    BN_copy(beta_elem.coeffs[0], beta_bn);
    ring_sub(&b0, &b0, &beta_elem, ctx);
    BN_free(beta_bn);

    ring_set_word_const(&one, 1, ctx);

    /* A0 := [1, a0, b0] * d0 */
    ring_mul(&ek->A0[0], &one, &msk->d0, ctx);
    ring_mul(&ek->A0[1], &a0, &msk->d0, ctx);
    ring_mul(&ek->A0[2], &b0, &msk->d0, ctx);

    /* A1 <- R_q^3 */
    ring_random_uniform(&ek->A1[0], ctx);
    ring_random_uniform(&ek->A1[1], ctx);
    ring_random_uniform(&ek->A1[2], ctx);

    /* A2 := [1, a2, b2] * d2, d2,a2,b2 <- R_q^x x R_q^2 */
    ring_random_uniform(&d2, ctx);
    ring_random_uniform(&a2, ctx);
    ring_random_uniform(&b2, ctx);
    ring_mul(&ek->A2[0], &one, &d2, ctx);
    ring_mul(&ek->A2[1], &a2, &d2, ctx);
    ring_mul(&ek->A2[2], &b2, &d2, ctx);

    /* G := [1, g, g^2], g ~ q^{1/3} (a fixed public constant, not random) */
    BIGNUM* g_bn = BN_new();
    compute_g(g_bn, q, ctx);
    BN_copy(g_elem.coeffs[0], g_bn);
    ring_copy(&ek->G[0], &one);
    ring_copy(&ek->G[1], &g_elem);
    ring_mul(&ek->G[2], &g_elem, &g_elem, ctx);
    BN_free(g_bn);

    /* r <- R_q */
    ring_random_uniform(&ek->r, ctx);

    ring_free(&a0);
    ring_free(&d2);
    ring_free(&a2);
    ring_free(&b2);
    ring_free(&b0);
    ring_free(&tmp);
    ring_free(&beta_elem);
    ring_free(&one);
    ring_free(&g_elem);
}

/* F_vk := [A0 | A1 - id*G | A2], written into a caller-supplied
 * (already ring_init'd) array of 9 ring elements. Shared between
 * Encrypt and the direct Decrypt below -- both need exactly this. */
static void
build_f_vk(ring_elem f_vk[9], const tibe_ek* ek, const ring_elem* id, BN_CTX* ctx)
{
    ring_elem id_g;
    ring_init(&id_g);
    for (int i = 0; i < 3; i++)
    {
        ring_copy(&f_vk[i], &ek->A0[i]);
        ring_mul(&id_g, id, &ek->G[i], ctx);
        ring_sub(&f_vk[3 + i], &ek->A1[i], &id_g, ctx);
        ring_copy(&f_vk[6 + i], &ek->A2[i]);
    }
    ring_free(&id_g);
}

/* 11 ring elements' worth of Box-Muller draws (s + e[9] + e'), 16
 * bytes (two 8-byte uniform01 draws) per coefficient. */
#define TIBE_ENCRYPT_PRG_BYTES ((size_t)11 * TIBE_D * 16)

void
tibe_encrypt_derand(tibe_ct* ct, const tibe_ek* ek, const ring_elem* id, const uint8_t msg[TIBE_MSG_BYTES],
                     const uint8_t seed[TIBE_ENCRYPT_SEED_BYTES], BN_CTX* ctx)
{
    ring_elem f_vk[9];
    for (int i = 0; i < 9; i++)
    {
        ring_init(&f_vk[i]);
    }
    build_f_vk(f_vk, ek, id, ctx);

    gauss_prg prg;
    gauss_prg_init(&prg, seed, TIBE_ENCRYPT_SEED_BYTES, TIBE_ENCRYPT_PRG_BYTES);

    /* s <- D_{R,sigma}: a single ring element -- see tibe.h's header
     * comment for why (forced by v's equation type-checking). */
    ring_elem s;
    ring_init(&s);
    gauss_sample_from_prg(&s, TIBE_SIGMA, &prg, ctx);

    /* e: 9 ring elements, middle third at width sigma', the rest at
     * sigma (Algorithm 4 line 3's "D_{R^3,sigma} x D_{R^3,sigma'} x
     * D_{R^3,sigma}" split). */
    ring_elem e[9];
    for (int i = 0; i < 9; i++)
    {
        ring_init(&e[i]);
        double width = (i >= 3 && i < 6) ? TIBE_SIGMA_PRIME : TIBE_SIGMA;
        gauss_sample_from_prg(&e[i], width, &prg, ctx);
    }

    ring_elem eprime;
    ring_init(&eprime);
    gauss_sample_from_prg(&eprime, TIBE_SIGMA, &prg, ctx);

    gauss_prg_free(&prg);

    /* u[k] := F_vk[k]*s + e[k] (F_vk^T*s is scalar broadcast since s
     * is a single ring element, per the header comment). */
    for (int i = 0; i < 9; i++)
    {
        ring_mul(&ct->u[i], &f_vk[i], &s, ctx);
        ring_add(&ct->u[i], &ct->u[i], &e[i], ctx);
    }

    /* v := r*s + e' + Encode(msg) */
    ring_elem encoded, r_s;
    ring_init(&encoded);
    ring_init(&r_s);
    tibe_encode(&encoded, msg, ctx);
    ring_mul(&r_s, &ek->r, &s, ctx);
    ring_add(&ct->v, &r_s, &eprime, ctx);
    ring_add(&ct->v, &ct->v, &encoded, ctx);

    for (int i = 0; i < 9; i++)
    {
        ring_free(&f_vk[i]);
        ring_free(&e[i]);
    }
    ring_free(&s);
    ring_free(&eprime);
    ring_free(&encoded);
    ring_free(&r_s);
}

void
tibe_encrypt(tibe_ct* ct, const tibe_ek* ek, const ring_elem* id, const uint8_t msg[TIBE_MSG_BYTES], BN_CTX* ctx)
{
    uint8_t seed[TIBE_ENCRYPT_SEED_BYTES];
    if (RAND_bytes(seed, sizeof(seed)) != 1)
    {
        fprintf(stderr, "tibe: RAND_bytes (encrypt seed) failed\n");
        abort();
    }
    tibe_encrypt_derand(ct, ek, id, msg, seed, ctx);
}

int
tibe_decrypt_direct(uint8_t msg_out[TIBE_MSG_BYTES], const tibe_ek* ek, const tibe_msk* msk, const ring_elem* id,
                     const tibe_ct* ct, BN_CTX* ctx)
{
    ring_elem f_vk[9];
    for (int i = 0; i < 9; i++)
    {
        ring_init(&f_vk[i]);
    }
    build_f_vk(f_vk, ek, id, ctx);

    /* Single virtual party, zero blinding: w = 0 (Algorithm 5's
     * y_{i,*} terms all involve blinding values this direct path never
     * samples -- see README.md "Phase 3"), so (c0,c1) :=
     * Decomp_beta(d0^-1 * r) directly. */
    ring_elem d0_inv, x, c0, c1;
    ring_init(&d0_inv);
    ring_init(&x);
    ring_init(&c0);
    ring_init(&c1);
    ring_inv(&d0_inv, &msk->d0, ctx);
    ring_mul(&x, &d0_inv, &ek->r, ctx);
    ring_decomp_beta(&c0, &c1, &x, ctx);

    /* z0 = c0*e_a + c1, z1 = c0*s_a, z2 = -c0; x0 = x1 = 0 (3 elements
     * each). Algorithm 7 lines 6-8 / Algorithm 8 lines 1-3 read
     * literally give z2 = +c0 with every per-shareholder blinding term
     * zeroed, but that does not satisfy Algorithm 8 line 7's own
     * F_vk*z==r assertion -- confirmed algebraically (see
     * scripts/tibe_algebra_check.py-style toy-ring symbolic check, not
     * committed here, redone by hand below) that z2 = -c0 is what
     * actually cancels the b0 = a0*s_a+e_a-beta term against A0's
     * d0*c0*beta target correctly: A0.z = d0*c1 + d0*c0*(e_a + a0*s_a
     * + b0) with z2=+c0, which needs e_a+a0*s_a+b0=beta and does NOT
     * hold for the paper's b0; with z2=-c0, A0.z = d0*c1 - d0*c0*b0 +
     * d0*c0*(-(e_a+a0*s_a)) after resubstituting reduces correctly to
     * d0*c0*beta+d0*c1 = r. Either the paper's own sign convention for
     * Decomp_beta or z_{i,2} differs from what PDF extraction rendered
     * here, or this is a transcription artifact -- flagged in
     * BCHK_TODO.md for Phase 5 to re-derive independently against the
     * real (threshold) Algorithm 7/8 rather than assuming this
     * direct-decrypt fix generalizes unchanged. */
    ring_elem z[9];
    for (int i = 0; i < 9; i++)
    {
        ring_init(&z[i]);
    }
    ring_mul(&z[0], &c0, &msk->e_a, ctx);
    ring_add(&z[0], &z[0], &c1, ctx);
    ring_mul(&z[1], &c0, &msk->s_a, ctx);
    ring_neg(&z[2], &c0, ctx);
    /* z[3..8] stay zero (x0, x1) */

    /* Algorithm 8 line 7's own correctness assertion: F_vk . z == r. */
    ring_elem lhs, term;
    ring_init(&lhs);
    ring_init(&term);
    for (int i = 0; i < 9; i++)
    {
        ring_mul(&term, &f_vk[i], &z[i], ctx);
        ring_add(&lhs, &lhs, &term, ctx);
    }
    int ok = ring_eq(&lhs, &ek->r);

    if (ok)
    {
        /* msg := Decode(v - z^T*u) */
        ring_elem zu, m;
        ring_init(&zu);
        ring_init(&m);
        for (int i = 0; i < 9; i++)
        {
            ring_mul(&term, &z[i], &ct->u[i], ctx);
            ring_add(&zu, &zu, &term, ctx);
        }
        ring_sub(&m, &ct->v, &zu, ctx);
        tibe_decode(msg_out, &m, ctx);
        ring_free(&zu);
        ring_free(&m);
    }

    for (int i = 0; i < 9; i++)
    {
        ring_free(&f_vk[i]);
        ring_free(&z[i]);
    }
    ring_free(&d0_inv);
    ring_free(&x);
    ring_free(&c0);
    ring_free(&c1);
    ring_free(&lhs);
    ring_free(&term);

    return ok;
}
