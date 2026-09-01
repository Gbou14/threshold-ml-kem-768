#include "threshold.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gauss.h"

/* Self-contained SHAKE-256 XOF, matching the pattern already used in
 * identity.c/wots.c (each file owns its own small hash wrapper rather
 * than sharing one, consistent with this module's independence from
 * src/kyber/). */
static void
shake256_xof(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!md || !mctx || !EVP_DigestInit_ex2(mctx, md, NULL) || !EVP_DigestUpdate(mctx, in, inlen) ||
        !EVP_DigestFinalXOF(mctx, out, outlen))
    {
        fprintf(stderr, "tibe/threshold: OpenSSL SHAKE256 XOF failed\n");
        abort();
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
}

static void
domain_prefix(uint8_t out[32], uint8_t constant)
{
    memset(out, 0, 32);
    out[31] = constant;
}

/* H_cmt : R_q -> {0,1}^{2*kappa} (BCHK_PAPER_SPEC.md Sec 4.2). */
static void
h_cmt(uint8_t out[TIBE_CMT_BYTES], const ring_elem* w)
{
    size_t ring_bytes = ring_serialized_bytes();
    uint8_t* buf = malloc(32 + ring_bytes);
    domain_prefix(buf, 0);
    ring_serialize(buf + 32, w);
    shake256_xof(out, TIBE_CMT_BYTES, buf, 32 + ring_bytes);
    free(buf);
}

/* H_mask : {0,1}^* -> R_q^2 (BCHK_PAPER_SPEC.md Sec 4.2). */
static void
h_mask(ring_elem* out0, ring_elem* out1, const uint8_t seed[TIBE_SEED_BYTES], const uint8_t* ctnt, size_t ctnt_len,
       BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    size_t ring_bytes = ring_serialized_bytes();
    size_t inlen = 32 + TIBE_SEED_BYTES + ctnt_len;
    uint8_t* in = malloc(inlen);
    domain_prefix(in, 1);
    memcpy(in + 32, seed, TIBE_SEED_BYTES);
    memcpy(in + 32 + TIBE_SEED_BYTES, ctnt, ctnt_len);

    uint8_t* out = malloc(2 * ring_bytes);
    shake256_xof(out, 2 * ring_bytes, in, inlen);

    for (int i = 0; i < TIBE_D; i++)
    {
        BN_bin2bn(out + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES, out0->coeffs[i]);
        BN_nnmod(out0->coeffs[i], out0->coeffs[i], q, ctx);
    }
    for (int i = 0; i < TIBE_D; i++)
    {
        BN_bin2bn(out + ring_bytes + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES, out1->coeffs[i]);
        BN_nnmod(out1->coeffs[i], out1->coeffs[i], q, ctx);
    }

    free(in);
    free(out);
}

/* Derives the two directional sub-seeds from a shared pairwise secret
 * (see threshold.h's header comment: the dealer hands both parties in
 * a pair the same pairseed, and each derives seed_{i->j}/seed_{j->i}
 * independently via domain-separated hashing). */
static void
derive_directional_seed(uint8_t out[TIBE_SEED_BYTES], const uint8_t pairseed[TIBE_SEED_BYTES], int from_x, int to_x)
{
    uint8_t in[32 + TIBE_SEED_BYTES + 8];
    domain_prefix(in, 2);
    memcpy(in + 32, pairseed, TIBE_SEED_BYTES);
    uint32_t from32 = (uint32_t)from_x;
    uint32_t to32 = (uint32_t)to_x;
    in[32 + TIBE_SEED_BYTES + 0] = (uint8_t)(from32 >> 24);
    in[32 + TIBE_SEED_BYTES + 1] = (uint8_t)(from32 >> 16);
    in[32 + TIBE_SEED_BYTES + 2] = (uint8_t)(from32 >> 8);
    in[32 + TIBE_SEED_BYTES + 3] = (uint8_t)(from32);
    in[32 + TIBE_SEED_BYTES + 4] = (uint8_t)(to32 >> 24);
    in[32 + TIBE_SEED_BYTES + 5] = (uint8_t)(to32 >> 16);
    in[32 + TIBE_SEED_BYTES + 6] = (uint8_t)(to32 >> 8);
    in[32 + TIBE_SEED_BYTES + 7] = (uint8_t)(to32);
    shake256_xof(out, TIBE_SEED_BYTES, in, sizeof(in));
}

/* ctnt = act || ct || {cmt_j, w_j}_{j in act} (Algorithm 7 line 2),
 * serialized canonically for hashing. Caller frees the returned
 * buffer. */
static uint8_t*
build_ctnt(size_t* len_out, const int* act_x, int act_size, const tibe_ct* ct, const uint8_t (*cmts)[TIBE_CMT_BYTES],
           const ring_elem* ws)
{
    size_t ring_bytes = ring_serialized_bytes();
    size_t total = (size_t)act_size * 4 + 9 * ring_bytes + ring_bytes +
                   (size_t)act_size * (TIBE_CMT_BYTES + ring_bytes);
    uint8_t* buf = malloc(total);
    uint8_t* p = buf;

    for (int i = 0; i < act_size; i++)
    {
        uint32_t x = (uint32_t)act_x[i];
        p[0] = (uint8_t)(x >> 24);
        p[1] = (uint8_t)(x >> 16);
        p[2] = (uint8_t)(x >> 8);
        p[3] = (uint8_t)(x);
        p += 4;
    }
    for (int i = 0; i < 9; i++)
    {
        ring_serialize(p, &ct->u[i]);
        p += ring_bytes;
    }
    ring_serialize(p, &ct->v);
    p += ring_bytes;

    for (int i = 0; i < act_size; i++)
    {
        memcpy(p, cmts[i], TIBE_CMT_BYTES);
        p += TIBE_CMT_BYTES;
        ring_serialize(p, &ws[i]);
        p += ring_bytes;
    }

    *len_out = total;
    return buf;
}

static void
lagrange_coeff_at_zero(BIGNUM* out, int my_x, const int* act_x, int act_size, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* num = BN_new();
    BIGNUM* den = BN_new();
    BIGNUM* xi = BN_new();
    BIGNUM* xj = BN_new();
    BIGNUM* tmp = BN_new();
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    BN_one(num);
    BN_one(den);
    BN_set_word(xi, (unsigned long)my_x);

    for (int k = 0; k < act_size; k++)
    {
        if (act_x[k] == my_x)
        {
            continue;
        }
        BN_set_word(xj, (unsigned long)act_x[k]);

        BN_mod_sub(tmp, zero, xj, q, ctx); /* 0 - xj */
        BN_mod_mul(num, num, tmp, q, ctx);

        BN_mod_sub(tmp, xi, xj, q, ctx); /* xi - xj */
        BN_mod_mul(den, den, tmp, q, ctx);
    }

    BIGNUM* den_inv = BN_new();
    BN_mod_inverse(den_inv, den, q, ctx);
    BN_mod_mul(out, num, den_inv, q, ctx);

    BN_free(num);
    BN_free(den);
    BN_free(xi);
    BN_free(xj);
    BN_free(tmp);
    BN_free(zero);
    BN_free(den_inv);
}

/* Coefficient-wise (T,[N])-Shamir sharing of one ring element:
 * degree-<T polynomials over Z_q, secret at x=0, evaluated via Horner
 * at x=1..N -- same construction as src/kyber/threshold.c's
 * threshold_split_secret, generalized from int32/mod-3329 to
 * BIGNUM/mod-q. */
static void
shamir_share_ring_elem(ring_elem shares_out[TIBE_N], const ring_elem* secret, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* coeffs[TIBE_T];
    for (int j = 0; j < TIBE_T; j++)
    {
        coeffs[j] = BN_new();
    }
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* power = BN_new();
    BIGNUM* term = BN_new();

    for (int c = 0; c < TIBE_D; c++)
    {
        BN_copy(coeffs[0], secret->coeffs[c]);
        for (int j = 1; j < TIBE_T; j++)
        {
            BN_rand_range(coeffs[j], q);
        }
        for (int i = 0; i < TIBE_N; i++)
        {
            BN_set_word(x, (unsigned long)(i + 1));
            BN_zero(y);
            BN_one(power);
            for (int j = 0; j < TIBE_T; j++)
            {
                BN_mod_mul(term, coeffs[j], power, q, ctx);
                BN_mod_add(y, y, term, q, ctx);
                BN_mod_mul(power, power, x, q, ctx);
            }
            BN_copy(shares_out[i].coeffs[c], y);
        }
    }

    for (int j = 0; j < TIBE_T; j++)
    {
        BN_free(coeffs[j]);
    }
    BN_free(x);
    BN_free(y);
    BN_free(power);
    BN_free(term);
}

void
threshold_share_init(threshold_share* s)
{
    ring_init(&s->share_s_a);
    ring_init(&s->share_e_a);
    ring_init(&s->d0);
    memset(s->pairwise_seed, 0, sizeof(s->pairwise_seed));
}

void
threshold_share_free(threshold_share* s)
{
    ring_free(&s->share_s_a);
    ring_free(&s->share_e_a);
    ring_free(&s->d0);
}

void
threshold_round0_state_init(threshold_round0_state* s)
{
    for (int i = 0; i < 3; i++)
    {
        ring_init(&s->x0[i]);
        ring_init(&s->x1[i]);
        ring_init(&s->p[i]);
    }
    ring_init(&s->w);
}

void
threshold_round0_state_free(threshold_round0_state* s)
{
    for (int i = 0; i < 3; i++)
    {
        ring_free(&s->x0[i]);
        ring_free(&s->x1[i]);
        ring_free(&s->p[i]);
    }
    ring_free(&s->w);
}

void
threshold_contrib2_init(threshold_contrib2* c)
{
    for (int i = 0; i < 3; i++)
    {
        ring_init(&c->z[i]);
        ring_init(&c->x0[i]);
        ring_init(&c->x1[i]);
    }
}

void
threshold_contrib2_free(threshold_contrib2* c)
{
    for (int i = 0; i < 3; i++)
    {
        ring_free(&c->z[i]);
        ring_free(&c->x0[i]);
        ring_free(&c->x1[i]);
    }
}

void
threshold_setup(threshold_share shares_out[TIBE_N], const tibe_msk* msk, BN_CTX* ctx)
{
    for (int i = 0; i < TIBE_N; i++)
    {
        shares_out[i].x = i + 1;
        ring_copy(&shares_out[i].d0, &msk->d0);
    }

    ring_elem s_a_shares[TIBE_N];
    ring_elem e_a_shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        ring_init(&s_a_shares[i]);
        ring_init(&e_a_shares[i]);
    }
    shamir_share_ring_elem(s_a_shares, &msk->s_a, ctx);
    shamir_share_ring_elem(e_a_shares, &msk->e_a, ctx);
    for (int i = 0; i < TIBE_N; i++)
    {
        ring_copy(&shares_out[i].share_s_a, &s_a_shares[i]);
        ring_copy(&shares_out[i].share_e_a, &e_a_shares[i]);
        ring_free(&s_a_shares[i]);
        ring_free(&e_a_shares[i]);
    }

    /* Pairwise seeds: one shared secret per unordered pair {i,j},
     * i<j, both parties receive it directly from the dealer (matching
     * Remark 1's "distributed over a secure channel" trust model) and
     * derive both directional sub-seeds from it themselves. */
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int j = i + 1; j < TIBE_N; j++)
        {
            uint8_t pairseed[TIBE_SEED_BYTES];
            if (RAND_bytes(pairseed, sizeof(pairseed)) != 1)
            {
                fprintf(stderr, "tibe/threshold: RAND_bytes (pairseed) failed\n");
                abort();
            }
            memcpy(shares_out[i].pairwise_seed[j], pairseed, TIBE_SEED_BYTES);
            memcpy(shares_out[j].pairwise_seed[i], pairseed, TIBE_SEED_BYTES);
        }
    }
}

void
threshold_round0(uint8_t cmt_out[TIBE_CMT_BYTES], threshold_round0_state* state, const tibe_ek* ek,
                  const ring_elem* id, BN_CTX* ctx)
{
    for (int i = 0; i < 3; i++)
    {
        gauss_sample(&state->x0[i], TIBE_SIGMA_P, ctx);
        gauss_sample(&state->x1[i], TIBE_SIGMA_P, ctx);
        gauss_sample(&state->p[i], TIBE_SIGMA_P, ctx);
    }

    ring_elem y0, y1, y2, tmp, tmp2, id_g;
    ring_init(&y0);
    ring_init(&y1);
    ring_init(&y2);
    ring_init(&tmp);
    ring_init(&tmp2);
    ring_init(&id_g);

    /* y0 = A0 . p -- see threshold.h's header comment: a proper
     * 3-vector dot product against the published A0, matching y1/y2's
     * own pattern (an earlier reading of this line as the scalar
     * "a0*p_0+p_1" using raw, unpublished a0 was a transcription slip
     * that made the full multi-party correctness algebra not close). */
    ring_zero(&y0);
    for (int k = 0; k < 3; k++)
    {
        ring_mul(&tmp2, &ek->A0[k], &state->p[k], ctx);
        ring_add(&y0, &y0, &tmp2, ctx);
    }

    /* y1 = (A1 - id*G) . x0 */
    ring_zero(&y1);
    for (int k = 0; k < 3; k++)
    {
        ring_mul(&id_g, id, &ek->G[k], ctx);
        ring_sub(&tmp, &ek->A1[k], &id_g, ctx);
        ring_mul(&tmp2, &tmp, &state->x0[k], ctx);
        ring_add(&y1, &y1, &tmp2, ctx);
    }

    /* y2 = A2 . x1 */
    ring_zero(&y2);
    for (int k = 0; k < 3; k++)
    {
        ring_mul(&tmp2, &ek->A2[k], &state->x1[k], ctx);
        ring_add(&y2, &y2, &tmp2, ctx);
    }

    ring_add(&state->w, &y0, &y1, ctx);
    ring_add(&state->w, &state->w, &y2, ctx);

    h_cmt(cmt_out, &state->w);

    ring_free(&y0);
    ring_free(&y1);
    ring_free(&y2);
    ring_free(&tmp);
    ring_free(&tmp2);
    ring_free(&id_g);
}

void
threshold_round1(ring_elem* w_out, const threshold_round0_state* state)
{
    ring_copy(w_out, &state->w);
}

int
threshold_round2(threshold_contrib2* out, const threshold_round0_state* state, const threshold_share* my_share,
                  const tibe_ek* ek, const tibe_ct* ct, const int* act_x, int act_size, int my_index,
                  const uint8_t (*cmts)[TIBE_CMT_BYTES], const ring_elem* ws, BN_CTX* ctx)
{
    /* Algorithm 7 line 1: catch anyone who lied about w_j in round 1. */
    for (int k = 0; k < act_size; k++)
    {
        if (k == my_index)
        {
            continue;
        }
        uint8_t recomputed[TIBE_CMT_BYTES];
        h_cmt(recomputed, &ws[k]);
        if (memcmp(recomputed, cmts[k], TIBE_CMT_BYTES) != 0)
        {
            return 0;
        }
    }

    size_t ctnt_len;
    uint8_t* ctnt = build_ctnt(&ctnt_len, act_x, act_size, ct, cmts, ws);

    /* m_i = sum_j H_mask(seed_{i->j}, ctnt) - sum_j H_mask(seed_{j->i}, ctnt) */
    ring_elem m0, m1, h0, h1;
    ring_init(&m0);
    ring_init(&m1);
    ring_init(&h0);
    ring_init(&h1);
    for (int k = 0; k < act_size; k++)
    {
        if (act_x[k] == my_share->x)
        {
            continue;
        }
        uint8_t seed_out[TIBE_SEED_BYTES], seed_in[TIBE_SEED_BYTES];
        derive_directional_seed(seed_out, my_share->pairwise_seed[act_x[k] - 1], my_share->x, act_x[k]);
        derive_directional_seed(seed_in, my_share->pairwise_seed[act_x[k] - 1], act_x[k], my_share->x);

        h_mask(&h0, &h1, seed_out, ctnt, ctnt_len, ctx);
        ring_add(&m0, &m0, &h0, ctx);
        ring_add(&m1, &m1, &h1, ctx);

        h_mask(&h0, &h1, seed_in, ctnt, ctnt_len, ctx);
        ring_sub(&m0, &m0, &h0, ctx);
        ring_sub(&m1, &m1, &h1, ctx);
    }
    free(ctnt);

    /* w = sum_j w_j */
    ring_elem w;
    ring_init(&w);
    for (int k = 0; k < act_size; k++)
    {
        ring_add(&w, &w, &ws[k], ctx);
    }

    /* (c0,c1) := Decomp_beta(d0^-1 * (r - w)) */
    ring_elem d0_inv, r_minus_w, x_arg, c0, c1;
    ring_init(&d0_inv);
    ring_init(&r_minus_w);
    ring_init(&x_arg);
    ring_init(&c0);
    ring_init(&c1);
    ring_inv(&d0_inv, &my_share->d0, ctx);
    ring_sub(&r_minus_w, &ek->r, &w, ctx);
    ring_mul(&x_arg, &d0_inv, &r_minus_w, ctx);
    ring_decomp_beta(&c0, &c1, &x_arg, ctx);

    /* lambda_{i,act} */
    BIGNUM* lambda = BN_new();
    lagrange_coeff_at_zero(lambda, my_share->x, act_x, act_size, ctx);

    /* z0 = p0 + c0*lambda*[[e_a]]_i + m0
     * z1 = p1 + c0*lambda*[[s_a]]_i + m1
     * z2 = p2 */
    ring_elem scaled_share, term;
    ring_init(&scaled_share);
    ring_init(&term);

    ring_scalar_mul(&scaled_share, &my_share->share_e_a, lambda, ctx);
    ring_mul(&term, &c0, &scaled_share, ctx);
    ring_add(&out->z[0], &state->p[0], &term, ctx);
    ring_add(&out->z[0], &out->z[0], &m0, ctx);

    ring_scalar_mul(&scaled_share, &my_share->share_s_a, lambda, ctx);
    ring_mul(&term, &c0, &scaled_share, ctx);
    ring_add(&out->z[1], &state->p[1], &term, ctx);
    ring_add(&out->z[1], &out->z[1], &m1, ctx);

    ring_copy(&out->z[2], &state->p[2]);

    ring_copy(&out->x0[0], &state->x0[0]);
    ring_copy(&out->x0[1], &state->x0[1]);
    ring_copy(&out->x0[2], &state->x0[2]);
    ring_copy(&out->x1[0], &state->x1[0]);
    ring_copy(&out->x1[1], &state->x1[1]);
    ring_copy(&out->x1[2], &state->x1[2]);

    BN_free(lambda);
    ring_free(&m0);
    ring_free(&m1);
    ring_free(&h0);
    ring_free(&h1);
    ring_free(&w);
    ring_free(&d0_inv);
    ring_free(&r_minus_w);
    ring_free(&x_arg);
    ring_free(&c0);
    ring_free(&c1);
    ring_free(&scaled_share);
    ring_free(&term);

    return 1;
}

int
threshold_combine(uint8_t msg_out[TIBE_MSG_BYTES], const tibe_ek* ek, const ring_elem* id, const tibe_ct* ct,
                   const ring_elem* d0, const int* act_x, int act_size, const ring_elem* ws,
                   const threshold_contrib2* contribs, BN_CTX* ctx)
{
    /* act_x isn't otherwise referenced below: Algorithm 8's own
     * formula only sums over contribs/ws positionally, and the caller
     * is responsible for having built contribs/ws in the same order
     * as act_x -- kept as a parameter for interface clarity/parity
     * with the paper's Combine(ct,vk,act,...) signature, not because
     * this function's body needs the actual x-coordinates. */
    (void)act_x;

    /* w = sum_j w_j; (c0,c1) := Decomp_beta(d0^-1*(r-w)) -- same
     * public-data-derivable computation every active party already
     * did locally in round 2; recomputed independently here rather
     * than trusting/reusing one party's value, at the cost of one
     * more ring_inv (see threshold.h's header comment). */
    ring_elem w;
    ring_init(&w);
    for (int k = 0; k < act_size; k++)
    {
        ring_add(&w, &w, &ws[k], ctx);
    }

    ring_elem d0_inv, r_minus_w, x_arg, c0, c1;
    ring_init(&d0_inv);
    ring_init(&r_minus_w);
    ring_init(&x_arg);
    ring_init(&c0);
    ring_init(&c1);
    ring_inv(&d0_inv, d0, ctx);
    ring_sub(&r_minus_w, &ek->r, &w, ctx);
    ring_mul(&x_arg, &d0_inv, &r_minus_w, ctx);
    ring_decomp_beta(&c0, &c1, &x_arg, ctx);

    /* z0 = sum(z_{i,0}) + c1
     * z1 = sum(z_{i,1})
     * z2 = sum(z_{i,2}) - c0   [see threshold.h: the paper's Algorithm 8
     *                            line 3 literally reads "+c0", but that
     *                            does not satisfy this function's own
     *                            F_vk*z==r assertion below -- Phase 3
     *                            found this exact sign issue for the
     *                            single-party stand-in, re-confirmed
     *                            here independently for the real
     *                            multi-party protocol]
     * x0 = sum(x_{i,0}), x1 = sum(x_{i,1}) */
    ring_elem z[9];
    for (int i = 0; i < 9; i++)
    {
        ring_init(&z[i]);
    }
    for (int k = 0; k < act_size; k++)
    {
        ring_add(&z[0], &z[0], &contribs[k].z[0], ctx);
        ring_add(&z[1], &z[1], &contribs[k].z[1], ctx);
        ring_add(&z[2], &z[2], &contribs[k].z[2], ctx);
        for (int i = 0; i < 3; i++)
        {
            ring_add(&z[3 + i], &z[3 + i], &contribs[k].x0[i], ctx);
            ring_add(&z[6 + i], &z[6 + i], &contribs[k].x1[i], ctx);
        }
    }
    ring_add(&z[0], &z[0], &c1, ctx);
    ring_sub(&z[2], &z[2], &c0, ctx);

    /* F_vk := [A0 | A1 - id*G | A2]; assert F_vk . z == r; decode. */
    ring_elem f_vk[9];
    for (int i = 0; i < 9; i++)
    {
        ring_init(&f_vk[i]);
    }
    ring_elem id_g;
    ring_init(&id_g);
    for (int i = 0; i < 3; i++)
    {
        ring_copy(&f_vk[i], &ek->A0[i]);
        ring_mul(&id_g, id, &ek->G[i], ctx);
        ring_sub(&f_vk[3 + i], &ek->A1[i], &id_g, ctx);
        ring_copy(&f_vk[6 + i], &ek->A2[i]);
    }

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

    ring_free(&w);
    ring_free(&d0_inv);
    ring_free(&r_minus_w);
    ring_free(&x_arg);
    ring_free(&c0);
    ring_free(&c1);
    for (int i = 0; i < 9; i++)
    {
        ring_free(&z[i]);
        ring_free(&f_vk[i]);
    }
    ring_free(&id_g);
    ring_free(&lhs);
    ring_free(&term);

    return ok;
}
