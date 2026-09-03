#include "v3s.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gauss.h" /* gauss_sample_coeff() */
#include "ring.h"  /* ring_modulus() */

/* Self-contained SHAKE-256 XOF, matching the pattern already used
 * throughout this module (identity.c/wots.c/threshold.c/merkle.c). */
static void
shake256_xof(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!md || !mctx || !EVP_DigestInit_ex2(mctx, md, NULL) || !EVP_DigestUpdate(mctx, in, inlen) ||
        !EVP_DigestFinalXOF(mctx, out, outlen))
    {
        fprintf(stderr, "tibe/v3s: OpenSSL SHAKE256 XOF failed\n");
        abort();
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
}

void
v3s_matrix_derive(v3s_matrix* R, const uint8_t seed[MERKLE_HASH_BYTES])
{
    size_t n_entries = (size_t)V3S_DIM_Y * V3S_DIM_X;
    size_t n_bytes = (n_entries + 3) / 4; /* 2 bits/entry, 4 entries/byte */
    uint8_t* buf = malloc(n_bytes);
    shake256_xof(buf, n_bytes, seed, MERKLE_HASH_BYTES);

    size_t idx = 0;
    for (int r = 0; r < V3S_DIM_Y; r++)
    {
        for (int c = 0; c < V3S_DIM_X; c++)
        {
            uint8_t byte = buf[idx / 4];
            int shift = (int)(idx % 4) * 2;
            uint8_t bits = (byte >> shift) & 0x3;
            /* 00,01 -> 0 (p=1/2); 10 -> +1 (p=1/4); 11 -> -1 (p=1/4) */
            int8_t v = (bits == 0x2) ? 1 : (bits == 0x3) ? -1 : 0;
            R->entries[r][c] = v;
            idx++;
        }
    }
    free(buf);
}

static void
bn_from_balanced_int64(BIGNUM* out, int64_t v, const BIGNUM* q, BN_CTX* ctx)
{
    uint64_t mag = (uint64_t)(v < 0 ? -v : v);
    BN_set_word(out, mag);
    if (v < 0)
    {
        BN_set_negative(out, 1);
    }
    BN_nnmod(out, out, q, ctx);
}

/* Coefficient-wise (T,[N])-Shamir sharing of one scalar mod-q secret
 * -- same construction as threshold.c's shamir_share_ring_elem
 * (itself generalized from src/kyber/threshold.c's
 * threshold_split_secret), applied here to one V3S coordinate at a
 * time (called V3S_DIM_X or V3S_DIM_Y times per v3s_share call)
 * rather than looping TIBE_D coefficients internally -- kept
 * self-contained in this file rather than exposed from threshold.c,
 * matching this project's established practice of each file owning
 * its own small primitives (see threshold.c's own SHAKE-256 wrapper
 * comment). */
static void
shamir_share_scalar(BIGNUM* shares_out[TIBE_N], int64_t secret_value, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    BIGNUM* coeffs[TIBE_T];
    for (int j = 0; j < TIBE_T; j++)
    {
        coeffs[j] = BN_new();
    }
    bn_from_balanced_int64(coeffs[0], secret_value, q, ctx);
    for (int j = 1; j < TIBE_T; j++)
    {
        BN_rand_range(coeffs[j], q);
    }

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* power = BN_new();
    BIGNUM* term = BN_new();
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
        BN_copy(shares_out[i], y);
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

/* acc := R . vec (mod q), a length-V3S_DIM_Y output from a
 * length-V3S_DIM_X input, R ternary. The dominant cost in this whole
 * module: V3S_DIM_Y*V3S_DIM_X = 2,097,152 conditional BIGNUM mod-add/
 * sub calls. */
static void
matvec_mul(BIGNUM* out[V3S_DIM_Y], const v3s_matrix* R, BIGNUM* const vec[V3S_DIM_X], const BIGNUM* q, BN_CTX* ctx)
{
    for (int r = 0; r < V3S_DIM_Y; r++)
    {
        BN_zero(out[r]);
        for (int c = 0; c < V3S_DIM_X; c++)
        {
            int8_t e = R->entries[r][c];
            if (e == 1)
            {
                BN_mod_add(out[r], out[r], vec[c], q, ctx);
            }
            else if (e == -1)
            {
                BN_mod_sub(out[r], out[r], vec[c], q, ctx);
            }
        }
    }
}

/* L_{my_x}(eval_x) = prod_{m != my_x, m in act_x} (eval_x - x_m)/(my_x - x_m) mod q --
 * the Lagrange basis polynomial for the party at x-coordinate my_x,
 * evaluated at an arbitrary point eval_x (not just 0), over the
 * points in act_x. Generalizes threshold.c's own lagrange_coeff_at_zero
 * (kept separate here, matching this project's per-file-owns-its-own-
 * primitives convention) since V3S.Reconstruct's soundness check
 * (Algorithm 3, step 3) needs to evaluate the interpolated polynomial
 * at points other than 0. */
static void
lagrange_coeff_at(BIGNUM* out, int eval_x, int my_x, const int* act_x, int act_size, const BIGNUM* q, BN_CTX* ctx)
{
    BIGNUM* num = BN_new();
    BIGNUM* den = BN_new();
    BIGNUM* xi = BN_new();
    BIGNUM* xj = BN_new();
    BIGNUM* tmp = BN_new();
    BIGNUM* ex = BN_new();
    BN_set_word(ex, (unsigned long)eval_x);
    BN_one(num);
    BN_one(den);
    BN_set_word(xi, (unsigned long)my_x);
    for (int m = 0; m < act_size; m++)
    {
        if (act_x[m] == my_x)
        {
            continue;
        }
        BN_set_word(xj, (unsigned long)act_x[m]);
        BN_mod_sub(tmp, ex, xj, q, ctx); /* eval_x - xj */
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
    BN_free(ex);
    BN_free(den_inv);
}

/* Converts a canonical [0,q) BIGNUM to a signed int64_t via its
 * balanced representative in (-q/2, q/2] -- exact/lossless here since
 * this module's actual values are always many orders of magnitude
 * smaller than q. */
static int64_t
bn_to_balanced_int64(const BIGNUM* v, const BIGNUM* q, const BIGNUM* q_half)
{
    if (BN_cmp(v, q_half) <= 0)
    {
        return (int64_t)BN_get_word(v);
    }
    BIGNUM* mag = BN_new();
    BN_sub(mag, q, v);
    int64_t result = -(int64_t)BN_get_word(mag);
    BN_free(mag);
    return result;
}

/* Fixed-width (TIBE_Q_BYTES) serialization of a coefficient array,
 * matching ring.c's ring_serialize convention. */
static void
serialize_coeffs(uint8_t* out, BIGNUM* const* coeffs, int n)
{
    for (int i = 0; i < n; i++)
    {
        BN_bn2binpad(coeffs[i], out + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES);
    }
}

static void
deserialize_coeffs(BIGNUM* const* coeffs, const uint8_t* in, int n)
{
    for (int i = 0; i < n; i++)
    {
        BN_bin2bn(in + (size_t)i * TIBE_Q_BYTES, TIBE_Q_BYTES, coeffs[i]);
    }
}

static void
leaf_hash(uint8_t out[MERKLE_HASH_BYTES], BIGNUM* const x_share[V3S_DIM_X], BIGNUM* const y_share[V3S_DIM_Y],
          const uint8_t nonce[MERKLE_HASH_BYTES])
{
    size_t x_bytes = (size_t)V3S_DIM_X * TIBE_Q_BYTES;
    size_t y_bytes = (size_t)V3S_DIM_Y * TIBE_Q_BYTES;
    size_t total = 1 + x_bytes + y_bytes + MERKLE_HASH_BYTES;
    uint8_t* buf = malloc(total);
    buf[0] = 0x02; /* domain byte: distinct from threshold.c's h_cmt(0)/h_mask(1) convention */
    serialize_coeffs(buf + 1, x_share, V3S_DIM_X);
    serialize_coeffs(buf + 1 + x_bytes, y_share, V3S_DIM_Y);
    memcpy(buf + 1 + x_bytes + y_bytes, nonce, MERKLE_HASH_BYTES);
    shake256_xof(out, MERKLE_HASH_BYTES, buf, total);
    free(buf);
}

void
v3s_share(v3s_share_output* out, const v3s_secret* x, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();

    for (int i = 0; i < TIBE_N; i++)
    {
        for (int c = 0; c < V3S_DIM_X; c++)
        {
            out->x_shares[i][c] = BN_new();
        }
        for (int c = 0; c < V3S_DIM_Y; c++)
        {
            out->y_shares[i][c] = BN_new();
            out->v_shares[i][c] = BN_new();
        }
        RAND_bytes(out->nonces[i], MERKLE_HASH_BYTES);
    }

    /* Shamir-share x, coordinate by coordinate. */
    BIGNUM* col_shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        col_shares[i] = BN_new();
    }
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        shamir_share_scalar(col_shares, x->coeffs[c], ctx);
        for (int i = 0; i < TIBE_N; i++)
        {
            BN_copy(out->x_shares[i][c], col_shares[i]);
        }
    }

    /* Sample y ~ D_{TIBE_DKG_SIGMA_Y}^{V3S_DIM_Y} (reuses gauss.c's
     * existing convolution-based sampler unmodified -- see
     * dkg_params.h) and Shamir-share it the same way. */
    for (int c = 0; c < V3S_DIM_Y; c++)
    {
        int64_t yc = gauss_sample_coeff(TIBE_DKG_SIGMA_Y);
        shamir_share_scalar(col_shares, yc, ctx);
        for (int i = 0; i < TIBE_N; i++)
        {
            BN_copy(out->y_shares[i][c], col_shares[i]);
        }
    }
    for (int i = 0; i < TIBE_N; i++)
    {
        BN_free(col_shares[i]);
    }

    /* Merkle tree over leaf_i = H(x_shares[i], y_shares[i], nonces[i]). */
    uint8_t* leaves = malloc((size_t)TIBE_N * MERKLE_HASH_BYTES);
    for (int i = 0; i < TIBE_N; i++)
    {
        leaf_hash(leaves + (size_t)i * MERKLE_HASH_BYTES, out->x_shares[i], out->y_shares[i], out->nonces[i]);
    }
    merkle_build(&out->tree, leaves, TIBE_N);
    free(leaves);
    merkle_root(out->root, &out->tree);

    v3s_matrix_derive(&out->R, out->root);

    /* v_i := R*x_i + y_i mod q, for every party i (all public). */
    for (int i = 0; i < TIBE_N; i++)
    {
        matvec_mul(out->v_shares[i], &out->R, out->x_shares[i], q, ctx);
        for (int c = 0; c < V3S_DIM_Y; c++)
        {
            BN_mod_add(out->v_shares[i][c], out->v_shares[i][c], out->y_shares[i][c], q, ctx);
        }
    }
}

void
v3s_share_free(v3s_share_output* out)
{
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int c = 0; c < V3S_DIM_X; c++)
        {
            BN_free(out->x_shares[i][c]);
        }
        for (int c = 0; c < V3S_DIM_Y; c++)
        {
            BN_free(out->y_shares[i][c]);
            BN_free(out->v_shares[i][c]);
        }
    }
    merkle_tree_free(&out->tree);
}

void
v3s_recipient_data_init(v3s_recipient_data* rd)
{
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        rd->x_share[c] = BN_new();
    }
    for (int c = 0; c < V3S_DIM_Y; c++)
    {
        rd->y_share[c] = BN_new();
    }
}

void
v3s_recipient_data_free(v3s_recipient_data* rd)
{
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        BN_free(rd->x_share[c]);
    }
    for (int c = 0; c < V3S_DIM_Y; c++)
    {
        BN_free(rd->y_share[c]);
    }
}

void
v3s_share_extract_recipient(v3s_recipient_data* rd, const v3s_share_output* out, int to_index)
{
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        BN_copy(rd->x_share[c], out->x_shares[to_index][c]);
    }
    for (int c = 0; c < V3S_DIM_Y; c++)
    {
        BN_copy(rd->y_share[c], out->y_shares[to_index][c]);
    }
    memcpy(rd->nonce, out->nonces[to_index], MERKLE_HASH_BYTES);
    merkle_proof_generate(&rd->proof, &out->tree, to_index);
}

int
v3s_verify(int my_index, BIGNUM* const v_shares[TIBE_N][V3S_DIM_Y], const uint8_t root[MERKLE_HASH_BYTES],
           const v3s_matrix* R, const v3s_recipient_data* rd, BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();

    uint8_t leaf[MERKLE_HASH_BYTES];
    leaf_hash(leaf, rd->x_share, rd->y_share, rd->nonce);
    if (!merkle_proof_verify(root, leaf, my_index, TIBE_N, &rd->proof))
    {
        return 0;
    }

    /* Local linear consistency: v_shares[my_index] == R*x_share + y_share. */
    BIGNUM* computed[V3S_DIM_Y];
    for (int c = 0; c < V3S_DIM_Y; c++)
    {
        computed[c] = BN_new();
    }
    matvec_mul(computed, R, rd->x_share, q, ctx);
    int consistent = 1;
    for (int c = 0; c < V3S_DIM_Y; c++)
    {
        BN_mod_add(computed[c], computed[c], rd->y_share[c], q, ctx);
        if (BN_cmp(computed[c], v_shares[my_index][c]) != 0)
        {
            consistent = 0;
        }
        BN_free(computed[c]);
    }
    if (!consistent)
    {
        return 0;
    }

    /* Shortness: reconstruct v from the (public) v_shares tuple via
     * the first TIBE_T indices, then check ||v||_2 <= TIBE_DKG_B_ACCEPT
     * via exact integer (sum-of-squares) comparison -- avoids any
     * floating-point precision/overflow concern for an adversarial
     * (potentially near-q-magnitude) v. */
    BIGNUM* q_half = BN_new();
    BN_rshift1(q_half, q);

    int act_x[TIBE_T];
    for (int k = 0; k < TIBE_T; k++)
    {
        act_x[k] = k + 1;
    }
    BIGNUM* lambda[TIBE_T];
    for (int k = 0; k < TIBE_T; k++)
    {
        lambda[k] = BN_new();
        lagrange_coeff_at(lambda[k], 0, act_x[k], act_x, TIBE_T, q, ctx);
    }
    BIGNUM* term = BN_new();
    BIGNUM* sum_sq = BN_new();
    BN_zero(sum_sq);
    for (int c = 0; c < V3S_DIM_Y; c++)
    {
        BIGNUM* acc = BN_new();
        BN_zero(acc);
        for (int k = 0; k < TIBE_T; k++)
        {
            BN_mod_mul(term, v_shares[act_x[k] - 1][c], lambda[k], q, ctx);
            BN_mod_add(acc, acc, term, q, ctx);
        }
        int64_t vc = bn_to_balanced_int64(acc, q, q_half);
        BIGNUM* sq = BN_new();
        BN_set_word(sq, (BN_ULONG)(vc < 0 ? -vc : vc));
        BN_sqr(sq, sq, ctx);
        BN_add(sum_sq, sum_sq, sq);
        BN_free(sq);
        BN_free(acc);
    }

    int64_t B_accept = (int64_t)TIBE_DKG_B_ACCEPT;
    BIGNUM* B2 = BN_new();
    BN_set_word(B2, (BN_ULONG)(B_accept * B_accept));
    int short_enough = BN_cmp(sum_sq, B2) <= 0;

    BN_free(q_half);
    BN_free(sum_sq);
    for (int k = 0; k < TIBE_T; k++)
    {
        BN_free(lambda[k]);
    }
    BN_free(term);
    BN_free(B2);

    return short_enough;
}

int
v3s_reconstruct(v3s_secret* out, BIGNUM* const x_shares[/* act_size */][V3S_DIM_X], const int* act_x, int act_size,
                 BN_CTX* ctx)
{
    if (act_size < TIBE_T)
    {
        return 0;
    }
    const BIGNUM* q = ring_modulus();
    BIGNUM* q_half = BN_new();
    BN_rshift1(q_half, q);

    /* Algorithm 3: J = the first TIBE_T indices in act_x. */
    BIGNUM* lambda_zero[TIBE_T];
    for (int k = 0; k < TIBE_T; k++)
    {
        lambda_zero[k] = BN_new();
        lagrange_coeff_at(lambda_zero[k], 0, act_x[k], act_x, TIBE_T, q, ctx);
    }

    BIGNUM* acc = BN_new();
    BIGNUM* term = BN_new();
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        BN_zero(acc);
        for (int k = 0; k < TIBE_T; k++)
        {
            BN_mod_mul(term, x_shares[k][c], lambda_zero[k], q, ctx);
            BN_mod_add(acc, acc, term, q, ctx);
        }
        out->coeffs[c] = bn_to_balanced_int64(acc, q, q_half);
    }

    /* Step 3: for every extra point i in act_x[T..), evaluate the
     * same degree-<T interpolated polynomial P at act_x[i] and check
     * it matches the given share -- any mismatch fails the whole
     * reconstruction (tier-1 semantics; Algorithm 4's Reed-Solomon
     * RobustReconstruct, which would instead correct through up to
     * (act_size-T)/2 such mismatches, is tier 2 and not implemented
     * here). */
    int ok = 1;
    BIGNUM* mu = BN_new();
    for (int extra = TIBE_T; extra < act_size && ok; extra++)
    {
        for (int c = 0; c < V3S_DIM_X && ok; c++)
        {
            BN_zero(acc);
            for (int k = 0; k < TIBE_T; k++)
            {
                lagrange_coeff_at(mu, act_x[extra], act_x[k], act_x, TIBE_T, q, ctx);
                BN_mod_mul(term, x_shares[k][c], mu, q, ctx);
                BN_mod_add(acc, acc, term, q, ctx);
            }
            if (BN_cmp(acc, x_shares[extra][c]) != 0)
            {
                ok = 0;
            }
        }
    }

    BN_free(mu);
    BN_free(acc);
    BN_free(term);
    for (int k = 0; k < TIBE_T; k++)
    {
        BN_free(lambda_zero[k]);
    }
    BN_free(q_half);
    return ok;
}

void
v3s_recipient_data_serialize(uint8_t* out, const v3s_recipient_data* rd)
{
    size_t x_bytes = (size_t)V3S_DIM_X * TIBE_Q_BYTES;
    size_t y_bytes = (size_t)V3S_DIM_Y * TIBE_Q_BYTES;
    serialize_coeffs(out, rd->x_share, V3S_DIM_X);
    serialize_coeffs(out + x_bytes, rd->y_share, V3S_DIM_Y);
    memcpy(out + x_bytes + y_bytes, rd->nonce, MERKLE_HASH_BYTES);
    merkle_proof_serialize(out + x_bytes + y_bytes + MERKLE_HASH_BYTES, &rd->proof);
}

void
v3s_recipient_data_deserialize(v3s_recipient_data* rd, const uint8_t* in)
{
    size_t x_bytes = (size_t)V3S_DIM_X * TIBE_Q_BYTES;
    size_t y_bytes = (size_t)V3S_DIM_Y * TIBE_Q_BYTES;
    deserialize_coeffs(rd->x_share, in, V3S_DIM_X);
    deserialize_coeffs(rd->y_share, in + x_bytes, V3S_DIM_Y);
    memcpy(rd->nonce, in + x_bytes + y_bytes, MERKLE_HASH_BYTES);
    merkle_proof_deserialize(&rd->proof, in + x_bytes + y_bytes + MERKLE_HASH_BYTES);
}

void
v3s_public_serialize(uint8_t* out, const uint8_t root[MERKLE_HASH_BYTES], BIGNUM* const v_shares[TIBE_N][V3S_DIM_Y])
{
    memcpy(out, root, MERKLE_HASH_BYTES);
    for (int i = 0; i < TIBE_N; i++)
    {
        serialize_coeffs(out + MERKLE_HASH_BYTES + (size_t)i * V3S_DIM_Y * TIBE_Q_BYTES, v_shares[i], V3S_DIM_Y);
    }
}

void
v3s_public_deserialize(uint8_t root[MERKLE_HASH_BYTES], BIGNUM* v_shares[TIBE_N][V3S_DIM_Y], const uint8_t* in)
{
    memcpy(root, in, MERKLE_HASH_BYTES);
    for (int i = 0; i < TIBE_N; i++)
    {
        deserialize_coeffs(v_shares[i], in + MERKLE_HASH_BYTES + (size_t)i * V3S_DIM_Y * TIBE_Q_BYTES, V3S_DIM_Y);
    }
}
