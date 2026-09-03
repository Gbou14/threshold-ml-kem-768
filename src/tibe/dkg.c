#include "dkg.h"

#include <string.h>

#include "gauss.h"
#include "ring.h" /* ring_modulus() */

void
dkg_round1(dkg_round1_state* state, BN_CTX* ctx)
{
    for (int c = 0; c < V3S_DIM_X; c++)
    {
        state->x.coeffs[c] = gauss_sample_coeff(TIBE_DKG_LOCAL_SIGMA);
    }
    v3s_share(&state->share, &state->x, ctx);
}

void
dkg_round1_state_free(dkg_round1_state* state)
{
    v3s_share_free(&state->share);
}

void
dkg_public_share_init(dkg_public_share* pub)
{
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int c = 0; c < V3S_DIM_Y; c++)
        {
            pub->v_shares[i][c] = BN_new();
        }
    }
}

void
dkg_public_share_free(dkg_public_share* pub)
{
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int c = 0; c < V3S_DIM_Y; c++)
        {
            BN_free(pub->v_shares[i][c]);
        }
    }
}

void
dkg_round1_extract_public(dkg_public_share* pub, const dkg_round1_state* state)
{
    memcpy(pub->root, state->share.root, MERKLE_HASH_BYTES);
    for (int i = 0; i < TIBE_N; i++)
    {
        for (int c = 0; c < V3S_DIM_Y; c++)
        {
            BN_copy(pub->v_shares[i][c], state->share.v_shares[i][c]);
        }
    }
}

void
dkg_round1_extract_recipient(v3s_recipient_data* rd, const dkg_round1_state* state, int to_index)
{
    v3s_share_extract_recipient(rd, &state->share, to_index);
}

void
dkg_round2(dkg_round2_verdicts* out, int my_index, const dkg_public_share pub[TIBE_N],
           const v3s_recipient_data received[TIBE_N], BN_CTX* ctx)
{
    /* Re-derived from pub[j].root, not stored -- see dkg_public_share's
     * comment. Declared once and reused across the loop (a single
     * 2MB local, not an array) rather than per-iteration to avoid
     * needlessly re-touching that much stack repeatedly. */
    v3s_matrix R;
    for (int j = 0; j < TIBE_N; j++)
    {
        v3s_matrix_derive(&R, pub[j].root);
        out->verdict[j] = v3s_verify(my_index, pub[j].v_shares, pub[j].root, &R, &received[j], ctx);
    }
}

void
dkg_compute_valid_set(int valid_out[TIBE_N], const dkg_round2_verdicts verdicts[TIBE_N])
{
    for (int j = 0; j < TIBE_N; j++)
    {
        int all_positive = 1;
        for (int k = 0; k < TIBE_N; k++)
        {
            if (!verdicts[k].verdict[j])
            {
                all_positive = 0;
                break;
            }
        }
        valid_out[j] = all_positive;
    }
}

void
dkg_aggregate(ring_elem* out_share_s_a, ring_elem* out_share_e_a, const int valid[TIBE_N],
              const v3s_recipient_data received[TIBE_N], BN_CTX* ctx)
{
    const BIGNUM* q = ring_modulus();
    ring_zero(out_share_s_a);
    ring_zero(out_share_e_a);
    for (int j = 0; j < TIBE_N; j++)
    {
        if (!valid[j])
        {
            continue;
        }
        for (int c = 0; c < TIBE_D; c++)
        {
            BN_mod_add(out_share_s_a->coeffs[c], out_share_s_a->coeffs[c], received[j].x_share[c], q, ctx);
        }
        for (int c = 0; c < TIBE_D; c++)
        {
            BN_mod_add(out_share_e_a->coeffs[c], out_share_e_a->coeffs[c], received[j].x_share[TIBE_D + c], q, ctx);
        }
    }
}
