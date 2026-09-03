/*
 * tibe_shareholder.c -- HTTP server for one BCHK+ threshold-KEM
 * shareholder party (Phase 7 for decapsulation; Phase 8d for setup --
 * the TIBE/BCHK+ counterpart to shareholder.c's Kyber-side role).
 *
 * REST API:
 *   GET  /health
 *
 *   -- Phase 8d, distributed setup (replaces the old dealer-issued
 *   /store_share entirely -- see BCHK_TODO.md Phase 8d, and dkg.h/
 *   dkg_pubkey.h for the underlying protocol). Orchestrated by
 *   tibe_dealer.c calling dkg_round1..dkg_round4 on every shareholder
 *   in sequence, relaying only PUBLIC broadcast data between rounds --
 *   dkg_receive is peer-to-peer instead, bypassing the coordinator,
 *   since it carries each party's PRIVATE per-recipient share data:
 *   POST /dkg_round1   -- generates this party's own local secret
 *                          contribution, V3S-shares it, and DIRECTLY
 *                          POSTs each other party its private payload
 *                          via /dkg_receive; returns this party's
 *                          public V3S data + a0/d0 commitment
 *   POST /dkg_receive  -- peer-to-peer target: stores another party's
 *                          private V3S payload (and, if that party's
 *                          index is lower than this one's, a fresh
 *                          pairwise seed and one-time b0-masking value)
 *   POST /dkg_round2   -- given every party's public data (relayed by
 *                          the coordinator), verifies every privately-
 *                          received payload and returns this party's
 *                          verdict vector, plus its a0/d0 reveal (safe
 *                          now that every commitment is already
 *                          locked in)
 *   POST /dkg_round3   -- given every verdict vector and a0/d0 reveal,
 *                          finalizes a0/d0, aggregates this party's
 *                          own final Shamir share of (s_a,e_a), and
 *                          returns its masked b0 contribution
 *   POST /dkg_round4   -- given every b0 contribution, finalizes b0,
 *                          derives A1/A2/G/r, and assembles this
 *                          party's own local copy of ek -- (s_a,e_a)
 *                          is never reconstructed by any party, ever,
 *                          at any point in this whole sequence
 *
 *   -- Decapsulation (unchanged from Phase 7):
 *   POST /round0       -- Algorithm 5 (via tkem_share_decaps_0):
 *                          verifies the ciphertext's WOTS+ signature
 *                          *before* doing any threshold-decryption
 *                          work, samples fresh blinding, returns a
 *                          commitment
 *   POST /round1       -- Algorithm 6 (via tkem_share_decaps_1):
 *                          trivial reveal of the value committed to
 *                          in round 0
 *   POST /round2       -- Algorithm 7 (via tkem_share_decaps_2):
 *                          verifies every other active party's
 *                          revealed value against its round-0
 *                          commitment, derives the pairwise mask, and
 *                          returns this party's contribution
 *
 * One decapsulation session (round0->round1->round2) is handled at a
 * time via global state, matching shareholder.c's existing
 * architecture -- not safe for concurrent sessions, fine for this
 * demo where the coordinator drives one session at a time. Likewise
 * only one distributed-setup run is supported per process lifetime.
 *
 * Request/response bodies here are much larger than the Kyber
 * demo's (a single ring element serializes to ~53 KB; a full
 * ciphertext to ~535 KB; a single v3s_recipient_data to ~110 KB), so
 * unlike shareholder.c's fixed 8 KB buffer, request bodies are
 * accumulated into a dynamically-grown buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <microhttpd.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "hexutil.h"
#include "tibe/dkg.h"
#include "tibe/dkg_pubkey.h"
#include "tibe/threshold.h"
#include "tibe/tkem.h"
#include "tibe/v3s.h"

/* ── Party state ─────────────────────────────────────────────────────────── */
static threshold_share g_share;
static int g_share_ready = 0;

static tibe_ek g_ek;
static int g_ek_ready = 0;

static tkem_ct g_ct;
static threshold_round0_state g_round0_state;
static int g_session_active = 0; /* round0 has run for g_ct, valid through round1/round2 */

static BN_CTX* g_ctx;

/* ── Phase 8d: distributed setup state ───────────────────────────────────
 *
 * Replaces tibe_dealer.c's old centralized TKEM.Keygen entirely -- see
 * BCHK_TODO.md Phase 8d. This shareholder now participates in a
 * 4-round protocol (dkg_round1..dkg_round4 below) orchestrated by
 * tibe_dealer.c (which itself never sees any secret -- it only relays
 * PUBLIC broadcast data between rounds: roots, v_shares, a0/d0
 * commitments and reveals, verdict vectors, b0 contributions).
 *
 * The one thing tibe_dealer.c does NOT relay is each party's PRIVATE
 * v3s_recipient_data (its individual Shamir sub-shares of every other
 * party's local secret) and the one-time b0-masking values -- those
 * go directly shareholder-to-shareholder over /dkg_receive, bypassing
 * the coordinator entirely. This is not an optional simplification:
 * if the coordinator saw every (dealer,recipient) private payload, it
 * would have enough shares to reconstruct every party's secret itself
 * (a full T-of-N share set), becoming a trusted dealer again and
 * defeating the whole point.
 */
static int g_my_index = -1;                                     /* 0-indexed */
static int g_n_hosts = 0;                                        /* peer count, should equal TIBE_N */
static char g_peer_hosts[TIBE_N][128];
static int g_peer_port = 0;

static dkg_round1_state g_dkg_state;
static dkg_public_share g_dkg_pub[TIBE_N];                       /* dealer j's public V3S data */
static int g_dkg_pub_ready[TIBE_N];
static v3s_recipient_data g_dkg_recv[TIBE_N];                    /* what dealer j privately sent this party */
static int g_dkg_recv_ready[TIBE_N];
static uint8_t g_pairseed_recv[TIBE_N][TIBE_SEED_BYTES];         /* pairwise seed received from j (j < my_index) */
static int g_pairseed_recv_ready[TIBE_N];
static uint8_t g_pairseed_sent[TIBE_N][TIBE_SEED_BYTES];         /* pairwise seed this party generated for j (j > my_index) */
static ring_elem g_b0mask_recv[TIBE_N];                           /* b0-masking value received from j (j < my_index) */
static int g_b0mask_recv_ready[TIBE_N];

static dkg_pubkey_round1_state g_pk_state;
static uint8_t g_pk_cmt[DKG_PUBKEY_CMT_BYTES];
static uint8_t g_pk_cmts[TIBE_N][DKG_PUBKEY_CMT_BYTES];

static int g_verdicts[TIBE_N][TIBE_N]; /* g_verdicts[k][j]: party k's verdict on dealer j */
static int g_valid[TIBE_N];            /* (s_a,e_a) DKG valid set */

static ring_elem g_a0_reveal[TIBE_N], g_d0_reveal[TIBE_N]; /* every party's revealed a0/d0 contribution */
static int g_valid_ab[TIBE_N];
static ring_elem g_a0, g_d0;

static ring_elem g_b0_contribs[TIBE_N];
static ring_elem g_b0;

static int g_setup_done = 0;

/* ── Peer-to-peer HTTP client (Phase 8d): this shareholder POSTing
 * directly to another shareholder, bypassing the coordinator -- see
 * the file header comment on why this must not go through the
 * coordinator. Mirrors tibe_dealer.c's own http_post helper. ── */
static long
peer_post(const char* host, int port, const char* path, const char* json)
{
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d%s", host, port, path);
    CURL* curl = curl_easy_init();
    if (!curl)
    {
        return -1;
    }
    struct curl_slist* hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L); /* v3s_recipient_data hex is ~220KB */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "[tibe_sh] peer_post to %s: %s\n", url, curl_easy_strerror(res));
        return -1;
    }
    return code;
}

/* ── Deterministic derivation of A1/d2/a2/b2/r (Phase 8d): these are
 * independent of (s_a,e_a)/a0/d0/b0 in tibe_setup, and G's g is
 * already a pure function of q (tibe_compute_g), so this is the only
 * remaining piece needed to build ek without a dealer. Derived here
 * from a hash of every party's public round-1/round-2 broadcast data
 * (all TIBE_N (root,v_shares) blobs and all TIBE_N a0/d0 commitments),
 * which every honest party computes identically with zero further
 * coordination.
 *
 * Deliberately flagged, not silently presented as equivalent to
 * a0/d0's own coin-flip: this does NOT have the same bias-resistance
 * guarantee. A party's own commitment is hiding, but nothing stops a
 * malicious *last-committing* party from trying several candidate
 * (a0_i,d0_i) contributions locally before submitting, each yielding
 * a different downstream hash here, and picking whichever favors it
 * -- the same class of concern the coin-flip protocol exists to
 * prevent for a0/d0 specifically. Acceptable for this demo because it
 * does not touch the plaintext-key-exposure property Phase 8d's DKG
 * actually targets; a rigorous fix (extending dkg_pubkey.c's
 * commit-reveal to cover these too) is documented, scoped future
 * work, not attempted here. See BCHK_TODO.md Phase 8d. */
static void
derive_public_setup_material(ring_elem A1[3], ring_elem* d2, ring_elem* a2, ring_elem* b2, ring_elem* r,
                              BN_CTX* ctx)
{
    size_t chunk = V3S_PUBLIC_SERIALIZED_BYTES;
    size_t total = (size_t)TIBE_N * chunk + (size_t)TIBE_N * DKG_PUBKEY_CMT_BYTES;
    uint8_t* buf = malloc(total);
    for (int i = 0; i < TIBE_N; i++)
    {
        v3s_public_serialize(buf + (size_t)i * chunk, g_dkg_pub[i].root, g_dkg_pub[i].v_shares);
    }
    for (int i = 0; i < TIBE_N; i++)
    {
        memcpy(buf + (size_t)TIBE_N * chunk + (size_t)i * DKG_PUBKEY_CMT_BYTES, g_pk_cmts[i], DKG_PUBKEY_CMT_BYTES);
    }

    uint8_t seed[32];
    EVP_MD* md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mctx, md, NULL);
    EVP_DigestUpdate(mctx, buf, total);
    EVP_DigestFinalXOF(mctx, seed, sizeof(seed));
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
    free(buf);

    size_t rb = ring_serialized_bytes();
    size_t out_len = 7 * rb; /* A1[3], d2, a2, b2, r */
    uint8_t* out = malloc(out_len);
    EVP_MD* md2 = EVP_MD_fetch(NULL, "SHAKE256", NULL);
    EVP_MD_CTX* mctx2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mctx2, md2, NULL);
    EVP_DigestUpdate(mctx2, seed, sizeof(seed));
    EVP_DigestFinalXOF(mctx2, out, out_len);
    EVP_MD_CTX_free(mctx2);
    EVP_MD_free(md2);

    const BIGNUM* q = ring_modulus();
    ring_elem* targets[7] = {&A1[0], &A1[1], &A1[2], d2, a2, b2, r};
    for (int t = 0; t < 7; t++)
    {
        for (int c = 0; c < TIBE_D; c++)
        {
            BN_bin2bn(out + (size_t)t * rb + (size_t)c * TIBE_Q_BYTES, TIBE_Q_BYTES, targets[t]->coeffs[c]);
            BN_nnmod(targets[t]->coeffs[c], targets[t]->coeffs[c], q, ctx);
        }
    }
    free(out);
}

/* ── JSON helpers (minimal, matching shareholder.c's philosophy --
 * this demo never sends nested objects or escaped strings, just
 * integers and hex strings, some of them large). ── */
static int
parse_json_int(const char* json, const char* key, int* out)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* p = strstr(json, search);
    if (!p)
    {
        return -1;
    }
    p = strchr(p + strlen(search), ':');
    if (!p)
    {
        return -1;
    }
    *out = atoi(p + 1);
    return 0;
}

/* Copies the string VALUE for "key" into a freshly malloc'd buffer
 * (caller frees) -- unlike a fixed-size parser, handles arbitrarily
 * large hex fields (hundreds of KB to ~1 MB in this module). */
static int
parse_json_string_dyn(const char* json, const char* key, char** out)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* p = strstr(json, search);
    if (!p)
    {
        return -1;
    }
    p = strchr(p + strlen(search), ':');
    if (!p)
    {
        return -1;
    }
    p++;
    while (*p == ' ')
    {
        p++;
    }
    if (*p != '"')
    {
        return -1;
    }
    p++;
    const char* end = strchr(p, '"');
    if (!end)
    {
        return -1;
    }
    size_t len = (size_t)(end - p);
    *out = malloc(len + 1);
    memcpy(*out, p, len);
    (*out)[len] = '\0';
    return 0;
}

static int
parse_csv_ints(const char* csv, int* out, int max)
{
    char tmp[256];
    strncpy(tmp, csv, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    int count = 0;
    char* tok = strtok(tmp, ",");
    while (tok && count < max)
    {
        out[count++] = atoi(tok);
        tok = strtok(NULL, ",");
    }
    return count;
}

static int
send_json(struct MHD_Connection* conn, unsigned int code, const char* body)
{
    struct MHD_Response* r = MHD_create_response_from_buffer(strlen(body), (void*)body, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(r, "Content-Type", "application/json");
    int ret = MHD_queue_response(conn, code, r);
    MHD_destroy_response(r);
    return ret;
}

static int
send_json_owned(struct MHD_Connection* conn, unsigned int code, char* body)
{
    /* Same as send_json, but for a malloc'd body this function frees
     * after queuing (MHD_RESPMEM_MUST_COPY means it's safe to free
     * immediately after MHD_create_response_from_buffer returns). */
    int ret = send_json(conn, code, body);
    free(body);
    return ret;
}

/* ── Dynamically-grown request body ─────────────────────────────────────── */
typedef struct
{
    char* buf;
    size_t len;
    size_t cap;
} ReqBody;

static void
reqbody_append(ReqBody* rb, const char* data, size_t n)
{
    if (rb->len + n + 1 > rb->cap)
    {
        size_t newcap = rb->cap == 0 ? (1 << 16) : rb->cap * 2;
        while (newcap < rb->len + n + 1)
        {
            newcap *= 2;
        }
        rb->buf = realloc(rb->buf, newcap);
        rb->cap = newcap;
    }
    memcpy(rb->buf + rb->len, data, n);
    rb->len += n;
    rb->buf[rb->len] = '\0';
}

/* ── Request handler ─────────────────────────────────────────────────────── */
static enum MHD_Result
handler(void* cls, struct MHD_Connection* conn, const char* url, const char* method, const char* version,
        const char* upload_data, size_t* upload_data_size, void** con_cls)
{
    (void)cls;
    (void)version;

    if (*con_cls == NULL)
    {
        ReqBody* rb = calloc(1, sizeof(ReqBody));
        if (!rb)
        {
            return MHD_NO;
        }
        *con_cls = rb;
        return MHD_YES;
    }
    ReqBody* rb = (ReqBody*)*con_cls;

    if (*upload_data_size > 0)
    {
        reqbody_append(rb, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* GET or HEAD /health -- CURLOPT_NOBODY (used by every caller's
     * wait_healthy loop, matching the existing Kyber demo's pattern)
     * makes curl issue a HEAD request, not GET; accepting only GET
     * here would make every health check 404 and wait_healthy burn
     * its full ~60-retry budget every time before proceeding anyway
     * (harmless there since wait_healthy doesn't block on success,
     * but a needless multi-minute delay -- caught by observing this
     * module's own tibe_coordinator actually stall on it in a live
     * run). */
    if ((strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) && strcmp(url, "/health") == 0)
    {
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"alive\"}");
    }

    /* POST /dkg_round1 -- {"my_index":N} -> {"pub_hex":"...","cmt_hex":"..."}
     * Triggers this party's own local round-1 computation and sends
     * every other party its private payload directly (peer-to-peer,
     * not through the coordinator -- see file header comment). */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/dkg_round1") == 0)
    {
        int my_index = -1;
        if (parse_json_int(rb->buf, "my_index", &my_index) != 0 || my_index < 0 || my_index >= TIBE_N)
        {
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing/bad my_index\"}");
        }
        g_my_index = my_index;

        dkg_round1(&g_dkg_state, g_ctx);
        dkg_pubkey_round1(&g_pk_state, g_my_index, g_pk_cmt, g_ctx);

        size_t rd_bytes = V3S_RECIPIENT_DATA_SERIALIZED_BYTES;
        uint8_t* rd_buf = malloc(rd_bytes);
        char* rd_hex = malloc(2 * rd_bytes + 1);
        for (int j = 0; j < TIBE_N; j++)
        {
            if (j == g_my_index)
            {
                continue;
            }
            v3s_recipient_data rd;
            v3s_recipient_data_init(&rd);
            dkg_round1_extract_recipient(&rd, &g_dkg_state, j);
            v3s_recipient_data_serialize(rd_buf, &rd);
            v3s_recipient_data_free(&rd);
            hex_encode(rd_hex, rd_buf, rd_bytes);

            size_t body_cap = 2 * rd_bytes + 2 * TIBE_SEED_BYTES + 2 * ring_serialized_bytes() + 256;
            char* body = malloc(body_cap);
            if (j > g_my_index)
            {
                RAND_bytes(g_pairseed_sent[j], TIBE_SEED_BYTES);
                char pairseed_hex[2 * TIBE_SEED_BYTES + 1];
                hex_encode(pairseed_hex, g_pairseed_sent[j], TIBE_SEED_BYTES);
                size_t maskbytes = ring_serialized_bytes();
                uint8_t* maskbuf = malloc(maskbytes);
                ring_serialize(maskbuf, &g_pk_state.mask_to[j]);
                char* mask_hex = malloc(2 * maskbytes + 1);
                hex_encode(mask_hex, maskbuf, maskbytes);
                free(maskbuf);
                snprintf(body, body_cap, "{\"from\":%d,\"rdata_hex\":\"%s\",\"pairseed_hex\":\"%s\",\"b0mask_hex\":\"%s\"}",
                         g_my_index, rd_hex, pairseed_hex, mask_hex);
                free(mask_hex);
            }
            else
            {
                snprintf(body, body_cap, "{\"from\":%d,\"rdata_hex\":\"%s\"}", g_my_index, rd_hex);
            }
            long code = peer_post(g_peer_hosts[j], g_peer_port, "/dkg_receive", body);
            free(body);
            if (code != 200)
            {
                fprintf(stderr, "[tibe_sh x=%d] WARNING: /dkg_receive to peer %d returned %ld\n", g_my_index + 1, j,
                        code);
            }
        }
        free(rd_buf);
        free(rd_hex);

        size_t pub_bytes = V3S_PUBLIC_SERIALIZED_BYTES;
        uint8_t* pub_buf = malloc(pub_bytes);
        v3s_public_serialize(pub_buf, g_dkg_state.share.root, g_dkg_state.share.v_shares);
        char* pub_hex = malloc(2 * pub_bytes + 1);
        hex_encode(pub_hex, pub_buf, pub_bytes);
        free(pub_buf);

        char cmt_hex[2 * DKG_PUBKEY_CMT_BYTES + 1];
        hex_encode(cmt_hex, g_pk_cmt, DKG_PUBKEY_CMT_BYTES);

        char* resp = malloc(2 * pub_bytes + 256);
        snprintf(resp, 2 * pub_bytes + 256, "{\"pub_hex\":\"%s\",\"cmt_hex\":\"%s\"}", pub_hex, cmt_hex);
        free(pub_hex);
        printf("[tibe_sh idx=%d] dkg_round1 done\n", g_my_index);
        fflush(stdout);
        return send_json_owned(conn, MHD_HTTP_OK, resp);
    }

    /* POST /dkg_receive -- {"from":N,"rdata_hex":"...","pairseed_hex":"...","b0mask_hex":"..."}
     * (the last two only present when from < this party's own index)
     * -> {"status":"ok"}. Peer-to-peer target, called by every other
     * party once. */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/dkg_receive") == 0)
    {
        int from = -1;
        char* rdata_hex = NULL;
        if (parse_json_int(rb->buf, "from", &from) != 0 || from < 0 || from >= TIBE_N ||
            parse_json_string_dyn(rb->buf, "rdata_hex", &rdata_hex) != 0)
        {
            free(rdata_hex);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing fields\"}");
        }
        size_t rd_bytes = V3S_RECIPIENT_DATA_SERIALIZED_BYTES;
        uint8_t* rd_buf = malloc(rd_bytes);
        int ok = (strlen(rdata_hex) == 2 * rd_bytes) && hex_decode(rd_buf, rd_bytes, rdata_hex) == 0;
        free(rdata_hex);
        if (!ok)
        {
            free(rd_buf);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"bad rdata_hex\"}");
        }
        v3s_recipient_data_deserialize(&g_dkg_recv[from], rd_buf);
        free(rd_buf);
        g_dkg_recv_ready[from] = 1;

        char* pairseed_hex = NULL;
        if (parse_json_string_dyn(rb->buf, "pairseed_hex", &pairseed_hex) == 0)
        {
            hex_decode(g_pairseed_recv[from], TIBE_SEED_BYTES, pairseed_hex);
            free(pairseed_hex);
            g_pairseed_recv_ready[from] = 1;

            char* mask_hex = NULL;
            if (parse_json_string_dyn(rb->buf, "b0mask_hex", &mask_hex) == 0)
            {
                size_t maskbytes = ring_serialized_bytes();
                uint8_t* maskbuf = malloc(maskbytes);
                if (strlen(mask_hex) == 2 * maskbytes && hex_decode(maskbuf, maskbytes, mask_hex) == 0)
                {
                    ring_deserialize(&g_b0mask_recv[from], maskbuf);
                    g_b0mask_recv_ready[from] = 1;
                }
                free(maskbuf);
                free(mask_hex);
            }
        }
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    }

    /* POST /dkg_round2 -- {"all_pub_hex":"...","all_cmt_hex":"..."}
     * -> {"verdict_csv":"...","a0_hex":"...","d0_hex":"...","nonce_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/dkg_round2") == 0)
    {
        char *all_pub_hex = NULL, *all_cmt_hex = NULL;
        if (parse_json_string_dyn(rb->buf, "all_pub_hex", &all_pub_hex) != 0 ||
            parse_json_string_dyn(rb->buf, "all_cmt_hex", &all_cmt_hex) != 0)
        {
            free(all_pub_hex);
            free(all_cmt_hex);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing fields\"}");
        }
        size_t pub_bytes = V3S_PUBLIC_SERIALIZED_BYTES;
        uint8_t* pub_chunk = malloc(pub_bytes);
        char* pub_chunk_hex = malloc(2 * pub_bytes + 1);
        for (int i = 0; i < TIBE_N; i++)
        {
            memcpy(pub_chunk_hex, all_pub_hex + (size_t)i * 2 * pub_bytes, 2 * pub_bytes);
            pub_chunk_hex[2 * pub_bytes] = '\0';
            hex_decode(pub_chunk, pub_bytes, pub_chunk_hex);
            v3s_public_deserialize(g_dkg_pub[i].root, g_dkg_pub[i].v_shares, pub_chunk);
            g_dkg_pub_ready[i] = 1;

            char cmt_chunk[2 * DKG_PUBKEY_CMT_BYTES + 1];
            memcpy(cmt_chunk, all_cmt_hex + (size_t)i * 2 * DKG_PUBKEY_CMT_BYTES, 2 * DKG_PUBKEY_CMT_BYTES);
            cmt_chunk[2 * DKG_PUBKEY_CMT_BYTES] = '\0';
            hex_decode(g_pk_cmts[i], DKG_PUBKEY_CMT_BYTES, cmt_chunk);
        }
        free(pub_chunk);
        free(pub_chunk_hex);
        free(all_pub_hex);
        free(all_cmt_hex);

        dkg_round2_verdicts my_verdicts;
        dkg_round2(&my_verdicts, g_my_index, g_dkg_pub, g_dkg_recv, g_ctx);

        char verdict_csv[4 * TIBE_N + 1];
        {
            char* p = verdict_csv;
            for (int j = 0; j < TIBE_N; j++)
            {
                p += snprintf(p, 4, "%d%s", my_verdicts.verdict[j], (j + 1 < TIBE_N) ? "," : "");
            }
        }

        size_t rb2 = ring_serialized_bytes();
        uint8_t* a0buf = malloc(rb2);
        uint8_t* d0buf = malloc(rb2);
        ring_serialize(a0buf, &g_pk_state.a0_contrib);
        ring_serialize(d0buf, &g_pk_state.d0_contrib);
        char* a0hex = malloc(2 * rb2 + 1);
        char* d0hex = malloc(2 * rb2 + 1);
        hex_encode(a0hex, a0buf, rb2);
        hex_encode(d0hex, d0buf, rb2);
        free(a0buf);
        free(d0buf);
        char nonce_hex[2 * DKG_PUBKEY_NONCE_BYTES + 1];
        hex_encode(nonce_hex, g_pk_state.nonce, DKG_PUBKEY_NONCE_BYTES);

        char* resp = malloc(4 * rb2 + 512);
        snprintf(resp, 4 * rb2 + 512, "{\"verdict_csv\":\"%s\",\"a0_hex\":\"%s\",\"d0_hex\":\"%s\",\"nonce_hex\":\"%s\"}",
                 verdict_csv, a0hex, d0hex, nonce_hex);
        free(a0hex);
        free(d0hex);
        printf("[tibe_sh idx=%d] dkg_round2 done\n", g_my_index);
        fflush(stdout);
        return send_json_owned(conn, MHD_HTTP_OK, resp);
    }

    /* POST /dkg_round3 -- {"all_verdicts_csv":"...","all_a0_hex":"...","all_d0_hex":"...","all_nonce_hex":"..."}
     * -> {"b0_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/dkg_round3") == 0)
    {
        char *all_verdicts_csv = NULL, *all_a0_hex = NULL, *all_d0_hex = NULL, *all_nonce_hex = NULL;
        if (parse_json_string_dyn(rb->buf, "all_verdicts_csv", &all_verdicts_csv) != 0 ||
            parse_json_string_dyn(rb->buf, "all_a0_hex", &all_a0_hex) != 0 ||
            parse_json_string_dyn(rb->buf, "all_d0_hex", &all_d0_hex) != 0 ||
            parse_json_string_dyn(rb->buf, "all_nonce_hex", &all_nonce_hex) != 0)
        {
            free(all_verdicts_csv);
            free(all_a0_hex);
            free(all_d0_hex);
            free(all_nonce_hex);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing fields\"}");
        }

        {
            int flat[TIBE_N * TIBE_N];
            int n = parse_csv_ints(all_verdicts_csv, flat, TIBE_N * TIBE_N);
            free(all_verdicts_csv);
            if (n != TIBE_N * TIBE_N)
            {
                free(all_a0_hex);
                free(all_d0_hex);
                free(all_nonce_hex);
                return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"bad all_verdicts_csv\"}");
            }
            for (int k = 0; k < TIBE_N; k++)
            {
                for (int j = 0; j < TIBE_N; j++)
                {
                    g_verdicts[k][j] = flat[k * TIBE_N + j];
                }
            }
        }
        dkg_round2_verdicts verdict_structs[TIBE_N];
        for (int k = 0; k < TIBE_N; k++)
        {
            for (int j = 0; j < TIBE_N; j++)
            {
                verdict_structs[k].verdict[j] = g_verdicts[k][j];
            }
        }
        dkg_compute_valid_set(g_valid, verdict_structs);

        size_t rb2 = ring_serialized_bytes();
        uint8_t* chunk = malloc(rb2);
        char* chunk_hex = malloc(2 * rb2 + 1);
        for (int i = 0; i < TIBE_N; i++)
        {
            memcpy(chunk_hex, all_a0_hex + (size_t)i * 2 * rb2, 2 * rb2);
            chunk_hex[2 * rb2] = '\0';
            hex_decode(chunk, rb2, chunk_hex);
            ring_deserialize(&g_a0_reveal[i], chunk);

            memcpy(chunk_hex, all_d0_hex + (size_t)i * 2 * rb2, 2 * rb2);
            chunk_hex[2 * rb2] = '\0';
            hex_decode(chunk, rb2, chunk_hex);
            ring_deserialize(&g_d0_reveal[i], chunk);
        }
        free(chunk);
        free(chunk_hex);
        free(all_a0_hex);
        free(all_d0_hex);

        uint8_t nonce_chunk[2 * DKG_PUBKEY_NONCE_BYTES + 1];
        uint8_t nonces[TIBE_N][DKG_PUBKEY_NONCE_BYTES];
        for (int i = 0; i < TIBE_N; i++)
        {
            memcpy(nonce_chunk, all_nonce_hex + (size_t)i * 2 * DKG_PUBKEY_NONCE_BYTES, 2 * DKG_PUBKEY_NONCE_BYTES);
            nonce_chunk[2 * DKG_PUBKEY_NONCE_BYTES] = '\0';
            hex_decode(nonces[i], DKG_PUBKEY_NONCE_BYTES, (char*)nonce_chunk);
        }
        free(all_nonce_hex);

        for (int i = 0; i < TIBE_N; i++)
        {
            g_valid_ab[i] = dkg_pubkey_verify_commit(g_pk_cmts[i], &g_a0_reveal[i], &g_d0_reveal[i], nonces[i]);
        }
        ring_elem* a0c[TIBE_N];
        ring_elem* d0c[TIBE_N];
        for (int i = 0; i < TIBE_N; i++)
        {
            a0c[i] = &g_a0_reveal[i];
            d0c[i] = &g_d0_reveal[i];
        }
        dkg_pubkey_finalize_a0_d0(&g_a0, &g_d0, g_valid_ab, a0c, d0c, g_ctx);

        /* g_share.share_s_a/share_e_a/d0 are already ring_init'd once
         * at startup via threshold_share_init (main()). */
        dkg_aggregate(&g_share.share_s_a, &g_share.share_e_a, g_valid, g_dkg_recv, g_ctx);
        ring_copy(&g_share.d0, &g_d0);
        g_share.x = g_my_index + 1;

        ring_elem b0_contrib;
        ring_init(&b0_contrib);
        if (g_valid[g_my_index])
        {
            ring_elem* received_masks[TIBE_N];
            for (int j = 0; j < TIBE_N; j++)
            {
                received_masks[j] = (j < g_my_index) ? &g_b0mask_recv[j] : NULL;
            }
            dkg_pubkey_b0_contribution(&b0_contrib, g_my_index, g_valid, &g_dkg_state.x, &g_a0, g_pk_state.mask_to,
                                        received_masks, g_ctx);
        }

        uint8_t* b0buf = malloc(rb2);
        ring_serialize(b0buf, &b0_contrib);
        ring_free(&b0_contrib);
        char* b0hex = malloc(2 * rb2 + 1);
        hex_encode(b0hex, b0buf, rb2);
        free(b0buf);

        char* resp = malloc(2 * rb2 + 64);
        snprintf(resp, 2 * rb2 + 64, "{\"b0_hex\":\"%s\"}", b0hex);
        free(b0hex);
        printf("[tibe_sh idx=%d] dkg_round3 done\n", g_my_index);
        fflush(stdout);
        return send_json_owned(conn, MHD_HTTP_OK, resp);
    }

    /* POST /dkg_round4 -- {"all_b0_hex":"..."} -> {"status":"ok"} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/dkg_round4") == 0)
    {
        char* all_b0_hex = NULL;
        if (parse_json_string_dyn(rb->buf, "all_b0_hex", &all_b0_hex) != 0)
        {
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing fields\"}");
        }
        size_t rb2 = ring_serialized_bytes();
        uint8_t* chunk = malloc(rb2);
        char* chunk_hex = malloc(2 * rb2 + 1);
        for (int i = 0; i < TIBE_N; i++)
        {
            memcpy(chunk_hex, all_b0_hex + (size_t)i * 2 * rb2, 2 * rb2);
            chunk_hex[2 * rb2] = '\0';
            hex_decode(chunk, rb2, chunk_hex);
            ring_deserialize(&g_b0_contribs[i], chunk);
        }
        free(chunk);
        free(chunk_hex);
        free(all_b0_hex);

        ring_elem* b0c[TIBE_N];
        for (int i = 0; i < TIBE_N; i++)
        {
            b0c[i] = &g_b0_contribs[i];
        }
        dkg_pubkey_finalize_b0(&g_b0, g_valid, b0c, g_ctx);

        ring_elem A1[3], d2, a2, b2, r;
        ring_init(&A1[0]);
        ring_init(&A1[1]);
        ring_init(&A1[2]);
        ring_init(&d2);
        ring_init(&a2);
        ring_init(&b2);
        ring_init(&r);
        derive_public_setup_material(A1, &d2, &a2, &b2, &r, g_ctx);

        const BIGNUM* q = ring_modulus();
        ring_elem one;
        ring_init(&one);
        ring_zero(&one);
        BN_set_word(one.coeffs[0], 1);
        ring_mul(&g_ek.A0[0], &one, &g_d0, g_ctx);
        ring_mul(&g_ek.A0[1], &g_a0, &g_d0, g_ctx);
        ring_mul(&g_ek.A0[2], &g_b0, &g_d0, g_ctx);
        ring_copy(&g_ek.A1[0], &A1[0]);
        ring_copy(&g_ek.A1[1], &A1[1]);
        ring_copy(&g_ek.A1[2], &A1[2]);
        ring_mul(&g_ek.A2[0], &one, &d2, g_ctx);
        ring_mul(&g_ek.A2[1], &a2, &d2, g_ctx);
        ring_mul(&g_ek.A2[2], &b2, &d2, g_ctx);
        ring_copy(&g_ek.r, &r);
        ring_free(&one);
        ring_free(&d2);
        ring_free(&a2);
        ring_free(&b2);
        ring_free(&r);
        ring_free(&A1[0]);
        ring_free(&A1[1]);
        ring_free(&A1[2]);

        ring_elem g_elem, one2;
        ring_init(&g_elem);
        ring_init(&one2);
        BIGNUM* g_bn = BN_new();
        tibe_compute_g(g_bn, q, g_ctx);
        BN_copy(g_elem.coeffs[0], g_bn);
        BN_free(g_bn);
        ring_zero(&one2);
        BN_set_word(one2.coeffs[0], 1);
        ring_copy(&g_ek.G[0], &one2);
        ring_copy(&g_ek.G[1], &g_elem);
        ring_mul(&g_ek.G[2], &g_elem, &g_elem, g_ctx);
        ring_free(&g_elem);
        ring_free(&one2);

        for (int j = 0; j < TIBE_N; j++)
        {
            if (j == g_my_index)
            {
                continue;
            }
            if (j > g_my_index)
            {
                memcpy(g_share.pairwise_seed[j], g_pairseed_sent[j], TIBE_SEED_BYTES);
            }
            else
            {
                memcpy(g_share.pairwise_seed[j], g_pairseed_recv[j], TIBE_SEED_BYTES);
            }
        }

        g_ek_ready = 1;
        g_share_ready = 1;
        g_setup_done = 1;

        printf("[tibe_sh idx=%d] dkg_round4 done -- fully dealer-free setup complete, x=%d\n", g_my_index,
               g_share.x);
        fflush(stdout);
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    }

    /* GET /dkg_get_public -> {"ek_hex":"...","d0_hex":"..."}
     * Queried once by tibe_dealer.c after every shareholder finishes
     * dkg_round4, purely so tibe_coordinator.c (unchanged from Phase
     * 7) still has a shared-volume file to read ek/d0 from -- ek/d0
     * are public regardless of how they were generated (see
     * tibe_dealer.c's own comment), so writing them to a shared file
     * once finalized is not a weaker trust model than before. Any
     * shareholder can answer this identically, since every honest
     * party computes the same ek from the same public broadcast
     * data. */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/dkg_get_public") == 0)
    {
        if (!g_setup_done)
        {
            return send_json(conn, MHD_HTTP_CONFLICT, "{\"error\":\"setup not complete\"}");
        }
        size_t ek_bytes = tibe_ek_serialized_bytes();
        uint8_t* ek_buf = malloc(ek_bytes);
        tibe_ek_serialize(ek_buf, &g_ek);
        char* ek_hex = malloc(2 * ek_bytes + 1);
        hex_encode(ek_hex, ek_buf, ek_bytes);
        free(ek_buf);

        size_t rb2 = ring_serialized_bytes();
        uint8_t* d0buf = malloc(rb2);
        ring_serialize(d0buf, &g_d0);
        char* d0hex = malloc(2 * rb2 + 1);
        hex_encode(d0hex, d0buf, rb2);
        free(d0buf);

        char* resp = malloc(2 * ek_bytes + 2 * rb2 + 64);
        snprintf(resp, 2 * ek_bytes + 2 * rb2 + 64, "{\"ek_hex\":\"%s\",\"d0_hex\":\"%s\"}", ek_hex, d0hex);
        free(ek_hex);
        free(d0hex);
        return send_json_owned(conn, MHD_HTTP_OK, resp);
    }

    /* POST /round0 -- {"ct_hex":"..."} -> {"cmt_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/round0") == 0)
    {
        if (!g_share_ready || !g_ek_ready)
        {
            return send_json(conn, MHD_HTTP_CONFLICT, "{\"error\":\"not ready\"}");
        }

        char* ct_hex = NULL;
        if (parse_json_string_dyn(rb->buf, "ct_hex", &ct_hex) != 0)
        {
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing ct_hex\"}");
        }
        size_t ct_bytes = tibe_ct_serialized_bytes() + WOTS_SEEDBYTES + WOTS_VK1BYTES + WOTS_SIGBYTES;
        uint8_t* buf = malloc(ct_bytes);
        int ok = (strlen(ct_hex) == 2 * ct_bytes) && hex_decode(buf, ct_bytes, ct_hex) == 0;
        free(ct_hex);
        if (!ok)
        {
            free(buf);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"bad ct_hex\"}");
        }

        tibe_ct_deserialize(&g_ct.ct, buf);
        memcpy(g_ct.vk.seed, buf + tibe_ct_serialized_bytes(), WOTS_SEEDBYTES);
        memcpy(g_ct.vk.vk1, buf + tibe_ct_serialized_bytes() + WOTS_SEEDBYTES, WOTS_VK1BYTES);
        memcpy(g_ct.sig, buf + tibe_ct_serialized_bytes() + WOTS_SEEDBYTES + WOTS_VK1BYTES, WOTS_SIGBYTES);
        free(buf);

        uint8_t cmt[TIBE_CMT_BYTES];
        int verify_ok = tkem_share_decaps_0(cmt, &g_round0_state, &g_ct, &g_ek, g_ctx);
        if (!verify_ok)
        {
            g_session_active = 0;
            printf("[tibe_sh x=%d] round0: ciphertext REJECTED (SIG.Verify failed)\n", g_share.x);
            fflush(stdout);
            return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"SIG.Verify failed\"}");
        }
        g_session_active = 1;

        char cmt_hex[2 * TIBE_CMT_BYTES + 1];
        hex_encode(cmt_hex, cmt, sizeof(cmt));
        char* resp = malloc(2 * TIBE_CMT_BYTES + 64);
        snprintf(resp, 2 * TIBE_CMT_BYTES + 64, "{\"cmt_hex\":\"%s\"}", cmt_hex);
        printf("[tibe_sh x=%d] round0 done\n", g_share.x);
        fflush(stdout);
        return send_json_owned(conn, MHD_HTTP_OK, resp);
    }

    /* POST /round1 -- {} -> {"w_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/round1") == 0)
    {
        if (!g_session_active)
        {
            return send_json(conn, MHD_HTTP_CONFLICT, "{\"error\":\"no active session (run round0 first)\"}");
        }
        ring_elem w;
        ring_init(&w);
        int ok = tkem_share_decaps_1(&w, &g_round0_state, &g_ct);
        if (!ok)
        {
            ring_free(&w);
            return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"SIG.Verify failed\"}");
        }

        size_t rbytes = ring_serialized_bytes();
        uint8_t* wbuf = malloc(rbytes);
        ring_serialize(wbuf, &w);
        ring_free(&w);
        char* w_hex = malloc(2 * rbytes + 1);
        hex_encode(w_hex, wbuf, rbytes);
        free(wbuf);
        char* resp = malloc(2 * rbytes + 64);
        snprintf(resp, 2 * rbytes + 64, "{\"w_hex\":\"%s\"}", w_hex);
        free(w_hex);
        printf("[tibe_sh x=%d] round1 done\n", g_share.x);
        fflush(stdout);
        return send_json_owned(conn, MHD_HTTP_OK, resp);
    }

    /* POST /round2 -- {"my_index":N,"act_x_csv":"...","cmts_hex":"...","ws_hex":"..."}
     * -> {"contrib_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/round2") == 0)
    {
        if (!g_session_active)
        {
            return send_json(conn, MHD_HTTP_CONFLICT, "{\"error\":\"no active session (run round0 first)\"}");
        }

        int my_index = -1;
        char *act_x_csv = NULL, *cmts_hex = NULL, *ws_hex = NULL;
        if (parse_json_int(rb->buf, "my_index", &my_index) != 0 ||
            parse_json_string_dyn(rb->buf, "act_x_csv", &act_x_csv) != 0 ||
            parse_json_string_dyn(rb->buf, "cmts_hex", &cmts_hex) != 0 ||
            parse_json_string_dyn(rb->buf, "ws_hex", &ws_hex) != 0)
        {
            free(act_x_csv);
            free(cmts_hex);
            free(ws_hex);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing fields\"}");
        }

        int act_x[TIBE_T];
        int act_size = parse_csv_ints(act_x_csv, act_x, TIBE_T);
        free(act_x_csv);

        uint8_t cmts[TIBE_T][TIBE_CMT_BYTES];
        ring_elem ws[TIBE_T];
        for (int i = 0; i < TIBE_T; i++)
        {
            ring_init(&ws[i]);
        }
        size_t rbytes = ring_serialized_bytes();
        int parse_ok = (act_size == TIBE_T) && (strlen(cmts_hex) == (size_t)TIBE_T * 2 * TIBE_CMT_BYTES) &&
                        (strlen(ws_hex) == (size_t)TIBE_T * 2 * rbytes);
        if (parse_ok)
        {
            /* hex_decode validates via strlen(hex), so each chunk needs
             * its own NUL-terminated copy -- a pointer into the middle
             * of cmts_hex/ws_hex would have hex_decode measure to the
             * end of the whole buffer, not just this entry. */
            char cmt_chunk[2 * TIBE_CMT_BYTES + 1];
            char* w_chunk = malloc(2 * rbytes + 1);
            for (int i = 0; i < TIBE_T; i++)
            {
                memcpy(cmt_chunk, cmts_hex + (size_t)i * 2 * TIBE_CMT_BYTES, 2 * TIBE_CMT_BYTES);
                cmt_chunk[2 * TIBE_CMT_BYTES] = '\0';
                if (hex_decode(cmts[i], TIBE_CMT_BYTES, cmt_chunk) != 0)
                {
                    parse_ok = 0;
                    break;
                }

                memcpy(w_chunk, ws_hex + (size_t)i * 2 * rbytes, 2 * rbytes);
                w_chunk[2 * rbytes] = '\0';
                uint8_t* wbuf = malloc(rbytes);
                int wok = (hex_decode(wbuf, rbytes, w_chunk) == 0);
                if (wok)
                {
                    ring_deserialize(&ws[i], wbuf);
                }
                free(wbuf);
                if (!wok)
                {
                    parse_ok = 0;
                    break;
                }
            }
            free(w_chunk);
        }
        free(cmts_hex);
        free(ws_hex);

        if (!parse_ok || my_index < 0 || my_index >= TIBE_T)
        {
            for (int i = 0; i < TIBE_T; i++)
            {
                ring_free(&ws[i]);
            }
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"bad round2 payload\"}");
        }

        threshold_contrib2 contrib;
        threshold_contrib2_init(&contrib);
        int ok = tkem_share_decaps_2(&contrib, &g_round0_state, &g_share, &g_ct, &g_ek, act_x, act_size, my_index,
                                      cmts, ws, g_ctx);
        for (int i = 0; i < TIBE_T; i++)
        {
            ring_free(&ws[i]);
        }

        if (!ok)
        {
            threshold_contrib2_free(&contrib);
            printf("[tibe_sh x=%d] round2: REJECTED (bad SIG or a caught liar in the commit check)\n", g_share.x);
            fflush(stdout);
            return send_json(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"round2 failed (verify or commit check)\"}");
        }

        size_t cbytes = threshold_contrib2_serialized_bytes();
        uint8_t* cbuf = malloc(cbytes);
        threshold_contrib2_serialize(cbuf, &contrib);
        threshold_contrib2_free(&contrib);
        char* c_hex = malloc(2 * cbytes + 1);
        hex_encode(c_hex, cbuf, cbytes);
        free(cbuf);
        char* resp = malloc(2 * cbytes + 64);
        snprintf(resp, 2 * cbytes + 64, "{\"contrib_hex\":\"%s\"}", c_hex);
        free(c_hex);

        g_session_active = 0; /* session complete */
        printf("[tibe_sh x=%d] round2 done\n", g_share.x);
        fflush(stdout);
        return send_json_owned(conn, MHD_HTTP_OK, resp);
    }

    return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
}

static void
on_complete(void* cls, struct MHD_Connection* conn, void** con_cls, enum MHD_RequestTerminationCode toe)
{
    (void)cls;
    (void)conn;
    (void)toe;
    ReqBody* rb = (ReqBody*)*con_cls;
    if (rb)
    {
        free(rb->buf);
        free(rb);
    }
    *con_cls = NULL;
}

int
main(int argc, char* argv[])
{
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    printf("[tibe_shareholder] Starting on port %d (BCHK+ threshold KEM, T=%d/N=%d)\n", port, TIBE_T, TIBE_N);
    fflush(stdout);

    g_ctx = BN_CTX_new();
    threshold_share_init(&g_share);
    tibe_ek_init(&g_ek);
    tkem_ct_init(&g_ct);
    threshold_round0_state_init(&g_round0_state);

    /* Phase 8d: peer hostnames (for the direct peer-to-peer /dkg_receive
     * calls, see file header comment) and per-global-array init --
     * every ring_elem this file deserializes/zeros into via the DKG
     * handlers must already have its BIGNUM coefficients allocated
     * (ring_init / *_init), or those calls dereference NULL. */
    const char* hosts_str = getenv("TIBE_SHAREHOLDER_HOSTS");
    const char* peer_port_str = getenv("TIBE_SHAREHOLDER_PORT");
    g_peer_port = peer_port_str ? atoi(peer_port_str) : port;
    const char* hosts_csv =
        hosts_str ? hosts_str : "tsh1,tsh2,tsh3,tsh4,tsh5,tsh6,tsh7,tsh8,tsh9,tsh10";
    {
        char tmp[2048];
        strncpy(tmp, hosts_csv, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        g_n_hosts = 0;
        char* tok = strtok(tmp, ",");
        while (tok && g_n_hosts < TIBE_N)
        {
            strncpy(g_peer_hosts[g_n_hosts], tok, sizeof(g_peer_hosts[0]) - 1);
            g_peer_hosts[g_n_hosts][sizeof(g_peer_hosts[0]) - 1] = '\0';
            g_n_hosts++;
            tok = strtok(NULL, ",");
        }
        if (g_n_hosts != TIBE_N)
        {
            fprintf(stderr, "[tibe_shareholder] WARNING: expected %d peer hosts, got %d\n", TIBE_N, g_n_hosts);
        }
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);

    dkg_pubkey_round1_init(&g_pk_state);
    for (int i = 0; i < TIBE_N; i++)
    {
        dkg_public_share_init(&g_dkg_pub[i]);
        v3s_recipient_data_init(&g_dkg_recv[i]);
        ring_init(&g_a0_reveal[i]);
        ring_init(&g_d0_reveal[i]);
        ring_init(&g_b0mask_recv[i]);
        ring_init(&g_b0_contribs[i]);
    }
    ring_init(&g_a0);
    ring_init(&g_d0);
    ring_init(&g_b0);

    struct MHD_Daemon* d =
        MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, (uint16_t)port, NULL, NULL, handler, NULL,
                          MHD_OPTION_NOTIFY_COMPLETED, on_complete, NULL, MHD_OPTION_END);
    if (!d)
    {
        fprintf(stderr, "Failed to start daemon\n");
        return 1;
    }
    printf("[tibe_shareholder] Ready.\n");
    fflush(stdout);
    while (1)
    {
        pause();
    }
    MHD_stop_daemon(d);
    return 0;
}
