/*
 * tibe_shareholder.c -- HTTP server for one BCHK+ threshold-KEM
 * shareholder party (Phase 7, the TIBE/BCHK+ counterpart to
 * shareholder.c's Kyber-side role).
 *
 * REST API:
 *   GET  /health
 *   POST /store_share  -- receives this party's private share (its
 *                          Shamir shares of s_a/e_a, d0, and the
 *                          pairwise-seed table); the master secret
 *                          (s_a, e_a) itself is never reconstructed
 *                          here or anywhere
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
 * demo where the coordinator drives one session at a time.
 *
 * Request/response bodies here are much larger than the Kyber
 * demo's (a single ring element serializes to ~53 KB; a full
 * ciphertext to ~535 KB), so unlike shareholder.c's fixed 8 KB
 * buffer, request bodies are accumulated into a dynamically-grown
 * buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <microhttpd.h>
#include <openssl/bn.h>

#include "hexutil.h"
#include "tibe/threshold.h"
#include "tibe/tkem.h"

/* ── Party state ─────────────────────────────────────────────────────────── */
static threshold_share g_share;
static int g_share_ready = 0;

static tibe_ek g_ek;
static int g_ek_ready = 0;

static tkem_ct g_ct;
static threshold_round0_state g_round0_state;
static int g_session_active = 0; /* round0 has run for g_ct, valid through round1/round2 */

static BN_CTX* g_ctx;

/* ── ek: lazily loaded from the shared volume (the dealer writes it
 * after this shareholder is already answering /health, so it can't
 * be loaded at startup without deadlocking the dealer's own
 * wait-for-healthy loop -- see src/tibe_dealer.c). ── */
static int
ensure_ek_loaded(void)
{
    if (g_ek_ready)
    {
        return 1;
    }
    const char* path = getenv("TIBE_EK_PATH");
    if (!path)
    {
        path = "/data/tibe_ek.bin";
    }
    size_t ek_bytes = tibe_ek_serialized_bytes();
    uint8_t* buf = malloc(ek_bytes);
    for (int attempt = 0; attempt < 120; attempt++)
    {
        FILE* f = fopen(path, "rb");
        if (f)
        {
            size_t n = fread(buf, 1, ek_bytes, f);
            fclose(f);
            if (n == ek_bytes)
            {
                tibe_ek_deserialize(&g_ek, buf);
                free(buf);
                g_ek_ready = 1;
                return 1;
            }
        }
        sleep(1);
    }
    free(buf);
    return 0;
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

    /* POST /store_share -- {"x":N,"share_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/store_share") == 0)
    {
        int x = 0;
        char* share_hex = NULL;
        if (parse_json_int(rb->buf, "x", &x) != 0 || parse_json_string_dyn(rb->buf, "share_hex", &share_hex) != 0)
        {
            free(share_hex);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing fields\"}");
        }

        size_t priv_bytes = threshold_share_private_serialized_bytes();
        uint8_t* priv_buf = malloc(priv_bytes);
        int ok = (strlen(share_hex) == 2 * priv_bytes) && hex_decode(priv_buf, priv_bytes, share_hex) == 0;
        free(share_hex);
        if (!ok)
        {
            free(priv_buf);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"bad share_hex\"}");
        }

        threshold_share_private_deserialize(&g_share, priv_buf);
        free(priv_buf);
        g_share.x = x;
        g_share_ready = 1;

        printf("[tibe_sh x=%d] Stored threshold share\n", x);
        fflush(stdout);
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    }

    /* POST /round0 -- {"ct_hex":"..."} -> {"cmt_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/round0") == 0)
    {
        if (!g_share_ready || !ensure_ek_loaded())
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
