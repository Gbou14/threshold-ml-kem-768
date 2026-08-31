/*
 * shareholder.c — HTTP server for one threshold-Kyber share-holder party
 *
 * REST API:
 *   GET  /health
 *   POST /store_share      — receives this party's share of the secret key
 *   POST /partial_decrypt  — computes this party's partial decryption of a
 *                            ciphertext, using its share; the secret key
 *                            itself is never reconstructed here or anywhere
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <microhttpd.h>

#include "hexutil.h"
#include "kyber/indcpa.h"
#include "kyber/threshold.h"

/* ── Party state ─────────────────────────────────────────────────────────── */
static int g_party_index = -1;
static int g_x = 0;
static polyvec g_share;
static int g_ready = 0;

/* ── JSON helpers ────────────────────────────────────────────────────────── */
static int
send_json(struct MHD_Connection *conn, unsigned int code, const char *body)
{
    struct MHD_Response *r =
        MHD_create_response_from_buffer(strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(r, "Content-Type", "application/json");
    int ret = MHD_queue_response(conn, code, r);
    MHD_destroy_response(r);
    return ret;
}

/* Extract the string value of "key" from a flat JSON object. Minimal
 * on purpose -- this demo never sends nested objects or escaped
 * strings, just integers and hex strings. */
static int
parse_json_string(const char *json, const char *key, char *out, size_t out_max)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
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
    while (*p == ' ' || *p == '"')
    {
        p++;
    }
    size_t j = 0;
    while (*p && *p != '"' && j < out_max - 1)
    {
        out[j++] = *p++;
    }
    out[j] = '\0';
    return j > 0 ? 0 : -1;
}

static int
parse_json_int(const char *json, const char *key, int *out)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
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

/* ── Request context ─────────────────────────────────────────────────────── */
#define MAX_BODY 8192
typedef struct
{
    char buf[MAX_BODY];
    size_t len;
} ReqBody;

/* ── Request handler ─────────────────────────────────────────────────────── */
static enum MHD_Result
handler(void *cls,
        struct MHD_Connection *conn,
        const char *url,
        const char *method,
        const char *version,
        const char *upload_data,
        size_t *upload_data_size,
        void **con_cls)
{
    (void)cls;
    (void)version;

    if (*con_cls == NULL)
    {
        ReqBody *rb = calloc(1, sizeof(ReqBody));
        if (!rb)
        {
            return MHD_NO;
        }
        *con_cls = rb;
        return MHD_YES;
    }
    ReqBody *rb = (ReqBody *)*con_cls;

    if (*upload_data_size > 0)
    {
        size_t copy = *upload_data_size;
        if (rb->len + copy >= MAX_BODY)
        {
            copy = MAX_BODY - rb->len - 1;
        }
        memcpy(rb->buf + rb->len, upload_data, copy);
        rb->len += copy;
        rb->buf[rb->len] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* GET /health */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/health") == 0)
    {
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"alive\"}");
    }

    /* POST /store_share — {"party_index":N,"x":N,"share_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/store_share") == 0)
    {
        int pi = 0, x = 0;
        char share_hex[2 * KYBER_POLYVECBYTES + 1];
        if (parse_json_int(rb->buf, "party_index", &pi) != 0 || parse_json_int(rb->buf, "x", &x) != 0 ||
            parse_json_string(rb->buf, "share_hex", share_hex, sizeof(share_hex)) != 0)
        {
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing fields\"}");
        }

        uint8_t share_bytes[KYBER_POLYVECBYTES];
        if (hex_decode(share_bytes, sizeof(share_bytes), share_hex) != 0)
        {
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"bad share_hex\"}");
        }
        polyvec_frombytes(&g_share, share_bytes);

        g_party_index = pi;
        g_x = x;
        g_ready = 1;

        printf("[sh%d] Stored threshold share (x=%d)\n", g_party_index, g_x);
        fflush(stdout);
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    }

    /* POST /partial_decrypt — {"ct_hex":"..."} */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/partial_decrypt") == 0)
    {
        if (!g_ready)
        {
            return send_json(conn, MHD_HTTP_CONFLICT, "{\"error\":\"no share stored yet\"}");
        }

        char ct_hex[2 * KYBER_INDCPA_BYTES + 1];
        if (parse_json_string(rb->buf, "ct_hex", ct_hex, sizeof(ct_hex)) != 0)
        {
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"missing ct_hex\"}");
        }
        uint8_t ct[KYBER_INDCPA_BYTES];
        if (hex_decode(ct, sizeof(ct), ct_hex) != 0)
        {
            return send_json(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"bad ct_hex\"}");
        }

        /* Public, secret-independent step: unpack the ciphertext's
         * vector part and bring it into NTT domain, exactly like
         * indcpa_dec does before its basemul step. */
        polyvec b;
        polyvec_decompress(&b, ct);
        polyvec_ntt(&b);

        poly partial;
        threshold_partial_decrypt(&partial, &g_share, &b);

        uint8_t partial_bytes[KYBER_POLYBYTES];
        poly_tobytes(partial_bytes, &partial);
        char partial_hex[2 * sizeof(partial_bytes) + 1];
        hex_encode(partial_hex, partial_bytes, sizeof(partial_bytes));

        printf("[sh%d] partial_decrypt computed (x=%d)\n", g_party_index, g_x);
        fflush(stdout);

        char resp[2 * sizeof(partial_bytes) + 64];
        snprintf(resp, sizeof(resp), "{\"x\":%d,\"partial_hex\":\"%s\"}", g_x, partial_hex);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
}

static void
on_complete(void *cls, struct MHD_Connection *conn, void **con_cls, enum MHD_RequestTerminationCode toe)
{
    (void)cls;
    (void)conn;
    (void)toe;
    free(*con_cls);
    *con_cls = NULL;
}

int
main(int argc, char *argv[])
{
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    printf("[shareholder] Starting on port %d (ML-KEM-768 threshold decryption)\n", port);
    fflush(stdout);

    struct MHD_Daemon *d = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD,
                                             (uint16_t)port,
                                             NULL,
                                             NULL,
                                             handler,
                                             NULL,
                                             MHD_OPTION_NOTIFY_COMPLETED,
                                             on_complete,
                                             NULL,
                                             MHD_OPTION_END);
    if (!d)
    {
        fprintf(stderr, "Failed to start daemon\n");
        return 1;
    }
    printf("[shareholder] Ready.\n");
    fflush(stdout);
    while (1)
    {
        pause();
    }
    MHD_stop_daemon(d);
    return 0;
}
