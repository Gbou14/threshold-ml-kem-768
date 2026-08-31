/*
 * shareholder.c — HTTP server for one share-holder party
 *
 * REST API:
 *   GET  /health
 *   POST /store_shares   (legacy toy LWE integer shares)
 *   POST /store_share    (real ssss hex share string)
 *   GET  /get_share      (return this party's ssss share)
 *   POST /partial_decrypt
 *   POST /dot
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>

#include "params.h"
#include "toy_crypto.h"

/* ── Party state ─────────────────────────────────────────────────────────── */
static int  g_party_index  = -1;
static int  g_x            = 0;
static int  g_share_vec[VECTOR_DIM];
static int  g_ready        = 0;
static char g_share_str[256];
static int  g_share_str_ready = 0;

/* ── JSON helpers ────────────────────────────────────────────────────────── */
static int send_json(struct MHD_Connection *conn, unsigned int code,
                     const char *body) {
    struct MHD_Response *r =
        MHD_create_response_from_buffer(strlen(body), (void*)body,
                                        MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(r, "Content-Type", "application/json");
    int ret = MHD_queue_response(conn, code, r);
    MHD_destroy_response(r);
    return ret;
}

static int parse_int_array(const char *json, const char *key,
                            int *out, int max_len) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\":[", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p = strchr(p, '[');
    if (!p) return -1;
    p++;
    int count = 0;
    while (*p && *p != ']' && count < max_len) {
        while (*p == ' ' || *p == ',') p++;
        if (*p == ']') break;
        out[count++] = atoi(p);
        while (*p && *p != ',' && *p != ']') p++;
    }
    return count;
}

/* ── Request context ─────────────────────────────────────────────────────── */
#define MAX_BODY 4096
typedef struct { char buf[MAX_BODY]; size_t len; } ReqBody;

/* ── Request handler ─────────────────────────────────────────────────────── */
static enum MHD_Result handler(void *cls,
                                struct MHD_Connection *conn,
                                const char *url, const char *method,
                                const char *version,
                                const char *upload_data, size_t *upload_data_size,
                                void **con_cls) {
    (void)cls; (void)version;

    if (*con_cls == NULL) {
        ReqBody *rb = calloc(1, sizeof(ReqBody));
        if (!rb) return MHD_NO;
        *con_cls = rb;
        return MHD_YES;
    }
    ReqBody *rb = (ReqBody*)*con_cls;

    if (*upload_data_size > 0) {
        size_t copy = *upload_data_size;
        if (rb->len + copy >= MAX_BODY) copy = MAX_BODY - rb->len - 1;
        memcpy(rb->buf + rb->len, upload_data, copy);
        rb->len += copy;
        rb->buf[rb->len] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* GET /health */
    if (strcmp(method,"GET")==0 && strcmp(url,"/health")==0)
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"alive\"}");

    /* POST /store_shares — legacy toy LWE integer shares */
    if (strcmp(method,"POST")==0 && strcmp(url,"/store_shares")==0) {
        int pi = 0, x = 0;
        const char *pi_p = strstr(rb->buf, "\"party_index\"");
        const char *x_p  = strstr(rb->buf, "\"x\"");
        if (!pi_p || !x_p)
            return send_json(conn, MHD_HTTP_BAD_REQUEST,
                             "{\"error\":\"missing fields\"}");
        pi_p = strchr(pi_p, ':'); if (pi_p) pi = atoi(pi_p+1);
        x_p  = strchr(x_p,  ':'); if (x_p)  x  = atoi(x_p+1);

        int ys[VECTOR_DIM];
        int cnt = parse_int_array(rb->buf, "shares", ys, VECTOR_DIM);
        if (cnt != VECTOR_DIM) {
            char err[128];
            snprintf(err, sizeof(err),
                     "{\"error\":\"expected %d shares, got %d\"}", VECTOR_DIM, cnt);
            return send_json(conn, MHD_HTTP_BAD_REQUEST, err);
        }
        g_party_index = pi;
        g_x           = x;
        for (int d = 0; d < VECTOR_DIM; d++) g_share_vec[d] = ys[d];
        g_ready = 1;

        printf("[sh%d] Stored legacy share: x=%d  vec=[", g_party_index, g_x);
        for (int d = 0; d < VECTOR_DIM; d++)
            printf("%d%s", g_share_vec[d], d<VECTOR_DIM-1?",":"");
        printf("]\n");
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    }

    /* POST /store_share — real ssss hex share string */
    if (strcmp(method,"POST")==0 && strcmp(url,"/store_share")==0) {
        const char *pi_p = strstr(rb->buf, "party_index");
        const char *sh_p = strstr(rb->buf, "\"share\"");
        if (!pi_p || !sh_p)
            return send_json(conn, MHD_HTTP_BAD_REQUEST,
                             "{\"error\":\"missing fields\"}");

        pi_p = strchr(pi_p, ':');
        if (pi_p) g_party_index = atoi(pi_p+1);

        sh_p = strchr(sh_p, ':');
        if (sh_p) {
            sh_p++;
            while (*sh_p == ' ' || *sh_p == '"') sh_p++;
            int j = 0;
            while (*sh_p && *sh_p != '"' && j < 255)
                g_share_str[j++] = *sh_p++;
            g_share_str[j] = '\0';
        }
        g_share_str_ready = 1;
        printf("[sh%d] Stored ssss share: %s\n", g_party_index, g_share_str);
        fflush(stdout);
        return send_json(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    }

    /* GET /get_share — return this party's ssss share string */
    if (strcmp(method,"GET")==0 && strcmp(url,"/get_share")==0) {
        if (!g_share_str_ready)
            return send_json(conn, MHD_HTTP_CONFLICT,
                             "{\"error\":\"no share stored yet\"}");
        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"party_index\":%d,\"share\":\"%s\"}",
                 g_party_index, g_share_str);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    /* POST /partial_decrypt */
    if (strcmp(method,"POST")==0 && strcmp(url,"/partial_decrypt")==0) {
        if (!g_ready)
            return send_json(conn, MHD_HTTP_CONFLICT,
                             "{\"error\":\"no shares stored yet\"}");
        int u[VECTOR_DIM];
        int cnt = parse_int_array(rb->buf, "u", u, VECTOR_DIM);
        if (cnt != VECTOR_DIM)
            return send_json(conn, MHD_HTTP_BAD_REQUEST,
                             "{\"error\":\"bad u vector\"}");
        int partial;
        partial_decrypt(g_share_vec, u, &partial);
        printf("[sh%d] partial_decrypt -> partial=%d  (x=%d)\n",
               g_party_index, partial, g_x);
        char resp[128];
        snprintf(resp, sizeof(resp), "{\"x\":%d,\"partial\":%d}", g_x, partial);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    /* POST /dot */
    if (strcmp(method,"POST")==0 && strcmp(url,"/dot")==0) {
        if (!g_ready)
            return send_json(conn, MHD_HTTP_CONFLICT,
                             "{\"error\":\"no shares stored yet\"}");
        int u[VECTOR_DIM];
        int cnt = parse_int_array(rb->buf, "u", u, VECTOR_DIM);
        if (cnt != VECTOR_DIM)
            return send_json(conn, MHD_HTTP_BAD_REQUEST,
                             "{\"error\":\"bad u vector\"}");
        int dot = 0;
        for (int d = 0; d < VECTOR_DIM; d++)
            dot = ((dot + g_share_vec[d] * u[d]) % Q + Q) % Q;
        char resp[128];
        snprintf(resp, sizeof(resp), "{\"x\":%d,\"dot\":%d}", g_x, dot);
        return send_json(conn, MHD_HTTP_OK, resp);
    }

    return send_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
}

static void on_complete(void *cls, struct MHD_Connection *conn,
                         void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls; (void)conn; (void)toe;
    free(*con_cls); *con_cls = NULL;
}

int main(int argc, char *argv[]) {
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    printf("[shareholder] Starting on port %d  (VECTOR_DIM=%d, Q=%d)\n",
           port, VECTOR_DIM, Q);
    fflush(stdout);

    struct MHD_Daemon *d =
        MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, (uint16_t)port,
                         NULL, NULL, handler, NULL,
                         MHD_OPTION_NOTIFY_COMPLETED, on_complete, NULL,
                         MHD_OPTION_END);
    if (!d) { fprintf(stderr,"Failed to start daemon\n"); return 1; }
    printf("[shareholder] Ready.\n");
    fflush(stdout);
    while (1) pause();
    MHD_stop_daemon(d);
    return 0;
}
/* cache bust Sat Apr 18 08:58:02 PM CDT 2026 */
