/*
 * tibe_dealer.c -- BCHK+ threshold-KEM distributed setup orchestrator
 * (Phase 8d; replaces the old Phase 7 centralized-keygen dealer
 * entirely -- see BCHK_TODO.md Phase 8d).
 *
 * This process NEVER holds, computes, or sees (s_a,e_a), a0, d0, or
 * b0 -- unlike the Phase 7 tibe_dealer, it is not a "dealer" in the
 * cryptographic sense at all anymore, only in the sense of being the
 * process that happens to kick off and sequence the setup rounds. It
 * orchestrates dkg_round1..dkg_round4 (src/tibe/dkg.h, dkg_pubkey.h)
 * across all TIBE_N shareholders by relaying only PUBLIC broadcast
 * data between rounds (roots, v_shares, a0/d0 commitments and
 * reveals, verdict vectors, b0 contributions) -- every shareholder's
 * PRIVATE per-recipient V3S payload goes directly shareholder-to-
 * shareholder instead (see tibe_shareholder.c's /dkg_receive), never
 * through this process. If this process saw those private payloads,
 * it would have enough Shamir shares to reconstruct every party's
 * individual secret itself, becoming a trusted dealer again -- see
 * tibe_shareholder.c's own header comment for the same point made in
 * more detail.
 *
 * At the end, ek/d0 (both public, regardless of how they were
 * generated -- see tibe_shareholder.c's /dkg_get_public comment) are
 * fetched from one shareholder and written to the same shared-volume
 * paths the old dealer used, purely so tibe_coordinator.c (unchanged
 * from Phase 7) still has somewhere to read them from.
 *
 * ENV:
 *   TIBE_SHAREHOLDER_HOSTS  comma-separated, TIBE_N of them
 *   TIBE_SHAREHOLDER_PORT   (default: 8080)
 *   TIBE_EK_PATH, TIBE_D0_PATH  where to write the finalized ek/d0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/bn.h>

#include "hexutil.h"
#include "tibe/dkg_pubkey.h"
#include "tibe/threshold.h"
#include "tibe/tkem.h"
#include "tibe/v3s.h"

#define MAX_HOST_LEN 64

/* ── HTTP helpers, matching tibe_coordinator.c's established pattern ── */
typedef struct
{
    char* data;
    size_t len;
} Buffer;

static size_t
write_cb(void* ptr, size_t size, size_t nmemb, void* ud)
{
    size_t total = size * nmemb;
    Buffer* b = (Buffer*)ud;
    b->data = realloc(b->data, b->len + total + 1);
    memcpy(b->data + b->len, ptr, total);
    b->len += total;
    b->data[b->len] = '\0';
    return total;
}

static char*
http_post_json(const char* url, const char* json)
{
    Buffer buf = {NULL, 0};
    CURL* curl = curl_easy_init();
    if (!curl)
    {
        return NULL;
    }
    struct curl_slist* hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180L); /* payloads can be several MB across TIBE_N parties */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK || code != 200)
    {
        fprintf(stderr, "[tibe_dealer] POST %s failed (curl=%d http=%ld)%s%s\n", url, res, code,
                buf.data ? " body=" : "", buf.data ? buf.data : "");
        free(buf.data);
        return NULL;
    }
    return buf.data;
}

static char*
http_get(const char* url)
{
    Buffer buf = {NULL, 0};
    CURL* curl = curl_easy_init();
    if (!curl)
    {
        return NULL;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK || code != 200)
    {
        fprintf(stderr, "[tibe_dealer] GET %s failed (curl=%d http=%ld)\n", url, res, code);
        free(buf.data);
        return NULL;
    }
    return buf.data;
}

static int
parse_hosts(const char* csv, char hosts[][MAX_HOST_LEN], int max)
{
    char tmp[2048];
    strncpy(tmp, csv, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    int count = 0;
    char* tok = strtok(tmp, ",");
    while (tok && count < max)
    {
        strncpy(hosts[count], tok, MAX_HOST_LEN - 1);
        hosts[count][MAX_HOST_LEN - 1] = '\0';
        count++;
        tok = strtok(NULL, ",");
    }
    return count;
}

static void
wait_healthy(const char* host, int port)
{
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
    for (int i = 0; i < 60; i++)
    {
        CURL* c = curl_easy_init();
        curl_easy_setopt(c, CURLOPT_URL, url);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 1L);
        curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
        CURLcode res = curl_easy_perform(c);
        long code = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
        curl_easy_cleanup(c);
        if (res == CURLE_OK && code == 200)
        {
            printf("[tibe_dealer] %s ready\n", host);
            fflush(stdout);
            return;
        }
        printf("[tibe_dealer] waiting for %s (%d/60)...\n", host, i + 1);
        fflush(stdout);
        sleep(1);
    }
    fprintf(stderr, "[tibe_dealer] WARNING: %s never healthy\n", host);
}

static char*
parse_json_string_dyn(const char* json, const char* key)
{
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* p = strstr(json, search);
    if (!p)
    {
        return NULL;
    }
    p = strchr(p + strlen(search), ':');
    if (!p)
    {
        return NULL;
    }
    p++;
    while (*p == ' ')
    {
        p++;
    }
    if (*p != '"')
    {
        return NULL;
    }
    p++;
    const char* end = strchr(p, '"');
    if (!end)
    {
        return NULL;
    }
    size_t len = (size_t)(end - p);
    char* out = malloc(len + 1);
    memcpy(out, p, len);
    out[len] = '\0';
    return out;
}

static int
write_file(const char* path, const uint8_t* data, size_t len)
{
    FILE* f = fopen(path, "wb");
    if (!f)
    {
        perror("[tibe_dealer] fopen");
        return -1;
    }
    int ok = (fwrite(data, 1, len, f) == len);
    fclose(f);
    if (!ok)
    {
        fprintf(stderr, "[tibe_dealer] short write to %s\n", path);
    }
    return ok ? 0 : -1;
}

int
main(void)
{
    printf("[tibe_dealer] starting distributed setup orchestration (T=%d, N=%d)\n", TIBE_T, TIBE_N);
    printf("[tibe_dealer] this process never sees (s_a,e_a), a0, d0, or b0 -- see file header comment\n");
    fflush(stdout);

    const char* hosts_str = getenv("TIBE_SHAREHOLDER_HOSTS");
    const char* port_str = getenv("TIBE_SHAREHOLDER_PORT");
    const char* ek_path_env = getenv("TIBE_EK_PATH");
    const char* d0_path_env = getenv("TIBE_D0_PATH");
    int sh_port = port_str ? atoi(port_str) : 8080;
    const char* hosts_csv = hosts_str ? hosts_str : "tsh1,tsh2,tsh3,tsh4,tsh5,tsh6,tsh7,tsh8,tsh9,tsh10";
    const char* ek_path = ek_path_env ? ek_path_env : "/data/tibe_ek.bin";
    const char* d0_path = d0_path_env ? d0_path_env : "/data/tibe_d0.bin";

    char hosts[TIBE_N][MAX_HOST_LEN];
    int hcount = parse_hosts(hosts_csv, hosts, TIBE_N);
    if (hcount != TIBE_N)
    {
        fprintf(stderr, "[tibe_dealer] need %d hosts, got %d\n", TIBE_N, hcount);
        return 1;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    for (int i = 0; i < TIBE_N; i++)
    {
        wait_healthy(hosts[i], sh_port);
    }

    size_t pub_bytes = V3S_PUBLIC_SERIALIZED_BYTES;
    size_t cmt_bytes = DKG_PUBKEY_CMT_BYTES;
    size_t rbytes = ring_serialized_bytes();
    size_t nonce_bytes = DKG_PUBKEY_NONCE_BYTES;

    /* ── Round 1: trigger each party's local secret generation +
     * peer-to-peer V3S delivery; collect public data. ── */
    printf("[tibe_dealer] round1: triggering local generation on all %d parties\n", TIBE_N);
    fflush(stdout);
    char* all_pub_hex = malloc(TIBE_N * 2 * pub_bytes + 1);
    char* all_cmt_hex = malloc(TIBE_N * 2 * cmt_bytes + 1);
    all_pub_hex[0] = '\0';
    all_cmt_hex[0] = '\0';
    for (int i = 0; i < TIBE_N; i++)
    {
        char url[256], body[64];
        snprintf(url, sizeof(url), "http://%s:%d/dkg_round1", hosts[i], sh_port);
        snprintf(body, sizeof(body), "{\"my_index\":%d}", i);
        char* resp = http_post_json(url, body);
        if (!resp)
        {
            fprintf(stderr, "[tibe_dealer] round1 failed for party %d\n", i);
            return 1;
        }
        char* pub_hex = parse_json_string_dyn(resp, "pub_hex");
        char* cmt_hex = parse_json_string_dyn(resp, "cmt_hex");
        free(resp);
        if (!pub_hex || !cmt_hex || strlen(pub_hex) != 2 * pub_bytes || strlen(cmt_hex) != 2 * cmt_bytes)
        {
            fprintf(stderr, "[tibe_dealer] round1: bad response from party %d\n", i);
            free(pub_hex);
            free(cmt_hex);
            return 1;
        }
        strcat(all_pub_hex, pub_hex);
        strcat(all_cmt_hex, cmt_hex);
        free(pub_hex);
        free(cmt_hex);
        printf("[tibe_dealer] round1: party %d done\n", i);
        fflush(stdout);
    }

    /* ── Round 2: relay all public data; collect verdicts + a0/d0 reveals. ── */
    printf("[tibe_dealer] round2: relaying public data, collecting verdicts + a0/d0 reveals\n");
    fflush(stdout);
    char* all_verdicts_csv = malloc((size_t)TIBE_N * (4 * TIBE_N + 2) + 1);
    char* all_a0_hex = malloc((size_t)TIBE_N * 2 * rbytes + 1);
    char* all_d0_hex = malloc((size_t)TIBE_N * 2 * rbytes + 1);
    char* all_nonce_hex = malloc((size_t)TIBE_N * 2 * nonce_bytes + 1);
    all_verdicts_csv[0] = '\0';
    all_a0_hex[0] = '\0';
    all_d0_hex[0] = '\0';
    all_nonce_hex[0] = '\0';
    {
        size_t body_cap = strlen(all_pub_hex) + strlen(all_cmt_hex) + 128;
        char* body = malloc(body_cap);
        snprintf(body, body_cap, "{\"all_pub_hex\":\"%s\",\"all_cmt_hex\":\"%s\"}", all_pub_hex, all_cmt_hex);
        for (int i = 0; i < TIBE_N; i++)
        {
            char url[256];
            snprintf(url, sizeof(url), "http://%s:%d/dkg_round2", hosts[i], sh_port);
            char* resp = http_post_json(url, body);
            if (!resp)
            {
                fprintf(stderr, "[tibe_dealer] round2 failed for party %d\n", i);
                free(body);
                return 1;
            }
            char* verdict_csv = parse_json_string_dyn(resp, "verdict_csv");
            char* a0_hex = parse_json_string_dyn(resp, "a0_hex");
            char* d0_hex = parse_json_string_dyn(resp, "d0_hex");
            char* nonce_hex = parse_json_string_dyn(resp, "nonce_hex");
            free(resp);
            if (!verdict_csv || !a0_hex || !d0_hex || !nonce_hex)
            {
                fprintf(stderr, "[tibe_dealer] round2: bad response from party %d\n", i);
                free(verdict_csv);
                free(a0_hex);
                free(d0_hex);
                free(nonce_hex);
                free(body);
                return 1;
            }
            strcat(all_verdicts_csv, verdict_csv);
            if (i + 1 < TIBE_N)
            {
                strcat(all_verdicts_csv, ",");
            }
            strcat(all_a0_hex, a0_hex);
            strcat(all_d0_hex, d0_hex);
            strcat(all_nonce_hex, nonce_hex);
            free(verdict_csv);
            free(a0_hex);
            free(d0_hex);
            free(nonce_hex);
            printf("[tibe_dealer] round2: party %d done\n", i);
            fflush(stdout);
        }
        free(body);
    }
    free(all_pub_hex);
    free(all_cmt_hex);

    /* ── Round 3: relay verdicts + a0/d0 reveals; collect masked b0 contributions. ── */
    printf("[tibe_dealer] round3: relaying verdicts + a0/d0 reveals, collecting b0 contributions\n");
    fflush(stdout);
    char* all_b0_hex = malloc((size_t)TIBE_N * 2 * rbytes + 1);
    all_b0_hex[0] = '\0';
    {
        size_t body_cap =
            strlen(all_verdicts_csv) + strlen(all_a0_hex) + strlen(all_d0_hex) + strlen(all_nonce_hex) + 256;
        char* body = malloc(body_cap);
        snprintf(body, body_cap, "{\"all_verdicts_csv\":\"%s\",\"all_a0_hex\":\"%s\",\"all_d0_hex\":\"%s\",\"all_nonce_hex\":\"%s\"}",
                 all_verdicts_csv, all_a0_hex, all_d0_hex, all_nonce_hex);
        for (int i = 0; i < TIBE_N; i++)
        {
            char url[256];
            snprintf(url, sizeof(url), "http://%s:%d/dkg_round3", hosts[i], sh_port);
            char* resp = http_post_json(url, body);
            if (!resp)
            {
                fprintf(stderr, "[tibe_dealer] round3 failed for party %d\n", i);
                free(body);
                return 1;
            }
            char* b0_hex = parse_json_string_dyn(resp, "b0_hex");
            free(resp);
            if (!b0_hex)
            {
                fprintf(stderr, "[tibe_dealer] round3: bad response from party %d\n", i);
                free(body);
                return 1;
            }
            strcat(all_b0_hex, b0_hex);
            free(b0_hex);
            printf("[tibe_dealer] round3: party %d done\n", i);
            fflush(stdout);
        }
        free(body);
    }
    free(all_verdicts_csv);
    free(all_a0_hex);
    free(all_d0_hex);
    free(all_nonce_hex);

    /* ── Round 4: relay b0 contributions; every party finalizes locally. ── */
    printf("[tibe_dealer] round4: relaying b0 contributions -- every party finalizes ek locally\n");
    fflush(stdout);
    {
        size_t body_cap = strlen(all_b0_hex) + 64;
        char* body = malloc(body_cap);
        snprintf(body, body_cap, "{\"all_b0_hex\":\"%s\"}", all_b0_hex);
        for (int i = 0; i < TIBE_N; i++)
        {
            char url[256];
            snprintf(url, sizeof(url), "http://%s:%d/dkg_round4", hosts[i], sh_port);
            char* resp = http_post_json(url, body);
            if (!resp)
            {
                fprintf(stderr, "[tibe_dealer] round4 failed for party %d\n", i);
                free(body);
                return 1;
            }
            free(resp);
            printf("[tibe_dealer] round4: party %d done\n", i);
            fflush(stdout);
        }
        free(body);
    }
    free(all_b0_hex);

    /* ── Fetch the (public) finalized ek/d0 from one party, write to
     * the shared volume for tibe_coordinator.c. ── */
    printf("[tibe_dealer] fetching finalized ek/d0 from party 0 for the shared volume\n");
    fflush(stdout);
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/dkg_get_public", hosts[0], sh_port);
    char* resp = http_get(url);
    if (!resp)
    {
        fprintf(stderr, "[tibe_dealer] failed to fetch final ek/d0\n");
        return 1;
    }
    char* ek_hex = parse_json_string_dyn(resp, "ek_hex");
    char* d0_hex = parse_json_string_dyn(resp, "d0_hex");
    free(resp);
    if (!ek_hex || !d0_hex)
    {
        fprintf(stderr, "[tibe_dealer] bad /dkg_get_public response\n");
        free(ek_hex);
        free(d0_hex);
        return 1;
    }
    size_t ek_bytes = strlen(ek_hex) / 2;
    uint8_t* ek_buf = malloc(ek_bytes);
    hex_decode(ek_buf, ek_bytes, ek_hex);
    uint8_t* d0_buf = malloc(rbytes);
    hex_decode(d0_buf, rbytes, d0_hex);
    free(ek_hex);
    free(d0_hex);
    if (write_file(ek_path, ek_buf, ek_bytes) != 0 || write_file(d0_path, d0_buf, rbytes) != 0)
    {
        free(ek_buf);
        free(d0_buf);
        return 1;
    }
    printf("[tibe_dealer] wrote ek (%zu bytes) to %s, d0 (%zu bytes) to %s\n", ek_bytes, ek_path, rbytes, d0_path);
    free(ek_buf);
    free(d0_buf);

    curl_global_cleanup();
    printf("[tibe_dealer] Distributed setup complete. No party, including this one, ever held (s_a,e_a).\n");
    return 0;
}
