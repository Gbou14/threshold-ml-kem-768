/*
 * coordinator.c — adapted directly from main.c experiment loop
 *
 * Runs 200 encrypt → partial_decrypt → reconstruct → measure trials,
 * but now the partial_decrypt step happens inside the shareholder
 * containers via HTTP POST /partial_decrypt.
 *
 * The logic mirrors original main.c exactly:
 *   for each trial:
 *     encrypt(s_dummy, u, &v, message, &noise)      ← but s is unknown to us!
 *     for i in 0..THRESHOLD:
 *       POST /partial_decrypt {u} to sh[i]           ← replaces partial_decrypt()
 *       partials[i] = {x, partial}
 *     combined = shamir_reconstruct(partials, THRESHOLD)
 *     recovered = (v + combined) % Q
 *     log noise, recovered, distance, success
 *
 * IMPORTANT: The coordinator does NOT know s. It only knows the
 * ciphertext (u, v) which it generates via the encrypt() function
 * using a zero secret (the real s lives only in the shareholders).
 * In a real deployment the coordinator would receive (u,v) from
 * an external party. Here for experiment reproducibility we call
 * encrypt() locally with s=0 so v = dot(0,u)+noise+msg = noise+msg.
 *
 * ENV:
 *   THRESHOLD           (default: 3)
 *   SHAREHOLDER_HOSTS   comma-separated (default: sh1,sh2,sh3,sh4,sh5)
 *   SHAREHOLDER_PORT    (default: 8080)
 *   USE_HOSTS           optional subset to contact (e.g. "sh1,sh3,sh5")
 *   N_TRIALS            number of trials (default: 200)
 *   OUTPUT_FILE         CSV path (default: /data/results.csv)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <curl/curl.h>

#include "params.h"
#include "toy_crypto.h"
#include "shamir.h"

#define MAX_HOST_LEN 64

/* ── HTTP helpers ──────────────────────────────────────────────────────────── */
typedef struct { char *data; size_t len; } Buffer;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *ud) {
    size_t total = size * nmemb;
    Buffer *b = (Buffer*)ud;
    b->data = realloc(b->data, b->len + total + 1);
    memcpy(b->data + b->len, ptr, total);
    b->len += total;
    b->data[b->len] = '\0';
    return total;
}

static int http_post_json(const char *url, const char *body,
                          char *resp_buf, size_t resp_max) {
    Buffer buf = {NULL, 0};
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,3L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs); curl_easy_cleanup(curl);
    if (res != CURLE_OK || code != 200) { free(buf.data); return -1; }
    if (buf.data && resp_buf) {
        strncpy(resp_buf, buf.data, resp_max-1);
        resp_buf[resp_max-1] = '\0';
    }
    free(buf.data);
    return 0;
}

static int parse_hosts(const char *csv, char hosts[][MAX_HOST_LEN], int max) {
    char tmp[1024]; strncpy(tmp, csv, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    int count = 0; char *tok = strtok(tmp, ",");
    while (tok && count < max) {
        strncpy(hosts[count], tok, MAX_HOST_LEN-1);
        hosts[count][MAX_HOST_LEN-1]='\0'; count++; tok=strtok(NULL,",");
    }
    return count;
}

/* Wait for dealer to finish (all shareholders healthy AND have shares) */
static void wait_for_shares(const char *host, int port) {
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
    for (int i = 0; i < 60; i++) {
        CURL *c = curl_easy_init();
        curl_easy_setopt(c, CURLOPT_URL, url);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 1L);
        curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
        CURLcode res = curl_easy_perform(c);
        long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
        curl_easy_cleanup(c);
        if (res == CURLE_OK && code == 200) return;
        sleep(1);
    }
}

int main(void) {
    srand((unsigned)time(NULL));

    const char *k_str      = getenv("THRESHOLD");
    const char *hosts_str  = getenv("SHAREHOLDER_HOSTS");
    const char *use_str    = getenv("USE_HOSTS");
    const char *port_str   = getenv("SHAREHOLDER_PORT");
    const char *ntrials_str= getenv("N_TRIALS");
    const char *outfile    = getenv("OUTPUT_FILE");

    int k       = k_str      ? atoi(k_str)      : THRESHOLD;
    int sh_port = port_str   ? atoi(port_str)   : 8080;
    int ntrials = ntrials_str? atoi(ntrials_str): 200;
    if (!outfile) outfile = "/data/results.csv";

    const char *hosts_csv = use_str ? use_str :
                            hosts_str ? hosts_str : "sh1,sh2,sh3,sh4,sh5";
    char hosts[N_PARTIES][MAX_HOST_LEN];
    int  hcount = parse_hosts(hosts_csv, hosts, N_PARTIES);

    if (hcount < k) {
        fprintf(stderr,"[coord] need at least %d hosts, got %d\n", k, hcount);
        return 1;
    }

    printf("[coord] Using first %d of %d available shareholders\n", k, hcount);
    printf("[coord] Threshold=%d  Trials=%d  Output=%s\n", k, ntrials, outfile);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Wait for all shareholders we plan to use */
    for (int i = 0; i < k; i++) wait_for_shares(hosts[i], sh_port);
    sleep(2); /* let dealer finish distributing */

    /* Open CSV — same header as original main.c */
    FILE *fp = fopen(outfile, "w");
    if (!fp) { perror("fopen"); return 1; }
    fprintf(fp, "noise,recovered,distance,success\n");

    int total_success = 0;

    for (int trial = 0; trial < ntrials; trial++) {

        /* ── Encrypt (same as original main.c) ──
           We use a zero secret here because the real s is split across
           shareholders. The coordinator only needs (u, v) to distribute. */
        int s_zero[VECTOR_DIM];
        memset(s_zero, 0, sizeof(s_zero));

        int u[VECTOR_DIM];
        int v, noise;
        int message = 1;
        encrypt(s_zero, u, &v, message, &noise);

        /* Build JSON for u: {"u":[u0,u1,...]} */
        char u_json[512];
        int pos = snprintf(u_json, sizeof(u_json), "{\"u\":[");
        for (int d = 0; d < VECTOR_DIM; d++)
            pos += snprintf(u_json+pos, sizeof(u_json)-pos,
                            "%d%s", u[d], d<VECTOR_DIM-1?",":"");
        snprintf(u_json+pos, sizeof(u_json)-pos, "]}");

        /* ── Collect partial decrypts (replaces the inner loop in main.c) ── */
        int partials[THRESHOLD][2];
        int collected = 0;

        for (int i = 0; i < hcount && collected < k; i++) {
            char url[256], resp[256];
            snprintf(url, sizeof(url), "http://%s:%d/partial_decrypt",
                     hosts[i], sh_port);

            if (http_post_json(url, u_json, resp, sizeof(resp)) == 0) {
                /* parse {"x":<int>,"partial":<int>} */
                int x = 0, partial = 0;
                const char *xp = strstr(resp, "\"x\"");
                const char *pp = strstr(resp, "\"partial\"");
                if (xp) { xp = strchr(xp,':'); if (xp) x       = atoi(xp+1); }
                if (pp) { pp = strchr(pp,':');  if (pp) partial = atoi(pp+1); }

                partials[collected][0] = x;
                partials[collected][1] = partial;
                collected++;
            }
        }

        if (collected < k) {
            fprintf(stderr,"[coord] trial %d: only got %d/%d partials, skipping\n",
                    trial, collected, k);
            continue;
        }

        /* ── Reconstruct + decode (identical to original main.c) ── */
        int combined = shamir_reconstruct(partials, k);
        int recovered = (v + combined) % Q;
        if (recovered < 0) recovered += Q;

        /* ── Research metrics (identical to original main.c) ── */
        int distance = recovered - message;
        if (distance < 0) distance = -distance;
        int success = (recovered == message);

        fprintf(fp, "%d,%d,%d,%d\n", noise, recovered, distance, success);
        total_success += success;
    }

    fclose(fp);
    curl_global_cleanup();

    printf("[coord] Done. %d/%d trials succeeded. Results at %s\n",
           total_success, ntrials, outfile);
    return 0;
}
