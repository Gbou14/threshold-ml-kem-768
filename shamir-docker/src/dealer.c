/*
 * dealer.c — adapted directly from main.c keygen + split section
 *
 * 1. Calls keygen() → secret vector s[VECTOR_DIM]
 * 2. Calls shamir_split() on each dimension (same loop as original main.c)
 * 3. POSTs each party's share-vector to its shareholder via HTTP
 *
 * ENV:
 *   SHAREHOLDER_HOSTS   comma-separated (default: sh1,sh2,sh3,sh4,sh5)
 *   SHAREHOLDER_PORT    (default: 8080)
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

static int parse_hosts(const char *csv, char hosts[][MAX_HOST_LEN], int max) {
    char tmp[1024];
    strncpy(tmp, csv, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';
    int count = 0;
    char *tok = strtok(tmp, ",");
    while (tok && count < max) {
        strncpy(hosts[count], tok, MAX_HOST_LEN-1);
        hosts[count][MAX_HOST_LEN-1] = '\0';
        count++; tok = strtok(NULL, ",");
    }
    return count;
}

static long http_post(const char *url, const char *json) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     json);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs); curl_easy_cleanup(curl);
    if (res != CURLE_OK) { fprintf(stderr,"[dealer] curl: %s\n", curl_easy_strerror(res)); return -1; }
    return code;
}

static void wait_healthy(const char *host, int port) {
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
    for (int i = 0; i < 30; i++) {
        CURL *c = curl_easy_init();
        curl_easy_setopt(c, CURLOPT_URL, url);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 1L);
        curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
        CURLcode res = curl_easy_perform(c);
        long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
        curl_easy_cleanup(c);
        if (res == CURLE_OK && code == 200) { printf("[dealer] %s ready\n", host); return; }
        printf("[dealer] waiting for %s (%d/30)...\n", host, i+1); sleep(1);
    }
    fprintf(stderr,"[dealer] WARNING: %s never healthy\n", host);
}

int main(void) {
    srand((unsigned)time(NULL));

    const char *hosts_str = getenv("SHAREHOLDER_HOSTS");
    const char *port_str  = getenv("SHAREHOLDER_PORT");
    int sh_port = port_str ? atoi(port_str) : 8080;
    const char *hosts_csv = hosts_str ? hosts_str : "sh1,sh2,sh3,sh4,sh5";

    char hosts[N_PARTIES][MAX_HOST_LEN];
    int  hcount = parse_hosts(hosts_csv, hosts, N_PARTIES);
    if (hcount != N_PARTIES) {
        fprintf(stderr,"[dealer] need %d hosts, got %d\n", N_PARTIES, hcount);
        return 1;
    }

    /* ── keygen — identical to original main.c ── */
    int s[VECTOR_DIM];
    keygen(s);
    printf("[dealer] s = [");
    for (int d = 0; d < VECTOR_DIM; d++) printf("%d%s", s[d], d<VECTOR_DIM-1?",":"");
    printf("]\n");

    /* ── shamir_split per dimension — identical loop to original main.c ── */
    int shares[N_PARTIES][VECTOR_DIM][2];
    for (int d = 0; d < VECTOR_DIM; d++) {
        int temp[N_PARTIES][2];
        shamir_split(s[d], temp, THRESHOLD, N_PARTIES);
        for (int i = 0; i < N_PARTIES; i++) {
            shares[i][d][0] = temp[i][0];   /* x-coordinate */
            shares[i][d][1] = temp[i][1];   /* y-value      */
        }
    }
    printf("[dealer] %d-of-%d scheme, dim=%d\n", THRESHOLD, N_PARTIES, VECTOR_DIM);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    for (int i = 0; i < N_PARTIES; i++) wait_healthy(hosts[i], sh_port);

    /* ── send each party its (x, share_vector[]) ── */
    for (int i = 0; i < N_PARTIES; i++) {
        /* JSON: {"party_index":i, "x":x, "shares":[y0,y1,...]} */
        char body[512];
        int pos = snprintf(body, sizeof(body),
                           "{\"party_index\":%d,\"x\":%d,\"shares\":[",
                           i, shares[i][0][0]);
        for (int d = 0; d < VECTOR_DIM; d++)
            pos += snprintf(body+pos, sizeof(body)-pos,
                            "%d%s", shares[i][d][1], d<VECTOR_DIM-1?",":"");
        snprintf(body+pos, sizeof(body)-pos, "]}");

        char url[256];
        snprintf(url, sizeof(url), "http://%s:%d/store_shares", hosts[i], sh_port);

        printf("[dealer] → %s  x=%d  y=[", hosts[i], shares[i][0][0]);
        for (int d = 0; d < VECTOR_DIM; d++)
            printf("%d%s", shares[i][d][1], d<VECTOR_DIM-1?",":"");
        printf("]\n");

        long code = http_post(url, body);
        printf("[dealer]   HTTP %ld\n", code);
    }

    curl_global_cleanup();
    printf("[dealer] All shares distributed.\n");
    return 0;
}
