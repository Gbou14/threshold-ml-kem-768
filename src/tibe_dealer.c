/*
 * tibe_dealer.c -- BCHK+ threshold-KEM keypair generation + threshold
 * secret-key splitting (Phase 7, the TIBE/BCHK+ counterpart to
 * dealer.c's Kyber-side role).
 *
 * Generates a TKEM keypair (tkem_keygen == TIBE.Setup), Shamir-shares
 * (s_a, e_a) across TIBE_N parties (threshold_setup), sends each
 * shareholder's own private share over HTTP, and writes the public ek
 * plus d0 (not secret-shared -- see src/tibe/tibe.h's tibe_msk
 * comment and src/tibe/threshold.h's threshold_share_private_*
 * comment for why every party needs d0 directly) to a shared volume
 * for shareholders and the coordinator to read.
 *
 * No party, including this process after it exits, ever holds
 * (s_a, e_a) again -- only individual Shamir shares exist from that
 * point on. ek and d0 are not secret: ek is fully public (Algorithm 1
 * line 8), and d0 is needed identically by every party (see above),
 * so publishing both to a shared volume all containers can read is
 * not a weaker trust model than the per-shareholder HTTP channel --
 * it's exactly the same "distributed by the trusted dealer over a
 * secure channel" model (Remark 1), just using a different channel
 * for the parts that are the same for everyone.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/bn.h>

#include "hexutil.h"
#include "tibe/threshold.h"
#include "tibe/tkem.h"

#define MAX_HOST_LEN 64

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

static long
http_post(const char* url, const char* json)
{
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L); /* payloads are large (hundreds of KB) */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "[tibe_dealer] curl: %s\n", curl_easy_strerror(res));
        return -1;
    }
    return code;
}

static void
wait_healthy(const char* host, int port)
{
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
    /* 60, not 30 (as the Kyber-side dealer.c uses): 10 containers
     * starting simultaneously contend for CPU/IO more than 5 do, and
     * this was observed to matter in practice -- tsh10 occasionally
     * needs a bit past 30s. */
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
            return;
        }
        printf("[tibe_dealer] waiting for %s (%d/60)...\n", host, i + 1);
        fflush(stdout);
        sleep(1);
    }
    fprintf(stderr, "[tibe_dealer] WARNING: %s never healthy\n", host);
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
    printf("[tibe_dealer] starting (T=%d, N=%d)\n", TIBE_T, TIBE_N);
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

    BN_CTX* ctx = BN_CTX_new();

    /* Step 1: TKEM.Keygen == TIBE.Setup. This is the only point in the
     * whole system where (s_a, e_a) exist unshared. */
    tibe_ek ek;
    tibe_msk msk;
    tibe_ek_init(&ek);
    tibe_msk_init(&msk);
    printf("[tibe_dealer] running TKEM.Keygen (Setup) -- this involves several O(D^2) ring "
           "operations, expect a few minutes\n");
    fflush(stdout);
    tkem_keygen(&ek, &msk, ctx);
    printf("[tibe_dealer] keypair generated\n");
    fflush(stdout);

    /* Step 2: Shamir-share (s_a, e_a) + generate pairwise seeds. */
    threshold_share shares[TIBE_N];
    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_init(&shares[i]);
    }
    threshold_setup(shares, &msk, ctx);
    printf("[tibe_dealer] Shamir-shared (s_a,e_a) across %d parties (T=%d)\n", TIBE_N, TIBE_T);
    fflush(stdout);

    /* Step 3: publish ek and d0 (see file comment for why d0 is not
     * secret) for shareholders/coordinator to read from the shared
     * volume. */
    size_t ek_bytes = tibe_ek_serialized_bytes();
    uint8_t* ek_buf = malloc(ek_bytes);
    tibe_ek_serialize(ek_buf, &ek);
    size_t rb = ring_serialized_bytes();
    uint8_t* d0_buf = malloc(rb);
    ring_serialize(d0_buf, &msk.d0);
    if (write_file(ek_path, ek_buf, ek_bytes) != 0 || write_file(d0_path, d0_buf, rb) != 0)
    {
        return 1;
    }
    printf("[tibe_dealer] wrote ek (%zu bytes) to %s, d0 (%zu bytes) to %s\n", ek_bytes, ek_path, rb, d0_path);
    fflush(stdout);
    free(ek_buf);
    free(d0_buf);

    /* Step 4: distribute each shareholder's private share over HTTP
     * once shareholders are up. */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    for (int i = 0; i < TIBE_N; i++)
    {
        wait_healthy(hosts[i], sh_port);
    }

    size_t priv_bytes = threshold_share_private_serialized_bytes();
    uint8_t* priv_buf = malloc(priv_bytes);
    char* priv_hex = malloc(2 * priv_bytes + 1);
    char* body = malloc(2 * priv_bytes + 128);

    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_private_serialize(priv_buf, &shares[i]);
        hex_encode(priv_hex, priv_buf, priv_bytes);

        snprintf(body, 2 * priv_bytes + 128, "{\"x\":%d,\"share_hex\":\"%s\"}", shares[i].x, priv_hex);

        char url[256];
        snprintf(url, sizeof(url), "http://%s:%d/store_share", hosts[i], sh_port);
        printf("[tibe_dealer] -> %s  (x=%d, %zu-byte share)\n", hosts[i], shares[i].x, priv_bytes);
        fflush(stdout);
        long code = http_post(url, body);
        printf("[tibe_dealer]   HTTP %ld\n", code);
        fflush(stdout);
    }

    free(priv_buf);
    free(priv_hex);
    free(body);
    curl_global_cleanup();

    for (int i = 0; i < TIBE_N; i++)
    {
        threshold_share_free(&shares[i]);
    }
    tibe_ek_free(&ek);
    tibe_msk_free(&msk);
    BN_CTX_free(ctx);

    printf("[tibe_dealer] All shares distributed. (s_a,e_a) discarded.\n");
    return 0;
}
