/*
 * dealer.c — real, full CCA-secure ML-KEM-768 keypair generation +
 * threshold secret-key splitting.
 *
 * Generates a Kyber KEM keypair (ek, dk), Shamir-shares dk's PKE
 * component -- its 768 NTT-domain coefficients over Z_3329
 * (src/kyber/threshold.c) -- sends one share to each shareholder over
 * HTTP, and writes ek and z to a shared volume for the coordinator.
 * Every shareholder gets only a share; no party, including the dealer
 * after this process exits, retains the whole private key.
 *
 * ek (the encapsulation key) is fully public. z is not the private
 * key -- it's ML-KEM's implicit-rejection value, needed by whichever
 * party finishes Decaps, exactly as it would be by a non-threshold
 * decryptor. See src/kyber/README.md's "Phase 5" section for the
 * combiner's trust assumption this reflects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/rand.h>

#include "hexutil.h"
#include "kyber/kem.h"
#include "kyber/threshold.h"
#include "params.h"

#define MAX_HOST_LEN 64

static int
parse_hosts(const char *csv, char hosts[][MAX_HOST_LEN], int max)
{
    char tmp[1024];
    strncpy(tmp, csv, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    int count = 0;
    char *tok = strtok(tmp, ",");
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
http_post(const char *url, const char *json)
{
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        return -1;
    }
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        fprintf(stderr, "[dealer] curl: %s\n", curl_easy_strerror(res));
        return -1;
    }
    return code;
}

static void
wait_healthy(const char *host, int port)
{
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
    for (int i = 0; i < 30; i++)
    {
        CURL *c = curl_easy_init();
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
            printf("[dealer] %s ready\n", host);
            return;
        }
        printf("[dealer] waiting for %s (%d/30)...\n", host, i + 1);
        sleep(1);
    }
    fprintf(stderr, "[dealer] WARNING: %s never healthy\n", host);
}

static int
write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
    {
        perror("[dealer] fopen");
        return -1;
    }
    int ok = (fwrite(data, 1, len, f) == len);
    fclose(f);
    if (!ok)
    {
        fprintf(stderr, "[dealer] short write to %s\n", path);
    }
    return ok ? 0 : -1;
}

int
main(void)
{
    printf("[dealer] starting\n");
    fflush(stdout);

    const char *hosts_str = getenv("SHAREHOLDER_HOSTS");
    const char *port_str = getenv("SHAREHOLDER_PORT");
    const char *ek_path_env = getenv("EK_PATH");
    const char *z_path_env = getenv("Z_PATH");
    int sh_port = port_str ? atoi(port_str) : 8080;
    const char *hosts_csv = hosts_str ? hosts_str : "sh1,sh2,sh3,sh4,sh5";
    const char *ek_path = ek_path_env ? ek_path_env : "/data/ek.bin";
    const char *z_path = z_path_env ? z_path_env : "/data/z.bin";

    char hosts[N_PARTIES][MAX_HOST_LEN];
    int hcount = parse_hosts(hosts_csv, hosts, N_PARTIES);
    if (hcount != N_PARTIES)
    {
        fprintf(stderr, "[dealer] need %d hosts, got %d\n", N_PARTIES, hcount);
        return 1;
    }

    /* Step 1: real, full CCA-secure ML-KEM-768 keypair. */
    uint8_t keygen_coins[2 * KYBER_SYMBYTES];
    if (RAND_bytes(keygen_coins, sizeof(keygen_coins)) != 1)
    {
        fprintf(stderr, "[dealer] RAND_bytes failed\n");
        return 1;
    }
    uint8_t ek[KYBER_PUBLICKEYBYTES];
    uint8_t dk[KYBER_SECRETKEYBYTES];
    kyber_keypair_derand(ek, dk, keygen_coins);
    const uint8_t *z = dk + KYBER_INDCPA_SECRETKEYBYTES + KYBER_PUBLICKEYBYTES + KYBER_SYMBYTES;

    polyvec skpv;
    polyvec_frombytes(&skpv, dk); /* dk's first bytes are dkPKE */

    printf("[dealer] generated ML-KEM-768 keypair (%d-of-%d threshold)\n", THRESHOLD, N_PARTIES);
    fflush(stdout);

    /* Step 2: Shamir-share dkPKE's NTT-domain coefficients. dk itself
     * is never written anywhere from this point on -- only the shares
     * below (and the separately-handled z, see the file comment)
     * leave this process. */
    polyvec shares[N_PARTIES];
    threshold_split_secret(&skpv, shares, THRESHOLD, N_PARTIES);

    /* Step 3: publish ek and z for the coordinator to pick up. */
    if (write_file(ek_path, ek, sizeof(ek)) != 0 || write_file(z_path, z, KYBER_SYMBYTES) != 0)
    {
        return 1;
    }
    printf("[dealer] wrote ek (%zu bytes) to %s, z (%d bytes) to %s\n", sizeof(ek), ek_path, KYBER_SYMBYTES, z_path);
    fflush(stdout);

    /* Step 4: distribute shares over HTTP once shareholders are up. */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    for (int i = 0; i < N_PARTIES; i++)
    {
        wait_healthy(hosts[i], sh_port);
    }

    uint8_t share_bytes[KYBER_POLYVECBYTES];
    char share_hex[2 * KYBER_POLYVECBYTES + 1];
    char body[2 * KYBER_POLYVECBYTES + 128];
    for (int i = 0; i < N_PARTIES; i++)
    {
        polyvec_tobytes(share_bytes, &shares[i]);
        hex_encode(share_hex, share_bytes, sizeof(share_bytes));

        int x = i + 1;
        snprintf(body, sizeof(body), "{\"party_index\":%d,\"x\":%d,\"share_hex\":\"%s\"}", i, x, share_hex);

        char url[256];
        snprintf(url, sizeof(url), "http://%s:%d/store_share", hosts[i], sh_port);
        printf("[dealer] -> %s  (x=%d, %zu-byte share)\n", hosts[i], x, sizeof(share_bytes));
        fflush(stdout);
        long code = http_post(url, body);
        printf("[dealer]   HTTP %ld\n", code);
        fflush(stdout);
    }

    curl_global_cleanup();
    printf("[dealer] All shares distributed. Secret key discarded.\n");
    return 0;
}
