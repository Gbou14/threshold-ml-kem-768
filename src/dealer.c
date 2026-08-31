/*
 * dealer.c — real SSS using ssss-split + OpenSSL key generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <openssl/rand.h>

#include "params.h"

#define MAX_HOST_LEN 64
#define AES_KEY_LEN  32
#define HEX_KEY_LEN  (AES_KEY_LEN * 2 + 1)

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
    if (res != CURLE_OK) {
        fprintf(stderr, "[dealer] curl: %s\n", curl_easy_strerror(res));
        return -1;
    }
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
        long code = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
        curl_easy_cleanup(c);
        if (res == CURLE_OK && code == 200) {
            printf("[dealer] %s ready\n", host);
            return;
        }
        printf("[dealer] waiting for %s (%d/30)...\n", host, i+1);
        sleep(1);
    }
    fprintf(stderr, "[dealer] WARNING: %s never healthy\n", host);
}

static int run_ssss_split(const char *hex_key, int threshold, int n_parties,
                           char shares[][256]) {
    /* Two pipes: one to feed stdin, one to read stdout */
    int in_pipe[2], out_pipe[2];
    if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
        perror("[dealer] pipe"); return -1;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("[dealer] fork"); return -1; }

    if (pid == 0) {
        /* Child process: wire up pipes and exec ssss-split */
        close(in_pipe[1]);
        close(out_pipe[0]);
        dup2(in_pipe[0],  STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        /* suppress stderr */
        int devnull = open("/dev/null", 1);
        if (devnull >= 0) dup2(devnull, STDERR_FILENO);
        close(in_pipe[0]);
        close(out_pipe[1]);

        char t_str[8], n_str[8];
        snprintf(t_str, sizeof(t_str), "%d", threshold);
        snprintf(n_str, sizeof(n_str), "%d", n_parties);
        execlp("ssss-split", "ssss-split",
               "-t", t_str, "-n", n_str, "-x", "-q", NULL);
        perror("[dealer] execlp ssss-split");
        exit(1);
    }

    /* Parent: write key to ssss-split stdin */
    close(in_pipe[0]);
    close(out_pipe[1]);

    write(in_pipe[1], hex_key, strlen(hex_key));
    close(in_pipe[1]);  /* EOF signals ssss-split to proceed */

    /* Read shares from ssss-split stdout */
    FILE *out = fdopen(out_pipe[0], "r");
    int count = 0;
    char line[256];
    while (count < n_parties && fgets(line, sizeof(line), out)) {
        line[strcspn(line, "\n")] = '\0';
        if (strlen(line) > 0) {
            strncpy(shares[count], line, 255);
            shares[count][255] = '\0';
            count++;
        }
    }
    fclose(out);
    waitpid(pid, NULL, 0);
    return count;
}

int main(void) {
    printf("[dealer] starting\n"); fflush(stdout);

    const char *hosts_str = getenv("SHAREHOLDER_HOSTS");
    const char *port_str  = getenv("SHAREHOLDER_PORT");
    int sh_port = port_str ? atoi(port_str) : 8080;
    const char *hosts_csv = hosts_str ? hosts_str : "sh1,sh2,sh3,sh4,sh5";

    char hosts[N_PARTIES][MAX_HOST_LEN];
    int hcount = parse_hosts(hosts_csv, hosts, N_PARTIES);
    if (hcount != N_PARTIES) {
        fprintf(stderr, "[dealer] need %d hosts, got %d\n", N_PARTIES, hcount);
        return 1;
    }

    /* Step 1: Generate 256-bit AES key */
    unsigned char aes_key[AES_KEY_LEN];
    if (RAND_bytes(aes_key, AES_KEY_LEN) != 1) {
        fprintf(stderr, "[dealer] RAND_bytes failed\n");
        return 1;
    }
    char hex_key[HEX_KEY_LEN];
    for (int i = 0; i < AES_KEY_LEN; i++)
        snprintf(hex_key + i*2, 3, "%02x", aes_key[i]);
    hex_key[HEX_KEY_LEN-1] = '\0';

    printf("[dealer] AES-256 key: %s\n", hex_key);
    printf("[dealer] %d-of-%d scheme\n", THRESHOLD, N_PARTIES);
    fflush(stdout);

    /* Step 2: Split with ssss using fork+exec */
    printf("[dealer] splitting key with ssss...\n"); fflush(stdout);
    char shares[N_PARTIES][256];
    int n = run_ssss_split(hex_key, THRESHOLD, N_PARTIES, shares);
    if (n != N_PARTIES) {
        fprintf(stderr, "[dealer] ssss-split produced %d shares, expected %d\n",
                n, N_PARTIES);
        return 1;
    }

    printf("[dealer] shares:\n");
    for (int i = 0; i < N_PARTIES; i++)
        printf("[dealer]   %s\n", shares[i]);
    fflush(stdout);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    for (int i = 0; i < N_PARTIES; i++) wait_healthy(hosts[i], sh_port);

    /* Step 3: Distribute shares */
    for (int i = 0; i < N_PARTIES; i++) {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"party_index\":%d,\"share\":\"%s\"}",
                 i, shares[i]);
        char url[256];
        snprintf(url, sizeof(url), "http://%s:%d/store_share", hosts[i], sh_port);
        printf("[dealer] -> %s  share=%s\n", hosts[i], shares[i]);
        fflush(stdout);
        long code = http_post(url, body);
        printf("[dealer]   HTTP %ld\n", code);
        fflush(stdout);
    }

    curl_global_cleanup();
    printf("[dealer] All shares distributed.\n");
    return 0;
}
