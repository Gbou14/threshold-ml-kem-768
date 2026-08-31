/*
 * coordinator.c — threshold decryption using real ssss + OpenSSL AES-256-GCM
 *
 * 1. Collects ssss share strings from THRESHOLD shareholders via GET /get_share
 * 2. Reconstructs the AES-256 key using ssss-combine
 * 3. Encrypts N_TRIALS messages with AES-256-GCM
 * 4. Decrypts and verifies each one
 * 5. Writes results to CSV
 *
 * ENV:
 *   THRESHOLD           (default: 3)
 *   SHAREHOLDER_HOSTS   comma-separated (default: sh1,sh2,sh3,sh4,sh5)
 *   SHAREHOLDER_PORT    (default: 8080)
 *   USE_HOSTS           optional subset (e.g. "sh1,sh3,sh5")
 *   N_TRIALS            number of trials (default: 200)
 *   OUTPUT_FILE         CSV path (default: /data/results.csv)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "params.h"

#define MAX_HOST_LEN  64
#define AES_KEY_LEN   32
#define IV_LEN        16
#define TAG_LEN       16
#define MAX_MSG_LEN   256

/* ── HTTP helpers ─────────────────────────────────────────────────────────── */
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

static int http_get(const char *url, char *resp_buf, size_t resp_max) {
    Buffer buf = {NULL, 0};
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,3L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
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

static void wait_for_share(const char *host, int port) {
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
    for (int i = 0; i < 60; i++) {
        CURL *c = curl_easy_init();
        curl_easy_setopt(c, CURLOPT_URL, url);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 1L);
        curl_easy_setopt(c, CURLOPT_NOBODY, 1L);
        CURLcode res = curl_easy_perform(c);
        long code = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
        curl_easy_cleanup(c);
        if (res == CURLE_OK && code == 200) return;
        sleep(1);
    }
}

/* Parse "share" field from JSON like {"party_index":0,"share":"1-abc..."} */
static int parse_share(const char *json, char *share_out, size_t max) {
    const char *p = strstr(json, "\"share\"");
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '"') p++;
    size_t j = 0;
    while (*p && *p != '"' && j < max-1)
        share_out[j++] = *p++;
    share_out[j] = '\0';
    return j > 0 ? 0 : -1;
}

/* Run ssss-combine with k share strings, return reconstructed hex key */
static int run_ssss_combine(char shares[][256], int k, char *hex_out, size_t hex_max) {
    /* Write shares to a temp file then pipe through ssss-combine */
    FILE *tmp = fopen("/tmp/shares.txt", "w");
    if (!tmp) { perror("[coord] fopen shares.txt"); return -1; }
    for (int i = 0; i < k; i++)
        fprintf(tmp, "%s\n", shares[i]);
    fclose(tmp);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "ssss-combine -t %d -x -q < /tmp/shares.txt 2>&1",
             k);

    FILE *fp = popen(cmd, "r");
    if (!fp) { perror("[coord] popen ssss-combine"); return -1; }

    char line[256] = {0};
    int got = (fgets(line, sizeof(line), fp) != NULL);
    if (got) {
        line[strcspn(line, "\n")] = '\0';
        strncpy(hex_out, line, hex_max-1);
        hex_out[hex_max-1] = '\0';
    }
    pclose(fp);
    unlink("/tmp/shares.txt");
    return strlen(hex_out) > 0 ? 0 : -1;
}

/* Convert hex string to bytes */
static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%02x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

/* AES-256-GCM encrypt */
static int aes_gcm_encrypt(const unsigned char *pt, int pt_len,
                            const unsigned char *key, const unsigned char *iv,
                            unsigned char *ct, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ct_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

/* AES-256-GCM decrypt */
static int aes_gcm_decrypt(const unsigned char *ct, int ct_len,
                            const unsigned char *key, const unsigned char *iv,
                            const unsigned char *tag, unsigned char *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, pt_len, ret;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag);
    ret = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) { pt_len += len; return pt_len; }
    return -1;
}

int main(void) {
    srand((unsigned)time(NULL));

    const char *k_str       = getenv("THRESHOLD");
    const char *hosts_str   = getenv("SHAREHOLDER_HOSTS");
    const char *use_str     = getenv("USE_HOSTS");
    const char *port_str    = getenv("SHAREHOLDER_PORT");
    const char *ntrials_str = getenv("N_TRIALS");
    const char *outfile     = getenv("OUTPUT_FILE");

    int k       = k_str       ? atoi(k_str)       : THRESHOLD;
    int sh_port = port_str    ? atoi(port_str)    : 8080;
    int ntrials = ntrials_str ? atoi(ntrials_str) : 200;
    if (!outfile) outfile = "/data/results.csv";

    const char *hosts_csv = use_str ? use_str :
                            hosts_str ? hosts_str : "sh1,sh2,sh3,sh4,sh5";
    char hosts[N_PARTIES][MAX_HOST_LEN];
    int hcount = parse_hosts(hosts_csv, hosts, N_PARTIES);
    if (hcount < k) {
        fprintf(stderr, "[coord] need at least %d hosts, got %d\n", k, hcount);
        return 1;
    }

    printf("[coord] Using first %d of %d shareholders\n", k, hcount);
    printf("[coord] Threshold=%d  Trials=%d  Output=%s\n", k, ntrials, outfile);
    fflush(stdout);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Wait for shareholders to be ready */
    for (int i = 0; i < k; i++) wait_for_share(hosts[i], sh_port);
    sleep(120); /* wait for dealer to finish distributing shares */

    /* ── Step 1: Collect shares from k shareholders ── */
    printf("[coord] Collecting shares from %d shareholders...\n", k);
    fflush(stdout);

    char share_strings[N_PARTIES][256];
    int collected = 0;
    for (int i = 0; i < hcount && collected < k; i++) {
        char url[256], resp[512];
        snprintf(url, sizeof(url), "http://%s:%d/get_share", hosts[i], sh_port);
        if (http_get(url, resp, sizeof(resp)) == 0) {
            if (parse_share(resp, share_strings[collected], 256) == 0) {
                printf("[coord] Got share from %s: %s\n",
                       hosts[i], share_strings[collected]);
                fflush(stdout);
                collected++;
            }
        }
    }

    if (collected < k) {
        fprintf(stderr, "[coord] only got %d/%d shares, aborting\n", collected, k);
        return 1;
    }

    /* ── Step 2: Reconstruct AES key via ssss-combine ── */
    printf("[coord] Reconstructing AES key with ssss-combine...\n");
    fflush(stdout);

    char hex_key[128] = {0};
    if (run_ssss_combine(share_strings, k, hex_key, sizeof(hex_key)) != 0) {
        fprintf(stderr, "[coord] ssss-combine failed\n");
        return 1;
    }
    printf("[coord] Reconstructed AES key: %s\n", hex_key);
    fflush(stdout);

    unsigned char aes_key[AES_KEY_LEN];
    if (hex_to_bytes(hex_key, aes_key, AES_KEY_LEN) != 0) {
        fprintf(stderr, "[coord] hex_to_bytes failed (key len=%zu)\n", strlen(hex_key));
        return 1;
    }

    /* ── Step 3: Run N_TRIALS encrypt/decrypt trials ── */
    FILE *fp = fopen(outfile, "w");
    if (!fp) { perror("fopen"); return 1; }
    fprintf(fp, "trial,message,decrypted,success\n");

    int total_success = 0;
    const char *messages[] = {
        "Hello from threshold crypto!",
        "AES-256-GCM with ssss key sharing",
        "Post-quantum ready architecture",
        "3-of-5 threshold decryption",
        "OpenSSL + ssss integration"
    };
    int n_messages = 5;

    for (int trial = 0; trial < ntrials; trial++) {
        const char *msg = messages[trial % n_messages];
        int msg_len = (int)strlen(msg);

        /* Generate fresh random IV for each trial */
        unsigned char iv[IV_LEN];
        RAND_bytes(iv, IV_LEN);

        /* Encrypt */
        unsigned char ct[MAX_MSG_LEN];
        unsigned char tag[TAG_LEN];
        int ct_len = aes_gcm_encrypt((unsigned char*)msg, msg_len,
                                      aes_key, iv, ct, tag);

        /* Decrypt */
        unsigned char pt[MAX_MSG_LEN];
        int pt_len = aes_gcm_decrypt(ct, ct_len, aes_key, iv, tag, pt);

        int success = 0;
        char decrypted[MAX_MSG_LEN] = {0};
        if (pt_len > 0) {
            pt[pt_len] = '\0';
            strncpy(decrypted, (char*)pt, MAX_MSG_LEN-1);
            success = (strcmp(msg, decrypted) == 0);
        }

        fprintf(fp, "%d,\"%s\",\"%s\",%d\n",
                trial, msg, decrypted, success);
        total_success += success;
    }

    fclose(fp);
    curl_global_cleanup();

    printf("[coord] Done. %d/%d trials succeeded. Results at %s\n",
           total_success, ntrials, outfile);
    return 0;
}
/* Sat Apr 18 09:22:19 PM CDT 2026 */
/* Sat Apr 18 09:28:08 PM CDT 2026 */
/* Sat Apr 18 09:32:55 PM CDT 2026 */
/* Sat Apr 18 09:43:41 PM CDT 2026 */
/* Sat Apr 18 09:59:27 PM CDT 2026 */
