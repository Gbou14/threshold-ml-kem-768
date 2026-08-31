/*
 * coordinator.c — full CCA-secure threshold ML-KEM-768 decapsulation +
 * AES-256-GCM demo
 *
 * Each trial:
 *   1. Encapsulate a fresh random value with the dealer's public key
 *      ek via the real KEM (kyber_encaps_derand) -- this is the
 *      "sender" role, and it's the actual Fujisaki-Okamoto-wrapped
 *      ML-KEM-768 Encaps, not the bare IND-CPA PKE.
 *   2. Send the ciphertext to k shareholders' /partial_decrypt; collect
 *      their partial decryptions (this part is unchanged from the
 *      IND-CPA-only version -- a shareholder's role is the same either
 *      way, see src/kyber/README.md's "Phase 5" section).
 *   3. threshold_decaps Lagrange-combines the k partials and finishes
 *      the FO re-encryption check -- this is the "receiver"/combiner
 *      role. It never touches the private key, but it does briefly
 *      reconstruct the decrypted message on the way to the real
 *      shared secret; that's the explicit, narrower trust assumption
 *      documented in src/kyber/README.md, not an oversight.
 *   4. Use the KEM's own output directly as the AES-256 key (ML-KEM's
 *      shared secret is already meant to be used this way -- no extra
 *      KDF step needed once you have a real KEM, unlike the earlier
 *      IND-CPA-only version of this file) and run an authenticated
 *      encrypt/decrypt round trip, so a wrong reconstruction fails GCM
 *      tag verification rather than silently producing garbage.
 *
 * ENV:
 *   THRESHOLD           (default: 3)
 *   SHAREHOLDER_HOSTS   comma-separated (default: sh1,sh2,sh3,sh4,sh5)
 *   SHAREHOLDER_PORT    (default: 8080)
 *   USE_HOSTS           optional subset (e.g. "sh1,sh3,sh5")
 *   N_TRIALS            number of trials (default: 200)
 *   OUTPUT_FILE         CSV path (default: /data/results.csv)
 *   EK_PATH             where the dealer wrote ek (default: /data/ek.bin)
 *   Z_PATH              where the dealer wrote z (default: /data/z.bin)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "hexutil.h"
#include "kyber/kem.h"
#include "kyber/threshold.h"
#include "params.h"

#define MAX_HOST_LEN 64
/* KYBER_SSBYTES (32) doubles as the AES-256 key length -- the KEM's
 * shared secret is used directly as the AES key, no separate KDF. */
#define IV_LEN 16
#define TAG_LEN 16
#define MAX_MSG_LEN 256

/* ── HTTP helpers ─────────────────────────────────────────────────────────── */
typedef struct
{
    char *data;
    size_t len;
} Buffer;

static size_t
write_cb(void *ptr, size_t size, size_t nmemb, void *ud)
{
    size_t total = size * nmemb;
    Buffer *b = (Buffer *)ud;
    b->data = realloc(b->data, b->len + total + 1);
    memcpy(b->data + b->len, ptr, total);
    b->len += total;
    b->data[b->len] = '\0';
    return total;
}

/* POST json to url, capturing the response body into resp_buf. Returns
 * 0 on success (HTTP 200), -1 otherwise. */
static int
http_post_json(const char *url, const char *json, char *resp_buf, size_t resp_max)
{
    Buffer buf = {NULL, 0};
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        return -1;
    }
    struct curl_slist *hdrs = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK || code != 200)
    {
        free(buf.data);
        return -1;
    }
    if (buf.data && resp_buf)
    {
        strncpy(resp_buf, buf.data, resp_max - 1);
        resp_buf[resp_max - 1] = '\0';
    }
    free(buf.data);
    return 0;
}

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

static void
wait_healthy(const char *host, int port)
{
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/health", host, port);
    for (int i = 0; i < 60; i++)
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
            return;
        }
        sleep(1);
    }
}

/* Parse {"x":N,"partial_hex":"..."} */
static int
parse_partial_response(const char *json, int *x_out, uint8_t partial_bytes[KYBER_POLYBYTES])
{
    const char *xp = strstr(json, "\"x\"");
    if (!xp)
    {
        return -1;
    }
    xp = strchr(xp, ':');
    if (!xp)
    {
        return -1;
    }
    *x_out = atoi(xp + 1);

    const char *hp = strstr(json, "\"partial_hex\"");
    if (!hp)
    {
        return -1;
    }
    hp = strchr(hp, ':');
    if (!hp)
    {
        return -1;
    }
    hp++;
    while (*hp == ' ' || *hp == '"')
    {
        hp++;
    }
    char hex[2 * KYBER_POLYBYTES + 1];
    size_t j = 0;
    while (*hp && *hp != '"' && j < sizeof(hex) - 1)
    {
        hex[j++] = *hp++;
    }
    hex[j] = '\0';
    return hex_decode(partial_bytes, KYBER_POLYBYTES, hex);
}

/* Wait for the dealer to publish a file (ek or z) of exactly len bytes. */
static int
wait_for_file(const char *path, uint8_t *out, size_t len)
{
    for (int i = 0; i < 120; i++)
    {
        FILE *f = fopen(path, "rb");
        if (f)
        {
            size_t n = fread(out, 1, len, f);
            fclose(f);
            if (n == len)
            {
                return 0;
            }
        }
        sleep(1);
    }
    return -1;
}

static int
aes_gcm_encrypt(const unsigned char *pt,
                 int pt_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 unsigned char *ct,
                 unsigned char *tag)
{
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

static int
aes_gcm_decrypt(const unsigned char *ct,
                 int ct_len,
                 const unsigned char *key,
                 const unsigned char *iv,
                 const unsigned char *tag,
                 unsigned char *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, pt_len, ret;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag);
    ret = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0)
    {
        pt_len += len;
        return pt_len;
    }
    return -1;
}

int
main(void)
{
    const char *k_str = getenv("THRESHOLD");
    const char *hosts_str = getenv("SHAREHOLDER_HOSTS");
    const char *use_str = getenv("USE_HOSTS");
    const char *port_str = getenv("SHAREHOLDER_PORT");
    const char *ntrials_str = getenv("N_TRIALS");
    const char *outfile = getenv("OUTPUT_FILE");
    const char *ek_path_env = getenv("EK_PATH");
    const char *z_path_env = getenv("Z_PATH");

    int k = k_str ? atoi(k_str) : THRESHOLD;
    int sh_port = port_str ? atoi(port_str) : 8080;
    int ntrials = ntrials_str ? atoi(ntrials_str) : 200;
    if (!outfile)
    {
        outfile = "/data/results.csv";
    }
    const char *ek_path = ek_path_env ? ek_path_env : "/data/ek.bin";
    const char *z_path = z_path_env ? z_path_env : "/data/z.bin";

    const char *hosts_csv = use_str ? use_str : (hosts_str ? hosts_str : "sh1,sh2,sh3,sh4,sh5");
    char hosts[N_PARTIES][MAX_HOST_LEN];
    int hcount = parse_hosts(hosts_csv, hosts, N_PARTIES);
    if (hcount < k)
    {
        fprintf(stderr, "[coord] need at least %d hosts, got %d\n", k, hcount);
        return 1;
    }

    printf("[coord] Using first %d of %d shareholders\n", k, hcount);
    printf("[coord] Threshold=%d  Trials=%d  Output=%s\n", k, ntrials, outfile);
    fflush(stdout);

    printf("[coord] Waiting for dealer's ek at %s and z at %s...\n", ek_path, z_path);
    fflush(stdout);
    uint8_t ek[KYBER_PUBLICKEYBYTES];
    uint8_t z[KYBER_SYMBYTES];
    if (wait_for_file(ek_path, ek, sizeof(ek)) != 0 || wait_for_file(z_path, z, sizeof(z)) != 0)
    {
        fprintf(stderr, "[coord] ek/z never appeared\n");
        return 1;
    }
    printf("[coord] Loaded ek and z.\n");
    fflush(stdout);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    for (int i = 0; i < k; i++)
    {
        wait_healthy(hosts[i], sh_port);
    }

    FILE *fp = fopen(outfile, "w");
    if (!fp)
    {
        perror("fopen");
        return 1;
    }
    fprintf(fp, "trial,kem_success,aes_success,message,decrypted\n");

    const char *messages[] = {"Hello from threshold Kyber!",
                               "ML-KEM-768 + Shamir key sharing",
                               "Post-quantum threshold decryption",
                               "3-of-5 threshold decapsulation",
                               "Real Kyber, not the toy LWE"};
    int n_messages = 5;

    int total_kem_success = 0, total_aes_success = 0;

    for (int trial = 0; trial < ntrials; trial++)
    {
        const char *msg = messages[trial % n_messages];
        int msg_len = (int)strlen(msg);

        /* ── Sender side: real ML-KEM-768 Encaps (KeyGen already ran in
         * the dealer; this is the FO-wrapped encapsulation, not the
         * bare IND-CPA PKE). ── */
        uint8_t enc_coins[KYBER_SYMBYTES]; /* the message being encapsulated */
        RAND_bytes(enc_coins, sizeof(enc_coins));

        uint8_t ct[KYBER_CIPHERTEXTBYTES];
        uint8_t ss_enc[KYBER_SSBYTES];
        kyber_encaps_derand(ct, ss_enc, ek, enc_coins);

        char ct_hex[2 * KYBER_CIPHERTEXTBYTES + 1];
        hex_encode(ct_hex, ct, sizeof(ct));
        char ct_body[2 * KYBER_CIPHERTEXTBYTES + 32];
        snprintf(ct_body, sizeof(ct_body), "{\"ct_hex\":\"%s\"}", ct_hex);

        /* ── Receiver side: collect k partial decryptions. ── */
        poly partials[N_PARTIES];
        int xs[N_PARTIES];
        int collected = 0;
        for (int i = 0; i < hcount && collected < k; i++)
        {
            char url[256];
            snprintf(url, sizeof(url), "http://%s:%d/partial_decrypt", hosts[i], sh_port);
            char resp[2 * KYBER_POLYBYTES + 64];
            if (http_post_json(url, ct_body, resp, sizeof(resp)) != 0)
            {
                continue;
            }
            uint8_t partial_bytes[KYBER_POLYBYTES];
            int x;
            if (parse_partial_response(resp, &x, partial_bytes) != 0)
            {
                continue;
            }
            poly_frombytes(&partials[collected], partial_bytes);
            xs[collected] = x;
            collected++;
        }

        int kem_success = 0;
        uint8_t ss_dec[KYBER_SSBYTES] = {0};
        if (collected == k)
        {
            threshold_decaps(ss_dec, partials, xs, k, ct, ek, z);
            kem_success = (memcmp(ss_dec, ss_enc, sizeof(ss_enc)) == 0);
        }
        total_kem_success += kem_success;

        /* ── AES-256-GCM round trip, keyed directly from each side's
         * shared secret -- ML-KEM's output is already meant to be used
         * this way, no extra KDF needed. A wrong reconstruction fails
         * tag verification here rather than silently decrypting to
         * garbage. ── */
        unsigned char iv[IV_LEN];
        RAND_bytes(iv, IV_LEN);
        unsigned char ct_aes[MAX_MSG_LEN];
        unsigned char tag[TAG_LEN];
        int ct_len = aes_gcm_encrypt((const unsigned char *)msg, msg_len, ss_enc, iv, ct_aes, tag);

        unsigned char pt[MAX_MSG_LEN];
        int pt_len = aes_gcm_decrypt(ct_aes, ct_len, ss_dec, iv, tag, pt);

        int aes_success = 0;
        char decrypted[MAX_MSG_LEN] = {0};
        if (pt_len > 0)
        {
            pt[pt_len] = '\0';
            strncpy(decrypted, (char *)pt, MAX_MSG_LEN - 1);
            aes_success = (strcmp(msg, decrypted) == 0);
        }
        total_aes_success += aes_success;

        fprintf(fp, "%d,%d,%d,\"%s\",\"%s\"\n", trial, kem_success, aes_success, msg, decrypted);
    }

    fclose(fp);
    curl_global_cleanup();

    printf("[coord] Done. KEM: %d/%d, AES: %d/%d trials succeeded. Results at %s\n",
           total_kem_success,
           ntrials,
           total_aes_success,
           ntrials,
           outfile);
    return 0;
}
