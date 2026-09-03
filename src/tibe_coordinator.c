/*
 * tibe_coordinator.c -- full BCHK+ threshold-KEM decapsulation demo
 * (Phase 7, the TIBE/BCHK+ counterpart to coordinator.c's Kyber-side
 * role).
 *
 * Each trial:
 *   1. tkem_encaps: fresh WOTS+ keypair, real derandomized TIBE
 *      Encrypt, sign the ciphertext -- this is the "sender" role.
 *   2. Round 0: POST the full ciphertext (ct+vk+sig) to T active
 *      shareholders' /round0; each independently verifies the
 *      signature *before* doing any threshold work (the actual
 *      trust-model delta this whole redesign exists for) and returns
 *      a commitment. Collected fully before round 1 starts.
 *   3. Round 1: POST /round1 to the same T shareholders; each reveals
 *      the value it committed to. Collected fully before round 2.
 *   4. Round 2: POST the *full* collected set of (act, commitments,
 *      revealed values) to each of the T shareholders' /round2; each
 *      independently re-verifies every other party's reveal against
 *      its round-0 commitment (catching a lying party) and returns
 *      its contribution.
 *   5. tkem_combine: sums contributions, re-derives (c0,c1), checks
 *      Combine's own F_vk*z==r assertion, and runs the FO-style
 *      re-encryption consistency check -- this is the
 *      "receiver"/combiner role. Unlike src/coordinator.c's Kyber-side
 *      threshold_decaps, nothing here was trusted *for security* --
 *      every ShareDecaps call already independently verified the
 *      ciphertext before this point (see src/tibe/README.md "The
 *      actual trust-model delta").
 *   6. AES-256-GCM round trip keyed directly from the shared secret,
 *      same demo pattern as src/coordinator.c.
 *
 * Real cost warning: a single decapsulation at this module's T=5/N=10
 * parameters takes on the order of 30 minutes on typical development
 * hardware (BIGNUM ring arithmetic, no NTT -- see
 * src/tibe/README.md "Performance"). N_TRIALS defaults to 1, not
 * src/coordinator.c's 200 -- this is not an oversight.
 *
 * ENV:
 *   TIBE_SHAREHOLDER_HOSTS  comma-separated, TIBE_N of them
 *   TIBE_SHAREHOLDER_PORT   (default: 8080)
 *   TIBE_ACT_X              comma-separated x-coordinates of the
 *                           active set, must have exactly TIBE_T
 *                           entries (default: "2,4,6,8,10")
 *   N_TRIALS                (default: 1 -- see cost warning above)
 *   OUTPUT_FILE              CSV path (default: /data/tibe_results.csv)
 *   TIBE_EK_PATH, TIBE_D0_PATH  where the dealer wrote ek/d0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "hexutil.h"
#include "tibe/threshold.h"
#include "tibe/tkem.h"

#define MAX_HOST_LEN 64
#define IV_LEN 16
#define TAG_LEN 16
#define MAX_MSG_LEN 256

/* ── HTTP helpers ─────────────────────────────────────────────────────────── */
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

/* POST json to url; on HTTP 200 returns the response body in a freshly
 * malloc'd buffer (caller frees), else NULL. */
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
    /* src/tibe/README.md documents round0 alone costing ~500s summed
     * across T=5 parties -- a single party's own share of that,
     * under real Docker Compose CPU contention with 10+ concurrent
     * shareholder containers on one host, can exceed what a 120s cap
     * assumed (caught live: a real round0 call timed out at 120s).
     * The whole trial budget is ~30 minutes, so give one call a
     * generous fraction of it rather than a tight per-call guess. */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1800L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK || code != 200)
    {
        fprintf(stderr, "[tibe_coord] POST %s failed (curl=%d http=%ld)%s%s\n", url, res, code,
                buf.data ? " body=" : "", buf.data ? buf.data : "");
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

static int
parse_csv_ints(const char* csv, int* out, int max)
{
    char tmp[256];
    strncpy(tmp, csv, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    int count = 0;
    char* tok = strtok(tmp, ",");
    while (tok && count < max)
    {
        out[count++] = atoi(tok);
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
            return;
        }
        sleep(1);
    }
}

static int
wait_for_file(const char* path, uint8_t* out, size_t len)
{
    for (int i = 0; i < 300; i++)
    {
        FILE* f = fopen(path, "rb");
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

/* Extracts the string VALUE for "key" from a flat JSON object into a
 * freshly malloc'd NUL-terminated buffer (caller frees), or NULL. */
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
aes_gcm_encrypt(const unsigned char* pt, int pt_len, const unsigned char* key, const unsigned char* iv,
                 unsigned char* ct, unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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
aes_gcm_decrypt(const unsigned char* ct, int ct_len, const unsigned char* key, const unsigned char* iv,
                 const unsigned char* tag, unsigned char* pt)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, pt_len, ret;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag);
    ret = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0)
    {
        pt_len += len;
        return pt_len;
    }
    return -1;
}

/* Serializes a full tkem_ct (ct + vk + sig) into one buffer, matching
 * tibe_shareholder.c's expected /round0 layout. */
static void
serialize_tkem_ct(uint8_t* out, const tkem_ct* ct)
{
    tibe_ct_serialize(out, &ct->ct);
    uint8_t* p = out + tibe_ct_serialized_bytes();
    memcpy(p, ct->vk.seed, WOTS_SEEDBYTES);
    memcpy(p + WOTS_SEEDBYTES, ct->vk.vk1, WOTS_VK1BYTES);
    memcpy(p + WOTS_SEEDBYTES + WOTS_VK1BYTES, ct->sig, WOTS_SIGBYTES);
}

int
main(void)
{
    const char* hosts_str = getenv("TIBE_SHAREHOLDER_HOSTS");
    const char* port_str = getenv("TIBE_SHAREHOLDER_PORT");
    const char* act_x_str = getenv("TIBE_ACT_X");
    const char* ntrials_str = getenv("N_TRIALS");
    const char* outfile_env = getenv("OUTPUT_FILE");
    const char* ek_path_env = getenv("TIBE_EK_PATH");
    const char* d0_path_env = getenv("TIBE_D0_PATH");

    int sh_port = port_str ? atoi(port_str) : 8080;
    int ntrials = ntrials_str ? atoi(ntrials_str) : 1;
    const char* outfile = outfile_env ? outfile_env : "/data/tibe_results.csv";
    const char* ek_path = ek_path_env ? ek_path_env : "/data/tibe_ek.bin";
    const char* d0_path = d0_path_env ? d0_path_env : "/data/tibe_d0.bin";

    const char* hosts_csv = hosts_str ? hosts_str : "tsh1,tsh2,tsh3,tsh4,tsh5,tsh6,tsh7,tsh8,tsh9,tsh10";
    char hosts[TIBE_N][MAX_HOST_LEN];
    int hcount = parse_hosts(hosts_csv, hosts, TIBE_N);
    if (hcount != TIBE_N)
    {
        fprintf(stderr, "[tibe_coord] need %d hosts, got %d\n", TIBE_N, hcount);
        return 1;
    }

    int act_x[TIBE_T];
    int act_size = parse_csv_ints(act_x_str ? act_x_str : "2,4,6,8,10", act_x, TIBE_T);
    if (act_size != TIBE_T)
    {
        fprintf(stderr, "[tibe_coord] TIBE_ACT_X must have exactly %d entries, got %d\n", TIBE_T, act_size);
        return 1;
    }
    char act_x_csv[128];
    {
        char* p = act_x_csv;
        for (int i = 0; i < TIBE_T; i++)
        {
            p += snprintf(p, sizeof(act_x_csv) - (size_t)(p - act_x_csv), i == 0 ? "%d" : ",%d", act_x[i]);
        }
    }

    printf("[tibe_coord] T=%d N=%d active_set=%s trials=%d\n", TIBE_T, TIBE_N, act_x_csv, ntrials);
    printf("[tibe_coord] WARNING: each trial is a real O(D^2) BIGNUM threshold decapsulation --\n"
           "             expect on the order of 30 minutes per trial, not seconds.\n");
    fflush(stdout);

    BN_CTX* ctx = BN_CTX_new();

    printf("[tibe_coord] waiting for dealer's ek/d0...\n");
    fflush(stdout);
    tibe_ek ek;
    tibe_ek_init(&ek);
    size_t ek_bytes = tibe_ek_serialized_bytes();
    uint8_t* ek_buf = malloc(ek_bytes);
    size_t rb = ring_serialized_bytes();
    uint8_t* d0_buf = malloc(rb);
    if (wait_for_file(ek_path, ek_buf, ek_bytes) != 0 || wait_for_file(d0_path, d0_buf, rb) != 0)
    {
        fprintf(stderr, "[tibe_coord] ek/d0 never appeared\n");
        return 1;
    }
    tibe_ek_deserialize(&ek, ek_buf);
    ring_elem d0;
    ring_init(&d0);
    ring_deserialize(&d0, d0_buf);
    free(ek_buf);
    free(d0_buf);
    printf("[tibe_coord] loaded ek and d0.\n");
    fflush(stdout);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    for (int i = 0; i < TIBE_T; i++)
    {
        wait_healthy(hosts[act_x[i] - 1], sh_port);
    }

    FILE* fp = fopen(outfile, "w");
    if (!fp)
    {
        perror("fopen");
        return 1;
    }
    fprintf(fp, "trial,tkem_success,aes_success,message,decrypted\n");

    const char* messages[] = {"Hello from threshold BCHK+!", "TIBE + real Shamir key sharing",
                               "No implicit trust in the combiner", "5-of-10 threshold decapsulation",
                               "BCHK+, not just patched FO"};
    int n_messages = 5;

    int total_tkem_success = 0, total_aes_success = 0;

    size_t ct_bytes = tibe_ct_serialized_bytes() + WOTS_SEEDBYTES + WOTS_VK1BYTES + WOTS_SIGBYTES;
    size_t cbytes = threshold_contrib2_serialized_bytes();

    for (int trial = 0; trial < ntrials; trial++)
    {
        const char* msg = messages[trial % n_messages];
        int msg_len = (int)strlen(msg);

        printf("[tibe_coord] trial %d: running tkem_encaps...\n", trial);
        fflush(stdout);
        tkem_ct tct;
        tkem_ct_init(&tct);
        uint8_t ss_enc[TKEM_SSBYTES];
        tkem_encaps(&tct, ss_enc, &ek, ctx);

        uint8_t* ct_buf = malloc(ct_bytes);
        serialize_tkem_ct(ct_buf, &tct);
        char* ct_hex = malloc(2 * ct_bytes + 1);
        hex_encode(ct_hex, ct_buf, ct_bytes);
        free(ct_buf);
        char* ct_body = malloc(2 * ct_bytes + 64);
        snprintf(ct_body, 2 * ct_bytes + 64, "{\"ct_hex\":\"%s\"}", ct_hex);
        free(ct_hex);

        /* ── Round 0: collect commitments from every active party
         * before revealing anything. ── */
        uint8_t cmts[TIBE_T][TIBE_CMT_BYTES];
        int round_ok = 1;
        for (int i = 0; i < TIBE_T && round_ok; i++)
        {
            char url[256];
            snprintf(url, sizeof(url), "http://%s:%d/round0", hosts[act_x[i] - 1], sh_port);
            printf("[tibe_coord] trial %d: round0 -> x=%d\n", trial, act_x[i]);
            fflush(stdout);
            char* resp = http_post_json(url, ct_body);
            if (!resp)
            {
                round_ok = 0;
                break;
            }
            char* cmt_hex = parse_json_string_dyn(resp, "cmt_hex");
            free(resp);
            if (!cmt_hex || strlen(cmt_hex) != 2 * TIBE_CMT_BYTES || hex_decode(cmts[i], TIBE_CMT_BYTES, cmt_hex) != 0)
            {
                free(cmt_hex);
                round_ok = 0;
                break;
            }
            free(cmt_hex);
        }
        free(ct_body);

        /* ── Round 1: collect reveals, only after every commitment is in. ── */
        ring_elem ws[TIBE_T];
        for (int i = 0; i < TIBE_T; i++)
        {
            ring_init(&ws[i]);
        }
        for (int i = 0; i < TIBE_T && round_ok; i++)
        {
            char url[256];
            snprintf(url, sizeof(url), "http://%s:%d/round1", hosts[act_x[i] - 1], sh_port);
            printf("[tibe_coord] trial %d: round1 -> x=%d\n", trial, act_x[i]);
            fflush(stdout);
            char* resp = http_post_json(url, "{}");
            if (!resp)
            {
                round_ok = 0;
                break;
            }
            char* w_hex = parse_json_string_dyn(resp, "w_hex");
            free(resp);
            if (!w_hex || strlen(w_hex) != 2 * rb)
            {
                free(w_hex);
                round_ok = 0;
                break;
            }
            uint8_t* wbuf = malloc(rb);
            int wok = (hex_decode(wbuf, rb, w_hex) == 0);
            free(w_hex);
            if (wok)
            {
                ring_deserialize(&ws[i], wbuf);
            }
            free(wbuf);
            if (!wok)
            {
                round_ok = 0;
                break;
            }
        }

        /* ── Round 2: send the full collected (act, cmts, ws) to every
         * active party, collect contributions. ── */
        threshold_contrib2 contribs[TIBE_T];
        for (int i = 0; i < TIBE_T; i++)
        {
            threshold_contrib2_init(&contribs[i]);
        }
        if (round_ok)
        {
            char* cmts_hex = malloc((size_t)TIBE_T * 2 * TIBE_CMT_BYTES + 1);
            char* p = cmts_hex;
            for (int i = 0; i < TIBE_T; i++)
            {
                hex_encode(p, cmts[i], TIBE_CMT_BYTES);
                p += 2 * TIBE_CMT_BYTES;
            }
            char* ws_hex = malloc((size_t)TIBE_T * 2 * rb + 1);
            p = ws_hex;
            for (int i = 0; i < TIBE_T; i++)
            {
                uint8_t* wbuf = malloc(rb);
                ring_serialize(wbuf, &ws[i]);
                hex_encode(p, wbuf, rb);
                free(wbuf);
                p += 2 * rb;
            }

            size_t body_cap = strlen(cmts_hex) + strlen(ws_hex) + strlen(act_x_csv) + 256;
            char* body = malloc(body_cap);

            for (int i = 0; i < TIBE_T && round_ok; i++)
            {
                snprintf(body, body_cap, "{\"my_index\":%d,\"act_x_csv\":\"%s\",\"cmts_hex\":\"%s\",\"ws_hex\":\"%s\"}",
                         i, act_x_csv, cmts_hex, ws_hex);
                char url[256];
                snprintf(url, sizeof(url), "http://%s:%d/round2", hosts[act_x[i] - 1], sh_port);
                printf("[tibe_coord] trial %d: round2 -> x=%d\n", trial, act_x[i]);
                fflush(stdout);
                char* resp = http_post_json(url, body);
                if (!resp)
                {
                    round_ok = 0;
                    break;
                }
                char* contrib_hex = parse_json_string_dyn(resp, "contrib_hex");
                free(resp);
                if (!contrib_hex || strlen(contrib_hex) != 2 * cbytes)
                {
                    free(contrib_hex);
                    round_ok = 0;
                    break;
                }
                uint8_t* cbuf = malloc(cbytes);
                int cok = (hex_decode(cbuf, cbytes, contrib_hex) == 0);
                free(contrib_hex);
                if (cok)
                {
                    threshold_contrib2_deserialize(&contribs[i], cbuf);
                }
                free(cbuf);
                if (!cok)
                {
                    round_ok = 0;
                    break;
                }
            }
            free(body);
            free(cmts_hex);
            free(ws_hex);
        }

        /* ── Combine ── */
        int tkem_success = 0;
        uint8_t ss_dec[TKEM_SSBYTES] = {0};
        if (round_ok)
        {
            printf("[tibe_coord] trial %d: running tkem_combine...\n", trial);
            fflush(stdout);
            int combine_ok = tkem_combine(ss_dec, &ek, &d0, &tct, act_x, TIBE_T, ws, contribs, ctx);
            tkem_success = combine_ok && (memcmp(ss_dec, ss_enc, TKEM_SSBYTES) == 0);
        }
        total_tkem_success += tkem_success;

        for (int i = 0; i < TIBE_T; i++)
        {
            ring_free(&ws[i]);
            threshold_contrib2_free(&contribs[i]);
        }
        tkem_ct_free(&tct);

        /* ── AES-256-GCM round trip, keyed directly from each side's
         * shared secret. ── */
        unsigned char iv[IV_LEN];
        RAND_bytes(iv, IV_LEN);
        unsigned char ct_aes[MAX_MSG_LEN];
        unsigned char tag[TAG_LEN];
        int ct_len = aes_gcm_encrypt((const unsigned char*)msg, msg_len, ss_enc, iv, ct_aes, tag);

        unsigned char pt[MAX_MSG_LEN];
        int pt_len = aes_gcm_decrypt(ct_aes, ct_len, ss_dec, iv, tag, pt);

        int aes_success = 0;
        char decrypted[MAX_MSG_LEN] = {0};
        if (pt_len > 0)
        {
            pt[pt_len] = '\0';
            strncpy(decrypted, (char*)pt, MAX_MSG_LEN - 1);
            aes_success = (strcmp(msg, decrypted) == 0);
        }
        total_aes_success += aes_success;

        fprintf(fp, "%d,%d,%d,\"%s\",\"%s\"\n", trial, tkem_success, aes_success, msg, decrypted);
        fflush(fp);
        printf("[tibe_coord] trial %d: tkem_success=%d aes_success=%d\n", trial, tkem_success, aes_success);
        fflush(stdout);
    }

    fclose(fp);
    curl_global_cleanup();
    ring_free(&d0);
    tibe_ek_free(&ek);
    BN_CTX_free(ctx);

    printf("[tibe_coord] Done. TKEM: %d/%d, AES: %d/%d trials succeeded. Results at %s\n", total_tkem_success,
           ntrials, total_aes_success, ntrials, outfile);
    return 0;
}
