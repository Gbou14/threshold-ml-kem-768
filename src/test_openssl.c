#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_LEN 32
#define IV_LEN  16
#define TAG_LEN 16

static void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%-12s: ", label);
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

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
    unsigned char key[KEY_LEN], iv[IV_LEN], tag[TAG_LEN];
    unsigned char ct[256], pt[256];

    const char *msg = "Threshold Kyber Research -- OpenSSL AES-256-GCM test";
    int msg_len = (int)strlen(msg);

    RAND_bytes(key, KEY_LEN);
    RAND_bytes(iv,  IV_LEN);

    printf("=== OpenSSL AES-256-GCM Test ===\n");
    printf("Plaintext   : %s\n", msg);
    print_hex("Key",        key, KEY_LEN);
    print_hex("IV",         iv,  IV_LEN);

    int ct_len = aes_gcm_encrypt((unsigned char*)msg, msg_len, key, iv, ct, tag);
    print_hex("Ciphertext", ct,  ct_len);
    print_hex("Tag",        tag, TAG_LEN);

    int pt_len = aes_gcm_decrypt(ct, ct_len, key, iv, tag, pt);
    if (pt_len < 0) {
        printf("FAIL: authentication/decryption error\n");
        return 1;
    }
    pt[pt_len] = '\0';
    printf("Decrypted   : %s\n", pt);

    if (memcmp(msg, pt, msg_len) == 0)
        printf("PASS: round-trip successful\n");
    else
        printf("FAIL: mismatch\n");

    /* Test 2: tampered ciphertext should fail authentication */
    ct[0] ^= 0xFF;
    int bad = aes_gcm_decrypt(ct, ct_len, key, iv, tag, pt);
    if (bad < 0)
        printf("PASS: tampered ciphertext correctly rejected\n");
    else
        printf("FAIL: tampered ciphertext was accepted\n");

    return 0;
}
