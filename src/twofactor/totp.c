#define _POSIX_C_SOURCE 200809L

#include "metalbear/twofactor/totp.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define GCM_NONCE_BYTES 12
#define GCM_TAG_BYTES 16

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

wf_status metalbear_base32_encode(const unsigned char *in, size_t in_len,
                                  char *out, size_t out_cap) {
    if (!out || (in_len && !in)) return WF_ERR_INVALID_ARG;
    size_t need = ((in_len + 4) / 5) * 8 + 1;
    if (out_cap < need) return WF_ERR_INVALID_ARG;
    size_t o = 0;
    unsigned int buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        buffer = ((buffer << 8) | in[i]) & 0xFFFF;
        bits += 8;
        while (bits >= 5) {
            out[o++] = base32_alphabet[(buffer >> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out[o++] = base32_alphabet[(buffer << (5 - bits)) & 31];
    out[o] = '\0';
    return WF_OK;
}

wf_status metalbear_base32_decode(const char *in, unsigned char *out,
                                  size_t out_cap, size_t *out_len) {
    if (!in || !out || !out_len) return WF_ERR_INVALID_ARG;
    *out_len = 0;
    unsigned int buffer = 0;
    int bits = 0;
    for (const char *p = in; *p; p++) {
        char c = *p;
        if (c == ' ') continue;
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        const char *v = strchr(base32_alphabet, c);
        if (!v) return WF_ERR_INVALID_ARG;
        buffer = ((buffer << 5) | (unsigned int)(v - base32_alphabet)) & 0xFFFF;
        bits += 5;
        if (bits >= 8) {
            if (*out_len >= out_cap) return WF_ERR_INVALID_ARG;
            out[(*out_len)++] = (unsigned char)((buffer >> (bits - 8)) & 0xFF);
            bits -= 8;
        }
    }
    return WF_OK;
}

wf_status
metalbear_totp_secret_new(unsigned char out[METALBEAR_TOTP_SECRET_BYTES]) {
    if (!out) return WF_ERR_INVALID_ARG;
    if (RAND_bytes(out, METALBEAR_TOTP_SECRET_BYTES) != 1) return WF_ERR_CRYPTO;
    return WF_OK;
}

wf_status metalbear_totp_code(const unsigned char *secret, size_t secret_len,
                              int64_t step, uint32_t *out_code) {
    if (!secret || !out_code || secret_len == 0 || step < 0)
        return WF_ERR_INVALID_ARG;
    unsigned char counter[8];
    uint64_t c = (uint64_t)step;
    for (int i = 7; i >= 0; i--) {
        counter[i] = (unsigned char)(c & 0xFF);
        c >>= 8;
    }
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha1(), secret, (int)secret_len, counter, sizeof(counter),
              mac, &mac_len) ||
        mac_len != 20)
        return WF_ERR_CRYPTO;
    /* Dynamic truncation (RFC 4226 section 5.3). */
    unsigned int offset = mac[19] & 0x0F;
    uint32_t bin = ((uint32_t)(mac[offset] & 0x7F) << 24) |
                   ((uint32_t)mac[offset + 1] << 16) |
                   ((uint32_t)mac[offset + 2] << 8) | (uint32_t)mac[offset + 3];
    *out_code = bin % 1000000u;
    return WF_OK;
}

bool metalbear_totp_verify(const unsigned char *secret, size_t secret_len,
                           uint32_t code, int64_t unix_time, int64_t last_step,
                           int64_t *accepted_step) {
    if (!secret || secret_len == 0 || !accepted_step || unix_time < 0 ||
        code > 999999u)
        return false;
    *accepted_step = -1;
    int64_t now_step = unix_time / METALBEAR_TOTP_STEP_SECONDS;
    bool matched = false;
    int64_t match = -1;
    /* Check every step in the window, rather than returning at the first hit,
     * so the time taken does not show which step matched. */
    for (int64_t d = -1; d <= 1; d++) {
        int64_t step = now_step + d;
        if (step < 0 || step <= last_step) continue;
        uint32_t expected = 0;
        if (metalbear_totp_code(secret, secret_len, step, &expected) != WF_OK)
            return false;
        if (CRYPTO_memcmp(&expected, &code, sizeof(code)) == 0 && !matched) {
            matched = true;
            match = step;
        }
    }
    if (matched) *accepted_step = match;
    return matched;
}

/* Reads the key file and refuses one that is readable by anyone but its owner,
 * or whose length is wrong. */
static wf_status key_read(const char *path,
                          unsigned char out[METALBEAR_TWOFACTOR_KEY_BYTES]) {
    struct stat st;
    if (stat(path, &st) != 0) return WF_ERR_NOT_FOUND;
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) return WF_ERR_INVALID_ARG;
    if (st.st_size != METALBEAR_TWOFACTOR_KEY_BYTES) return WF_ERR_INVALID_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return WF_ERR_NOT_FOUND;
    size_t got = fread(out, 1, METALBEAR_TWOFACTOR_KEY_BYTES, f);
    fclose(f);
    return got == METALBEAR_TWOFACTOR_KEY_BYTES ? WF_OK : WF_ERR_INTERNAL;
}

wf_status metalbear_twofactor_key_load_or_create(
    const char *path, unsigned char out[METALBEAR_TWOFACTOR_KEY_BYTES]) {
    if (!path || !*path || !out) return WF_ERR_INVALID_ARG;
    wf_status st = key_read(path, out);
    if (st == WF_OK) return WF_OK;
    /* Only a missing file is created. A file that exists but is unusable is
     * refused, rather than replaced, since replacing it would strand every
     * secret encrypted under it. */
    if (st != WF_ERR_NOT_FOUND) return st;
    if (RAND_bytes(out, METALBEAR_TWOFACTOR_KEY_BYTES) != 1)
        return WF_ERR_CRYPTO;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return WF_ERR_INTERNAL;
    ssize_t wrote = write(fd, out, METALBEAR_TWOFACTOR_KEY_BYTES);
    int synced = fsync(fd) == 0;
    int closed = close(fd) == 0;
    if (wrote != METALBEAR_TWOFACTOR_KEY_BYTES || !synced || !closed) {
        unlink(path);
        return WF_ERR_INTERNAL;
    }
    return WF_OK;
}

wf_status
metalbear_twofactor_seal(const unsigned char key[METALBEAR_TWOFACTOR_KEY_BYTES],
                         const unsigned char *plain, size_t plain_len,
                         unsigned char **out, size_t *out_len) {
    if (!key || !out || !out_len || (plain_len && !plain))
        return WF_ERR_INVALID_ARG;
    *out = NULL;
    *out_len = 0;
    unsigned char *buf = malloc(GCM_NONCE_BYTES + plain_len + GCM_TAG_BYTES);
    if (!buf) return WF_ERR_ALLOC;
    if (RAND_bytes(buf, GCM_NONCE_BYTES) != 1) {
        free(buf);
        return WF_ERR_CRYPTO;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    wf_status st = WF_OK;
    if (!ctx ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, buf) != 1) {
        st = WF_ERR_CRYPTO;
    } else if (plain_len && EVP_EncryptUpdate(ctx, buf + GCM_NONCE_BYTES, &len,
                                              plain, (int)plain_len) != 1) {
        st = WF_ERR_CRYPTO;
    } else {
        total = len;
        if (EVP_EncryptFinal_ex(ctx, buf + GCM_NONCE_BYTES + total, &len) !=
                1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES,
                                buf + GCM_NONCE_BYTES + plain_len) != 1) {
            st = WF_ERR_CRYPTO;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (st != WF_OK) {
        free(buf);
        return st;
    }
    *out = buf;
    *out_len = GCM_NONCE_BYTES + plain_len + GCM_TAG_BYTES;
    return WF_OK;
}

wf_status
metalbear_twofactor_open(const unsigned char key[METALBEAR_TWOFACTOR_KEY_BYTES],
                         const unsigned char *sealed, size_t sealed_len,
                         unsigned char **out, size_t *out_len) {
    if (!key || !sealed || !out || !out_len) return WF_ERR_INVALID_ARG;
    *out = NULL;
    *out_len = 0;
    if (sealed_len < GCM_NONCE_BYTES + GCM_TAG_BYTES) return WF_ERR_INVALID_ARG;
    size_t plain_len = sealed_len - GCM_NONCE_BYTES - GCM_TAG_BYTES;
    unsigned char *buf = malloc(plain_len ? plain_len : 1);
    if (!buf) return WF_ERR_ALLOC;
    const unsigned char *nonce = sealed;
    const unsigned char *cipher = sealed + GCM_NONCE_BYTES;
    const unsigned char *tag = sealed + GCM_NONCE_BYTES + plain_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    wf_status st = WF_OK;
    if (!ctx ||
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        st = WF_ERR_CRYPTO;
    } else if (plain_len &&
               EVP_DecryptUpdate(ctx, buf, &len, cipher, (int)plain_len) != 1) {
        st = WF_ERR_CRYPTO;
    } else {
        total = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_BYTES,
                                (void *)tag) != 1 ||
            EVP_DecryptFinal_ex(ctx, buf + total, &len) != 1) {
            st = WF_ERR_INVALID_ARG; /* wrong key or altered ciphertext */
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (st != WF_OK) {
        free(buf);
        return st;
    }
    *out = buf;
    *out_len = plain_len;
    return WF_OK;
}

wf_status metalbear_backup_code_new(char out[METALBEAR_BACKUP_CODE_CHARS + 1]) {
    if (!out) return WF_ERR_INVALID_ARG;
    unsigned char raw[METALBEAR_BACKUP_CODE_BYTES];
    if (RAND_bytes(raw, sizeof(raw)) != 1) return WF_ERR_CRYPTO;
    return metalbear_base32_encode(raw, sizeof(raw), out,
                                   METALBEAR_BACKUP_CODE_CHARS + 1);
}

wf_status metalbear_backup_code_hash(
    const unsigned char key[METALBEAR_TWOFACTOR_KEY_BYTES], const char *code,
    unsigned char out[32]) {
    if (!key || !code || !out) return WF_ERR_INVALID_ARG;
    /* Compare without the separators and case a person might type. */
    char norm[64];
    size_t n = 0;
    for (const char *p = code; *p; p++) {
        char c = *p;
        if (c == '-' || c == ' ') continue;
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        if (n + 1 >= sizeof(norm)) return WF_ERR_INVALID_ARG;
        norm[n++] = c;
    }
    norm[n] = '\0';
    if (n == 0) return WF_ERR_INVALID_ARG;
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key, METALBEAR_TWOFACTOR_KEY_BYTES,
              (const unsigned char *)norm, n, out, &len) ||
        len != 32)
        return WF_ERR_CRYPTO;
    return WF_OK;
}
