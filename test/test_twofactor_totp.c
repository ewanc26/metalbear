/*
 * The TOTP primitives: RFC 6238 test vectors, RFC 4648 base32 vectors, the
 * accept window and single-use rule, the server key file, authenticated
 * encryption of stored secrets, and backup codes.
 */
#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "metalbear/twofactor/totp.h"

static int failures = 0;

#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* RFC 6238 appendix B, SHA-1, secret "12345678901234567890". The 8-digit
 * values in the RFC, reduced to the last six digits. */
static const unsigned char RFC_SECRET[] = "12345678901234567890";
static void check_rfc_vector(int64_t unix_time, uint32_t expected) {
    uint32_t code = 0;
    int64_t step = unix_time / 30;
    CHECK(metalbear_totp_code(RFC_SECRET, 20, step, &code) == WF_OK);
    CHECK(code == expected);
}

static void test_base32(void) {
    /* RFC 4648 section 10, without padding. */
    struct {
        const char *plain;
        const char *encoded;
    } vectors[] = {
        {"f", "MY"},         {"fo", "MZXQ"},        {"foo", "MZXW6"},
        {"foob", "MZXW6YQ"}, {"fooba", "MZXW6YTB"}, {"foobar", "MZXW6YTBOI"},
    };
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        char out[32];
        CHECK(metalbear_base32_encode((const unsigned char *)vectors[i].plain,
                                      strlen(vectors[i].plain), out,
                                      sizeof(out)) == WF_OK);
        CHECK(strcmp(out, vectors[i].encoded) == 0);
        unsigned char back[16];
        size_t n = 0;
        CHECK(metalbear_base32_decode(vectors[i].encoded, back, sizeof(back),
                                      &n) == WF_OK);
        CHECK(n == strlen(vectors[i].plain) &&
              memcmp(back, vectors[i].plain, n) == 0);
    }
    /* Lower case and spaces are accepted when decoding. */
    unsigned char back[16];
    size_t n = 0;
    CHECK(metalbear_base32_decode("mzxw 6ytb oi", back, sizeof(back), &n) ==
          WF_OK);
    CHECK(n == 6 && memcmp(back, "foobar", 6) == 0);
    /* A character outside the alphabet is refused. */
    CHECK(metalbear_base32_decode("MZXW1", back, sizeof(back), &n) != WF_OK);
}

static void test_codes_and_window(void) {
    check_rfc_vector(59, 287082);
    check_rfc_vector(1111111109, 81804);
    check_rfc_vector(1111111111, 50471);
    check_rfc_vector(1234567890, 5924);
    check_rfc_vector(2000000000, 279037);
    check_rfc_vector(20000000000LL, 353130);

    /* Step 1 (unix time 59) is the code 287082. It is accepted at its own
     * time, and one step later, and refused two steps later. */
    int64_t accepted = -1;
    CHECK(metalbear_totp_verify(RFC_SECRET, 20, 287082, 59, -1, &accepted));
    CHECK(accepted == 1);
    CHECK(metalbear_totp_verify(RFC_SECRET, 20, 287082, 89, -1, &accepted));
    CHECK(accepted == 1);
    CHECK(!metalbear_totp_verify(RFC_SECRET, 20, 287082, 150, -1, &accepted));

    /* A code is accepted once: the same step, or an earlier one, is refused
     * after it has been used. */
    CHECK(!metalbear_totp_verify(RFC_SECRET, 20, 287082, 59, 1, &accepted));
    CHECK(!metalbear_totp_verify(RFC_SECRET, 20, 287082, 89, 1, &accepted));
    /* A later step is still accepted after an earlier one was used. */
    CHECK(metalbear_totp_verify(RFC_SECRET, 20, 287082, 89, 0, &accepted));
    CHECK(accepted == 1);

    /* A wrong code is refused, and so is an out-of-range code. */
    CHECK(!metalbear_totp_verify(RFC_SECRET, 20, 287083, 59, -1, &accepted));
    CHECK(!metalbear_totp_verify(RFC_SECRET, 20, 1000000, 59, -1, &accepted));
}

static void test_key_file(void) {
    char dir[] = "/tmp/metalbear-totp-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char path[256];
    snprintf(path, sizeof(path), "%s/totp.key", dir);

    unsigned char created[32], again[32];
    CHECK(metalbear_twofactor_key_load_or_create(path, created) == WF_OK);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(metalbear_twofactor_key_load_or_create(path, again) == WF_OK);
    CHECK(memcmp(created, again, 32) == 0);

    /* A key readable by others is refused, not used. */
    CHECK(chmod(path, 0644) == 0);
    CHECK(metalbear_twofactor_key_load_or_create(path, again) != WF_OK);
    CHECK(chmod(path, 0600) == 0);

    /* A file of the wrong length is refused, not replaced. */
    FILE *f = fopen(path, "wb");
    if (f) {
        fputs("short", f);
        fclose(f);
    }
    CHECK(metalbear_twofactor_key_load_or_create(path, again) != WF_OK);
    unlink(path);
    rmdir(dir);
}

static void test_sealing(void) {
    unsigned char key[32], other[32];
    memset(key, 7, sizeof(key));
    memset(other, 9, sizeof(other));
    const unsigned char secret[20] = "12345678901234567890";

    unsigned char *sealed = NULL, *plain = NULL;
    size_t sealed_len = 0, plain_len = 0;
    CHECK(metalbear_twofactor_seal(key, secret, sizeof(secret), &sealed,
                                   &sealed_len) == WF_OK);
    CHECK(sealed_len == 12 + sizeof(secret) + 16);
    CHECK(memcmp(sealed + 12, secret, sizeof(secret)) != 0);
    CHECK(metalbear_twofactor_open(key, sealed, sealed_len, &plain,
                                   &plain_len) == WF_OK);
    CHECK(plain_len == sizeof(secret) &&
          memcmp(plain, secret, sizeof(secret)) == 0);
    free(plain);
    plain = NULL;

    /* Wrong key, and any altered byte, are both refused. */
    CHECK(metalbear_twofactor_open(other, sealed, sealed_len, &plain,
                                   &plain_len) != WF_OK);
    sealed[15] ^= 0x01;
    CHECK(metalbear_twofactor_open(key, sealed, sealed_len, &plain,
                                   &plain_len) != WF_OK);
    sealed[15] ^= 0x01;
    free(sealed);

    /* An empty plaintext round-trips too. */
    unsigned char *empty = NULL;
    size_t empty_len = 0;
    CHECK(metalbear_twofactor_seal(key, NULL, 0, &empty, &empty_len) == WF_OK);
    CHECK(empty_len == 28);
    CHECK(metalbear_twofactor_open(key, empty, empty_len, &plain, &plain_len) ==
          WF_OK);
    CHECK(plain_len == 0);
    free(plain);
    free(empty);
}

static void test_backup_codes(void) {
    unsigned char key[32], other[32];
    memset(key, 3, sizeof(key));
    memset(other, 4, sizeof(other));

    char code[METALBEAR_BACKUP_CODE_CHARS + 1];
    CHECK(metalbear_backup_code_new(code) == WF_OK);
    CHECK(strlen(code) == METALBEAR_BACKUP_CODE_CHARS);
    for (const char *p = code; *p; p++)
        CHECK((*p >= 'A' && *p <= 'Z') || (*p >= '2' && *p <= '7'));

    unsigned char h1[32], h2[32], h3[32], h4[32];
    CHECK(metalbear_backup_code_hash(key, code, h1) == WF_OK);
    /* Case and separators do not change the stored form. */
    char typed[64];
    snprintf(typed, sizeof(typed), "%.4s-%s", code, code + 4);
    for (char *p = typed; *p; p++)
        if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');
    CHECK(metalbear_backup_code_hash(key, typed, h2) == WF_OK);
    CHECK(memcmp(h1, h2, 32) == 0);
    /* A different key gives a different stored form, so a leaked database
     * alone does not let codes be checked offline. */
    CHECK(metalbear_backup_code_hash(other, code, h3) == WF_OK);
    CHECK(memcmp(h1, h3, 32) != 0);
    /* A different code gives a different stored form. */
    char changed[METALBEAR_BACKUP_CODE_CHARS + 1];
    memcpy(changed, code, sizeof(changed));
    changed[0] = changed[0] == 'A' ? 'B' : 'A';
    CHECK(metalbear_backup_code_hash(key, changed, h4) == WF_OK);
    CHECK(memcmp(h1, h4, 32) != 0);
}

int main(void) {
    test_base32();
    test_codes_and_window();
    test_key_file();
    test_sealing();
    test_backup_codes();
    if (failures == 0) {
        printf("PASS: TOTP primitives\n");
        return 0;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
