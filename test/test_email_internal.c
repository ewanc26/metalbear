#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_email_internal.c — regression coverage for two bugs in
 * src/email.c's SMTP send path, both found in the same audit pass:
 *
 *  (a) CURLOPT_READFUNCTION was set to plain libc `fread` with
 *      CURLOPT_READDATA pointing at the plain `const char *body` string.
 *      fread's fourth parameter must be a FILE*; a raw string is not one,
 *      so curl calling fread(buf, size, n, body) dereferences `body` as if
 *      it were a FILE struct -- memory corruption or a crash on every
 *      email send that got far enough to start uploading. Fixed with
 *      email_read_body(), a real chunked reader over an in-memory buffer.
 *
 *  (b) email->smtp_host was handed to CURLOPT_URL with no scheme. Without
 *      CURLOPT_DEFAULT_PROTOCOL set, curl treats a schemeless URL as
 *      http://, so every email send silently sent an HTTP request at the
 *      SMTP port instead of speaking SMTP at all -- confirmed live against
 *      smtp.resend.com:465. Fixed with email_build_smtp_url(), which
 *      chooses smtp:// (STARTTLS, port 587 convention) or smtps://
 *      (implicit TLS, port 465 convention) from smtp_starttls.
 *
 * Both fixed functions are pure (no network I/O), so they're tested
 * directly here rather than via a live SMTP exchange, which would need a
 * real TLS-capable fake SMTP server to exercise either scheme.
 */

#include "../src/email_internal.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void test_read_body_single_chunk(void) {
    const char *body = "hello, world";
    email_body_reader reader = {.cursor = body, .remaining = strlen(body)};
    char buf[64] = {0};
    size_t n = email_read_body(buf, 1, sizeof(buf), &reader);
    CHECK(n == strlen(body));
    CHECK(memcmp(buf, body, n) == 0);
    CHECK(reader.remaining == 0);
    /* Exhausted: the next call must report EOF (0), matching what curl's
     * CURLOPT_READFUNCTION contract requires to stop uploading. */
    CHECK(email_read_body(buf, 1, sizeof(buf), &reader) == 0);
}

static void test_read_body_small_chunks(void) {
    /* curl calls the read function repeatedly with whatever buffer size
     * its internal upload buffer happens to have room for -- exercise
     * that by draining a longer body through a buffer far smaller than
     * the whole message, byte-for-byte across many calls. */
    const char *body =
        "Subject: test\r\n\r\nThis is a body long enough to need several "
        "small reads to fully drain through a tiny buffer.\r\n";
    size_t body_len = strlen(body);
    email_body_reader reader = {.cursor = body, .remaining = body_len};
    char reassembled[512] = {0};
    size_t total = 0;
    for (;;) {
        char chunk[7]; /* deliberately not a divisor of body_len */
        size_t n = email_read_body(chunk, 1, sizeof(chunk), &reader);
        if (n == 0) break;
        CHECK(total + n <= sizeof(reassembled));
        memcpy(reassembled + total, chunk, n);
        total += n;
    }
    CHECK(total == body_len);
    CHECK(memcmp(reassembled, body, body_len) == 0);
    CHECK(reader.remaining == 0);
}

static void test_read_body_empty(void) {
    email_body_reader reader = {.cursor = "", .remaining = 0};
    char buf[16];
    CHECK(email_read_body(buf, 1, sizeof(buf), &reader) == 0);
}

static void test_build_smtp_url(void) {
    char url[256];

    /* STARTTLS: smtp:// -- curl connects in the clear, then requires a
     * successful STARTTLS upgrade via CURLOPT_USE_SSL=ALL. */
    email_build_smtp_url(true, "smtp.example.com", url, sizeof(url));
    CHECK(strcmp(url, "smtp://smtp.example.com") == 0);

    /* Implicit TLS: smtps://, matching the smtp.resend.com:465 case this
     * bug was found against -- port 465 speaks TLS from the first byte,
     * which only the smtps:// scheme requests from curl. */
    email_build_smtp_url(false, "smtp.resend.com", url, sizeof(url));
    CHECK(strcmp(url, "smtps://smtp.resend.com") == 0);

    /* Never bare/schemeless, regardless of host shape -- the actual bug
     * being regression-tested here. */
    email_build_smtp_url(true, "email-smtp.us-east-1.amazonaws.com", url,
                         sizeof(url));
    CHECK(strncmp(url, "smtp://", 7) == 0);
}

int main(void) {
    test_read_body_single_chunk();
    test_read_body_small_chunks();
    test_read_body_empty();
    test_build_smtp_url();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_email_internal: OK\n");
    return 0;
}
