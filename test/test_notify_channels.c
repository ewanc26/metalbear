#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_notify_channels.c — coverage for the notification channel interface
 * introduced for issue #132.
 *
 * The fake channel proves the dispatcher fans out to every channel, passes
 * the exact subject/body the old email-only call sites built, and reports the
 * first failure. The email channel is exercised through the same interface
 * against a closed local port, proving the adapter is really on the call path
 * (the old behaviour was a direct call from the route). The webhook channel
 * is exercised against a local HTTP server, checking both the JSON payload
 * and that its bearer secret never reaches stderr.
 */

#include "metalbear/notify.h"
#ifdef METALBEAR_MODULE_EMAIL
#include "metalbear/email.h"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ---- Fake channel ------------------------------------------------------- */

typedef struct fake_ctx {
    int calls;
    metalbear_notification_kind kind;
    char to[256];
    char did[256];
    char code[256];
    char subject[256];
    char body[1024];
    wf_status result;
} fake_ctx;

static void copy_field(char *dst, size_t len, const char *src) {
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, len, "%s", src);
}

static wf_status fake_send(void *ctx, const metalbear_notification *note) {
    fake_ctx *fake = ctx;
    fake->calls++;
    fake->kind = note->kind;
    copy_field(fake->to, sizeof(fake->to), note->to_address);
    copy_field(fake->did, sizeof(fake->did), note->account_did);
    copy_field(fake->code, sizeof(fake->code), note->code);
    copy_field(fake->subject, sizeof(fake->subject), note->subject);
    copy_field(fake->body, sizeof(fake->body), note->body);
    return fake->result;
}

static void test_dispatch_and_copy(void) {
    metalbear_notifier *notifier = NULL;
    CHECK(metalbear_notifier_new(&notifier) == WF_OK);
    CHECK(notifier != NULL);
    if (!notifier) return;

    fake_ctx fake = {.result = WF_OK};
    metalbear_notify_channel channel = {
        .name = "fake", .send = fake_send, .free = NULL, .ctx = &fake};
    CHECK(metalbear_notifier_add(notifier, &channel));
    CHECK(metalbear_notifier_channel_count(notifier) == 1);

    CHECK(metalbear_notify_send_verification(notifier, "alice@example.com",
                                             "VERIFY123",
                                             "did:plc:alice") == WF_OK);
    CHECK(fake.calls == 1);
    CHECK(fake.kind == METALBEAR_NOTIFY_VERIFICATION);
    CHECK(strcmp(fake.to, "alice@example.com") == 0);
    CHECK(strcmp(fake.did, "did:plc:alice") == 0);
    CHECK(strcmp(fake.code, "VERIFY123") == 0);
    /* Exactly the copy src/email.cpp has always sent. */
    CHECK(strcmp(fake.subject, "Verify your email address") == 0);
    CHECK(strstr(fake.body, "Your verification code is: VERIFY123") != NULL);
    CHECK(strstr(fake.body, "please ignore this email.") != NULL);

    CHECK(metalbear_notify_send_password_reset(notifier, "alice@example.com",
                                               "RESET456", NULL) == WF_OK);
    CHECK(fake.calls == 2);
    CHECK(fake.kind == METALBEAR_NOTIFY_PASSWORD_RESET);
    CHECK(strcmp(fake.subject, "Reset your password") == 0);
    CHECK(strstr(fake.body, "RESET456") != NULL);

    CHECK(metalbear_notify_send_account_deletion(notifier, "alice@example.com",
                                                 "DELETE789", NULL) == WF_OK);
    CHECK(fake.calls == 3);
    CHECK(fake.kind == METALBEAR_NOTIFY_ACCOUNT_DELETION);
    CHECK(strcmp(fake.subject, "Confirm account deletion") == 0);
    CHECK(strstr(fake.body, "DELETE789") != NULL);

    CHECK(metalbear_notify_send_message(notifier, NULL, "Subject", "Body",
                                        NULL) == WF_OK);
    CHECK(fake.calls == 4);
    CHECK(fake.kind == METALBEAR_NOTIFY_MESSAGE);
    CHECK(strcmp(fake.subject, "Subject") == 0);
    CHECK(strcmp(fake.body, "Body") == 0);

    metalbear_notifier_free(notifier);
}

static void test_no_channels_is_noop(void) {
    metalbear_notifier *notifier = NULL;
    CHECK(metalbear_notifier_new(&notifier) == WF_OK);
    CHECK(metalbear_notifier_channel_count(notifier) == 0);
    CHECK(metalbear_notify_send_verification(notifier, "alice@example.com",
                                             "CODE", NULL) == WF_OK);
    CHECK(metalbear_notify_send_message(notifier, NULL, "s", "b", NULL) ==
          WF_OK);
    /* NULL is a no-op too; callers need not special-case an empty table. */
    CHECK(metalbear_notify_send_message(NULL, NULL, "s", "b", NULL) == WF_OK);
    metalbear_notifier_free(notifier);
}

static void test_fanout_and_failure(void) {
    metalbear_notifier *notifier = NULL;
    CHECK(metalbear_notifier_new(&notifier) == WF_OK);

    fake_ctx first = {.result = WF_ERR_INTERNAL};
    fake_ctx second = {.result = WF_OK};
    metalbear_notify_channel a = {
        .name = "a", .send = fake_send, .ctx = &first};
    metalbear_notify_channel b = {
        .name = "b", .send = fake_send, .ctx = &second};
    CHECK(metalbear_notifier_add(notifier, &a));
    CHECK(metalbear_notifier_add(notifier, &b));
    /* Fixed-size table: the fifth add must be rejected, not written past. */
    for (int i = 0; i < 2; i++) CHECK(metalbear_notifier_add(notifier, &a));
    CHECK(!metalbear_notifier_add(notifier, &a));
    CHECK(metalbear_notifier_channel_count(notifier) == 4);

    CHECK(metalbear_notify_send_message(notifier, NULL, "s", "b", NULL) ==
          WF_ERR_INTERNAL);
    /* A failing channel must not stop delivery to the others. */
    CHECK(first.calls == 3); /* a, then two more capacity slots */
    CHECK(second.calls == 1);
    metalbear_notifier_free(notifier);
}

#ifdef METALBEAR_MODULE_EMAIL
static void test_email_channel_through_interface(void) {
    metalbear_email *email = NULL;
    metalbear_email_config config = {
        .smtp_host = "127.0.0.1",
        .smtp_port = 1, /* no listener: connection refused, no TLS needed */
        .from_address = "pds@example.com",
    };
    CHECK(metalbear_email_open(&config, &email) == WF_OK);
    if (!email) return;

    metalbear_notify_channel channel;
    CHECK(metalbear_notify_email_channel(email, &channel) == WF_OK);
    CHECK(strcmp(channel.name, "email") == 0);
    CHECK(channel.free == NULL); /* borrowed: server owns the email client */

    metalbear_notifier *notifier = NULL;
    CHECK(metalbear_notifier_new(&notifier) == WF_OK);
    CHECK(metalbear_notifier_add(notifier, &channel));
    /* Reaching the email adapter is what this proves: the status comes back
     * through the interface instead of being ignored at the call site. */
    CHECK(metalbear_notify_send_verification(notifier, "alice@example.com",
                                             "CODE", NULL) != WF_OK);
    metalbear_notifier_free(notifier);
    metalbear_email_free(email);
}
#endif

/* ---- Webhook channel against a local HTTP receiver ---------------------- */

#define WEBHOOK_CAPTURE 8192

typedef struct webhook_mock {
    int listen_fd;
    pthread_t thread;
    char captured[WEBHOOK_CAPTURE];
} webhook_mock;

static int write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 0;
        cursor += written;
        length -= (size_t)written;
    }
    return 1;
}

static void *webhook_mock_run(void *arg) {
    webhook_mock *mock = arg;
    int fd = accept(mock->listen_fd, NULL, NULL);
    if (fd < 0) return NULL;
    size_t total = 0;
    for (;;) {
        ssize_t n =
            read(fd, mock->captured + total, WEBHOOK_CAPTURE - total - 1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        total += (size_t)n;
        mock->captured[total] = '\0';
        char *split = strstr(mock->captured, "\r\n\r\n");
        if (split) {
            char *len_header = strstr(mock->captured, "Content-Length:");
            size_t want =
                len_header ? (size_t)strtoul(len_header + 15, NULL, 10) : 0;
            if (total >= (size_t)(split + 4 - mock->captured) + want) break;
        }
        if (total >= WEBHOOK_CAPTURE - 2) break;
    }
    static const char response[] = "HTTP/1.1 204 No Content\r\n"
                                   "Content-Length: 0\r\n"
                                   "Connection: close\r\n"
                                   "\r\n";
    write_all(fd, response, sizeof(response) - 1);
    close(fd);
    return NULL;
}

static int webhook_mock_start(webhook_mock *mock, uint16_t *port_out) {
    memset(mock, 0, sizeof(*mock));
    mock->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (mock->listen_fd < 0) return 0;
    int reuse = 1;
    setsockopt(mock->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
               sizeof(reuse));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0;
    if (bind(mock->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(mock->listen_fd);
        return 0;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(mock->listen_fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(mock->listen_fd);
        return 0;
    }
    *port_out = ntohs(addr.sin_port);
    if (listen(mock->listen_fd, 2) != 0 ||
        pthread_create(&mock->thread, NULL, webhook_mock_run, mock) != 0) {
        close(mock->listen_fd);
        return 0;
    }
    return 1;
}

static void test_webhook_delivery(void) {
    webhook_mock mock;
    uint16_t port = 0;
    if (!webhook_mock_start(&mock, &port)) {
        CHECK(0);
        return;
    }

    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/notify", (unsigned)port);
    metalbear_notify_channel channel;
    CHECK(metalbear_notify_webhook_channel(url, "webhook-test-secret",
                                           &channel) == WF_OK);
    CHECK(strcmp(channel.name, "webhook") == 0);
    CHECK(channel.free != NULL);

    metalbear_notifier *notifier = NULL;
    CHECK(metalbear_notifier_new(&notifier) == WF_OK);
    CHECK(metalbear_notifier_add(notifier, &channel));

    /* Capture stderr while sending so the no-secret-logging promise is
     * checked with the real delivery code, not just by reading it. */
    FILE *log = tmpfile();
    CHECK(log != NULL);
    int saved_stderr = dup(STDERR_FILENO);
    if (log && saved_stderr >= 0) dup2(fileno(log), STDERR_FILENO);

    wf_status status = metalbear_notify_send_message(
        notifier, "alice@example.com", "Test subject", "Test body with CODE42",
        "did:plc:alice");

    fflush(stderr);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    CHECK(status == WF_OK);

    if (log) {
        char captured_log[4096] = {0};
        rewind(log);
        size_t n = fread(captured_log, 1, sizeof(captured_log) - 1, log);
        captured_log[n] = '\0';
        CHECK(strstr(captured_log, "webhook-test-secret") == NULL);
        CHECK(strstr(captured_log, "CODE42") == NULL);
        fclose(log);
    }

    pthread_join(mock.thread, NULL);
    close(mock.listen_fd);

    CHECK(strstr(mock.captured, "POST /notify HTTP/1.1") != NULL);
    CHECK(strstr(mock.captured, "Content-Type: application/json") != NULL);
    CHECK(strstr(mock.captured, "Authorization: Bearer webhook-test-secret") !=
          NULL);
    CHECK(strstr(mock.captured, "\"kind\":\"message\"") != NULL);
    CHECK(strstr(mock.captured, "\"code\":\"") ==
          NULL); /* no code on message */
    CHECK(strstr(mock.captured, "\"to\":\"alice@example.com\"") != NULL);
    CHECK(strstr(mock.captured, "\"did\":\"did:plc:alice\"") != NULL);
    CHECK(strstr(mock.captured, "Test body with CODE42") != NULL);

    metalbear_notifier_free(notifier);
}

/* Operator branding (issue #260) signs the built-in bodies without changing
 * them at all when no branding is configured. */
static void test_branding_signature(void) {
    metalbear_notifier *notifier = NULL;
    CHECK(metalbear_notifier_new(&notifier) == WF_OK);
    if (!notifier) return;

    fake_ctx fake = {.result = WF_OK};
    metalbear_notify_channel channel = {
        .name = "fake", .send = fake_send, .free = NULL, .ctx = &fake};
    CHECK(metalbear_notifier_add(notifier, &channel));

    CHECK(metalbear_notify_send_password_reset(notifier, "alice@example.com",
                                               "RESET456", NULL) == WF_OK);
    CHECK(strstr(fake.body, "--\n") == NULL);

    CHECK(metalbear_notifier_set_branding(notifier, "Bear Hosting",
                                          "https://example.com/logo.svg") ==
          WF_OK);
    CHECK(metalbear_notify_send_verification(notifier, "alice@example.com",
                                             "VERIFY123", NULL) == WF_OK);
    CHECK(strstr(fake.body, "Your verification code is: VERIFY123") != NULL);
    CHECK(strstr(fake.body, "--\nBear Hosting\n") != NULL);
    CHECK(strstr(fake.body, "https://example.com/logo.svg") != NULL);

    /* Clearing both fields restores the original body exactly. */
    CHECK(metalbear_notifier_set_branding(notifier, NULL, NULL) == WF_OK);
    CHECK(metalbear_notify_send_verification(notifier, "alice@example.com",
                                             "VERIFY123", NULL) == WF_OK);
    CHECK(strstr(fake.body, "--\n") == NULL);

    metalbear_notifier_free(notifier);
}

int main(void) {
    test_dispatch_and_copy();
    test_branding_signature();
    test_no_channels_is_noop();
    test_fanout_and_failure();
#ifdef METALBEAR_MODULE_EMAIL
    test_email_channel_through_interface();
#endif
    test_webhook_delivery();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_notify_channels: OK\n");
    return 0;
}
