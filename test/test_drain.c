/*
 * test_drain.c -- graceful shutdown write gate (issue #164).
 *
 * End-to-end over a loopback XRPC server: a mutating procedure registered
 * through the drain gate (1) completes normally before a drain, (2) once a
 * drain begins a new write gets 503 ServiceUnavailable, and (3) a write
 * already in flight when the drain starts is allowed to finish. Also checks
 * latch/reset semantics for the next server instance.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/server_drain.h"
#include "wolfram/xrpc_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int failures;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* Minimal one-shot HTTP/1.1 client (Connection: close => EOF terminates). */
static int raw_http(uint16_t port, const char *path, long *out_status,
                    unsigned char **out_body, size_t *out_len) {
    *out_status = 0;
    *out_body = NULL;
    *out_len = 0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
        connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }
    char req[512];
    int rh = snprintf(req, sizeof(req),
                      "POST %s HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n"
                      "Content-Type: application/json\r\nContent-Length: 2\r\n"
                      "Connection: close\r\n\r\n{}",
                      path, (unsigned)port);
    if (send(sock, req, (size_t)rh, 0) < 0) {
        close(sock);
        return -1;
    }
    size_t cap = 8192, got = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) {
        close(sock);
        return -1;
    }
    for (;;) {
        if (got == cap) {
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                close(sock);
                return -1;
            }
            buf = nb;
        }
        ssize_t n = recv(sock, buf + got, cap - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(sock);
    const char *sep = NULL;
    for (size_t i = 0; i + 3 < got; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
            buf[i + 3] == '\n') {
            sep = (const char *)&buf[i + 4];
            break;
        }
    }
    if (!sep) {
        free(buf);
        return -1;
    }
    sscanf((const char *)buf, "HTTP/%*s %ld", out_status);
    size_t blen = got - (size_t)(sep - (char *)buf);
    unsigned char *body = malloc(blen ? blen : 1);
    if (body) memcpy(body, sep, blen);
    free(buf);
    *out_body = body;
    *out_len = blen;
    return 0;
}

static atomic_int entered;
static atomic_int finished;

static wf_status held_write(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    (void)ctx;
    (void)req;
    (void)resp;
    atomic_fetch_add(&entered, 1);
    while (!atomic_load(&finished)) {
        struct timespec nap = {0, 10 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    return WF_OK;
}

struct writer_arg {
    uint16_t port;
    long status;
    int sent;
};

static void *writer(void *arg) {
    struct writer_arg *w = arg;
    unsigned char *body = NULL;
    size_t len = 0;
    w->sent =
        raw_http(w->port, "/xrpc/test.heldWrite", &w->status, &body, &len);
    free(body);
    return NULL;
}

int main(void) {
    metalbear_drain_reset(0);
    CHECK(!metalbear_drain_is_active());

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 4);
    CHECK(server != NULL);
    if (!server) return 1;
    CHECK(metalbear_register_write_procedure(server, "test.heldWrite",
                                             held_write, NULL) == WF_OK);
    uint16_t port = wf_xrpc_server_port(server);

    /* Normal write before drain completes with a 2xx. */
    atomic_store(&finished, 1);
    struct writer_arg first = {port, 0, -1};
    writer(&first);
    CHECK(first.sent == 0);
    CHECK(first.status >= 200 && first.status < 300);
    CHECK(atomic_load(&entered) == 1);

    /* Start a write, wait until it is inside the handler, then drain. */
    atomic_store(&finished, 0);
    struct writer_arg in_flight = {port, 0, -1};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, writer, &in_flight) == 0);
    for (int i = 0; i < 500 && atomic_load(&entered) < 2; i++) {
        struct timespec nap = {0, 10 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    CHECK(atomic_load(&entered) == 2);
    CHECK(metalbear_drain_begin() == 1); /* one write still in flight */
    CHECK(metalbear_drain_is_active());

    /* A new write during drain is refused with 503. */
    struct writer_arg late = {port, 0, -1};
    writer(&late);
    CHECK(late.sent == 0);
    CHECK(late.status == 503);

    /* Release the held write; the drain already returned on timeout (0). */
    atomic_store(&finished, 1);
    pthread_join(thread, NULL);
    CHECK(in_flight.sent == 0);
    CHECK(in_flight.status >= 200 && in_flight.status < 300);

    metalbear_drain_shutdown();
    wf_xrpc_server_free(server);
    metalbear_drain_reset(5);
    CHECK(!metalbear_drain_is_active());

    if (failures) {
        fprintf(stderr, "%d drain check(s) failed\n", failures);
        return 1;
    }
    printf("drain: ok\n");
    return 0;
}
