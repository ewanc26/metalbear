#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_handle_dns_rfc2136.c — TSIG-signed dynamic DNS update.
 *
 * The update is a wire format sent to somebody else's nameserver, so the only
 * thing worth asserting is what actually goes down the socket. These tests run
 * the publisher against a stand-in nameserver that parses the message and
 * recomputes the TSIG MAC from scratch — deliberately not by calling the
 * signing code, since verifying our encoder with our encoder proves nothing.
 * A signature that is wrong in a way both sides share is exactly the defect
 * that makes every update fail against a real server while the suite is green.
 */

#include "metalbear/dns/handle_dns.h"
#include "metalbear/dns/handle_dns_rfc2136.h"

#include <openssl/hmac.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
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

/* The key both sides share. "secret bytes here!!" in base64. */
static const char *KEY_NAME = "metalbear-key";
static const unsigned char KEY_SECRET[] = "secret bytes here!!";
#define KEY_SECRET_LEN (sizeof(KEY_SECRET) - 1)

/* ------------------------------------------------------------------ */
/* A stand-in nameserver                                               */
/* ------------------------------------------------------------------ */

static struct {
    int listen_fd;
    unsigned short port;
    pthread_t thread;
    /* What the last request contained, for the assertions. */
    unsigned char request[4096];
    size_t request_len;
    bool tsig_verified;
    bool is_update;
    unsigned rcode_to_send;
    /* A TXT value to answer a query with, or "" for none. */
    char answer[256];
    int served;
} ns;

/* Skip a wire-format name, returning the offset just past it. */
static size_t skip_name(const unsigned char *buf, size_t len, size_t at) {
    while (at < len && buf[at] != 0) {
        if ((buf[at] & 0xc0) == 0xc0) return at + 2;
        at += buf[at] + 1;
    }
    return at + 1;
}

/*
 * Recompute the MAC over the request and compare it with the one the TSIG
 * record carries.
 *
 * The digest covers the message up to the TSIG record with ARCOUNT reduced by
 * one — the count as it stood before the record was appended — followed by the
 * TSIG variables. Reconstructing that here, from the bytes on the wire, is
 * what makes this an independent check rather than a restatement.
 */
static bool verify_tsig(const unsigned char *msg, size_t len) {
    if (len < 12) return false;
    unsigned qdcount = (unsigned)((msg[4] << 8) | msg[5]);
    unsigned ancount = (unsigned)((msg[6] << 8) | msg[7]);
    unsigned nscount = (unsigned)((msg[8] << 8) | msg[9]);
    unsigned arcount = (unsigned)((msg[10] << 8) | msg[11]);
    if (arcount == 0) return false;

    size_t at = 12;
    for (unsigned i = 0; i < qdcount; i++) {
        at = skip_name(msg, len, at);
        at += 4;
    }
    /* Answer and authority sections carry full records. */
    for (unsigned i = 0; i < ancount + nscount; i++) {
        at = skip_name(msg, len, at);
        if (at + 10 > len) return false;
        unsigned rdlength = (unsigned)((msg[at + 8] << 8) | msg[at + 9]);
        at += 10 + rdlength;
    }
    /* Additional records before the TSIG, which must be last. */
    for (unsigned i = 0; i + 1 < arcount; i++) {
        at = skip_name(msg, len, at);
        if (at + 10 > len) return false;
        unsigned rdlength = (unsigned)((msg[at + 8] << 8) | msg[at + 9]);
        at += 10 + rdlength;
    }
    size_t tsig_at = at;
    if (tsig_at >= len) return false;

    /* The TSIG record itself. */
    size_t name_start = at;
    at = skip_name(msg, len, at);
    size_t name_len = at - name_start;
    if (at + 10 > len) return false;
    unsigned type = (unsigned)((msg[at] << 8) | msg[at + 1]);
    if (type != 250) return false;
    at += 10;
    size_t rdata_at = at;
    size_t algo_start = at;
    at = skip_name(msg, len, at);
    size_t algo_len = at - algo_start;
    if (at + 10 > len) return false;
    const unsigned char *time_signed = msg + at; /* 6 bytes */
    const unsigned char *fudge = msg + at + 6;   /* 2 bytes */
    unsigned mac_len = (unsigned)((msg[at + 8] << 8) | msg[at + 9]);
    at += 10;
    if (at + mac_len > len) return false;
    const unsigned char *mac = msg + at;
    (void)rdata_at;

    /* The message as it was when signed: everything before the TSIG, with
     * ARCOUNT one lower. */
    unsigned char signed_copy[4096];
    if (tsig_at > sizeof(signed_copy)) return false;
    memcpy(signed_copy, msg, tsig_at);
    unsigned before = arcount - 1;
    signed_copy[10] = (unsigned char)(before >> 8);
    signed_copy[11] = (unsigned char)before;

    unsigned char vars[512];
    size_t v = 0;
    memcpy(vars + v, msg + name_start, name_len);
    v += name_len;
    vars[v++] = 0x00;
    vars[v++] = 0xff; /* class ANY */
    vars[v++] = 0;
    vars[v++] = 0;
    vars[v++] = 0;
    vars[v++] = 0; /* TTL 0 */
    memcpy(vars + v, msg + algo_start, algo_len);
    v += algo_len;
    memcpy(vars + v, time_signed, 6);
    v += 6;
    memcpy(vars + v, fudge, 2);
    v += 2;
    vars[v++] = 0;
    vars[v++] = 0; /* error */
    vars[v++] = 0;
    vars[v++] = 0; /* other len */

    unsigned char digest_input[sizeof(signed_copy) + sizeof(vars)];
    memcpy(digest_input, signed_copy, tsig_at);
    memcpy(digest_input + tsig_at, vars, v);

    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len = 0;
    if (!HMAC(EVP_sha256(), KEY_SECRET, (int)KEY_SECRET_LEN, digest_input,
              tsig_at + v, expected, &expected_len))
        return false;
    return expected_len == mac_len && memcmp(expected, mac, mac_len) == 0;
}

static void *serve(void *arg) {
    (void)arg;
    for (;;) {
        int fd = accept(ns.listen_fd, NULL, NULL);
        if (fd < 0) return NULL;

        unsigned char prefix[2];
        size_t got = 0;
        while (got < 2) {
            ssize_t n = recv(fd, prefix + got, 2 - got, 0);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (got != 2) {
            close(fd);
            continue;
        }
        size_t want = (size_t)((prefix[0] << 8) | prefix[1]);
        if (want > sizeof(ns.request)) {
            close(fd);
            continue;
        }
        got = 0;
        while (got < want) {
            ssize_t n = recv(fd, ns.request + got, want - got, 0);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (got != want) {
            close(fd);
            continue;
        }
        ns.request_len = got;
        ns.tsig_verified = verify_tsig(ns.request, ns.request_len);
        ns.is_update = ((ns.request[2] >> 3) & 0x0f) == 5;
        ns.served++;

        /* A minimal reply: the request's header, flipped to a response, with
         * the configured RCODE and — for a query — one TXT answer. */
        unsigned char reply[1024];
        size_t rl = 12;
        memcpy(reply, ns.request, 12);
        reply[2] = (unsigned char)(ns.request[2] | 0x80);
        reply[3] = (unsigned char)ns.rcode_to_send;
        reply[6] = 0;
        reply[7] = 0; /* ANCOUNT */
        reply[8] = 0;
        reply[9] = 0;
        reply[10] = 0;
        reply[11] = 0;

        if (!ns.is_update) {
            /* Echo the question, then answer it if a value is configured. */
            size_t qend = skip_name(ns.request, ns.request_len, 12) + 4;
            memcpy(reply + rl, ns.request + 12, qend - 12);
            rl += qend - 12;
            if (ns.answer[0]) {
                size_t value_len = strlen(ns.answer);
                memcpy(reply + rl, ns.request + 12, qend - 12 - 4);
                rl += qend - 12 - 4;
                reply[rl++] = 0;
                reply[rl++] = 16; /* TXT */
                reply[rl++] = 0;
                reply[rl++] = 1; /* IN */
                reply[rl++] = 0;
                reply[rl++] = 0;
                reply[rl++] = 0;
                reply[rl++] = 60; /* TTL */
                reply[rl++] = 0;
                reply[rl++] = (unsigned char)(value_len + 1);
                reply[rl++] = (unsigned char)value_len;
                memcpy(reply + rl, ns.answer, value_len);
                rl += value_len;
                reply[6] = 0;
                reply[7] = 1;
            }
        }
        unsigned char out_prefix[2] = {(unsigned char)(rl >> 8),
                                       (unsigned char)rl};
        send(fd, out_prefix, 2, 0);
        send(fd, reply, rl, 0);
        close(fd);
    }
}

static bool start_nameserver(void) {
    ns.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ns.listen_fd < 0) return false;
    int one = 1;
    setsockopt(ns.listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(ns.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        return false;
    socklen_t len = sizeof(addr);
    if (getsockname(ns.listen_fd, (struct sockaddr *)&addr, &len) != 0)
        return false;
    ns.port = ntohs(addr.sin_port);
    if (listen(ns.listen_fd, 4) != 0) return false;
    return pthread_create(&ns.thread, NULL, serve, NULL) == 0;
}

/* ------------------------------------------------------------------ */

static metalbear_handle_dns *open_publisher(void) {
    char server[64];
    snprintf(server, sizeof(server), "127.0.0.1:%u", (unsigned)ns.port);
    /* "secret bytes here!!" base64-encoded, the form an operator copies out
     * of a BIND key stanza. */
    char credential[128];
    snprintf(credential, sizeof(credential), "%s:%s", KEY_NAME,
             "c2VjcmV0IGJ5dGVzIGhlcmUhIQ==");
    metalbear_handle_dns *dns = NULL;
    CHECK(metalbear_handle_dns_open_ex("rfc2136", credential, "example.com",
                                       server, 300, &dns) == WF_OK);
    return dns;
}

static void reset(void) {
    ns.request_len = 0;
    ns.tsig_verified = false;
    ns.rcode_to_send = 0;
    ns.answer[0] = '\0';
    ns.served = 0;
}

/*
 * The signature has to verify against a MAC computed independently. This is
 * the whole test: three defects of this kind — the wrong ARCOUNT in the
 * digest, an uncanonicalised key name, a missing algorithm name — all produce
 * a message that looks correct and that no nameserver accepts.
 */
static void test_update_is_signed_correctly(void) {
    reset();
    metalbear_handle_dns *dns = open_publisher();
    if (!dns) return;
    CHECK(metalbear_handle_dns_publish(dns, "alice.example.com",
                                       "did:plc:alice") == WF_OK);
    /* A read and a write, both signed. */
    CHECK(ns.served == 2);
    CHECK(ns.tsig_verified);
    CHECK(ns.is_update);
    metalbear_handle_dns_free(dns);
}

/* The update must delete the RRset and add the new value in one message, or a
 * reader between the two calls sees a handle with no record. */
static void test_update_replaces_the_rrset(void) {
    reset();
    metalbear_handle_dns *dns = open_publisher();
    if (!dns) return;
    CHECK(metalbear_handle_dns_publish(dns, "alice.example.com",
                                       "did:plc:alice") == WF_OK);
    /* UPCOUNT of 2: the delete and the add. */
    unsigned upcount = (unsigned)((ns.request[8] << 8) | ns.request[9]);
    CHECK(upcount == 2);
    /* And the value is in there, length-prefixed as TXT rdata. */
    bool found = false;
    const char *needle = "did=did:plc:alice";
    size_t nlen = strlen(needle);
    for (size_t i = 0; i + nlen <= ns.request_len; i++)
        if (memcmp(ns.request + i, needle, nlen) == 0) found = true;
    CHECK(found);
    metalbear_handle_dns_free(dns);
}

/* A record already saying the right thing is left alone: the read happens
 * first, and a match means no update at all. */
static void test_publish_is_idempotent(void) {
    reset();
    snprintf(ns.answer, sizeof(ns.answer), "did=did:plc:bob");
    metalbear_handle_dns *dns = open_publisher();
    if (!dns) return;
    CHECK(metalbear_handle_dns_publish(dns, "bob.example.com", "did:plc:bob") ==
          WF_OK);
    CHECK(ns.served == 1);
    CHECK(!ns.is_update);
    metalbear_handle_dns_free(dns);
}

/* A stale record is corrected. */
static void test_publish_updates_a_stale_record(void) {
    reset();
    snprintf(ns.answer, sizeof(ns.answer), "did=did:plc:old");
    metalbear_handle_dns *dns = open_publisher();
    if (!dns) return;
    CHECK(metalbear_handle_dns_publish(dns, "carol.example.com",
                                       "did:plc:new") == WF_OK);
    CHECK(ns.served == 2);
    CHECK(ns.is_update);
    CHECK(ns.tsig_verified);
    metalbear_handle_dns_free(dns);
}

/* Retract removes the RRset, and does so with an update carrying only the
 * delete. */
static void test_retract_deletes_the_rrset(void) {
    reset();
    snprintf(ns.answer, sizeof(ns.answer), "did=did:plc:dave");
    metalbear_handle_dns *dns = open_publisher();
    if (!dns) return;
    CHECK(metalbear_handle_dns_retract(dns, "dave.example.com") == WF_OK);
    CHECK(ns.served == 2);
    CHECK(ns.is_update);
    unsigned upcount = (unsigned)((ns.request[8] << 8) | ns.request[9]);
    CHECK(upcount == 1);
    metalbear_handle_dns_free(dns);
}

/* Absent already: nothing to delete, and no update sent. */
static void test_retract_of_an_absent_record_sends_no_update(void) {
    reset();
    metalbear_handle_dns *dns = open_publisher();
    if (!dns) return;
    CHECK(metalbear_handle_dns_retract(dns, "erin.example.com") == WF_OK);
    CHECK(ns.served == 1);
    CHECK(!ns.is_update);
    metalbear_handle_dns_free(dns);
}

/*
 * A refused update must fail loudly and name the RCODE. NOTAUTH in particular
 * almost always means the key is right and the server does not allow it to
 * update that zone, which is a different thing for the operator to fix than a
 * wrong key.
 */
static void test_a_refused_update_is_a_failure(void) {
    reset();
    ns.rcode_to_send = 9; /* NOTAUTH */
    metalbear_handle_dns *dns = open_publisher();
    if (!dns) return;
    CHECK(metalbear_handle_dns_publish(dns, "frank.example.com",
                                       "did:plc:frank") != WF_OK);
    CHECK(strstr(metalbear_handle_dns_last_error(dns), "NOTAUTH") != NULL);
    metalbear_handle_dns_free(dns);
}

/*
 * rfc2136 without a server has nowhere to send an update, and a key that is
 * not `name:secret` cannot be used to sign one. Both are refused at open
 * rather than accepted into a host that silently writes no records.
 */
static void test_incomplete_configuration_is_refused(void) {
    metalbear_handle_dns *dns = NULL;
    CHECK(metalbear_handle_dns_open_ex("rfc2136", "key:c2VjcmV0", "example.com",
                                       NULL, 300, &dns) != WF_OK);
    CHECK(dns == NULL);
    CHECK(metalbear_handle_dns_open_ex("rfc2136", "no-colon-here",
                                       "example.com", "127.0.0.1", 300,
                                       &dns) != WF_OK);
    CHECK(dns == NULL);
    /* And the plain open, which cannot supply a server, refuses it too. */
    CHECK(metalbear_handle_dns_open("rfc2136", "key:c2VjcmV0", "example.com",
                                    300, &dns) != WF_OK);
    CHECK(dns == NULL);
}

int main(void) {
    printf("MetalBear RFC 2136 handle DNS tests\n");
    if (!start_nameserver()) {
        fprintf(stderr, "could not start the stand-in nameserver\n");
        return 1;
    }

    test_incomplete_configuration_is_refused();
    test_update_is_signed_correctly();
    test_update_replaces_the_rrset();
    test_publish_is_idempotent();
    test_publish_updates_a_stale_record();
    test_retract_deletes_the_rrset();
    test_retract_of_an_absent_record_sends_no_update();
    test_a_refused_update_is_a_failure();

    close(ns.listen_fd);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("All tests passed.\n");
    return 0;
}
