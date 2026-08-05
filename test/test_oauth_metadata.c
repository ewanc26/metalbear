/*
 * test_oauth_metadata.c — offline test for the OAuth server metadata
 * endpoints (.well-known/oauth-authorization-server and
 * .well-known/oauth-protected-resource).
 *
 * Locks in the reference PDS's advertised token endpoint auth methods
 * (build-metadata.ts): both "none" and "private_key_jwt" must be
 * advertised, and the token endpoint must actually verify a client
 * assertion (see test_oauth_token_assertion.c). Also locks in
 * `dpop_signing_alg_values_supported` being ES256-only, matching
 * wf_oauth_verify_dpop's hardcoded `alg == "ES256"` check — advertising
 * an algorithm this server cannot actually verify a DPoP proof with would
 * be the same class of bug — and that `resource_documentation` (present in
 * the reference, previously absent here) is now included on the
 * protected-resource endpoint.
 *
 * Requires WOLFRAM_BUILD_SERVER.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth_routes.h"
#include "wolfram/xrpc_server.h"

#include "test.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Minimal raw HTTP GET (mirrors the pattern in test_blob_store.c /
 * test_repo_store_resolver.c / test_blob_gc.c). */
static int raw_get(const char *host, uint16_t port, const char *path,
                   unsigned char **out_body, size_t *out_len,
                   long *out_status) {
    *out_body = NULL;
    *out_len = 0;
    *out_status = 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    char req[256];
    int rh =
        snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\n\r\n",
                 path, host, (unsigned)port);
    if (send(sock, req, (size_t)rh, 0) < 0) {
        close(sock);
        return -1;
    }

    size_t cap = 65536, got = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) {
        close(sock);
        return -1;
    }
    for (;;) {
        if (got == cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char *)realloc(buf, cap);
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
    unsigned char *body_out = (unsigned char *)malloc(blen ? blen : 1);
    if (!body_out) {
        free(buf);
        return -1;
    }
    memcpy(body_out, sep, blen);
    *out_body = body_out;
    *out_len = blen;
    free(buf);
    return 0;
}

static bool array_contains_string(const cJSON *arr, const char *needle) {
    const cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (cJSON_IsString(item) && strcmp(item->valuestring, needle) == 0)
            return true;
    }
    return false;
}

static int no_op_resolver(void *ctx, const char *hint, char *out,
                          size_t out_len) {
    (void)ctx;
    (void)hint;
    (void)out;
    (void)out_len;
    return 0;
}

static int no_op_verifier(void *ctx, const char *identifier,
                          const char *password, char *out, size_t out_len) {
    (void)ctx;
    (void)identifier;
    (void)password;
    (void)out;
    (void)out_len;
    return 0;
}

static int run(void) {
    int failures_before = wf_test_fail_count;

    char path[] = "/tmp/metalbear-oauth-metadata-XXXXXX";
    int fd = mkstemp(path);
    WF_CHECK(fd >= 0);
    if (fd >= 0) close(fd);
    unlink(path);

    metalbear_oauth_store *store = NULL;
    WF_CHECK(metalbear_oauth_store_open(path, "https://pds.example.com",
                                        &store) == WF_OK);
    if (!store) {
        unlink(path);
        return wf_test_fail_count - failures_before;
    }

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 1);
    WF_CHECK(server != NULL);
    if (!server) {
        metalbear_oauth_store_free(store);
        unlink(path);
        return wf_test_fail_count - failures_before;
    }
    WF_CHECK(metalbear_oauth_routes_register(
                 server, store, "https://pds.example.com", NULL, no_op_resolver,
                 no_op_verifier, NULL) == WF_OK);

    uint16_t port = wf_xrpc_server_port(server);
    unsigned char *body = NULL;
    size_t len = 0;
    long status = 0;
    WF_CHECK(raw_get("127.0.0.1", port,
                     "/.well-known/oauth-authorization-server", &body, &len,
                     &status) == 0);
    WF_CHECK(status == 200);

    cJSON *root = cJSON_ParseWithLength((const char *)body, len);
    WF_CHECK(root != NULL);
    if (root) {
        cJSON *methods = cJSON_GetObjectItemCaseSensitive(
            root, "token_endpoint_auth_methods_supported");
        WF_CHECK(cJSON_IsArray(methods));
        WF_CHECK(array_contains_string(methods, "none"));
        WF_CHECK(array_contains_string(methods, "private_key_jwt"));

        cJSON *token_algs = cJSON_GetObjectItemCaseSensitive(
            root, "token_endpoint_auth_signing_alg_values_supported");
        WF_CHECK(cJSON_IsArray(token_algs));
        WF_CHECK(cJSON_GetArraySize(token_algs) == 1);
        WF_CHECK(array_contains_string(token_algs, "ES256"));

        cJSON *dpop_algs = cJSON_GetObjectItemCaseSensitive(
            root, "dpop_signing_alg_values_supported");
        WF_CHECK(cJSON_IsArray(dpop_algs));
        WF_CHECK(cJSON_GetArraySize(dpop_algs) == 1);
        WF_CHECK(array_contains_string(dpop_algs, "ES256"));

        cJSON *issuer = cJSON_GetObjectItemCaseSensitive(root, "issuer");
        WF_CHECK(cJSON_IsString(issuer) &&
                 strcmp(issuer->valuestring, "https://pds.example.com") == 0);

        cJSON_Delete(root);
    }
    free(body);

    unsigned char *pr_body = NULL;
    size_t pr_len = 0;
    long pr_status = 0;
    WF_CHECK(raw_get("127.0.0.1", port, "/.well-known/oauth-protected-resource",
                     &pr_body, &pr_len, &pr_status) == 0);
    WF_CHECK(pr_status == 200);
    cJSON *pr_root = cJSON_ParseWithLength((const char *)pr_body, pr_len);
    WF_CHECK(pr_root != NULL);
    if (pr_root) {
        cJSON *docs =
            cJSON_GetObjectItemCaseSensitive(pr_root, "resource_documentation");
        WF_CHECK(cJSON_IsString(docs) &&
                 strcmp(docs->valuestring, "https://atproto.com") == 0);
        cJSON_Delete(pr_root);
    }
    free(pr_body);

    wf_xrpc_server_free(server);
    metalbear_oauth_store_free(store);
    unlink(path);
    char sidecar[256];
    snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
    unlink(sidecar);

    return wf_test_fail_count - failures_before;
}

int main(void) {
    run();
    WF_TEST_SUMMARY();
}
