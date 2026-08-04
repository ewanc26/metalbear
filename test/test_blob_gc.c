/*
 * test_blob_gc.c — offline end-to-end tests for blob reference tracking on
 * the real repo write path (createRecord / putRecord / deleteRecord /
 * applyWrites), driven over HTTP against a real wf_xrpc_server.
 *
 * test_blob_store.c covers the blob_store API in isolation
 * (associate/dissociate/is_referenced); this file proves the write-path
 * wiring in repo_store.c actually calls it at the right times:
 *
 *   - createRecord referencing an uploaded blob associates it.
 *   - putRecord replacing a record's value dereferences the blobs the old
 *     value named (deleted once nothing else references them) while
 *     associating the blobs the new value names.
 *   - putRecord that keeps referencing the SAME blob across old and new
 *     values never transiently deletes it (the reference-then-dereference
 *     ordering in repo_store.c must not touch zero in between).
 *   - deleteRecord dereferences the blobs the deleted value named.
 *   - applyWrites does the same, batched, including a blob shared by two
 *     records surviving until the last one drops it.
 *
 * Requires WOLFRAM_BUILD_SERVER.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/repo_store.h"
#include "metalbear/blob_store.h"
#include "wolfram/xrpc.h"
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

static const char *ACCOUNT_DID = "did:plc:bloggc";

static void temp_path(char *buf, size_t n) {
    snprintf(buf, n, "/tmp/metalbear_blob_gc_XXXXXX");
    int fd = mkstemp(buf);
    if (fd >= 0) close(fd);
    unlink(buf);
}

static wf_status resolver(void *ctx, const wf_xrpc_request *req,
                          metalbear_repo_store **out_repo,
                          metalbear_blob_store **out_blobs) {
    (void)req;
    struct { metalbear_repo_store *repo; metalbear_blob_store *blobs; } *pair = ctx;
    *out_repo = pair->repo;
    *out_blobs = pair->blobs;
    return WF_OK;
}

/* Minimal raw HTTP client (mirrors test_blob_store.c / test_repo_store_resolver.c). */
static int raw_http(const char *host, uint16_t port, const char *method,
                    const char *path, const unsigned char *body,
                    size_t body_len, const char *content_type,
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
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) { close(sock); return -1; }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    char req[512];
    int rh = snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: %s:%u\r\n",
                      method, path, host, (unsigned)port);
    if (body && body_len > 0 && content_type) {
        rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                       "Content-Type: %s\r\n", content_type);
        rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                       "Content-Length: %zu\r\n", body_len);
    }
    rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                   "Connection: close\r\n\r\n");
    if (send(sock, req, (size_t)rh, 0) < 0) { close(sock); return -1; }
    if (body && body_len > 0 && send(sock, body, body_len, 0) < 0) {
        close(sock);
        return -1;
    }

    size_t cap = 65536, got = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) { close(sock); return -1; }
    for (;;) {
        if (got == cap) {
            cap *= 2;
            unsigned char *nb = (unsigned char *)realloc(buf, cap);
            if (!nb) { free(buf); close(sock); return -1; }
            buf = nb;
        }
        ssize_t n = recv(sock, buf + got, cap - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(sock);

    const char *sep = NULL;
    for (size_t i = 0; i + 3 < got; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            sep = (const char *)&buf[i + 4];
            break;
        }
    }
    if (!sep) { free(buf); return -1; }
    sscanf((const char *)buf, "HTTP/%*s %ld", out_status);
    size_t blen = got - (size_t)(sep - (char *)buf);
    unsigned char *body_out = (unsigned char *)malloc(blen ? blen : 1);
    if (!body_out) { free(buf); return -1; }
    memcpy(body_out, sep, blen);
    *out_body = body_out;
    *out_len = blen;
    free(buf);
    return 0;
}

/* Upload a small blob via raw HTTP and return its CID (caller frees), or
 * NULL on failure. */
static char *upload_blob(const char *host, uint16_t port,
                         const unsigned char *data, size_t len,
                         const char *mime) {
    unsigned char *body = NULL; size_t blen = 0; long status = 0;
    if (raw_http(host, port, "POST", "/xrpc/com.atproto.repo.uploadBlob",
                 data, len, mime, &body, &blen, &status) != 0 ||
        status != 200) {
        free(body);
        return NULL;
    }
    cJSON *root = cJSON_ParseWithLength((const char *)body, blen);
    free(body);
    cJSON *blob = root ? cJSON_GetObjectItemCaseSensitive(root, "blob") : NULL;
    cJSON *ref = blob ? cJSON_GetObjectItemCaseSensitive(blob, "ref") : NULL;
    cJSON *link = ref ? cJSON_GetObjectItemCaseSensitive(ref, "$link") : NULL;
    char *cid = (link && cJSON_IsString(link)) ? strdup(link->valuestring) : NULL;
    cJSON_Delete(root);
    return cid;
}

/* Build an app.bsky.feed.post record referencing zero or one blob CID. */
static void build_post(char *out, size_t out_len, const char *text,
                       const char *blob_cid) {
    if (blob_cid) {
        snprintf(out, out_len,
            "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
            "\"rkey\":\"%s\",\"record\":{\"$type\":\"app.bsky.feed.post\","
            "\"text\":\"%s\",\"embed\":{\"$type\":\"app.bsky.embed.images\","
            "\"images\":[{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
            "\"ref\":{\"$link\":\"%s\"},\"mimeType\":\"image/png\",\"size\":4}}]},"
            "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
            ACCOUNT_DID, text, text, blob_cid);
    } else {
        snprintf(out, out_len,
            "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
            "\"rkey\":\"%s\",\"record\":{\"$type\":\"app.bsky.feed.post\","
            "\"text\":\"%s\",\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
            ACCOUNT_DID, text, text);
    }
}

static int run(void) {
    int failures_before = wf_test_fail_count;

    char repo_path[256];
    temp_path(repo_path, sizeof(repo_path));
    metalbear_repo_store *repo = NULL;
    WF_CHECK(metalbear_repo_store_open(repo_path, ACCOUNT_DID,
                                       "bloggc.example.com", &repo) == WF_OK);
    metalbear_blob_store *blobs = metalbear_blob_store_new(NULL);
    WF_CHECK(blobs != NULL);
    if (!repo || !blobs) goto cleanup;

    struct { metalbear_repo_store *repo; metalbear_blob_store *blobs; } pair = {repo, blobs};

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 1);
    WF_CHECK(server != NULL);
    if (!server) goto cleanup;
    WF_CHECK(metalbear_xrpc_server_register_pds_repo_resolver(
                 server, resolver, &pair, NULL, NULL) == WF_OK);
    WF_CHECK(metalbear_xrpc_server_register_blob_store_resolver(
                  server, resolver, &pair) == WF_OK);

    uint16_t port = wf_xrpc_server_port(server);
    WF_CHECK(port != 0);
    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u", (unsigned)port);
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    WF_CHECK(client != NULL);

    const unsigned char png_a[] = {0x01, 0x02, 0x03, 0x04};
    const unsigned char png_b[] = {0x05, 0x06, 0x07, 0x08};
    const unsigned char png_c[] = {0x09, 0x0a, 0x0b, 0x0c};

    /* ── createRecord associates the blob it references ────────────── */
    char *cid_a = upload_blob("127.0.0.1", port, png_a, sizeof(png_a), "image/png");
    WF_CHECK(cid_a != NULL);
    if (cid_a) {
        WF_CHECK(metalbear_blob_store_is_referenced(blobs, cid_a) == WF_ERR_NOT_FOUND);
        char body[1024];
        build_post(body, sizeof(body), "post-a", cid_a);
        wf_response res = {0};
        WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                   body, &res) == WF_OK && res.status == 200);
        wf_response_free(&res);
        WF_CHECK(metalbear_blob_store_is_referenced(blobs, cid_a) == WF_OK);

        /* ── putRecord replacing the value with a different blob
         *    dereferences the old blob (deleted, nothing else names it)
         *    and associates the new one. ────────────────────────────── */
        char *cid_b = upload_blob("127.0.0.1", port, png_b, sizeof(png_b), "image/png");
        WF_CHECK(cid_b != NULL);
        if (cid_b) {
            char put_body[1024];
            snprintf(put_body, sizeof(put_body),
                "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
                "\"rkey\":\"post-a\",\"record\":{\"$type\":\"app.bsky.feed.post\","
                "\"text\":\"post-a-v2\",\"embed\":{\"$type\":\"app.bsky.embed.images\","
                "\"images\":[{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
                "\"ref\":{\"$link\":\"%s\"},\"mimeType\":\"image/png\",\"size\":4}}]},"
                "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
                ACCOUNT_DID, cid_b);
            wf_response put_res = {0};
            WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.putRecord",
                                       put_body, &put_res) == WF_OK &&
                     put_res.status == 200);
            wf_response_free(&put_res);

            WF_CHECK(metalbear_blob_store_exists(blobs, cid_a) == WF_ERR_NOT_FOUND);
            WF_CHECK(metalbear_blob_store_is_referenced(blobs, cid_b) == WF_OK);

            /* ── deleteRecord dereferences the blob the deleted value
             *    named. ────────────────────────────────────────────── */
            char del_body[256];
            snprintf(del_body, sizeof(del_body),
                "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
                "\"rkey\":\"post-a\"}", ACCOUNT_DID);
            wf_response del_res = {0};
            WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.deleteRecord",
                                       del_body, &del_res) == WF_OK &&
                     del_res.status == 200);
            wf_response_free(&del_res);
            WF_CHECK(metalbear_blob_store_exists(blobs, cid_b) == WF_ERR_NOT_FOUND);
            free(cid_b);
        }
        free(cid_a);
    }

    /* ── putRecord that keeps referencing the SAME blob across old and
     *    new values must not transiently delete it. ──────────────────── */
    {
        char *cid_same = upload_blob("127.0.0.1", port, png_c, sizeof(png_c),
                                     "image/png");
        WF_CHECK(cid_same != NULL);
        if (cid_same) {
            char body[1024];
            build_post(body, sizeof(body), "post-same", cid_same);
            wf_response res = {0};
            WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                       body, &res) == WF_OK && res.status == 200);
            wf_response_free(&res);
            WF_CHECK(metalbear_blob_store_is_referenced(blobs, cid_same) == WF_OK);

            /* Re-put with the identical blob ref (only the text changes). */
            char put_body[1024];
            snprintf(put_body, sizeof(put_body),
                "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
                "\"rkey\":\"post-same\",\"record\":{\"$type\":\"app.bsky.feed.post\","
                "\"text\":\"post-same-v2\",\"embed\":{\"$type\":\"app.bsky.embed.images\","
                "\"images\":[{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
                "\"ref\":{\"$link\":\"%s\"},\"mimeType\":\"image/png\",\"size\":4}}]},"
                "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
                ACCOUNT_DID, cid_same);
            wf_response put_res = {0};
            WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.putRecord",
                                       put_body, &put_res) == WF_OK &&
                     put_res.status == 200);
            wf_response_free(&put_res);
            WF_CHECK(metalbear_blob_store_exists(blobs, cid_same) == WF_OK);
            WF_CHECK(metalbear_blob_store_is_referenced(blobs, cid_same) == WF_OK);
            free(cid_same);
        }
    }

    /* ── applyWrites: a blob shared by two records survives until the
     *    last one drops it. ─────────────────────────────────────────── */
    {
        const unsigned char png_d[] = {0x0d, 0x0e, 0x0f, 0x10};
        char *cid_shared = upload_blob("127.0.0.1", port, png_d, sizeof(png_d),
                                       "image/png");
        WF_CHECK(cid_shared != NULL);
        if (cid_shared) {
            char writes_body[2048];
            snprintf(writes_body, sizeof(writes_body),
                "{\"repo\":\"%s\",\"writes\":["
                "{\"$type\":\"com.atproto.repo.applyWrites#create\","
                "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"shared-1\","
                "\"value\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"s1\","
                "\"embed\":{\"$type\":\"app.bsky.embed.images\",\"images\":["
                "{\"alt\":\"a\",\"image\":{\"$type\":\"blob\",\"ref\":{\"$link\":\"%s\"},"
                "\"mimeType\":\"image/png\",\"size\":4}}]},"
                "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}},"
                "{\"$type\":\"com.atproto.repo.applyWrites#create\","
                "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"shared-2\","
                "\"value\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"s2\","
                "\"embed\":{\"$type\":\"app.bsky.embed.images\",\"images\":["
                "{\"alt\":\"a\",\"image\":{\"$type\":\"blob\",\"ref\":{\"$link\":\"%s\"},"
                "\"mimeType\":\"image/png\",\"size\":4}}]},"
                "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}"
                "]}", ACCOUNT_DID, cid_shared, cid_shared);
            wf_response aw_res = {0};
            WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.applyWrites",
                                       writes_body, &aw_res) == WF_OK &&
                     aw_res.status == 200);
            wf_response_free(&aw_res);
            WF_CHECK(metalbear_blob_store_is_referenced(blobs, cid_shared) == WF_OK);

            /* Delete one of the two: the blob must survive. */
            char del1[2048];
            snprintf(del1, sizeof(del1),
                "{\"repo\":\"%s\",\"writes\":["
                "{\"$type\":\"com.atproto.repo.applyWrites#delete\","
                "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"shared-1\"}]}",
                ACCOUNT_DID);
            wf_response d1 = {0};
            WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.applyWrites",
                                       del1, &d1) == WF_OK && d1.status == 200);
            wf_response_free(&d1);
            WF_CHECK(metalbear_blob_store_exists(blobs, cid_shared) == WF_OK);

            /* Delete the second: now nothing references it. */
            char del2[2048];
            snprintf(del2, sizeof(del2),
                "{\"repo\":\"%s\",\"writes\":["
                "{\"$type\":\"com.atproto.repo.applyWrites#delete\","
                "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"shared-2\"}]}",
                ACCOUNT_DID);
            wf_response d2 = {0};
            WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.applyWrites",
                                       del2, &d2) == WF_OK && d2.status == 200);
            wf_response_free(&d2);
            WF_CHECK(metalbear_blob_store_exists(blobs, cid_shared) == WF_ERR_NOT_FOUND);
            free(cid_shared);
        }
    }

    wf_xrpc_client_free(client);
    wf_xrpc_server_free(server);

cleanup:
    metalbear_repo_store_free(repo);
    metalbear_blob_store_free(blobs);
    unlink(repo_path);
    return wf_test_fail_count - failures_before;
}

int main(void) {
    run();
    WF_TEST_SUMMARY();
}
