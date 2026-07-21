/*
 * test_pds_repo_resolver.c — offline tests for the per-request PDS
 * repo/blob resolver (multi-tenant server support).
 *
 * Registers a single wf_xrpc_server with a resolver that routes each
 * request to one of two distinct, in-process repo/blob stores keyed by a
 * DID. The DID is taken from the request (req->params `did`/`repo` for
 * JSON query/procedure calls, or req->authed_subject for raw blob
 * uploads that carry no body JSON — mirroring how a real PDS resolves
 * the authenticated account). Exercises:
 *
 *   - createRecord / getRecord / describeRepo route to the correct store
 *     for each DID, and a record created under one DID is invisible to
 *     the other (proving per-request store selection).
 *   - uploadBlob / getBlob route to the correct blob store per DID.
 *   - An unknown DID yields a 400 RepoNotFound from the repo handlers and
 *     a 400 AccountNotFound from the blob handlers.
 *
 * The single-store path (metalbear_xrpc_server_register_pds_repo /
 * wf_xrpc_server_register_blob_store) is covered by test_pds_repo.c /
 * test_blob_store.c and is left intact.
 *
 * Requires WOLFRAM_BUILD_SERVER.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/repo_store.h"
#include "metalbear/blob_store.h"
#include "wolfram/xrpc.h"
#include "wolfram/xrpc_server.h"
#include "wolfram/repo/cid.h"

#include "test.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* ------------------------------------------------------------------ */
/* Test accounts + resolver                                            */
/* ------------------------------------------------------------------ */

typedef struct acct {
    const char   *did;
    metalbear_repo_store *repo;
    metalbear_blob_store *blobs;
    char          path[256];   /* file-backed repo store path (temp) */
} acct_t;

typedef struct registry {
    acct_t *a;
    size_t  n;
} registry_t;

/* Pull the target DID out of a request: prefer `did` then `repo` in the
 * parsed params (query args or JSON body), then the authenticated subject
 * (set by the test auth middleware for raw blob uploads). */
static const char *did_from_req(const wf_xrpc_request *req) {
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        if (cJSON_IsString(d) && d->valuestring && *d->valuestring)
            return d->valuestring;
        cJSON *r = cJSON_GetObjectItemCaseSensitive(req->params, "repo");
        if (cJSON_IsString(r) && r->valuestring && *r->valuestring)
            return r->valuestring;
    }
    if (req->authed_subject && *req->authed_subject)
        return req->authed_subject;
    return NULL;
}

static wf_status resolver(void *ctx, const wf_xrpc_request *req,
                          metalbear_repo_store **out_repo,
                          metalbear_blob_store **out_blobs) {
    registry_t *reg = (registry_t *)ctx;
    const char *did = did_from_req(req);
    if (!did) return WF_ERR_NOT_FOUND;
    for (size_t i = 0; i < reg->n; i++) {
        if (strcmp(reg->a[i].did, did) == 0) {
            *out_repo = reg->a[i].repo;
            *out_blobs = reg->a[i].blobs;
            return WF_OK;
        }
    }
    return WF_ERR_NOT_FOUND;
}

static wf_status blob_resolver(void *ctx, const wf_xrpc_request *req,
                               metalbear_repo_store **out_repo,
                               metalbear_blob_store **out_blobs) {
    metalbear_repo_store *repo = NULL;
    wf_status status = resolver(ctx, req, &repo, out_blobs);
    *out_repo = (metalbear_repo_store *)repo;
    return status;
}


/*
 * Test auth middleware: derive the authenticated DID from a
 * "Bearer <did>" Authorization header and expose it on req->authed_subject
 * (server-owned). This is how a real PDS would know which account a raw
 * blob upload belongs to. It never rejects a request; the resolver enforces
 * account existence.
 */
static wf_status auth_cb(wf_xrpc_request *req, void *ctx) {
    (void)ctx;
    if (req->auth_header && strncmp(req->auth_header, "Bearer ", 7) == 0) {
        const char *d = req->auth_header + 7;
        size_t len = strlen(d);
        char *sub = (char *)malloc(len + 1);
        if (sub) {
            memcpy(sub, d, len);
            sub[len] = '\0';
            req->authed_subject = sub;
        }
    }
    return WF_OK;
}

/* ------------------------------------------------------------------ */
/* Minimal raw HTTP client (POSIX sockets) — mirrors test_blob_store.c */
/* ------------------------------------------------------------------ */

static int raw_http(const char *host, uint16_t port, const char *method,
                    const char *path, const unsigned char *body,
                    size_t body_len, const char *content_type,
                    const char *auth, unsigned char **out_body,
                    size_t *out_len, char **out_content_type,
                    long *out_status) {
    *out_body = NULL;
    *out_len = 0;
    *out_content_type = NULL;
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

    char req[2048];
    int rh = snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: %s:%u\r\n",
                      method, path, host, (unsigned)port);
    if (auth && *auth)
        rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                       "Authorization: %s\r\n", auth);
    if (body && body_len > 0 && content_type) {
        rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                       "Content-Type: %s\r\n", content_type);
        rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                       "Content-Length: %zu\r\n", body_len);
    }
    rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                   "Connection: close\r\n\r\n");

    if (send(sock, req, (size_t)rh, 0) < 0) { close(sock); return -1; }
    if (body && body_len > 0) {
        if (send(sock, body, body_len, 0) < 0) { close(sock); return -1; }
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

    size_t head_len = (size_t)(sep - (char *)buf);
    sscanf((const char *)buf, "HTTP/%*s %ld", out_status);

    const char *p = (const char *)buf;
    const char *end = (const char *)buf + head_len;
    while (p + 13 < end) {
        if (strncasecmp(p, "content-type:", 13) == 0) {
            const char *v = p + 13;
            while (*v == ' ' || *v == '\t') v++;
            const char *ve = v;
            while (ve < end && *ve != '\r' && *ve != '\n') ve++;
            size_t vl = (size_t)(ve - v);
            char *ct = (char *)malloc(vl + 1);
            if (ct) { memcpy(ct, v, vl); ct[vl] = '\0'; *out_content_type = ct; }
            break;
        }
        p++;
    }

    size_t blen = got - (size_t)(sep - (char *)buf);
    unsigned char *body_out = (unsigned char *)malloc(blen ? blen : 1);
    if (!body_out) { free(buf); free(*out_content_type); return -1; }
    memcpy(body_out, sep, blen);
    *out_body = body_out;
    *out_len = blen;
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void temp_path(char *buf, size_t n, const char *tag) {
    snprintf(buf, n, "/tmp/metalbear_repo_store_resolver_%s_XXXXXX", tag);
    int fd = mkstemp(buf);
    if (fd >= 0) close(fd);
    unlink(buf);
}

/* ------------------------------------------------------------------ */
/* Test body                                                            */
/* ------------------------------------------------------------------ */

static int run(void) {
    int failures = 0;

    acct_t accounts[2] = {
        { .did = "did:plc:alpha" },
        { .did = "did:plc:beta" },
    };
    registry_t reg = { accounts, 2 };

    for (size_t i = 0; i < reg.n; i++) {
        temp_path(accounts[i].path, sizeof(accounts[i].path),
                  (i == 0) ? "alpha" : "beta");
        wf_status s = metalbear_repo_store_open(accounts[i].path, accounts[i].did,
                                         (i == 0) ? "a.example.com"
                                                  : "b.example.com",
                                         &accounts[i].repo);
        WF_CHECK(s == WF_OK && accounts[i].repo != NULL);
        if (s != WF_OK) {
            for (size_t j = 0; j < i; j++) {
                metalbear_repo_store_free(accounts[j].repo);
                metalbear_blob_store_free(accounts[j].blobs);
                unlink(accounts[j].path);
            }
            return failures + 1;
        }
        accounts[i].blobs = metalbear_blob_store_new(NULL);
        WF_CHECK(accounts[i].blobs != NULL);
    }

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 1);
    WF_CHECK(server != NULL);
    if (!server) goto cleanup;
    wf_xrpc_server_set_auth_callback(server, auth_cb, NULL);
    WF_CHECK(metalbear_xrpc_server_register_pds_repo_resolver(
                 server, resolver, &reg) == WF_OK);
    WF_CHECK(metalbear_xrpc_server_register_blob_store_resolver(
                  server, blob_resolver, &reg) == WF_OK);

    uint16_t port = wf_xrpc_server_port(server);
    WF_CHECK(port != 0);
    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u", (unsigned)port);
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    WF_CHECK(client != NULL);

    /* ── createRecord routes to the correct store per DID ──────────── */
    char body[512];
    for (size_t i = 0; i < reg.n; i++) {
        snprintf(body, sizeof(body),
                 "{\"repo\":\"%s\",\"collection\":\"com.example.posts\","
                 "\"rkey\":\"sharedrkey\","
                 "\"record\":{\"$type\":\"com.example.posts\",\"text\":\"%s\"}}",
                 accounts[i].did, (i == 0) ? "alpha-text" : "beta-text");
        wf_response res = {0};
        wf_status s = wf_xrpc_procedure(client,
            "com.atproto.repo.createRecord", body, &res);
        WF_CHECK(s == WF_OK && res.status == 200);
        wf_response_free(&res);
    }

    /* ── getRecord on the owning DID returns the record ───────────── */
    for (size_t i = 0; i < reg.n; i++) {
        wf_xrpc_param params[] = {
            {"repo", (char *)accounts[i].did},
            {"collection", "com.example.posts"},
            {"rkey", "sharedrkey"},
        };
        wf_response res = {0};
        wf_status s = wf_xrpc_query_params(client,
            "com.atproto.repo.getRecord", params, 3, &res);
        WF_CHECK(s == WF_OK && res.status == 200);
        cJSON *root = cJSON_ParseWithLength(res.body, res.body_len);
        cJSON *val = root ? cJSON_GetObjectItemCaseSensitive(root, "value")
                          : NULL;
        cJSON *text = val ? cJSON_GetObjectItemCaseSensitive(val, "text")
                          : NULL;
        WF_CHECK(text && cJSON_IsString(text) &&
                 strcmp(text->valuestring,
                        (i == 0) ? "alpha-text" : "beta-text") == 0);
        cJSON_Delete(root);
        wf_response_free(&res);
    }

    /* ── a record created only in alpha is 404 on beta (isolation) ── */
    {
        snprintf(body, sizeof(body),
                 "{\"repo\":\"%s\",\"collection\":\"com.example.posts\","
                 "\"rkey\":\"alphaonly\","
                 "\"record\":{\"$type\":\"com.example.posts\",\"text\":\"x\"}}",
                 accounts[0].did);
        wf_response res = {0};
        wf_status s = wf_xrpc_procedure(client,
            "com.atproto.repo.createRecord", body, &res);
        WF_CHECK(s == WF_OK && res.status == 200);
        wf_response_free(&res);

        wf_xrpc_param params[] = {
            {"repo", (char *)"did:plc:beta"},
            {"collection", "com.example.posts"},
            {"rkey", "alphaonly"},
        };
        s = wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                                 params, 3, &res);
        /* Non-2xx yields WF_ERR_HTTP but still populates res.status. */
        WF_CHECK(res.status == 404);
        wf_response_free(&res);
    }

    /* ── describeRepo reports the per-DID did/handle ──────────────── */
    for (size_t i = 0; i < reg.n; i++) {
        wf_xrpc_param params[] = { {"did", (char *)accounts[i].did} };
        wf_response res = {0};
        wf_status s = wf_xrpc_query_params(client,
            "com.atproto.repo.describeRepo", params, 1, &res);
        WF_CHECK(s == WF_OK && res.status == 200);
        cJSON *root = cJSON_ParseWithLength(res.body, res.body_len);
        cJSON *did = root ? cJSON_GetObjectItemCaseSensitive(root, "did")
                          : NULL;
        WF_CHECK(did && cJSON_IsString(did) &&
                 strcmp(did->valuestring, accounts[i].did) == 0);
        cJSON_Delete(root);
        wf_response_free(&res);
    }

    /* ── unknown DID -> 400 RepoNotFound ──────────────────────────── */
    {
        wf_xrpc_param params[] = { {"did", (char *)"did:plc:unknown"} };
        wf_response res = {0};
        wf_xrpc_query_params(client, "com.atproto.repo.describeRepo",
                              params, 1, &res);
        WF_CHECK(res.status == 400);
        cJSON *root = cJSON_ParseWithLength(res.body, res.body_len);
        cJSON *err = root ? cJSON_GetObjectItemCaseSensitive(root, "error")
                          : NULL;
        WF_CHECK(err && cJSON_IsString(err) &&
                 strcmp(err->valuestring, "RepoNotFound") == 0);
        cJSON_Delete(root);
        wf_response_free(&res);
    }

    /* ── uploadBlob / getBlob route to the correct blob store ────── */
    const unsigned char payload[] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a};
    const char *mime = "image/png";
    char auth[64];
    snprintf(auth, sizeof(auth), "Bearer %s", accounts[0].did);
    unsigned char *up_body = NULL; size_t up_len = 0; char *up_ct = NULL;
    long up_status = 0;
    if (raw_http("127.0.0.1", port, "POST",
                 "/xrpc/com.atproto.repo.uploadBlob", payload,
                 sizeof(payload), mime, auth, &up_body, &up_len, &up_ct,
                 &up_status) != 0) {
        WF_CHECK(0);
    } else {
        WF_CHECK(up_status == 200);
        char *cid = NULL;
        if (up_status == 200) {
            cJSON *root = cJSON_ParseWithLength((const char *)up_body, up_len);
            cJSON *blob = root ? cJSON_GetObjectItemCaseSensitive(root, "blob")
                               : NULL;
            cJSON *ref = blob ? cJSON_GetObjectItemCaseSensitive(blob, "ref")
                              : NULL;
            cJSON *link = ref ? cJSON_GetObjectItemCaseSensitive(ref, "$link")
                              : NULL;
            WF_CHECK(link && cJSON_IsString(link) && link->valuestring);
            if (link && cJSON_IsString(link))
                cid = strdup(link->valuestring);
            cJSON_Delete(root);
        }
        free(up_body); free(up_ct);

        if (cid) {
            /* getBlob on the owning DID returns the bytes. */
            char gb_path[256];
            snprintf(gb_path, sizeof(gb_path),
                     "/xrpc/com.atproto.sync.getBlob?cid=%s", cid);
            unsigned char *gb_body = NULL; size_t gb_len = 0;
            char *gb_ct = NULL; long gb_status = 0;
            if (raw_http("127.0.0.1", port, "GET", gb_path, NULL, 0, NULL,
                         auth, &gb_body, &gb_len, &gb_ct, &gb_status) == 0) {
                WF_CHECK(gb_status == 200);
                WF_CHECK(gb_len == sizeof(payload) &&
                         memcmp(gb_body, payload, gb_len) == 0);
                WF_CHECK(gb_ct && strcmp(gb_ct, mime) == 0);
                free(gb_body); free(gb_ct);
            } else {
                WF_CHECK(0);
            }

            /* getBlob on the OTHER DID 404s (blob store isolation). */
            char auth2[64];
            snprintf(auth2, sizeof(auth2), "Bearer %s", accounts[1].did);
            unsigned char *gb2 = NULL; size_t gb2_len = 0;
            char *gb2_ct = NULL; long gb2_status = 0;
            if (raw_http("127.0.0.1", port, "GET", gb_path, NULL, 0, NULL,
                         auth2, &gb2, &gb2_len, &gb2_ct, &gb2_status) == 0) {
                WF_CHECK(gb2_status == 404);
                free(gb2); free(gb2_ct);
            } else {
                WF_CHECK(0);
            }
            free(cid);
        }
    }

    wf_xrpc_client_free(client);
    wf_xrpc_server_free(server);

cleanup:
    for (size_t i = 0; i < reg.n; i++) {
        if (accounts[i].repo) metalbear_repo_store_free(accounts[i].repo);
        if (accounts[i].blobs) metalbear_blob_store_free(accounts[i].blobs);
        unlink(accounts[i].path);
    }
    return failures;
}

int main(void) {
    run();
    WF_TEST_SUMMARY();
}
