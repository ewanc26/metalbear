/*
 * test_blob_store.c — offline tests for the blob store and its XRPC server
 * integration (blob persistence + serving as a self-hosted PDS).
 *
 *   1. Unit: in-memory put/get/exists/not-found.
 *   2. File-backed: persistence across re-open of the same directory.
 *   3. Server round-trip: start an wf_xrpc_server with the blob-store routes,
 *      POST a raw blob to com.atproto.repo.uploadBlob, read back its CID, then
 *      GET com.atproto.sync.getBlob?did=...&cid=... and assert the bytes and
 *      Content-Type match what was uploaded.
 *
 * Requires WOLFRAM_BUILD_SERVER (raw HTTP helper + server registration).
 */

#include "metalbear/blob_store.h"
#include "wolfram/xrpc_server.h"
#include "wolfram/repo/cid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <strings.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cJSON.h>

/* ------------------------------------------------------------------ */
/* Minimal raw HTTP client (POSIX sockets)                              */
/* ------------------------------------------------------------------ */

/* One-shot HTTP request. On success returns 0; *out_body (free with free)
 * holds the raw response body, *out_len its length, *out_content_type
 * (free with free) the response Content-Type or NULL, *out_status the code. */
static int raw_http(const char *host, uint16_t port, const char *method,
                    const char *path, const unsigned char *body,
                    size_t body_len, const char *content_type,
                    unsigned char **out_body, size_t *out_len,
                    char **out_content_type, long *out_status) {
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
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    char req[1024];
    int rh = snprintf(req, sizeof(req),
                      "%s %s HTTP/1.1\r\nHost: %s:%u\r\n", method, path, host,
                      (unsigned)port);
    if (body && body_len > 0 && content_type) {
        rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                       "Content-Type: %s\r\n", content_type);
        rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                       "Content-Length: %zu\r\n", body_len);
    }
    rh += snprintf(req + rh, sizeof(req) - (size_t)rh,
                   "Connection: close\r\n\r\n");

    if (send(sock, req, (size_t)rh, 0) < 0) {
        close(sock);
        return -1;
    }
    if (body && body_len > 0) {
        if (send(sock, body, body_len, 0) < 0) {
            close(sock);
            return -1;
        }
    }

    /* Read the entire response (Connection: close => EOF terminates it). */
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

    /* Split headers from body. */
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

    /* Extract Content-Type (case-insensitive). */
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
/* 1. In-memory unit tests                                              */
/* ------------------------------------------------------------------ */

static int test_unit_memory(void) {
    metalbear_blob_store *store = metalbear_blob_store_new(NULL);
    if (!store) {
        fprintf(stderr, "FAIL: metalbear_blob_store_new(NULL)\n");
        return 1;
    }

    const unsigned char payload[] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a,
                                     0x0a, 0xde, 0xad, 0xbe, 0xef};
    const char *mime = "image/png";
    const char *cid = "bafytestcidmemory";

    if (metalbear_blob_store_put(store, cid, mime, payload, sizeof(payload)) != WF_OK) {
        fprintf(stderr, "FAIL: put (memory)\n");
        metalbear_blob_store_free(store);
        return 1;
    }

    if (metalbear_blob_store_exists(store, cid) != WF_OK) {
        fprintf(stderr, "FAIL: exists present\n");
        metalbear_blob_store_free(store);
        return 1;
    }
    if (metalbear_blob_store_exists(store, "absent") != WF_ERR_NOT_FOUND) {
        fprintf(stderr, "FAIL: exists absent should be NOT_FOUND\n");
        metalbear_blob_store_free(store);
        return 1;
    }

    char **cids = NULL;
    size_t cids_count = 0;
    if (metalbear_blob_store_list(store, &cids, &cids_count) != WF_OK ||
        cids_count != 1 || !cids || strcmp(cids[0], cid) != 0) {
        fprintf(stderr, "FAIL: list (memory) expected one matching CID\n");
        metalbear_blob_store_list_free(cids, cids_count);
        metalbear_blob_store_free(store);
        return 1;
    }
    metalbear_blob_store_list_free(cids, cids_count);

    unsigned char *data = NULL;
    size_t len = 0;
    char *got_mime = NULL;
    if (metalbear_blob_store_get(store, cid, &data, &len, &got_mime) != WF_OK) {
        fprintf(stderr, "FAIL: get (memory)\n");
        metalbear_blob_store_free(store);
        return 1;
    }
    int fail = 0;
    if (len != sizeof(payload) ||
        memcmp(data, payload, len) != 0) {
        fprintf(stderr, "FAIL: get bytes mismatch\n");
        fail = 1;
    }
    if (!got_mime || strcmp(got_mime, mime) != 0) {
        fprintf(stderr, "FAIL: get mime mismatch (%s)\n",
                got_mime ? got_mime : "NULL");
        fail = 1;
    }
    free(data);
    free(got_mime);

    if (metalbear_blob_store_get(store, "absent", &data, &len, &got_mime) !=
        WF_ERR_NOT_FOUND) {
        fprintf(stderr, "FAIL: get absent should be NOT_FOUND\n");
        fail = 1;
    }

    /* Overwrite with new bytes. */
    const unsigned char repl[] = {0x01, 0x02, 0x03};
    if (metalbear_blob_store_put(store, cid, "application/octet-stream", repl,
                          sizeof(repl)) != WF_OK) {
        fprintf(stderr, "FAIL: put overwrite\n");
        fail = 1;
    } else {
        unsigned char *d2 = NULL; size_t l2 = 0; char *m2 = NULL;
        if (metalbear_blob_store_get(store, cid, &d2, &l2, &m2) == WF_OK) {
            if (l2 != sizeof(repl) || memcmp(d2, repl, l2) != 0 ||
                strcmp(m2, "application/octet-stream") != 0) {
                fprintf(stderr, "FAIL: overwrite not applied\n");
                fail = 1;
            }
            free(d2); free(m2);
        }
    }

    if (metalbear_blob_store_delete(store, cid) != WF_OK) {
        fprintf(stderr, "FAIL: delete (memory)\n");
        fail = 1;
    }
    if (metalbear_blob_store_exists(store, cid) != WF_ERR_NOT_FOUND) {
        fprintf(stderr, "FAIL: deleted blob still exists (memory)\n");
        fail = 1;
    }
    data = NULL;
    len = 0;
    got_mime = NULL;
    if (metalbear_blob_store_get(store, cid, &data, &len, &got_mime) !=
        WF_ERR_NOT_FOUND) {
        fprintf(stderr, "FAIL: deleted blob still readable (memory)\n");
        free(data);
        free(got_mime);
        fail = 1;
    }
    cids = NULL;
    cids_count = 0;
    if (metalbear_blob_store_list(store, &cids, &cids_count) != WF_OK ||
        cids_count != 0 || cids != NULL) {
        fprintf(stderr, "FAIL: deleted blob still listed (memory)\n");
        metalbear_blob_store_list_free(cids, cids_count);
        fail = 1;
    }
    if (metalbear_blob_store_delete(store, cid) != WF_ERR_NOT_FOUND) {
        fprintf(stderr, "FAIL: repeated delete should be NOT_FOUND\n");
        fail = 1;
    }

    metalbear_blob_store_free(store);
    if (!fail) printf("PASS: in-memory unit\n");
    return fail;
}

static int test_delete_invalid_args(void) {
    metalbear_blob_store *store = metalbear_blob_store_new(NULL);
    if (!store) {
        fprintf(stderr, "FAIL: store (delete invalid args)\n");
        return 1;
    }
    int fail = 0;
    if (metalbear_blob_store_delete(NULL, "bafytest") != WF_ERR_INVALID_ARG ||
        metalbear_blob_store_delete(store, NULL) != WF_ERR_INVALID_ARG ||
        metalbear_blob_store_delete(store, "") != WF_ERR_INVALID_ARG ||
        metalbear_blob_store_delete(store, "../bafytest") != WF_ERR_INVALID_ARG) {
        fprintf(stderr, "FAIL: delete invalid args\n");
        fail = 1;
    }
    metalbear_blob_store_free(store);
    if (!fail) printf("PASS: delete invalid args\n");
    return fail;
}

/* ------------------------------------------------------------------ */
/* 2. File-backed persistence                                           */
/* ------------------------------------------------------------------ */

static int test_file_backed(void) {
    char tmpl[] = "/tmp/metalbear_blob_store.XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        fprintf(stderr, "FAIL: mkdtemp\n");
        return 1;
    }

    const unsigned char payload[] = {'h', 'e', 'l', 'l', 'o', ' ', 'b', 'l',
                                      'o', 'b'};
    const char *cid = "bafytestcidfilebacked";

    metalbear_blob_store *s1 = metalbear_blob_store_new(dir);
    if (!s1) { fprintf(stderr, "FAIL: new (file)\n"); return 1; }
    if (metalbear_blob_store_put(s1, cid, "text/plain", payload, sizeof(payload)) !=
        WF_OK) {
        fprintf(stderr, "FAIL: put (file)\n");
        metalbear_blob_store_free(s1);
        return 1;
    }
    metalbear_blob_store_free(s1);

    /* Re-open the same directory; the blob must be reloaded from disk. */
    metalbear_blob_store *s2 = metalbear_blob_store_new(dir);
    if (!s2) { fprintf(stderr, "FAIL: reopen (file)\n"); return 1; }
    int fail = 0;
    unsigned char *data = NULL; size_t len = 0; char *mime = NULL;
    if (metalbear_blob_store_get(s2, cid, &data, &len, &mime) != WF_OK) {
        fprintf(stderr, "FAIL: get after reopen\n");
        fail = 1;
    } else {
        if (len != sizeof(payload) || memcmp(data, payload, len) != 0 ||
            strcmp(mime, "text/plain") != 0) {
            fprintf(stderr, "FAIL: persisted content mismatch\n");
            fail = 1;
        }
        free(data); free(mime);
    }
    if (metalbear_blob_store_delete(s2, cid) != WF_OK ||
        metalbear_blob_store_exists(s2, cid) != WF_ERR_NOT_FOUND) {
        fprintf(stderr, "FAIL: delete (file)\n");
        fail = 1;
    }
    char **cids = NULL;
    size_t cids_count = 0;
    if (metalbear_blob_store_list(s2, &cids, &cids_count) != WF_OK ||
        cids_count != 0 || cids != NULL) {
        fprintf(stderr, "FAIL: deleted blob still listed (file)\n");
        metalbear_blob_store_list_free(cids, cids_count);
        fail = 1;
    }
    metalbear_blob_store_free(s2);

    metalbear_blob_store *s3 = metalbear_blob_store_new(dir);
    if (!s3) {
        fprintf(stderr, "FAIL: reopen after delete (file)\n");
        fail = 1;
    } else {
        data = NULL;
        len = 0;
        mime = NULL;
        if (metalbear_blob_store_get(s3, cid, &data, &len, &mime) !=
            WF_ERR_NOT_FOUND) {
            fprintf(stderr, "FAIL: deleted blob returned after reopen\n");
            free(data);
            free(mime);
            fail = 1;
        }
        metalbear_blob_store_free(s3);
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, cid);
    if (access(path, F_OK) == 0) {
        fprintf(stderr, "FAIL: deleted data file remains\n");
        remove(path);
        fail = 1;
    }
    snprintf(path, sizeof(path), "%s/%s.mime", dir, cid);
    if (access(path, F_OK) == 0) {
        fprintf(stderr, "FAIL: deleted MIME file remains\n");
        remove(path);
        fail = 1;
    }
    rmdir(dir);

    if (!fail) printf("PASS: file-backed persistence\n");
    return fail;
}

/* ------------------------------------------------------------------ */
/* 3. Server round-trip                                                 */
/* ------------------------------------------------------------------ */

static int test_server_roundtrip(void) {
    metalbear_blob_store *store = metalbear_blob_store_new(NULL);
    if (!store) { fprintf(stderr, "FAIL: store (server)\n"); return 1; }

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 1);
    if (!server) {
        fprintf(stderr, "FAIL: server start\n");
        metalbear_blob_store_free(store);
        return 1;
    }
    if (metalbear_xrpc_server_register_blob_store(server, store) != WF_OK) {
        fprintf(stderr, "FAIL: register blob store routes\n");
        wf_xrpc_server_free(server);
        metalbear_blob_store_free(store);
        return 1;
    }

    uint16_t port = wf_xrpc_server_port(server);
    const char *host = "127.0.0.1";

    const unsigned char payload[] = {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10,
                                     0x4a, 0x46, 0x49, 0x46, 0x00, 0x01};
    const char *mime = "image/jpeg";

    /* Upload via raw HTTP POST (body = bytes, Content-Type = image/jpeg). */
    char up_path[128];
    snprintf(up_path, sizeof(up_path), "/xrpc/com.atproto.repo.uploadBlob");
    unsigned char *up_body = NULL; size_t up_len = 0; char *up_ct = NULL;
    long up_status = 0;
    if (raw_http(host, port, "POST", up_path, payload, sizeof(payload), mime,
                 &up_body, &up_len, &up_ct, &up_status) != 0) {
        fprintf(stderr, "FAIL: upload request\n");
        wf_xrpc_server_free(server); metalbear_blob_store_free(store);
        return 1;
    }
    int fail = 0;
    if (up_status != 200) {
        fprintf(stderr, "FAIL: upload status=%ld\n", up_status);
        fail = 1;
    }

    char *cid = NULL;
    char *resp_mime = NULL;
    if (!fail) {
        cJSON *root = cJSON_ParseWithLength((const char *)up_body, up_len);
        if (!root) {
            fprintf(stderr, "FAIL: upload response parse\n");
            fail = 1;
        } else {
            cJSON *blob = cJSON_GetObjectItemCaseSensitive(root, "blob");
            cJSON *ref = blob ? cJSON_GetObjectItemCaseSensitive(blob, "ref")
                              : NULL;
            cJSON *link = ref ? cJSON_GetObjectItemCaseSensitive(ref, "$link")
                              : NULL;
            cJSON *mm = blob ? cJSON_GetObjectItemCaseSensitive(blob, "mimeType")
                             : NULL;
            if (!cJSON_IsString(link) || !link->valuestring ||
                !cJSON_IsString(mm)) {
                fprintf(stderr, "FAIL: upload response shape\n");
                fail = 1;
            } else {
                cid = strdup(link->valuestring);
                resp_mime = strdup(mm->valuestring);
            }
            cJSON_Delete(root);
        }
    }
    free(up_body); free(up_ct);

    if (!fail && cid) {
        /* Verify the CID matches MetalBear's own raw-codec computation. */
        wf_cid expect;
        char *expect_str = NULL;
        if (wf_cid_of_bytes(payload, sizeof(payload), &expect) == WF_OK &&
            (expect_str = wf_cid_to_string(&expect)) != NULL) {
            if (strcmp(cid, expect_str) != 0) {
                fprintf(stderr, "FAIL: cid mismatch (got %s want %s)\n", cid,
                        expect_str);
                fail = 1;
            }
            free(expect_str);
        }
        if (resp_mime && strcmp(resp_mime, mime) != 0) {
            fprintf(stderr, "FAIL: upload mime (got %s)\n", resp_mime);
            fail = 1;
        }
    }

    /* GET via raw HTTP (did is required by the lexicon but ignored here). */
    if (!fail && cid) {
        char get_path[512];
        snprintf(get_path, sizeof(get_path),
                 "/xrpc/com.atproto.sync.getBlob?did=did:example:alice&cid=%s",
                 cid);
        unsigned char *gb = NULL; size_t gl = 0; char *gct = NULL;
        long gstatus = 0;
        if (raw_http(host, port, "GET", get_path, NULL, 0, NULL, &gb, &gl,
                     &gct, &gstatus) != 0) {
            fprintf(stderr, "FAIL: get request\n");
            fail = 1;
        } else {
            if (gstatus != 200) {
                fprintf(stderr, "FAIL: get status=%ld\n", gstatus);
                fail = 1;
            } else if (gl != sizeof(payload) ||
                       memcmp(gb, payload, gl) != 0) {
                fprintf(stderr, "FAIL: get body mismatch\n");
                fail = 1;
            } else if (!gct || strcmp(gct, mime) != 0) {
                fprintf(stderr, "FAIL: get content-type (got %s want %s)\n",
                        gct ? gct : "NULL", mime);
                fail = 1;
            }
            free(gb); free(gct);
        }
    }

    free(cid); free(resp_mime);
    wf_xrpc_server_free(server);
    metalbear_blob_store_free(store);

    if (!fail) printf("PASS: server round-trip\n");
    return fail;
}

int main(void) {
    int failures = 0;
    failures += test_unit_memory();
    failures += test_delete_invalid_args();
    failures += test_file_backed();
    failures += test_server_roundtrip();
    if (failures == 0) printf("ALL PASS: blob_store\n");
    return failures;
}
