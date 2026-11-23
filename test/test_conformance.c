/*
 * test_conformance.c -- issue #161: a small self-check that walks the core
 * AT Protocol flows against a running PDS and reports one line per check.
 *
 * With no argument it starts a local MetalBear on a loopback port (the ctest
 * path). With a base URL argument it checks that live instance instead, so the
 * same checks can be pointed at the dev beta or a self-hosted deployment.
 *
 * This is a client of the protocol surface only: it asserts response shapes
 * and round-trips, not MetalBear internals, and makes no server-side change.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "metalbear/server.h"
#include "wolfram/sync_subscribe.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ftw.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int rmtree_remove_cb(const char *path, const struct stat *sb, int type,
                            struct FTW *ftwbuf) {
    (void)sb;
    (void)type;
    (void)ftwbuf;
    return remove(path);
}
static void rmtree(const char *path) {
    nftw(path, rmtree_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

static int checks_run;
static int checks_failed;

static void report(const char *name, bool ok, const char *detail) {
    checks_run++;
    if (ok) {
        printf("  PASS  %s\n", name);
    } else {
        checks_failed++;
        printf("  FAIL  %s%s%s\n", name, detail ? ": " : "",
               detail ? detail : "");
    }
}

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

static bool write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        cursor += written;
        length -= (size_t)written;
    }
    return true;
}

static bool read_exact(int fd, void *data, size_t length) {
    unsigned char *cursor = data;
    while (length > 0) {
        struct pollfd poll_fd = {fd, POLLIN, 0};
        if (poll(&poll_fd, 1, 5000) <= 0) return false;
        ssize_t received = read(fd, cursor, length);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return false;
        cursor += received;
        length -= (size_t)received;
    }
    return true;
}

/* Minimal WebSocket upgrade + one frame read, mirroring the repo's firehose
 * tests. Returns true when at least one firehose frame decodes. */
static bool read_firehose_frame(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (fd < 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return false;
    }
    char request[512];
    int length = snprintf(
        request, sizeof(request),
        "GET /xrpc/com.atproto.sync.subscribeRepos?cursor=0 HTTP/1.1\r\n"
        "Host: 127.0.0.1:%u\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        (unsigned)port);
    if (!write_all(fd, request, (size_t)length)) {
        close(fd);
        return false;
    }
    char header[2048] = {0};
    size_t used = 0;
    while (used + 1 < sizeof(header) && !strstr(header, "\r\n\r\n")) {
        if (!read_exact(fd, header + used, 1)) break;
        used++;
        header[used] = '\0';
    }
    if (!strstr(header, " 101 ") && strncmp(header, "HTTP/1.1 101", 12) != 0) {
        close(fd);
        return false;
    }

    bool decoded = false;
    for (int attempt = 0; attempt < 64 && !decoded; attempt++) {
        unsigned char frame[10];
        if (!read_exact(fd, frame, 2) || (frame[0] & 0x0f) != 0x2 ||
            (frame[1] & 0x80))
            break;
        uint64_t len = frame[1] & 0x7f;
        if (len == 126) {
            if (!read_exact(fd, frame + 2, 2)) break;
            len = ((uint64_t)frame[2] << 8) | frame[3];
        } else if (len == 127) {
            if (!read_exact(fd, frame + 2, 8)) break;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | frame[2 + i];
        }
        if (len > 16 * 1024 * 1024) break;
        unsigned char *payload = malloc(len ? (size_t)len : 1);
        if (!payload || !read_exact(fd, payload, (size_t)len)) {
            free(payload);
            break;
        }
        wf_subscribe_event event;
        memset(&event, 0, sizeof(event));
        if (wf_subscribe_decode_frame(payload, (size_t)len, &event) == WF_OK) {
            decoded = true;
            wf_subscribe_event_free(&event);
        }
        free(payload);
    }
    close(fd);
    return decoded;
}

int main(int argc, char **argv) {
    printf("MetalBear conformance self-check\n");
    printf("=================================\n\n");

    char directory[] = "/tmp/metalbear-conformance-XXXXXX";
    metalbear_server *server = NULL;
    const char *base = (argc > 1 && argv[1][0]) ? argv[1] : NULL;
    char base_buf[128];

    if (!base) {
        if (!mkdtemp(directory)) {
            fprintf(stderr, "could not make temp dir\n");
            return 2;
        }
        metalbear_config config = {
            .listen_address = "127.0.0.1",
            .port = 0,
            .thread_count = 2,
            .data_directory = directory,
            .service_did = "did:web:pds.example.com",
            .user_domain = ".example.com",
            .invite_required = false,
            .rate_limit = 10000,
        };
        server = metalbear_server_start(&config);
        if (!server) {
            fprintf(stderr, "could not start local MetalBear\n");
            rmtree(directory);
            return 2;
        }
        snprintf(base_buf, sizeof(base_buf), "http://127.0.0.1:%u",
                 (unsigned)metalbear_server_port(server));
        base = base_buf;
    }
    printf("Target: %s\n\n", base);

    wf_xrpc_client *client = wf_xrpc_client_new(base);
    wf_response response = {0};

    /* describeServer */
    {
        wf_status st = wf_xrpc_query(
            client, "com.atproto.server.describeServer", NULL, &response);
        bool ok = st == WF_OK && response.status == 200;
        if (ok) {
            cJSON *json = json_response(&response);
            ok =
                json &&
                cJSON_IsString(cJSON_GetObjectItemCaseSensitive(json, "did")) &&
                cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(
                    json, "availableUserDomains"));
            cJSON_Delete(json);
        }
        report("describeServer", ok, "unexpected response");
        wf_response_free(&response);
    }

    /* createAccount (setup for the authenticated checks) */
    char *token = NULL, *did = NULL;
    {
        wf_status st =
            wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                              "{\"handle\":\"conform.example.com\","
                              "\"password\":\"correct horse battery staple\","
                              "\"email\":\"conform@example.com\"}",
                              &response);
        bool ok = st == WF_OK && response.status == 200;
        if (ok) {
            cJSON *json = json_response(&response);
            cJSON *access =
                json ? cJSON_GetObjectItemCaseSensitive(json, "accessJwt")
                     : NULL;
            cJSON *did_item =
                json ? cJSON_GetObjectItemCaseSensitive(json, "did") : NULL;
            if (cJSON_IsString(access)) token = strdup(access->valuestring);
            if (cJSON_IsString(did_item)) did = strdup(did_item->valuestring);
            ok = token && did;
            cJSON_Delete(json);
        }
        report("createAccount", ok, "signup must return session and DID");
        wf_response_free(&response);
    }

    if (!token || !did) {
        printf("\nCannot run authenticated checks without an account.\n");
    } else {
        wf_xrpc_client_set_auth(client, token);

        /* createSession */
        {
            char body[512];
            snprintf(body, sizeof(body),
                     "{\"identifier\":\"conform.example.com\","
                     "\"password\":\"correct horse battery staple\"}");
            wf_status st = wf_xrpc_procedure(
                client, "com.atproto.server.createSession", body, &response);
            bool ok = st == WF_OK && response.status == 200;
            if (ok) {
                cJSON *json = json_response(&response);
                ok = json && cJSON_IsString(cJSON_GetObjectItemCaseSensitive(
                                 json, "accessJwt"));
                cJSON_Delete(json);
            }
            report("createSession", ok, "session token missing");
            wf_response_free(&response);
        }

        /* repo write/read round-trip */
        {
            char body[1024];
            snprintf(body, sizeof(body),
                     "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
                     "\"rkey\":\"conformance\","
                     "\"record\":{\"$type\":\"app.bsky.feed.post\","
                     "\"text\":\"conformance round-trip\","
                     "\"createdAt\":\"2026-11-22T00:00:00.000Z\"}}",
                     did);
            wf_status st = wf_xrpc_procedure(
                client, "com.atproto.repo.createRecord", body, &response);
            bool wrote = st == WF_OK && response.status == 200;
            cJSON *created = wrote ? json_response(&response) : NULL;
            cJSON *uri = created
                             ? cJSON_GetObjectItemCaseSensitive(created, "uri")
                             : NULL;
            bool ok = wrote && cJSON_IsString(uri);
            cJSON_Delete(created);
            wf_response_free(&response);

            if (ok) {
                wf_xrpc_param params[] = {{"repo", did},
                                          {"collection", "app.bsky.feed.post"},
                                          {"rkey", "conformance"}};
                st = wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                                          params, 3, &response);
                bool got = st == WF_OK && response.status == 200;
                cJSON *json = got ? json_response(&response) : NULL;
                cJSON *value =
                    json ? cJSON_GetObjectItemCaseSensitive(json, "value")
                         : NULL;
                cJSON *text =
                    value ? cJSON_GetObjectItemCaseSensitive(value, "text")
                          : NULL;
                ok = got && cJSON_IsString(text) &&
                     strcmp(text->valuestring, "conformance round-trip") == 0;
                cJSON_Delete(json);
                wf_response_free(&response);
            }
            report("repo write/read round-trip", ok, "getRecord mismatch");
        }

        /* blob upload/get */
        {
            const unsigned char payload[] = {0xff, 0xd8, 0xff, 0xe0, 0x00,
                                             0x10, 0x4a, 0x46, 0x49};
            wf_status st = wf_xrpc_upload_blob(
                client, "com.atproto.repo.uploadBlob", payload, sizeof(payload),
                "image/jpeg", &response);
            bool uploaded = st == WF_OK && response.status == 200;
            char *cid = NULL;
            if (uploaded) {
                cJSON *json = json_response(&response);
                cJSON *blob =
                    json ? cJSON_GetObjectItemCaseSensitive(json, "blob")
                         : NULL;
                cJSON *ref =
                    blob ? cJSON_GetObjectItemCaseSensitive(blob, "ref") : NULL;
                cJSON *link =
                    ref ? cJSON_GetObjectItemCaseSensitive(ref, "$link") : NULL;
                if (cJSON_IsString(link)) cid = strdup(link->valuestring);
                cJSON_Delete(json);
            }
            wf_response_free(&response);

            bool ok = cid != NULL;
            char url[512], get_path[512];
            snprintf(get_path, sizeof(get_path),
                     "/xrpc/com.atproto.sync.getBlob?did=%s&cid=%s", did,
                     cid ? cid : "");
            snprintf(url, sizeof(url), "%s%s", base, get_path);
            if (ok) {
                /* A freshly uploaded blob is temporary: not yet downloadable
                 * and not distributed until a record references it. */
                st = wf_http_get(client, url, &response);
                /* wf_http_get reports non-2xx as WF_ERR_HTTP; the 404 is the
                 * expected "temporary blobs are not downloadable" answer. */
                ok = st == WF_ERR_HTTP && response.status == 404;
                wf_response_free(&response);
            }
            if (ok) {
                /* Reference the blob from a record, which promotes it to
                 * durable and makes it publicly downloadable. */
                char body[1024];
                snprintf(
                    body, sizeof(body),
                    "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
                    "\"rkey\":\"blob-ref\",\"record\":{"
                    "\"$type\":\"app.bsky.feed.post\","
                    "\"text\":\"blob ref conformance\","
                    "\"embed\":{\"$type\":\"app.bsky.embed.images\","
                    "\"images\":[{\"alt\":\"a\",\"image\":{"
                    "\"$type\":\"blob\",\"ref\":{\"$link\":\"%s\"},"
                    "\"mimeType\":\"image/jpeg\",\"size\":%zu}}]},"
                    "\"createdAt\":\"2026-11-22T00:00:00.000Z\"}}",
                    did, cid, sizeof(payload));
                st = wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                       body, &response);
                ok = st == WF_OK && response.status == 200;
                wf_response_free(&response);
            }
            if (ok) {
                st = wf_http_get(client, url, &response);
                ok = st == WF_OK && response.status == 200 &&
                     response.body_len == sizeof(payload) &&
                     memcmp(response.body, payload, sizeof(payload)) == 0;
                wf_response_free(&response);
            }
            report("blob upload/get", ok, "CID or bytes mismatch");
            free(cid);
        }

        /* sync.getLatestCommit */
        {
            wf_xrpc_param params[] = {{"did", did}};
            wf_status st =
                wf_xrpc_query_params(client, "com.atproto.sync.getLatestCommit",
                                     params, 1, &response);
            bool ok = st == WF_OK && response.status == 200;
            if (ok) {
                cJSON *json = json_response(&response);
                ok = json &&
                     cJSON_IsString(
                         cJSON_GetObjectItemCaseSensitive(json, "cid")) &&
                     cJSON_IsString(
                         cJSON_GetObjectItemCaseSensitive(json, "rev"));
                cJSON_Delete(json);
            }
            report("sync.getLatestCommit", ok, "missing cid/rev");
            wf_response_free(&response);
        }

        /* identity.resolveHandle */
        {
            wf_xrpc_param params[] = {{"handle", "conform.example.com"}};
            wf_status st = wf_xrpc_query_params(
                client, "com.atproto.identity.resolveHandle", params, 1,
                &response);
            bool ok = st == WF_OK && response.status == 200;
            if (ok) {
                cJSON *json = json_response(&response);
                cJSON *resolved =
                    json ? cJSON_GetObjectItemCaseSensitive(json, "did") : NULL;
                ok = cJSON_IsString(resolved) &&
                     strcmp(resolved->valuestring, did) == 0;
                cJSON_Delete(json);
            }
            report("identity.resolveHandle", ok, "DID mismatch");
            wf_response_free(&response);
        }

        /* subscribeRepos frame (loopback only: derived from the base URL) */
        {
            uint16_t port = 0;
            const char *host_start = strstr(base, "://");
            host_start = host_start ? host_start + 3 : base;
            const char *colon = strrchr(host_start, ':');
            if (colon && colon > host_start) port = (uint16_t)atoi(colon + 1);
            if (port == 0)
                report("subscribeRepos frame", false,
                       "no loopback port to connect to");
            else
                report("subscribeRepos frame", read_firehose_frame(port),
                       "no decodable frame");
        }
    }

    printf("\n%d/%d checks passed\n", checks_run - checks_failed, checks_run);
    free(token);
    free(did);
    wf_xrpc_client_free(client);
    if (server) metalbear_server_free(server);
    if (directory[0]) rmtree(directory);
    return checks_failed ? 1 : 0;
}
