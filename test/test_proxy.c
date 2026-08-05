#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_proxy.c — proves the AppView-proxied request paths (proxy_appview
 * and its generic sibling proxy_fallback, both in server.c) actually put
 * X-Forwarded-For on the outgoing upstream request.
 *
 * The reference PDS's forwardedFor() (packages/pds/src/api/proxy.ts) sets
 * x-forwarded-for on every proxied/pipethrough request so the AppView sees
 * the original client's address rather than the PDS's own. Wolfram's
 * wf_xrpc_request already exposed the resolved client IP
 * (wf_server_client_ip / req->client_ip); this test exercises both
 * MetalBear call sites that mint an upstream request (the well-known
 * app.bsky.* handlers routed through proxy_appview, and the catch-all
 * proxy_fallback for anything else) against a tiny local mock AppView and
 * checks the header actually arrives — not just that the code compiles.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <arpa/inet.h>
#include <cJSON.h>
#include <errno.h>
#include <ftw.h>
#include <netinet/in.h>
#include <pthread.h>
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

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

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

/* A mock AppView: accepts up to MOCK_UPSTREAM_REQUESTS connections in turn,
 * capturing each request's raw header block (up to the first blank line) so
 * the test can grep it for X-Forwarded-For, then answers 200 with a small
 * JSON body and closes. */
#define MOCK_UPSTREAM_REQUESTS 2
#define MOCK_CAPTURE_SIZE 4096

typedef struct {
    int listen_fd;
    pthread_t thread;
    char captured[MOCK_UPSTREAM_REQUESTS][MOCK_CAPTURE_SIZE];
} mock_upstream;

static void *mock_upstream_run(void *arg) {
    mock_upstream *mock = arg;
    for (int i = 0; i < MOCK_UPSTREAM_REQUESTS; i++) {
        int fd = accept(mock->listen_fd, NULL, NULL);
        if (fd < 0) break;
        char *buf = mock->captured[i];
        size_t total = 0;
        for (;;) {
            ssize_t n = read(fd, buf + total, MOCK_CAPTURE_SIZE - total - 1);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            total += (size_t)n;
            buf[total] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
            if (total >= MOCK_CAPTURE_SIZE - 1) break;
        }
        static const char response[] = "HTTP/1.1 200 OK\r\n"
                                       "Content-Type: application/json\r\n"
                                       "Content-Length: 2\r\n"
                                       "Connection: close\r\n"
                                       "\r\n"
                                       "{}";
        write_all(fd, response, sizeof(response) - 1);
        close(fd);
    }
    return NULL;
}

static int mock_upstream_start(mock_upstream *mock, uint16_t *port_out) {
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
    if (listen(mock->listen_fd, 4) != 0) {
        close(mock->listen_fd);
        return 0;
    }
    if (pthread_create(&mock->thread, NULL, mock_upstream_run, mock) != 0) {
        close(mock->listen_fd);
        return 0;
    }
    return 1;
}

static void mock_upstream_join(mock_upstream *mock) {
    pthread_join(mock->thread, NULL);
    close(mock->listen_fd);
}

int main(void) {
    char directory[] = "/tmp/metalbear-proxy-test-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);

    mock_upstream mock;
    uint16_t mock_port = 0;
    CHECK(mock_upstream_start(&mock, &mock_port));

    char appview_url[64];
    snprintf(appview_url, sizeof(appview_url), "http://127.0.0.1:%u",
             (unsigned)mock_port);

    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .admin_password = "secret-admin",
        .invite_required = false,
        .rate_limit = 10000,
        .appview_url = appview_url,
        .appview_did = "did:web:appview.example.com",
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);

    if (server) {
        char base[80];
        snprintf(base, sizeof(base), "http://127.0.0.1:%u",
                 (unsigned)metalbear_server_port(server));
        wf_xrpc_client *client = wf_xrpc_client_new(base);
        CHECK(client != NULL);

        if (client) {
            /*
             * app.bsky.* proxy routes require an authenticated session even
             * for the "public" (no-service-auth-to-upstream) endpoints —
             * the auth middleware runs before the handler either way, per
             * appview_proxy's own comment ("Auth runs first, so handlers
             * see req->authed_subject"). Create an account to get one.
             */
            wf_response create_response = {0};
            CHECK(wf_xrpc_procedure(
                      client, "com.atproto.server.createAccount",
                      "{\"handle\":\"alice.example.com\","
                      "\"password\":\"correct horse battery staple\","
                      "\"did\":\"did:plc:metalbearproxytest\","
                      "\"email\":\"alice@example.com\"}",
                      &create_response) == WF_OK);
            CHECK(create_response.status == 200);
            cJSON *create_json = cJSON_ParseWithLength(
                create_response.body ? create_response.body : "",
                create_response.body_len);
            cJSON *access =
                create_json
                    ? cJSON_GetObjectItemCaseSensitive(create_json, "accessJwt")
                    : NULL;
            char *access_token =
                cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
            cJSON_Delete(create_json);
            wf_response_free(&create_response);
            CHECK(access_token != NULL);

            /* A registered app.bsky.* NSID routes through appview_public ->
             * proxy_appview. send_auth is false, so no service-auth JWT is
             * minted for the upstream call, but the inbound request still
             * needs a valid session. */
            wf_response feed_response = {0};
            wf_xrpc_client_set_auth(client, access_token);
            CHECK(wf_xrpc_query(client, "app.bsky.feed.getFeedGenerators", NULL,
                                &feed_response) == WF_OK);
            CHECK(feed_response.status == 200);
            wf_response_free(&feed_response);

            /* An NSID nothing registers falls through to the generic
             * proxy_fallback; drive it anonymously since that path runs
             * before auth. */
            wf_response fallback_response = {0};
            wf_xrpc_client_set_auth(client, NULL);
            CHECK(wf_xrpc_query(client, "app.test.metalbearProxyProbe", NULL,
                                &fallback_response) == WF_OK);
            CHECK(fallback_response.status == 200);
            wf_response_free(&fallback_response);

            free(access_token);
            wf_xrpc_client_free(client);
        }

        metalbear_server_free(server);
    }

    mock_upstream_join(&mock);

    CHECK(strstr(mock.captured[0], "X-Forwarded-For: 127.0.0.1") != NULL);
    CHECK(strstr(mock.captured[1], "X-Forwarded-For: 127.0.0.1") != NULL);

    rmtree(directory);
    if (failures) fprintf(stderr, "%d test(s) failed\n", failures);
    return failures ? 1 : 0;
}
