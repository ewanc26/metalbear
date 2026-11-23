#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_proxy_refusal.c — an `atproto-proxy` destination allowlist is not an
 * open relay (issue #251). This drives real XRPC calls at a running PDS with
 * proxy headers naming an unknown DID, a known DID with an unknown service id,
 * and the configured AppView, and asserts the first two are refused with a
 * counted 403 while the third is forwarded. Separately, Wolfram's
 * wf_xrpc_set_handler seam proves the client actually emits the header and
 * surfaces a refusal response to its caller.
 */

#include "metalbear/ops/metrics.h"
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

/* A mock AppView that counts requests and captures the latest upstream header
 * block, so an allowed destination can be seen to reach it. */
typedef struct {
    int listen_fd;
    pthread_t thread;
    pthread_mutex_t mutex;
    int count;
    char captured[8192];
} mock_upstream;

static void *mock_upstream_run(void *arg) {
    mock_upstream *mock = arg;
    for (;;) {
        int fd = accept(mock->listen_fd, NULL, NULL);
        if (fd < 0) break;
        char buf[8192];
        size_t total = 0;
        for (;;) {
            ssize_t n = read(fd, buf + total, sizeof(buf) - total - 1);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            total += (size_t)n;
            buf[total] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
            if (total >= sizeof(buf) - 1) break;
        }
        pthread_mutex_lock(&mock->mutex);
        mock->count++;
        memcpy(mock->captured, buf, total + 1);
        pthread_mutex_unlock(&mock->mutex);
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
    pthread_mutex_init(&mock->mutex, NULL);
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

static void mock_upstream_stop(mock_upstream *mock) {
    close(mock->listen_fd);
    pthread_join(mock->thread, NULL);
    pthread_mutex_destroy(&mock->mutex);
}

/* wf_xrpc_set_handler seam: capture the outgoing atproto-proxy header and
 * answer with a canned 403, then prove the client returns WF_ERR_HTTP with the
 * status and body intact. */
typedef struct {
    const char *expected;
    int saw_header;
    int called;
} seam_ctx;

static wf_status refusal_seam(void *userdata, const char *method,
                              const char *url, const char *content_type,
                              const char *body, size_t body_len,
                              const wf_http_header *headers,
                              size_t header_count, wf_response *out) {
    (void)method;
    (void)url;
    (void)content_type;
    (void)body;
    (void)body_len;
    seam_ctx *ctx = userdata;
    ctx->called++;
    for (size_t i = 0; i < header_count; i++) {
        if (strcmp(headers[i].name, "atproto-proxy") == 0 && headers[i].value &&
            strcmp(headers[i].value, ctx->expected) == 0)
            ctx->saw_header = 1;
    }
    static const char refusal[] =
        "{\"error\":\"Forbidden\",\"message\":\"atproto-proxy destination is "
        "not allowed\"}";
    out->status = 403;
    out->body = strdup(refusal);
    out->body_len = strlen(refusal);
    /* The real transport maps a non-2xx HTTP status to WF_ERR_HTTP while
     * still handing the body to the caller; the seam must do the same to
     * model a refusal faithfully. */
    return WF_ERR_HTTP;
}

int main(void) {
    char directory[] = "/tmp/metalbear-proxy-refusal-test-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);

    mock_upstream mock;
    uint16_t mock_port = 0;
    CHECK(mock_upstream_start(&mock, &mock_port));

    char appview_url[80];
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
        .mod_service_did = "did:web:ozone.example.com",
        .proxy_destinations = "did:web:labeler.example.com#atproto_labeler, "
                              "did:web:custom.example.com",
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
            wf_response create_response = {0};
            CHECK(wf_xrpc_procedure(
                      client, "com.atproto.server.createAccount",
                      "{\"handle\":\"alice.example.com\","
                      "\"password\":\"correct horse battery staple\","
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
            wf_xrpc_client_set_auth(client, access_token);

            uint64_t before =
                metalbear_metrics_get(METALBEAR_METRIC_PROXY_REFUSALS);

            /* An unknown DID is refused before any upstream request. */
            CHECK(wf_xrpc_client_set_proxy(
                      client, "did:web:evil.example.com#bsky_chat") == WF_OK);
            wf_response unknown = {0};
            wf_status st = wf_xrpc_query(client, "chat.bsky.convo.listConvos",
                                         NULL, &unknown);
            CHECK(st == WF_ERR_HTTP);
            CHECK(unknown.status == 403);
            CHECK(unknown.body && strstr(unknown.body, "not allowed") != NULL);
            wf_response_free(&unknown);

            /* A known DID with a service id that is not one of the protocol's
             * known types is refused too. */
            CHECK(wf_xrpc_client_set_proxy(
                      client, "did:web:api.bsky.chat#not_a_real_service") ==
                  WF_OK);
            wf_response bad_service = {0};
            st = wf_xrpc_query(client, "chat.bsky.convo.listConvos", NULL,
                               &bad_service);
            CHECK(st == WF_ERR_HTTP);
            CHECK(bad_service.status == 403);
            wf_response_free(&bad_service);

            /* A bare DID with no `#service` must be refused cleanly too: it
             * is a real client shape, and the service-id alias lookup used
             * on the allowlist path must not dereference a NULL id. */
            CHECK(wf_xrpc_client_set_proxy(
                      client, "did:web:labeler.example.com") == WF_OK);
            wf_response bare_did = {0};
            st = wf_xrpc_query(client, "chat.bsky.convo.listConvos", NULL,
                               &bare_did);
            CHECK(st == WF_ERR_HTTP);
            CHECK(bare_did.status == 403);
            wf_response_free(&bare_did);

            uint64_t after =
                metalbear_metrics_get(METALBEAR_METRIC_PROXY_REFUSALS);
            CHECK(after - before == 3);

            /* The configured AppView DID is on the allowlist: its header maps
             * to appview_url without a did:web lookup and reaches the mock. */
            pthread_mutex_lock(&mock.mutex);
            int count_before = mock.count;
            pthread_mutex_unlock(&mock.mutex);
            CHECK(wf_xrpc_client_set_proxy(
                      client, "did:web:appview.example.com#bsky_appview") ==
                  WF_OK);
            wf_response allowed = {0};
            st = wf_xrpc_query(client, "app.bsky.feed.getFeedGenerators", NULL,
                               &allowed);
            CHECK(st == WF_OK);
            CHECK(allowed.status == 200);
            wf_response_free(&allowed);
            pthread_mutex_lock(&mock.mutex);
            CHECK(mock.count == count_before + 1);
            CHECK(strstr(mock.captured, "GET /xrpc/") != NULL);
            pthread_mutex_unlock(&mock.mutex);

            /* The client-side seam proves the header reaches the wire and a
             * refusal is surfaced intact to the caller. */
            const char *proxy = "did:web:evil.example.com#bsky_chat";
            CHECK(wf_xrpc_client_set_proxy(client, proxy) == WF_OK);
            seam_ctx seam = {.expected = proxy};
            wf_xrpc_set_handler(client, refusal_seam, &seam);
            wf_response seam_response = {0};
            st = wf_xrpc_query(client, "chat.bsky.convo.listConvos", NULL,
                               &seam_response);
            CHECK(st == WF_ERR_HTTP);
            CHECK(seam_response.status == 403);
            CHECK(seam_response.body &&
                  strstr(seam_response.body, "not allowed") != NULL);
            CHECK(seam.called == 1);
            CHECK(seam.saw_header == 1);
            wf_response_free(&seam_response);
            wf_xrpc_set_handler(client, NULL, NULL);

            free(access_token);
            wf_xrpc_client_free(client);
        }

        metalbear_server_free(server);
    }

    mock_upstream_stop(&mock);
    rmtree(directory);
    if (failures) fprintf(stderr, "%d test(s) failed\n", failures);
    return failures ? 1 : 0;
}
