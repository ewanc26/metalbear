#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_appview_route_classification.c — every registered app.bsky.* /
 * chat.bsky.* AppView-proxy route must forward the caller's identity as a
 * minted service-auth Authorization header when (and only when) it's
 * classified "private" in appview_routes.c, and every one of them must
 * actually proxy at all.
 *
 * test_proxy.c already proves the shared plumbing (appview_proxy /
 * proxy_appview) forwards X-Forwarded-For and, for one sample public route
 * plus the generic fallback, gets the Authorization behaviour right. It
 * does not check that each of the ~30 individually-registered routes was
 * wired to the *correct* classification. Each appview_get_* handler is a
 * one-line dispatch to either appview_public or appview_private (see
 * appview_routes.c) -- the actual risk is a route being wired to the wrong
 * one, e.g. a user-specific endpoint like getTimeline silently proxying
 * anonymously. app.bsky.notification.getUnreadCount did exactly the
 * adjacent wrong thing: instead of a misrouted proxy call it skipped
 * proxying entirely and returned a hardcoded {"count":0}, which is a
 * fabricated success no test caught. This test walks the full route table
 * (kept in sync with server.c's registrations and appview_routes.c's
 * classifications by hand -- there's no single source of truth to derive it
 * from) and asserts each one both reaches the mock AppView and carries -- or
 * doesn't carry -- auth as documented.
 *
 * Each route is sent and awaited one at a time (the client blocks until the
 * response comes back), and MetalBear's proxy call is itself synchronous: a
 * handler thread only returns to the client after the upstream request
 * completes. So a connection landing at the mock is guaranteed to have
 * finished (accepted, read, answered, closed) by the time the corresponding
 * client call returns -- no polling or timing race needed to correlate a
 * captured connection with the route that caused it. What does need care is
 * a route that DOESN'T proxy at all: nothing then arrives at the mock for
 * that slot, and if the mock's accept loop still insists on exactly one
 * connection per route, it hangs on that slot forever rather than failing.
 * The mock instead tracks a running count of connections actually accepted;
 * the main thread reads it before and after each route to learn whether
 * that specific route caused a connection, without assuming position.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <arpa/inet.h>
#include <cJSON.h>
#include <errno.h>
#include <ftw.h>
#include <netinet/in.h>
#include <poll.h>
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

/* Route table: every NSID server.c registers against an appview_get_*
 * handler, whether it's a procedure (vs. query), and whether
 * appview_routes.c's dispatcher sends it through appview_private (auth
 * forwarded) or appview_public (no auth forwarded). Cross-checked against
 * both files by hand when this test was written; a route added to one
 * without a matching entry here won't be caught automatically, but every
 * entry here pins real, currently-shipping behaviour. */
typedef struct {
    const char *nsid;
    int is_procedure;
    int expect_private;
} route_case;

static const route_case ROUTES[] = {
    {"app.bsky.feed.getFeed", 0, 0},
    {"app.bsky.feed.getFeedSkeleton", 0, 0},
    {"app.bsky.feed.getAuthorFeed", 0, 0},
    {"app.bsky.feed.getActorFeeds", 0, 0},
    {"app.bsky.feed.getFeedGenerators", 0, 0},
    {"app.bsky.feed.getFeedGenerator", 0, 0},
    {"app.bsky.feed.getPosts", 0, 0},
    {"app.bsky.actor.getProfile", 0, 0},
    {"app.bsky.actor.getProfiles", 0, 0},
    {"app.bsky.feed.getActorLikes", 0, 1},
    {"app.bsky.feed.getTimeline", 0, 1},
    {"app.bsky.feed.getPostThread", 0, 0},
    {"app.bsky.notification.registerPush", 1, 1},
    {"app.bsky.notification.unregisterPush", 1, 1},
    {"app.bsky.actor.getActorStatistics", 0, 0},
    {"app.bsky.actor.getActorRankings", 0, 0},
    {"app.bsky.graph.getFollows", 0, 0},
    {"app.bsky.graph.getFollowers", 0, 0},
    {"app.bsky.graph.getBlocks", 0, 1},
    {"app.bsky.graph.getList", 0, 0},
    {"app.bsky.graph.getLists", 0, 0},
    {"app.bsky.graph.getListItems", 0, 0},
    {"app.bsky.graph.getStarterPack", 0, 0},
    {"app.bsky.graph.getStarterPacks", 0, 0},
    {"app.bsky.notification.getUnreadCount", 0, 1},
    {"app.bsky.notification.listNotifications", 0, 1},
    {"chat.bsky.convo.getConvo", 0, 1},
    {"chat.bsky.convo.getConvos", 0, 1},
    {"chat.bsky.convo.getMessages", 0, 1},
    {"app.bsky.labeler.getServices", 0, 0},
    {"app.bsky.unspecced.getAgeAssuranceState", 0, 0},
    {"app.bsky.unspecced.getAgeAssuranceConfig", 0, 0},
    {"app.bsky.unspecced.getAgeAssurance", 0, 0},
};
#define ROUTE_COUNT (sizeof(ROUTES) / sizeof(ROUTES[0]))

typedef struct {
    int listen_fd;
    pthread_t thread;
    pthread_mutex_t mutex;
    volatile int stop;
    int count; /* connections accepted so far, protected by mutex */
    char captured[ROUTE_COUNT][2048];
} mock_upstream;

static void *mock_upstream_run(void *arg) {
    mock_upstream *mock = arg;
    for (;;) {
        struct pollfd pfd = {.fd = mock->listen_fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) {
            if (mock->stop) break;
            continue;
        }
        int fd = accept(mock->listen_fd, NULL, NULL);
        if (fd < 0) continue;

        pthread_mutex_lock(&mock->mutex);
        int slot = mock->count;
        pthread_mutex_unlock(&mock->mutex);
        if (slot >= (int)ROUTE_COUNT) {
            close(fd);
            continue;
        }

        char *buf = mock->captured[slot];
        size_t total = 0;
        for (;;) {
            ssize_t n =
                read(fd, buf + total, sizeof(mock->captured[slot]) - total - 1);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            total += (size_t)n;
            buf[total] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
            if (total >= sizeof(mock->captured[slot]) - 1) break;
        }
        static const char response[] = "HTTP/1.1 200 OK\r\n"
                                       "Content-Type: application/json\r\n"
                                       "Content-Length: 2\r\n"
                                       "Connection: close\r\n"
                                       "\r\n"
                                       "{}";
        write_all(fd, response, sizeof(response) - 1);
        close(fd);

        pthread_mutex_lock(&mock->mutex);
        mock->count++;
        pthread_mutex_unlock(&mock->mutex);
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
    if (listen(mock->listen_fd, (int)ROUTE_COUNT) != 0) {
        close(mock->listen_fd);
        return 0;
    }
    if (pthread_create(&mock->thread, NULL, mock_upstream_run, mock) != 0) {
        close(mock->listen_fd);
        return 0;
    }
    return 1;
}

static int mock_upstream_count(mock_upstream *mock) {
    pthread_mutex_lock(&mock->mutex);
    int c = mock->count;
    pthread_mutex_unlock(&mock->mutex);
    return c;
}

static void mock_upstream_stop_and_join(mock_upstream *mock) {
    mock->stop = 1;
    pthread_join(mock->thread, NULL);
    close(mock->listen_fd);
    pthread_mutex_destroy(&mock->mutex);
}

int main(void) {
    char directory[] = "/tmp/metalbear-appview-class-test-XXXXXX";
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

            for (size_t i = 0; i < ROUTE_COUNT; i++) {
                const route_case *rc = &ROUTES[i];
                int before = mock_upstream_count(&mock);

                wf_response resp = {0};
                wf_status st =
                    rc->is_procedure
                        ? wf_xrpc_procedure(client, rc->nsid, "{}", &resp)
                        : wf_xrpc_query(client, rc->nsid, NULL, &resp);
                CHECK(st == WF_OK);
                CHECK(resp.status == 200);
                wf_response_free(&resp);

                int after = mock_upstream_count(&mock);
                if (after <= before) {
                    failures++;
                    fprintf(stderr,
                            "FAIL %s:%d: %s never reached the mock AppView "
                            "at all -- it answered without proxying\n",
                            __FILE__, __LINE__, rc->nsid);
                    continue;
                }

                int has_auth = strstr(mock.captured[before],
                                      "Authorization: Bearer ") != NULL;
                if (rc->expect_private) {
                    CHECK(has_auth);
                    if (!has_auth)
                        fprintf(stderr,
                                "  %s: expected service-auth forwarded, got "
                                "none\n",
                                rc->nsid);
                } else {
                    CHECK(!has_auth);
                    if (has_auth)
                        fprintf(stderr,
                                "  %s: expected NO auth forwarded (public "
                                "route), but one was sent -- this leaks the "
                                "requester's identity to a public AppView "
                                "call\n",
                                rc->nsid);
                }
            }

            free(access_token);
            wf_xrpc_client_free(client);
        }

        metalbear_server_free(server);
    }

    mock_upstream_stop_and_join(&mock);
    rmtree(directory);
    if (failures) fprintf(stderr, "%d test(s) failed\n", failures);
    return failures ? 1 : 0;
}
