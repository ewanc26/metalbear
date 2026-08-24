#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <errno.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Recursively remove a directory tree (used for test cleanup). */
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

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

/* Extract a Prometheus gauge value following `name ` in the /metrics body. */
static long long metric_value(const wf_response *response, const char *name) {
    if (!response || !response->body || !name) return -1;
    size_t nlen = strlen(name);
    const char *p = response->body;
    size_t len = response->body_len;
    for (size_t i = 0; i + nlen + 1 < len; i++) {
        if (memcmp(p + i, name, nlen) == 0 && p[i + nlen] == ' ' &&
            p[i + nlen + 1] >= '0' && p[i + nlen + 1] <= '9') {
            const char *v = p + i + nlen + 1;
            char *end = NULL;
            long long val = strtoll(v, &end, 10);
            if (end && *end == '\n') return val;
            return val;
        }
    }
    return -1;
}

int main(void) {
    /* Enforce a tiny resident budget so the cache must evict under load.
     * The server honours this env var at startup (overriding the default of
     * unbounded). */
    setenv("METALBEAR_MAX_RESIDENT_ACCOUNTS", "2", 1);

    char directory[] = "/tmp/metalbear-cache-test-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);

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
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) return 1;

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);
    wf_response response = {0};

    const char *handles[] = {"alice.example.com", "bob.example.com",
                             "carol.example.com", "dave.example.com",
                             "erin.example.com"};
    const char *passwords[] = {"alicepass", "bobpass", "carolpass", "davepass",
                               "erinpass"};
    const char *emails[] = {"alice@x.com", "bob@x.com", "carol@x.com",
                            "dave@x.com", "erin@x.com"};

    char access_token[512];
    for (int i = 0; i < 5; i++) {
        char body[256];
        snprintf(body, sizeof(body),
                 "{\"handle\":\"%s\",\"password\":\"%s\",\"email\":\"%s\"}",
                 handles[i], passwords[i], emails[i]);
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                                body, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *j = json_response(&response);
        cJSON *tok = cJSON_GetObjectItemCaseSensitive(j, "accessJwt");
        CHECK(cJSON_IsString(tok));
        snprintf(access_token, sizeof(access_token), "%s", tok->valuestring);
        cJSON_Delete(j);
        wf_response_free(&response);

        /* Authenticate and hit getSession: this resolves the account context
         * through the cache (cache_get + request observer release), so each
         * iteration opens one distinct account under the resident budget. */
        wf_xrpc_client_set_auth(client, access_token);
        CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }

    /* Read the admin-gated Prometheus exposition and confirm the cache stayed
     * bounded. Evictions happen synchronously inside cache_get on a miss while
     * the resident set already meets the budget, so by the time the fifth
     * getSession returned, three accounts (5 - budget 2) must have been
     * evicted. Use a fresh client: the request client above carries a bearer
     * token from set_auth, which would otherwise override this Basic header. */
    wf_xrpc_client *mclient = wf_xrpc_client_new(base);
    CHECK(mclient != NULL);
    char cred[64];
    int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
    char b64[128];
    int blen =
        EVP_EncodeBlock((unsigned char *)b64, (const unsigned char *)cred, n);
    b64[blen] = '\0';
    char auth[160];
    snprintf(auth, sizeof(auth), "Basic %s", b64);
    wf_http_header hdr = {"Authorization", auth};
    char metrics_url[96];
    snprintf(metrics_url, sizeof(metrics_url), "%s/metrics", base);
    CHECK(wf_http_get_with_headers(mclient, metrics_url, &hdr, 1, &response) ==
          WF_OK);
    CHECK(response.status == 200);

    long long resident =
        metric_value(&response, "metalbear_account_cache_resident");
    long long idle = metric_value(&response, "metalbear_account_cache_idle");
    long long evictions =
        metric_value(&response, "metalbear_account_cache_evictions_total");

    wf_response_free(&response);

    CHECK(resident >= 0);
    CHECK(idle >= 0);
    CHECK(evictions >= 0);
    /* Eviction fired under the budget: 5 distinct accounts, budget 2. */
    CHECK(evictions >= 3);
    /* Bounding holds: at most the budget plus one in-flight request. */
    CHECK(resident <= 3);
    CHECK(idle <= 2);

    metalbear_server_free(server);
    wf_xrpc_client_free(client);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("account cache bounded-eviction test OK\n");
    return 0;
}
