#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_rate_limits.c — the endpoint-specific rate limits server.c wires up
 * to mirror the reference PDS actually reject requests, not just compile.
 *
 * Wolfram's own wf_xrpc_server_set_route_rate_limiter was, until recently,
 * silently dead code: it stored an entry nothing ever read back, so calling
 * it changed nothing about which requests got limited. That bug would have
 * hidden a matching bug here just as easily — a route-specific limiter that
 * never fires looks identical to one that was never wired up at all. So
 * this drives real HTTP requests against a real server and checks for a
 * real 429, for one representative endpoint per key pattern:
 *
 *   - createAccount:      single-tier, IP-keyed (the framework's automatic
 *                          per-route wiring)
 *   - createSession:      two-tier, keyed by identifier+IP — also checks
 *                          that a different identifier from the same IP is
 *                          not caught by another identifier's exhausted
 *                          bucket
 *   - requestAccountDelete: two-tier, keyed by the caller's own DID
 *
 * All three are driven with intentionally-invalid bodies/credentials so the
 * check fires (or the handler 400s) without needing real signing-key
 * generation for every attempt — the rate limiter runs before the handler
 * decides anything, so an invalid request is charged identically to a
 * valid one.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *did, const char *password) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\",\"did\":\"%s\","
             "\"email\":\"%s@example.com\"}",
             handle, password, did, handle);
    wf_response response = {0};
    if (wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                          &response) != WF_OK ||
        response.status != 200) {
        wf_response_free(&response);
        return NULL;
    }
    cJSON *json = cJSON_ParseWithLength(response.body ? response.body : "",
                                        response.body_len);
    cJSON *access =
        json ? cJSON_GetObjectItemCaseSensitive(json, "accessJwt") : NULL;
    char *token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* createAccount's route-specific budget is 100/300s, IP-keyed — shared with
 * whatever real account creations this same test process already made.
 * `already_spent` is how many of those 100 tokens are already gone by the
 * time this runs, so it must run last, after every real createAccount call
 * this test needs. An invalid body (no handle/password/etc.) reaches the
 * handler and gets a 400 — the rate limiter runs before that, so it is
 * charged all the same. */
static int run_create_account_limit(wf_xrpc_client *client, int already_spent) {
    int failures_before = failures;
    wf_response response = {0};
    int last_status = 0;
    int remaining = 100 - already_spent;

    for (int i = 0; i < remaining; i++) {
        wf_response_free(&response);
        wf_status s = wf_xrpc_procedure(
            client, "com.atproto.server.createAccount", "{}", &response);
        last_status = (int)response.status;
        if (s != WF_OK && s != WF_ERR_HTTP) {
            fprintf(stderr,
                    "FAIL createAccount attempt %d: transport error %d\n", i,
                    (int)s);
            failures++;
        }
    }
    CHECK(last_status == 400); /* the last one still reached the handler */

    wf_response_free(&response);
    wf_status s = wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                                    "{}", &response);
    CHECK(s == WF_ERR_HTTP && response.status == 429);
    cJSON *body = cJSON_ParseWithLength(response.body ? response.body : "",
                                        response.body_len);
    cJSON *err = body ? cJSON_GetObjectItemCaseSensitive(body, "error") : NULL;
    CHECK(cJSON_IsString(err) &&
          strcmp(err->valuestring, "RateLimitExceeded") == 0);
    cJSON_Delete(body);
    wf_response_free(&response);

    return failures == failures_before ? 0 : 1;
}

/* createSession's tighter tier is 30/300s, keyed by "<identifier>-<ip>".
 * Wrong-password attempts for one identifier must not affect a different
 * identifier from the same (loopback) IP. */
static int run_create_session_limit(wf_xrpc_client *client) {
    int failures_before = failures;
    wf_response response = {0};

    for (int i = 0; i < 30; i++) {
        wf_response_free(&response);
        wf_status s = wf_xrpc_procedure(
            client, "com.atproto.server.createSession",
            "{\"identifier\":\"quota-user\",\"password\":\"wrong\"}",
            &response);
        if (s != WF_ERR_HTTP || response.status != 401) {
            fprintf(stderr,
                    "FAIL createSession attempt %d: expected 401 (bad "
                    "credentials, not yet limited), got s=%d status=%ld\n",
                    i, (int)s, response.status);
            failures++;
        }
    }

    wf_response_free(&response);
    wf_status s = wf_xrpc_procedure(
        client, "com.atproto.server.createSession",
        "{\"identifier\":\"quota-user\",\"password\":\"wrong\"}", &response);
    CHECK(s == WF_ERR_HTTP && response.status == 429);
    wf_response_free(&response);

    /* A different identifier, same IP: its own bucket is untouched. */
    s = wf_xrpc_procedure(
        client, "com.atproto.server.createSession",
        "{\"identifier\":\"someone-else\",\"password\":\"wrong\"}", &response);
    CHECK(s == WF_ERR_HTTP && response.status == 401);
    wf_response_free(&response);

    return failures == failures_before ? 0 : 1;
}

/* requestAccountDelete's tighter tier is 5/hour, keyed by the caller's own
 * DID. Needs one real authenticated account (not per-attempt — the same
 * session is reused for every call). */
static wf_status bearer_post(wf_xrpc_client *client, const char *base,
                             const char *nsid, const char *access_jwt,
                             wf_response *out) {
    char auth[512];
    snprintf(auth, sizeof(auth), "Bearer %s", access_jwt);
    wf_http_header hdr = {"Authorization", auth};
    char url[256];
    snprintf(url, sizeof(url), "%s/xrpc/%s", base, nsid);
    return wf_http_post(client, url, "application/json", "{}", &hdr, 1, out);
}

static int run_request_account_delete_limit(wf_xrpc_client *client,
                                            const char *base,
                                            const char *access_jwt) {
    int failures_before = failures;
    wf_response response = {0};
    int last_status = 0;

    for (int i = 0; i < 5; i++) {
        wf_response_free(&response);
        wf_status s =
            bearer_post(client, base, "com.atproto.server.requestAccountDelete",
                        access_jwt, &response);
        last_status = (int)response.status;
        if (s != WF_OK) {
            fprintf(
                stderr,
                "FAIL requestAccountDelete attempt %d: transport error %d\n", i,
                (int)s);
            failures++;
        }
    }
    CHECK(last_status == 200); /* the 5th still reached the handler */

    wf_response_free(&response);
    wf_status s =
        bearer_post(client, base, "com.atproto.server.requestAccountDelete",
                    access_jwt, &response);
    CHECK(s == WF_ERR_HTTP && response.status == 429);
    wf_response_free(&response);

    return failures == failures_before ? 0 : 1;
}

int main(void) {
    char directory[] = "/tmp/metalbear-ratelimit-XXXXXX";
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
        /* Generous global budget: these tests exist to prove the
         * *endpoint-specific* limiters (which ignore this setting
         * entirely), not to be starved by the general one. */
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

    if (client) {
        /* Real account creation first — the createAccount exhaustion test
         * below burns through that route's entire per-IP budget for the
         * rest of this process's life (the window is 300s, longer than this
         * test runs), so nothing else can call it afterward. */
        char *access_jwt = create_account(client, "quota.example.com",
                                          "did:plc:quotatest", "quotasecret");
        CHECK(access_jwt != NULL);
        if (access_jwt) {
            if (run_request_account_delete_limit(client, base, access_jwt) !=
                0) {
                fprintf(stderr,
                        "requestAccountDelete rate limit test failed\n");
            } else {
                printf("PASS: requestAccountDelete rate limit (5/hour, "
                       "DID-keyed)\n");
            }
            free(access_jwt);
        }

        if (run_create_session_limit(client) != 0) {
            fprintf(stderr, "createSession rate limit test failed\n");
        } else {
            printf("PASS: createSession rate limit (30/300s, "
                   "identifier+IP-keyed)\n");
        }

        if (run_create_account_limit(client, 1) != 0) {
            fprintf(stderr, "createAccount rate limit test failed\n");
        } else {
            printf("PASS: createAccount rate limit (100/300s, IP-keyed)\n");
        }

        wf_xrpc_client_free(client);
    }

    metalbear_server_free(server);
    rmtree(directory);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_rate_limits: OK\n");
    return 0;
}
