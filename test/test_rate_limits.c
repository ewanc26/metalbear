#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
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
                            const char *password, char **out_did) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\","
             "\"email\":\"%s@example.com\"}",
             handle, password, handle);
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
    if (out_did) {
        cJSON *did =
            json ? cJSON_GetObjectItemCaseSensitive(json, "did") : NULL;
        *out_did = cJSON_IsString(did) ? strdup(did->valuestring) : NULL;
    }
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* createAccount's route-specific budget is 100/300s, IP-keyed. An invalid
 * body (no handle/password/etc.) reaches the handler and gets a 400 — the
 * rate limiter runs before that, so it is charged all the same. The token
 * bucket refills 0.33/s, so on a slow runner the budget takes a few extra
 * requests to bottom out; loop until the limiter actually rejects rather
 * than assuming the exact 100-request count exhausts it. */
static int run_create_account_limit(wf_xrpc_client *client) {
    int failures_before = failures;
    wf_response response = {0};
    bool reached_handler = false;
    wf_status s = WF_OK;
    int attempts = 0;

    for (; attempts < 400; attempts++) {
        wf_response_free(&response);
        s = wf_xrpc_procedure(client, "com.atproto.server.createAccount", "{}",
                              &response);
        if (s == WF_ERR_HTTP && response.status == 429) break;
        if (s != WF_OK && s != WF_ERR_HTTP) {
            fprintf(stderr,
                    "FAIL createAccount attempt %d: transport error %d\n",
                    attempts, (int)s);
            failures++;
        }
        if (s == WF_ERR_HTTP && response.status == 400) reached_handler = true;
    }
    CHECK(s == WF_ERR_HTTP && response.status == 429);
    CHECK(reached_handler);
    cJSON *body = cJSON_ParseWithLength(response.body ? response.body : "",
                                        response.body_len);
    cJSON *err = body ? cJSON_GetObjectItemCaseSensitive(body, "error") : NULL;
    CHECK(cJSON_IsString(err) &&
          strcmp(err->valuestring, "RateLimitExceeded") == 0);
    cJSON_Delete(body);
    wf_response_free(&response);

    return failures == failures_before ? 0 : 1;
}

/* passkey authenticate/verify's route-specific budget is 30/300s, IP-keyed
 * -- unlike createAccount/createSession this is a plain HTTP route
 * (registered via wf_xrpc_server_register_http_route, not an XRPC
 * procedure), so it's driven with wf_http_post directly rather than
 * wf_xrpc_procedure. `{}` is a well-formed JSON object missing the
 * required "id" field, so it reaches the handler's own 400 before the
 * limiter would ever need real credential data to fire. */
static int run_passkey_authenticate_limit(wf_xrpc_client *client,
                                          const char *base) {
    int failures_before = failures;
    wf_response response = {0};
    bool reached_handler = false;
    wf_status s = WF_OK;
    int attempts = 0;
    char url[256];
    snprintf(url, sizeof(url), "%s/oauth/passkey/authenticate/verify", base);

    for (; attempts < 400; attempts++) {
        wf_response_free(&response);
        s = wf_http_post(client, url, "application/json", "{}", NULL, 0,
                         &response);
        if (s == WF_ERR_HTTP && response.status == 429) break;
        if (s != WF_OK && s != WF_ERR_HTTP) {
            fprintf(stderr,
                    "FAIL passkey authenticate attempt %d: transport error "
                    "%d\n",
                    attempts, (int)s);
            failures++;
        }
        if (s == WF_ERR_HTTP && response.status == 400) reached_handler = true;
    }
    CHECK(s == WF_ERR_HTTP && response.status == 429);
    CHECK(reached_handler);
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

static wf_status bearer_post_body(wf_xrpc_client *client, const char *base,
                                  const char *nsid, const char *access_jwt,
                                  const char *body, wf_response *out) {
    char auth[512];
    snprintf(auth, sizeof(auth), "Bearer %s", access_jwt);
    wf_http_header hdr = {"Authorization", auth};
    char url[256];
    snprintf(url, sizeof(url), "%s/xrpc/%s", base, nsid);
    return wf_http_post(client, url, "application/json", body, &hdr, 1, out);
}

/* updateHandle.ts's tighter tier is 10/5min, keyed by the caller's own DID.
 * Re-assigning your own current handle is a harmless no-op the handler
 * accepts every time (the "already in use" check only rejects a handle a
 * *different* DID owns), so the same request can be repeated to exhaust the
 * budget without needing a fresh handle per attempt. */
static int run_update_handle_limit(wf_xrpc_client *client, const char *base,
                                   const char *access_jwt) {
    int failures_before = failures;
    wf_response response = {0};
    int last_status = 0;

    for (int i = 0; i < 10; i++) {
        wf_response_free(&response);
        wf_status s = bearer_post_body(
            client, base, "com.atproto.identity.updateHandle", access_jwt,
            "{\"handle\":\"quota.example.com\"}", &response);
        last_status = (int)response.status;
        if (s != WF_OK) {
            fprintf(stderr,
                    "FAIL updateHandle attempt %d: transport error %d\n", i,
                    (int)s);
            failures++;
        }
    }
    CHECK(last_status == 200); /* the 10th still reached the handler */

    wf_response_free(&response);
    wf_status s = bearer_post_body(
        client, base, "com.atproto.identity.updateHandle", access_jwt,
        "{\"handle\":\"quota.example.com\"}", &response);
    CHECK(s == WF_ERR_HTTP && response.status == 429);
    wf_response_free(&response);

    return failures == failures_before ? 0 : 1;
}

/*
 * repo-write-hour/-day (rate-limits.ts) is a shared bucket across
 * createRecord/putRecord/deleteRecord/applyWrites, weighted 3/2/1 points,
 * with a 5000/35000 budget too large to practically exhaust in a unit test
 * (unlike the small per-route budgets above). This instead proves the new
 * check does not spuriously reject a normal write on any of the four routes
 * it now gates -- a regression test for the wiring, not the ceiling. Full
 * point-weighting is covered by direct code inspection of
 * repo_write_rate_limit_cost/apply_writes_rate_limit_cost in server.c.
 */
static int run_repo_write_smoke(wf_xrpc_client *client, const char *base,
                                const char *access_jwt,
                                const char *account_did) {
    int failures_before = failures;
    wf_response response = {0};
    char body[512];

    snprintf(
        body, sizeof(body),
        "{\"repo\":\"%s\",\"collection\":\"com.example.posts\","
        "\"rkey\":\"rl-smoke\",\"record\":{\"$type\":\"com.example.posts\","
        "\"text\":\"hi\"}}",
        account_did);
    wf_status s =
        bearer_post_body(client, base, "com.atproto.repo.createRecord",
                         access_jwt, body, &response);
    CHECK(s == WF_OK && response.status == 200);
    wf_response_free(&response);

    snprintf(
        body, sizeof(body),
        "{\"repo\":\"%s\",\"collection\":\"com.example.posts\","
        "\"rkey\":\"rl-smoke\",\"record\":{\"$type\":\"com.example.posts\","
        "\"text\":\"hi again\"}}",
        account_did);
    s = bearer_post_body(client, base, "com.atproto.repo.putRecord", access_jwt,
                         body, &response);
    CHECK(s == WF_OK && response.status == 200);
    wf_response_free(&response);

    snprintf(
        body, sizeof(body),
        "{\"repo\":\"%s\",\"writes\":[{\"$type\":\"com.atproto."
        "repo.applyWrites#create\",\"collection\":\"com.example.posts\","
        "\"rkey\":\"rl-smoke-2\",\"value\":{\"$type\":\"com.example.posts\","
        "\"text\":\"batch\"}}]}",
        account_did);
    s = bearer_post_body(client, base, "com.atproto.repo.applyWrites",
                         access_jwt, body, &response);
    CHECK(s == WF_OK && response.status == 200);
    wf_response_free(&response);

    snprintf(body, sizeof(body),
             "{\"repo\":\"%s\",\"collection\":\"com.example.posts\","
             "\"rkey\":\"rl-smoke\"}",
             account_did);
    s = bearer_post_body(client, base, "com.atproto.repo.deleteRecord",
                         access_jwt, body, &response);
    CHECK(s == WF_OK && response.status == 200);
    wf_response_free(&response);

    return failures == failures_before ? 0 : 1;
}

/* getRepo.ts's 6000/5min IP-keyed budget is likewise too large to exhaust
 * here -- smoke test only, same rationale as run_repo_write_smoke. */
static int run_get_repo_smoke(wf_xrpc_client *client, const char *account_did) {
    int failures_before = failures;
    wf_xrpc_param params[] = {{"did", account_did}};
    wf_response response = {0};
    wf_status s = wf_xrpc_query_params(client, "com.atproto.sync.getRepo",
                                       params, 1, &response);
    CHECK(s == WF_OK && response.status == 200);
    wf_response_free(&response);
    return failures == failures_before ? 0 : 1;
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
        char *account_did = NULL;
        char *access_jwt = create_account(client, "quota.example.com",
                                          "quotasecret", &account_did);
        CHECK(access_jwt != NULL);
        CHECK(account_did != NULL);
        if (access_jwt && account_did) {
            if (run_request_account_delete_limit(client, base, access_jwt) !=
                0) {
                fprintf(stderr,
                        "requestAccountDelete rate limit test failed\n");
            } else {
                printf("PASS: requestAccountDelete rate limit (5/hour, "
                       "DID-keyed)\n");
            }

            if (run_repo_write_smoke(client, base, access_jwt, account_did) !=
                0) {
                fprintf(stderr, "repo-write rate limit smoke test failed\n");
            } else {
                printf("PASS: repo-write rate limit smoke test "
                       "(createRecord/putRecord/applyWrites/deleteRecord "
                       "still succeed)\n");
            }

            if (run_get_repo_smoke(client, account_did) != 0) {
                fprintf(stderr, "getRepo rate limit smoke test failed\n");
            } else {
                printf("PASS: getRepo rate limit smoke test (still "
                       "succeeds)\n");
            }

            if (run_update_handle_limit(client, base, access_jwt) != 0) {
                fprintf(stderr, "updateHandle rate limit test failed\n");
            } else {
                printf("PASS: updateHandle rate limit (10/5min, "
                       "DID-keyed)\n");
            }

            free(access_jwt);
            free(account_did);
        }

        if (run_create_session_limit(client) != 0) {
            fprintf(stderr, "createSession rate limit test failed\n");
        } else {
            printf("PASS: createSession rate limit (30/300s, "
                   "identifier+IP-keyed)\n");
        }

        if (run_create_account_limit(client) != 0) {
            fprintf(stderr, "createAccount rate limit test failed\n");
        } else {
            printf("PASS: createAccount rate limit (100/300s, IP-keyed)\n");
        }

        if (run_passkey_authenticate_limit(client, base) != 0) {
            fprintf(stderr, "passkey authenticate rate limit test failed\n");
        } else {
            printf("PASS: passkey authenticate rate limit (30/300s, "
                   "IP-keyed)\n");
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
