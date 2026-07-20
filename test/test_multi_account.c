#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_multi_account.c — offline end-to-end coverage for MetalBear's
 * multi-tenant, per-request account routing:
 *
 *   (a) two accounts created via com.atproto.server.createAccount,
 *   (b) a record written as account A is NOT visible under account B
 *       (per-account repository isolation through the repo resolver),
 *   (c) auth routing by the access token's JWT `sub` claim selects the
 *       writer's own repository even when a foreign `repo` DID is supplied,
 *   (d) the dynamic landing page enumerates every hosted account's handle
 *       and DID.
 *
 * Cleanup removes the entire data directory (every per-account SQLite file —
 * repo/auth/account/sequencer/oauth/keys — the shared account registry, and
 * all blob directories).
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Recursively remove a directory tree (used for test cleanup). */
static int rmtree_remove_cb(const char *path, const struct stat *sb,
                            int type, struct FTW *ftwbuf) {
    (void)sb; (void)type; (void)ftwbuf;
    return remove(path);
}
static void rmtree(const char *path) {
    nftw(path, rmtree_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

static int failures;
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    failures++; } } while (0)

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

/* Case-sensitive substring search over a length-delimited body. */
static bool body_contains(const wf_response *response, const char *needle) {
    if (!response || !response->body || !needle) return false;
    size_t nlen = strlen(needle);
    if (nlen == 0) return true;
    if (response->body_len < nlen) return false;
    for (size_t i = 0; i + nlen <= response->body_len; i++) {
        if (memcmp(response->body + i, needle, nlen) == 0) return true;
    }
    return false;
}

/* Create an account and return its access token (caller frees). */
static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *did, const char *password) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\",\"did\":\"%s\"}",
             handle, password, did);
    wf_response response = {0};
    if (wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                          &response) != WF_OK || response.status != 200) {
        wf_response_free(&response);
        return NULL;
    }
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* createRecord as the currently-authenticated client. Returns HTTP status. */
static long create_record(wf_xrpc_client *client, const char *repo,
                          const char *rkey, const char *text) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
             "\"rkey\":\"%s\",\"record\":{\"$type\":\"app.bsky.feed.post\","
             "\"text\":\"%s\",\"createdAt\":\"2026-07-20T00:00:00.000Z\"}}",
             repo, rkey, text);
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.repo.createRecord", body, &response);
    long status = response.status;
    wf_response_free(&response);
    return status;
}

/* getRecord for repo/rkey. Returns HTTP status; on 200 copies the record text
 * into `out_text` (may be NULL). */
static long get_record(wf_xrpc_client *client, const char *repo,
                       const char *rkey, char *out_text, size_t out_len) {
    wf_xrpc_param params[] = {
        {"repo", repo},
        {"collection", "app.bsky.feed.post"},
        {"rkey", rkey},
    };
    wf_response response = {0};
    wf_xrpc_query_params(client, "com.atproto.repo.getRecord", params, 3,
                         &response);
    long status = response.status;
    if (status == 200 && out_text && out_len) {
        cJSON *json = json_response(&response);
        cJSON *value = cJSON_GetObjectItemCaseSensitive(json, "value");
        cJSON *text = cJSON_GetObjectItemCaseSensitive(value, "text");
        if (cJSON_IsString(text))
            snprintf(out_text, out_len, "%s", text->valuestring);
        cJSON_Delete(json);
    }
    wf_response_free(&response);
    return status;
}

int main(void) {
    char directory[] = "/tmp/metalbear-multi-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .account_did = "did:plc:metalbeartest",
        .account_handle = "alice.example.com",
        .user_domain = ".example.com",
        .password = "correct horse battery staple",
        .admin_password = "secret-admin",
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) { rmtree(directory); return 1; }

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);

    /* (a) Two accounts created via createAccount. */
    char *token_bob = create_account(client, "bob.example.com", "did:plc:bob",
                                     "bobsecret");
    char *token_carol = create_account(client, "carol.example.com",
                                       "did:plc:carol", "carolsecret");
    CHECK(token_bob != NULL);
    CHECK(token_carol != NULL);

    /* (c) The access token's `sub` claim must route the request to that
     * account's own auth store. Bob's token authenticates bob-owned routes. */
    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        /* getSession still reports the bootstrap identity (session endpoints
         * are not multi-tenant in this slice), but the request must have been
         * accepted by routing bob's token to bob's auth store. */
        CHECK(cJSON_IsObject(json));
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* (b) Isolation: a record written as bob must live only in bob's repo. */
    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        CHECK(create_record(client, "did:plc:bob", "isolated",
                            "bob-only-secret") == 200);
    }
    char text[256] = {0};
    CHECK(get_record(client, "did:plc:bob", "isolated", text,
                     sizeof(text)) == 200);
    CHECK(strcmp(text, "bob-only-secret") == 0);
    /* The same record key must NOT resolve under carol's repository. */
    CHECK(get_record(client, "did:plc:carol", "isolated", NULL, 0) == 404);

    /* (c) Auth routing by `sub`: bob's token wins over a spoofed foreign
     * `repo` DID. Writing with token=bob but repo=carol must land in BOB's
     * repository, never carol's. */
    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        CHECK(create_record(client, "did:plc:carol", "spoof",
                            "still-bobs") == 200);
    }
    text[0] = '\0';
    CHECK(get_record(client, "did:plc:bob", "spoof", text, sizeof(text)) == 200);
    CHECK(strcmp(text, "still-bobs") == 0);
    CHECK(get_record(client, "did:plc:carol", "spoof", NULL, 0) == 404);

    /* Carol writes to her own repo with her own token; bob cannot see it. */
    if (token_carol) {
        wf_xrpc_client_set_auth(client, token_carol);
        CHECK(create_record(client, "did:plc:carol", "carolpost",
                            "carol-only") == 200);
    }
    text[0] = '\0';
    CHECK(get_record(client, "did:plc:carol", "carolpost", text,
                     sizeof(text)) == 200);
    CHECK(strcmp(text, "carol-only") == 0);
    CHECK(get_record(client, "did:plc:bob", "carolpost", NULL, 0) == 404);

    wf_xrpc_client_set_auth(client, NULL);

    /* listRepos must enumerate every hosted repository, not just bootstrap. */
    {
        wf_response response = {0};
        CHECK(wf_xrpc_query(client, "com.atproto.sync.listRepos", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(body_contains(&response, "did:plc:bob"));
        CHECK(body_contains(&response, "did:plc:carol"));
        wf_response_free(&response);
    }

    /* (d) The landing page lists both accounts' handles and DIDs. */
    {
        wf_response response = {0};
        CHECK(wf_http_get(client, base, &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(strncmp(response.body, "<!DOCTYPE html>", 15) == 0);
        CHECK(body_contains(&response, "alice.example.com"));
        CHECK(body_contains(&response, "did:plc:metalbeartest"));
        CHECK(body_contains(&response, "bob.example.com"));
        CHECK(body_contains(&response, "did:plc:bob"));
        CHECK(body_contains(&response, "carol.example.com"));
        CHECK(body_contains(&response, "did:plc:carol"));
        wf_response_free(&response);
    }

    free(token_bob);
    free(token_carol);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);

    if (failures == 0) {
        printf("test_multi_account: all checks passed\n");
        return 0;
    }
    fprintf(stderr, "test_multi_account: %d checks failed\n", failures);
    return 1;
}
