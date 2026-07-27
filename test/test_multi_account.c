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
#include <sqlite3.h>
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
             "{\"handle\":\"%s\",\"password\":\"%s\",\"did\":\"%s\",\"email\":\"%s@example.com\"}",
             handle, password, did, handle);
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

static bool create_session(wf_xrpc_client *client, const char *identifier,
                           const char *password, const char *expected_handle,
                           char **out_access, char **out_refresh) {
    *out_access = NULL;
    *out_refresh = NULL;
    char body[512];
    snprintf(body, sizeof(body),
             "{\"identifier\":\"%s\",\"password\":\"%s\"}",
             identifier, password);
    wf_response response = {0};
    if (wf_xrpc_procedure(client, "com.atproto.server.createSession", body,
                          &response) != WF_OK || response.status != 200) {
        wf_response_free(&response);
        return false;
    }
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    cJSON *refresh = cJSON_GetObjectItemCaseSensitive(json, "refreshJwt");
    cJSON *handle = cJSON_GetObjectItemCaseSensitive(json, "handle");
    cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
    bool valid = cJSON_IsString(access) && cJSON_IsString(refresh) &&
                 cJSON_IsString(handle) &&
                 strcmp(handle->valuestring, expected_handle) == 0 &&
                 cJSON_IsString(did) &&
                 strcmp(did->valuestring, "did:plc:bob") == 0;
    if (valid) {
        *out_access = strdup(access->valuestring);
        *out_refresh = strdup(refresh->valuestring);
        valid = *out_access != NULL && *out_refresh != NULL;
    }
    cJSON_Delete(json);
    wf_response_free(&response);
    if (!valid) {
        free(*out_access);
        free(*out_refresh);
        *out_access = NULL;
        *out_refresh = NULL;
    }
    return valid;
}

/* Number of #commit frames in a sequencer log. Commit frames carry the record
 * blocks, so they are far larger than the identity/account frames seeded when
 * an account is created. */
static int count_commit_events(const char *seq_path) {
    sqlite3 *db = NULL;
    int commits = 0;
    if (sqlite3_open(seq_path, &db) == SQLITE_OK) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT COUNT(*) FROM events WHERE length(frame) > 400;",
                -1, &stmt, NULL) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_ROW)
            commits = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return commits;
}

/*
 * Count events in the shared log that mention `did`.
 *
 * createAccount used to open the new account against a private per-account
 * sequencer, so its #identity and #account events were written to a file
 * nothing ever reads. The account then federated with a bare #commit for a
 * DID the network had never been introduced to. The events must land in the
 * host-wide log — this looks for the DID in the stored frames.
 */
static int count_events_mentioning(const char *seq_path, const char *did) {
    sqlite3 *db = NULL;
    int found = 0;
    if (sqlite3_open(seq_path, &db) == SQLITE_OK) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT COUNT(*) FROM events WHERE instr(frame, ?) > 0;",
                -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, did, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                found = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return found;
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
        .user_domain = ".example.com",
        .admin_password = "secret-admin",
        /* Nothing is configured as "the" account: every account below, the
         * first included, arrives through createAccount. */
        .invite_required = false,
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) { rmtree(directory); return 1; }

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);

    /* (a) Accounts created via createAccount — including the one this test
     * later expects to see listed. No account exists until one is created. */
    char *token_alice = create_account(client, "alice.example.com",
                                       "did:plc:metalbeartest",
                                       "correct horse battery staple");
    CHECK(token_alice != NULL);
    free(token_alice);
    char *token_bob = create_account(client, "bob.example.com", "did:plc:bob",
                                     "bobsecret");
    char *token_carol = create_account(client, "carol.example.com",
                                       "did:plc:carol", "carolsecret");
    CHECK(token_bob != NULL);
    CHECK(token_carol != NULL);

    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *handle = cJSON_GetObjectItemCaseSensitive(json, "handle");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
        CHECK(cJSON_IsString(handle));
        CHECK(cJSON_IsString(handle) &&
              strcmp(handle->valuestring, "bob.example.com") == 0);
        CHECK(cJSON_IsString(did));
        CHECK(cJSON_IsString(did) &&
              strcmp(did->valuestring, "did:plc:bob") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    char *login_access = NULL;
    char *login_refresh = NULL;
    CHECK(create_session(client, "bob.example.com", "bobsecret",
                         "bob.example.com", &login_access, &login_refresh));
    if (login_refresh) {
        wf_xrpc_client_set_auth(client, login_refresh);
        wf_response response = {0};
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *handle = cJSON_GetObjectItemCaseSensitive(json, "handle");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
        CHECK(cJSON_IsString(handle) &&
              strcmp(handle->valuestring, "bob.example.com") == 0);
        CHECK(cJSON_IsString(did) &&
              strcmp(did->valuestring, "did:plc:bob") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    free(login_access);
    free(login_refresh);

    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                          "{\"handle\":\"carol.example.com\"}", &response);
        CHECK(response.status == 400);
        wf_response_free(&response);
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                "{\"handle\":\"robert.example.com\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }
    {
        wf_xrpc_param params[] = {{"handle", "robert.example.com"}};
        wf_response response = {0};
        CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveHandle",
                                   params, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
        CHECK(cJSON_IsString(did) &&
              strcmp(did->valuestring, "did:plc:bob") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    {
        wf_xrpc_param params[] = {{"repo", "did:plc:bob"}};
        wf_response response = {0};
        CHECK(wf_xrpc_query_params(client, "com.atproto.repo.describeRepo",
                                   params, 1, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *handle = cJSON_GetObjectItemCaseSensitive(json, "handle");
        CHECK(cJSON_IsString(handle) &&
              strcmp(handle->valuestring, "robert.example.com") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    login_access = NULL;
    login_refresh = NULL;
    CHECK(create_session(client, "robert.example.com", "bobsecret",
                         "robert.example.com", &login_access, &login_refresh));
    free(login_access);
    free(login_refresh);

    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.createAppPassword",
                                "{}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.createAppPassword",
                                "{\"name\":\"shared-device\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *name = cJSON_GetObjectItemCaseSensitive(json, "name");
        cJSON *password = cJSON_GetObjectItemCaseSensitive(json, "password");
        cJSON *created_at = cJSON_GetObjectItemCaseSensitive(json, "createdAt");
        CHECK(cJSON_IsString(name) &&
              strcmp(name->valuestring, "shared-device") == 0);
        CHECK(cJSON_IsString(password) && password->valuestring[0]);
        CHECK(cJSON_IsString(created_at) && created_at->valuestring[0]);
        cJSON_Delete(json);
        wf_response_free(&response);
        CHECK(wf_xrpc_query(client, "com.atproto.server.listAppPasswords",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(body_contains(&response, "shared-device"));
        wf_response_free(&response);
    }
    if (token_carol) {
        wf_xrpc_client_set_auth(client, token_carol);
        wf_response response = {0};
        CHECK(wf_xrpc_query(client, "com.atproto.server.listAppPasswords",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(!body_contains(&response, "shared-device"));
        wf_response_free(&response);
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.createAppPassword",
                                "{\"name\":\"shared-device\",\"privileged\":true}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }
    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.revokeAppPassword",
                                "{\"name\":\"shared-device\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        CHECK(wf_xrpc_query(client, "com.atproto.server.listAppPasswords",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(!body_contains(&response, "shared-device"));
        wf_response_free(&response);
    }
    if (token_carol) {
        wf_xrpc_client_set_auth(client, token_carol);
        wf_response response = {0};
        CHECK(wf_xrpc_query(client, "com.atproto.server.listAppPasswords",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(body_contains(&response, "shared-device"));
        wf_response_free(&response);
    }
    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.updateEmail",
                                "{\"email\":\"bob@example.net\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(body_contains(&response, "bob@example.net"));
        CHECK(!body_contains(&response, "carol@example.net"));
        wf_response_free(&response);
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.requestEmailUpdate",
                                NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(body_contains(&response, "\"tokenRequired\":true"));
        wf_response_free(&response);
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.requestEmailConfirmation",
                                NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(body_contains(&response, "\"success\":true"));
        wf_response_free(&response);
    }
    if (token_carol) {
        wf_xrpc_client_set_auth(client, token_carol);
        wf_response response = {0};
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.updateEmail",
                                "{\"email\":\"carol@example.net\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        CHECK(wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                            &response) == WF_OK);
        CHECK(response.status == 200);
        CHECK(body_contains(&response, "carol@example.net"));
        CHECK(!body_contains(&response, "bob@example.net"));
        wf_response_free(&response);
        wf_xrpc_procedure(client, "com.atproto.server.confirmEmail",
                          "{\"email\":\"carol@example.net\","
                          "\"token\":\"invalid\"}", &response);
        CHECK(response.status == 400);
        CHECK(body_contains(&response, "InvalidToken"));
        wf_response_free(&response);
    }
    wf_xrpc_client_set_auth(client, NULL);
    {
        wf_response response = {0};
        wf_xrpc_procedure(client, "com.atproto.server.updateEmail",
                          "{\"email\":\"none@example.net\"}", &response);
        CHECK(response.status == 401);
        wf_response_free(&response);
    }
    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.deactivateAccount",
                                "{\"deleteAfter\":1}", &response) ==
              WF_ERR_HTTP);
        CHECK(response.status == 400);
        wf_response_free(&response);
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.deactivateAccount",
                                "{}", &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        CHECK(wf_xrpc_query(client,
                            "com.atproto.server.checkAccountStatus",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *activated = cJSON_GetObjectItemCaseSensitive(json, "activated");
        CHECK(cJSON_IsFalse(activated));
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    if (token_carol) {
        wf_xrpc_client_set_auth(client, token_carol);
        wf_response response = {0};
        CHECK(wf_xrpc_query(client,
                            "com.atproto.server.checkAccountStatus",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *activated = cJSON_GetObjectItemCaseSensitive(json, "activated");
        CHECK(cJSON_IsTrue(activated));
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_procedure(client,
                                "com.atproto.server.activateAccount",
                                NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        CHECK(wf_xrpc_query(client,
                            "com.atproto.server.checkAccountStatus",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *activated = cJSON_GetObjectItemCaseSensitive(json, "activated");
        CHECK(cJSON_IsTrue(activated));
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    wf_xrpc_client_set_auth(client, NULL);
    {
        wf_response response = {0};
        CHECK(wf_xrpc_query(client, "com.atproto.server.checkAccountStatus",
                            NULL, &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
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
    char shared_seq[512];
    snprintf(shared_seq, sizeof(shared_seq), "%s/sequencer.sqlite3", directory);
    int commits_before = count_commit_events(shared_seq);
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

    /*
     * A non-bootstrap account's write must reach the firehose.
     *
     * The repo-to-sequencer callback was once wired by hand for the bootstrap
     * account only, so every other account wrote records that no relay could
     * ever learn about: the data was in the repo and served by getRepo, but
     * nothing was ever published. That is indistinguishable from the account
     * not federating, and no test noticed because reads all still worked.
     */
    /* Carol is not the bootstrap account, and her commit must still reach the
     * PDS-wide log at the data root — that single stream is what
     * subscribeRepos serves, so anything landing elsewhere is invisible to
     * every relay however correctly it was recorded. Counting either side of
     * her write attributes the new event to her rather than to the primary
     * account's traffic. */
    CHECK(count_commit_events(shared_seq) > commits_before);

    /*
     * Account creation must announce itself on that same host-wide log.
     *
     * Carol was created through createAccount, so the log has to carry her
     * #identity and #account as well as her commit — more than one event
     * naming her DID. With the creation events going to a private per-account
     * file, the only frame mentioning her here was the commit, and a relay's
     * first sight of the DID was a commit for a repo it had never been told
     * existed.
     */
    CHECK(count_events_mentioning(shared_seq, "did:plc:carol") > 1);

    if (token_bob) {
        wf_xrpc_client_set_auth(client, token_bob);
        wf_response response = {0};
        CHECK(wf_xrpc_query(client, "com.atproto.server.checkAccountStatus",
                            NULL, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *repo_blocks = cJSON_GetObjectItemCaseSensitive(json, "repoBlocks");
        cJSON *indexed_records = cJSON_GetObjectItemCaseSensitive(
            json, "indexedRecords");
        cJSON *imported_blobs = cJSON_GetObjectItemCaseSensitive(
            json, "importedBlobs");
        CHECK(cJSON_IsNumber(repo_blocks) && repo_blocks->valuedouble > 0);
        CHECK(cJSON_IsNumber(indexed_records) &&
              indexed_records->valuedouble == 2);
        CHECK(cJSON_IsNumber(imported_blobs) &&
              imported_blobs->valuedouble == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

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
        CHECK(body_contains(&response, "robert.example.com"));
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
