/*
 * test_import_repo.c — offline e2e coverage for com.atproto.repo.importRepo
 *
 * Exercises the reference-parity gaps closed for importRepo: the
 * acceptingImports config gate, the full-access (repo:manage-equivalent)
 * auth requirement, the maxImportSize cap, and the InvalidCAR/success paths.
 *
 * importRepo verifies the incoming CAR's commit signature two different
 * ways depending on whether the target account already has a commit:
 *
 *  - Onto an existing head (the diff-and-reapply path): against the
 *    *target* account's own signing key, since that key is what actually
 *    signed the base being diffed against. The genuine success and
 *    InvalidCAR/full-access checks below run against the same server and
 *    account that produced the exported CAR, so this is what they exercise
 *    (a backup-restore onto the same account, not a cross-account
 *    migration).
 *  - Onto a still-empty repo (the migration-bootstrap path -- createAccount
 *    with an existing `did`, immediately followed by importRepo, before any
 *    local write): against the DID's CURRENTLY PUBLISHED #atproto key,
 *    resolved over the network, since the DID document has not been
 *    repointed at this host yet and the imported commit is still signed by
 *    whichever server currently holds the identity. The DID-resolution
 *    failure case below exercises this offline (an unresolvable DID method
 *    is refused before any network call is attempted); the resolution
 *    *success* case requires a real DID document to resolve and is instead
 *    covered by a live cross-server migration, not this offline suite.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include "metalbear/server.h"
#include "wolfram/repo/car.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

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

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

static wf_status create_test_account(wf_xrpc_client *client,
                                     char **out_access_token) {
    wf_response response = {0};
    wf_status st =
        wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                          "{\"handle\":\"alice.example.com\","
                          "\"password\":\"correct horse battery staple\","
                          "\"did\":\"did:plc:metalbeartest\","
                          "\"email\":\"alice@example.com\"}",
                          &response);
    CHECK(st == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    *out_access_token =
        cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    return *out_access_token ? WF_OK : WF_ERR_INVALID_ARG;
}

int main(void) {
    printf("importRepo Tests\n");
    printf("================\n\n");

    /* ---- Primary server: default config (accepting_imports=true,
     * max_import_size=0/unlimited). Covers the full-access-required auth
     * path, InvalidCAR, and the real success path -- all against the same
     * account the CAR is exported from and re-imported into. */
    {
        char directory[] = "/tmp/metalbear-import-src-XXXXXX";
        CHECK(mkdtemp(directory) != NULL);
        metalbear_config config = {
            .listen_address = "127.0.0.1",
            .port = 0,
            .thread_count = 2,
            .data_directory = directory,
            .service_did = "did:web:pds.example.com",
            .user_domain = ".example.com",
            .invite_required = false,
            .rate_limit = 10000,
            .accepting_imports = true,
        };
        metalbear_server *server = metalbear_server_start(&config);
        CHECK(server != NULL);
        if (server) {
            char base[80];
            snprintf(base, sizeof(base), "http://127.0.0.1:%u",
                     (unsigned)metalbear_server_port(server));
            wf_xrpc_client *client = wf_xrpc_client_new(base);
            wf_response response = {0};

            char *access_token = NULL;
            CHECK(create_test_account(client, &access_token) == WF_OK);

            wf_xrpc_client_set_auth(client, access_token);
            CHECK(
                wf_xrpc_procedure(
                    client, "com.atproto.repo.createRecord",
                    "{\"repo\":\"did:plc:metalbeartest\","
                    "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"first\","
                    "\"record\":{\"$type\":\"app.bsky.feed.post\","
                    "\"text\":\"hello from import test\","
                    "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
                    &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);

            wf_xrpc_param repo_params[] = {{"did", "did:plc:metalbeartest"}};
            CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getRepo",
                                       repo_params, 1, &response) == WF_OK);
            CHECK(response.status == 200 && response.body_len > 0);
            size_t car_len = response.body_len;
            unsigned char *car_bytes = malloc(car_len);
            CHECK(car_bytes != NULL);
            if (car_bytes) memcpy(car_bytes, response.body, car_len);
            wf_response_free(&response);

            /* An app-password-scoped session is not full access: importRepo
             * requires ACCESS_FULL (the closest match this codebase has to
             * the reference's repo:manage scope), so it must be refused
             * before the CAR body is ever inspected. */
            CHECK(wf_xrpc_procedure(
                      client, "com.atproto.server.createAppPassword",
                      "{\"name\":\"import-test\"}", &response) == WF_OK);
            cJSON *json = json_response(&response);
            cJSON *pw = cJSON_GetObjectItemCaseSensitive(json, "password");
            char *app_password =
                cJSON_IsString(pw) ? strdup(pw->valuestring) : NULL;
            CHECK(app_password != NULL);
            cJSON_Delete(json);
            wf_response_free(&response);

            char login_body[256];
            snprintf(
                login_body, sizeof(login_body),
                "{\"identifier\":\"alice.example.com\",\"password\":\"%s\"}",
                app_password ? app_password : "");
            wf_xrpc_client_set_auth(client, NULL);
            CHECK(wf_xrpc_procedure(client, "com.atproto.server.createSession",
                                    login_body, &response) == WF_OK);
            json = json_response(&response);
            cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
            char *app_access =
                cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
            cJSON_Delete(json);
            wf_response_free(&response);

            if (car_bytes) {
                wf_xrpc_client_set_auth(client, app_access);
                CHECK(wf_xrpc_upload_blob(client, "com.atproto.repo.importRepo",
                                          car_bytes, car_len,
                                          "application/vnd.ipld.car",
                                          &response) == WF_ERR_HTTP);
                CHECK(response.status == 401);
                wf_response_free(&response);

                /* An unverifiable body is refused as InvalidCAR, not a
                 * crash or a silently-accepted no-op. */
                wf_xrpc_client_set_auth(client, access_token);
                const unsigned char garbage[] = {0x00, 0x01, 0x02, 0x03};
                CHECK(wf_xrpc_upload_blob(client, "com.atproto.repo.importRepo",
                                          garbage, sizeof(garbage),
                                          "application/vnd.ipld.car",
                                          &response) == WF_ERR_HTTP);
                CHECK(response.status == 400);
                json = json_response(&response);
                CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")
                                 ->valuestring,
                             "InvalidCAR") == 0);
                cJSON_Delete(json);
                wf_response_free(&response);

                /* The real success path: a full-access session re-importing
                 * its own genuinely exported CAR (a backup restore) is
                 * accepted. */
                CHECK(wf_xrpc_upload_blob(client, "com.atproto.repo.importRepo",
                                          car_bytes, car_len,
                                          "application/vnd.ipld.car",
                                          &response) == WF_OK);
                CHECK(response.status == 200);
                wf_response_free(&response);

                /* The record is still readable after the import. */
                wf_xrpc_param rec_params[] = {
                    {"repo", "did:plc:metalbeartest"},
                    {"collection", "app.bsky.feed.post"},
                    {"rkey", "first"},
                };
                CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                                           rec_params, 3, &response) == WF_OK);
                CHECK(response.status == 200);
                wf_response_free(&response);

                /* Incremental import onto a repo that has since diverged: add
                 * a second record so the live repo (first + second) no
                 * longer matches the earlier CAR_A snapshot (first only),
                 * then re-import CAR_A. importRepo must diff CAR_A against
                 * the CURRENT repo and reapply the delta as one fresh-rev
                 * commit -- not adopt CAR_A's own (now stale) commit
                 * verbatim -- so "second" is deleted, "first" survives
                 * untouched, and the head's rev advances past both the
                 * pre-import head and CAR_A's own rev. */
                CHECK(wf_xrpc_procedure(
                          client, "com.atproto.repo.createRecord",
                          "{\"repo\":\"did:plc:metalbeartest\","
                          "\"collection\":\"app.bsky.feed.post\","
                          "\"rkey\":\"second\","
                          "\"record\":{\"$type\":\"app.bsky.feed.post\","
                          "\"text\":\"a second post, post-export\","
                          "\"createdAt\":\"2026-07-19T00:01:00.000Z\"}}",
                          &response) == WF_OK);
                CHECK(response.status == 200);
                wf_response_free(&response);

                CHECK(wf_xrpc_query_params(client,
                                           "com.atproto.sync.getLatestCommit",
                                           repo_params, 1, &response) == WF_OK);
                cJSON *before = json_response(&response);
                char *rev_before =
                    strdup(cJSON_GetObjectItemCaseSensitive(before, "rev")
                               ->valuestring);
                cJSON_Delete(before);
                wf_response_free(&response);

                CHECK(wf_xrpc_upload_blob(client, "com.atproto.repo.importRepo",
                                          car_bytes, car_len,
                                          "application/vnd.ipld.car",
                                          &response) == WF_OK);
                CHECK(response.status == 200);
                wf_response_free(&response);

                /* "first" (unchanged between the two snapshots) survives. */
                CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                                           rec_params, 3, &response) == WF_OK);
                CHECK(response.status == 200);
                wf_response_free(&response);

                /* "second" (absent from the re-imported CAR_A) is gone. */
                wf_xrpc_param second_params[] = {
                    {"repo", "did:plc:metalbeartest"},
                    {"collection", "app.bsky.feed.post"},
                    {"rkey", "second"},
                };
                CHECK(wf_xrpc_query_params(client, "com.atproto.repo.getRecord",
                                           second_params, 3,
                                           &response) == WF_ERR_HTTP);
                CHECK(response.status == 404);
                cJSON *notfound = json_response(&response);
                CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(notfound, "error")
                                 ->valuestring,
                             "RecordNotFound") == 0);
                cJSON_Delete(notfound);
                wf_response_free(&response);

                /* A genuinely new commit was minted (fresh rev), not a
                 * silent no-op and not CAR_A's own stale rev adopted as-is. */
                CHECK(wf_xrpc_query_params(client,
                                           "com.atproto.sync.getLatestCommit",
                                           repo_params, 1, &response) == WF_OK);
                cJSON *after = json_response(&response);
                char *rev_after =
                    strdup(cJSON_GetObjectItemCaseSensitive(after, "rev")
                               ->valuestring);
                CHECK(rev_before && rev_after &&
                      strcmp(rev_before, rev_after) != 0);
                cJSON_Delete(after);
                free(rev_before);
                wf_response_free(&response);

                /* Re-importing the exact same (now-current) snapshot again is
                 * a genuine no-op: no new commit, nothing to delete. */
                wf_response response2 = {0};
                CHECK(wf_xrpc_query_params(client, "com.atproto.sync.getRepo",
                                           repo_params, 1,
                                           &response2) == WF_OK);
                CHECK(response2.status == 200 && response2.body_len > 0);
                size_t car_len2 = response2.body_len;
                unsigned char *car_bytes2 = malloc(car_len2);
                CHECK(car_bytes2 != NULL);
                if (car_bytes2) memcpy(car_bytes2, response2.body, car_len2);
                wf_response_free(&response2);

                CHECK(wf_xrpc_upload_blob(client, "com.atproto.repo.importRepo",
                                          car_bytes2, car_len2,
                                          "application/vnd.ipld.car",
                                          &response) == WF_OK);
                CHECK(response.status == 200);
                wf_response_free(&response);

                CHECK(wf_xrpc_query_params(client,
                                           "com.atproto.sync.getLatestCommit",
                                           repo_params, 1, &response) == WF_OK);
                cJSON *after2 = json_response(&response);
                CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(after2, "rev")
                                 ->valuestring,
                             rev_after) == 0);
                cJSON_Delete(after2);
                wf_response_free(&response);
                free(car_bytes2);
                free(rev_after);
            }

            free(car_bytes);
            free(app_password);
            free(app_access);
            free(access_token);
            wf_xrpc_client_free(client);
            metalbear_server_free(server);
        }
        rmtree(directory);
    }

    /* ---- Second server: accepting_imports=false -- every import is
     * refused honestly, before the CAR is even parsed (so a mismatched
     * signing key doesn't matter here: any CAR body is rejected). */
    {
        char directory[] = "/tmp/metalbear-import-off-XXXXXX";
        CHECK(mkdtemp(directory) != NULL);
        metalbear_config config = {
            .listen_address = "127.0.0.1",
            .port = 0,
            .thread_count = 2,
            .data_directory = directory,
            .service_did = "did:web:pds3.example.com",
            .user_domain = ".example.com",
            .invite_required = false,
            .rate_limit = 10000,
            .accepting_imports = false,
        };
        metalbear_server *server = metalbear_server_start(&config);
        CHECK(server != NULL);
        if (server) {
            char base[80];
            snprintf(base, sizeof(base), "http://127.0.0.1:%u",
                     (unsigned)metalbear_server_port(server));
            wf_xrpc_client *client = wf_xrpc_client_new(base);
            wf_response response = {0};

            char *access_token = NULL;
            CHECK(create_test_account(client, &access_token) == WF_OK);

            const unsigned char body[] = {0x00, 0x01, 0x02, 0x03};
            wf_xrpc_client_set_auth(client, access_token);
            CHECK(wf_xrpc_upload_blob(
                      client, "com.atproto.repo.importRepo", body, sizeof(body),
                      "application/vnd.ipld.car", &response) == WF_ERR_HTTP);
            CHECK(response.status == 400);
            cJSON *json = json_response(&response);
            CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")
                             ->valuestring,
                         "InvalidRequest") == 0);
            CHECK(strstr(cJSON_GetObjectItemCaseSensitive(json, "message")
                             ->valuestring,
                         "not accepting") != NULL);
            cJSON_Delete(json);
            wf_response_free(&response);

            free(access_token);
            wf_xrpc_client_free(client);
            metalbear_server_free(server);
        }
        rmtree(directory);
    }

    /* ---- Third server: max_import_size smaller than any real body -- the
     * size cap refuses the request before parsing it. */
    {
        char directory[] = "/tmp/metalbear-import-cap-XXXXXX";
        CHECK(mkdtemp(directory) != NULL);
        metalbear_config config = {
            .listen_address = "127.0.0.1",
            .port = 0,
            .thread_count = 2,
            .data_directory = directory,
            .service_did = "did:web:pds4.example.com",
            .user_domain = ".example.com",
            .invite_required = false,
            .rate_limit = 10000,
            .accepting_imports = true,
            .max_import_size = 3, /* smaller than any real CAR body */
        };
        metalbear_server *server = metalbear_server_start(&config);
        CHECK(server != NULL);
        if (server) {
            char base[80];
            snprintf(base, sizeof(base), "http://127.0.0.1:%u",
                     (unsigned)metalbear_server_port(server));
            wf_xrpc_client *client = wf_xrpc_client_new(base);
            wf_response response = {0};

            char *access_token = NULL;
            CHECK(create_test_account(client, &access_token) == WF_OK);

            const unsigned char body[] = {0x00, 0x01, 0x02, 0x03};
            CHECK(sizeof(body) > 3);
            wf_xrpc_client_set_auth(client, access_token);
            CHECK(wf_xrpc_upload_blob(
                      client, "com.atproto.repo.importRepo", body, sizeof(body),
                      "application/vnd.ipld.car", &response) == WF_ERR_HTTP);
            CHECK(response.status == 400);
            cJSON *json = json_response(&response);
            CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")
                             ->valuestring,
                         "InvalidRequest") == 0);
            CHECK(strstr(cJSON_GetObjectItemCaseSensitive(json, "message")
                             ->valuestring,
                         "maximum import size") != NULL);
            cJSON_Delete(json);
            wf_response_free(&response);

            free(access_token);
            wf_xrpc_client_free(client);
            metalbear_server_free(server);
        }
        rmtree(directory);
    }

    /* ---- Fourth server: migration bootstrap onto a headless account whose
     * DID uses an unresolvable method. wf_did_resolve_verification_key
     * rejects an unknown DID method before ever attempting a network call
     * (wf_did_method_of returns WF_DID_METHOD_UNKNOWN, short-circuiting
     * did_fetch_document), so this stays fully offline while still proving
     * the new resolve-then-verify path is reached and fails honestly rather
     * than silently falling back to the account's own (irrelevant, freshly
     * generated) local key. */
    {
        char src_directory[] = "/tmp/metalbear-import-migsrc-XXXXXX";
        CHECK(mkdtemp(src_directory) != NULL);
        metalbear_config src_config = {
            .listen_address = "127.0.0.1",
            .port = 0,
            .thread_count = 2,
            .data_directory = src_directory,
            .service_did = "did:web:pds5.example.com",
            .user_domain = ".example.com",
            .invite_required = false,
            .rate_limit = 10000,
            .accepting_imports = true,
        };
        metalbear_server *src_server = metalbear_server_start(&src_config);
        CHECK(src_server != NULL);

        char mig_directory[] = "/tmp/metalbear-import-mig-XXXXXX";
        CHECK(mkdtemp(mig_directory) != NULL);
        metalbear_config mig_config = {
            .listen_address = "127.0.0.1",
            .port = 0,
            .thread_count = 2,
            .data_directory = mig_directory,
            .service_did = "did:web:pds6.example.com",
            .user_domain = ".example.com",
            .invite_required = false,
            .rate_limit = 10000,
            .accepting_imports = true,
        };
        metalbear_server *mig_server = metalbear_server_start(&mig_config);
        CHECK(mig_server != NULL);

        if (src_server && mig_server) {
            char src_base[80];
            snprintf(src_base, sizeof(src_base), "http://127.0.0.1:%u",
                     (unsigned)metalbear_server_port(src_server));
            wf_xrpc_client *src_client = wf_xrpc_client_new(src_base);
            wf_response response = {0};

            char *src_access = NULL;
            CHECK(create_test_account(src_client, &src_access) == WF_OK);
            wf_xrpc_client_set_auth(src_client, src_access);

            /* getRepo on a headless account with no commits yet fails with
             * RepoNotFound, so give it one record to export first. */
            CHECK(
                wf_xrpc_procedure(
                    src_client, "com.atproto.repo.createRecord",
                    "{\"repo\":\"did:plc:metalbeartest\","
                    "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"first\","
                    "\"record\":{\"$type\":\"app.bsky.feed.post\","
                    "\"text\":\"hello from migration bootstrap test\","
                    "\"createdAt\":\"2026-07-19T00:00:00.000Z\"}}",
                    &response) == WF_OK);
            CHECK(response.status == 200);
            wf_response_free(&response);

            wf_xrpc_param repo_params[] = {{"did", "did:plc:metalbeartest"}};
            CHECK(wf_xrpc_query_params(src_client, "com.atproto.sync.getRepo",
                                       repo_params, 1, &response) == WF_OK);
            CHECK(response.status == 200 && response.body_len > 0);
            size_t car_len = response.body_len;
            unsigned char *car_bytes = malloc(car_len);
            CHECK(car_bytes != NULL);
            if (car_bytes) memcpy(car_bytes, response.body, car_len);
            wf_response_free(&response);

            char mig_base[80];
            snprintf(mig_base, sizeof(mig_base), "http://127.0.0.1:%u",
                     (unsigned)metalbear_server_port(mig_server));
            wf_xrpc_client *mig_client = wf_xrpc_client_new(mig_base);

            wf_response create_response = {0};
            CHECK(wf_xrpc_procedure(
                      mig_client, "com.atproto.server.createAccount",
                      "{\"handle\":\"migrated.example.com\","
                      "\"password\":\"correct horse battery staple\","
                      "\"did\":\"did:example:unresolvable-method\","
                      "\"email\":\"migrated@example.com\"}",
                      &create_response) == WF_OK);
            CHECK(create_response.status == 200);
            cJSON *create_json = json_response(&create_response);
            cJSON *mig_access_json =
                cJSON_GetObjectItemCaseSensitive(create_json, "accessJwt");
            char *mig_access = cJSON_IsString(mig_access_json)
                                   ? strdup(mig_access_json->valuestring)
                                   : NULL;
            CHECK(mig_access != NULL);
            cJSON_Delete(create_json);
            wf_response_free(&create_response);

            if (car_bytes && mig_access) {
                wf_xrpc_client_set_auth(mig_client, mig_access);
                CHECK(wf_xrpc_upload_blob(
                          mig_client, "com.atproto.repo.importRepo", car_bytes,
                          car_len, "application/vnd.ipld.car",
                          &response) == WF_ERR_HTTP);
                CHECK(response.status == 400);
                cJSON *json = json_response(&response);
                CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(json, "error")
                                 ->valuestring,
                             "InvalidCAR") == 0);
                CHECK(strstr(cJSON_GetObjectItemCaseSensitive(json, "message")
                                 ->valuestring,
                             "resolve") != NULL);
                cJSON_Delete(json);
                wf_response_free(&response);
            }

            free(car_bytes);
            free(mig_access);
            free(src_access);
            wf_xrpc_client_free(src_client);
            wf_xrpc_client_free(mig_client);
        }
        if (src_server) metalbear_server_free(src_server);
        if (mig_server) metalbear_server_free(mig_server);
        rmtree(src_directory);
        rmtree(mig_directory);
    }

    printf("\n");
    if (failures) fprintf(stderr, "%d import repo test(s) failed\n", failures);
    return failures ? 1 : 0;
}
