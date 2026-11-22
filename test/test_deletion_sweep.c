#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

/*
 * test_deletion_sweep.c -- offline coverage for issue #159: a deactivated
 * account is hard-deleted only after the configured hold, with the same
 * firehose announcement as deleteAccount. Accounts still inside the hold,
 * active accounts, and deactivated accounts with no recorded timestamp are
 * left alone.
 *
 * Accounts are created and deactivated through the real XRPC handlers on a
 * loopback server, so the deactivation timestamp is the one the route writes.
 * A forced sweep (metalbear_deletion_sweep_run with an explicit `now`)
 * exercises the hold arithmetic without sleeping; the background timer is off
 * because the configured hold is 0.
 */

#include "../src/server_internal.h"

#include "metalbear/account/deletion_sweep.h"

#include <cJSON.h>
#include <ftw.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

/* Sign up a fresh account and return its access JWT and minted DID. */
static bool create_account_session(wf_xrpc_client *client, const char *handle,
                                   const char *password, const char *email,
                                   char **out_token, char **out_did) {
    *out_token = NULL;
    *out_did = NULL;
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\",\"email\":\"%s\"}", handle,
             password, email);
    wf_response response = {0};
    bool ok = wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                                body, &response) == WF_OK &&
              response.status == 200;
    if (ok) {
        cJSON *json = json_response(&response);
        cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
        if (cJSON_IsString(access)) *out_token = strdup(access->valuestring);
        if (cJSON_IsString(did)) *out_did = strdup(did->valuestring);
        cJSON_Delete(json);
        ok = *out_token && *out_did;
    }
    wf_response_free(&response);
    return ok;
}

/* Send com.atproto.server.deactivateAccount with the account's own token. */
static bool deactivate(wf_xrpc_client *client, const char *token) {
    wf_xrpc_client_set_auth(client, token);
    wf_response response = {0};
    bool ok = wf_xrpc_procedure(client, "com.atproto.server.deactivateAccount",
                                "{}", &response) == WF_OK &&
              response.status == 200;
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, NULL);
    return ok;
}

/* Rewrite an account's deactivated_at directly in its store. The route only
 * writes "now", so a forced sweep needs a deliberately aged timestamp. `ts`
 * may be NULL to simulate an older database with no recorded time at all. */
static void set_deactivated_at(metalbear_server *server, const char *did,
                               const char *ts) {
    metalbear_account_entry *entry = NULL;
    CHECK(metalbear_account_registry_find_by_did(server->registry, did,
                                                 &entry) == WF_OK);
    if (!entry) return;
    char path[1024];
    snprintf(path, sizeof(path), "%s/account.sqlite3", entry->data_directory);
    metalbear_account_entry_free(entry);

    sqlite3 *db = NULL;
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    char sql[256];
    if (ts)
        snprintf(sql, sizeof(sql),
                 "UPDATE account_state SET deactivated_at='%s' WHERE id=0;",
                 ts);
    else
        snprintf(sql, sizeof(sql),
                 "UPDATE account_state SET deactivated_at=NULL WHERE id=0;");
    CHECK(sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
}

static bool registry_has(metalbear_server *server, const char *did) {
    metalbear_account_entry *entry = NULL;
    wf_status status =
        metalbear_account_registry_find_by_did(server->registry, did, &entry);
    if (entry) metalbear_account_entry_free(entry);
    return status == WF_OK;
}

static bool dir_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int count_frames_with(const char *seq_path, const char *needle) {
    sqlite3 *db = NULL;
    int found = 0;
    if (sqlite3_open(seq_path, &db) == SQLITE_OK) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(
                db, "SELECT COUNT(*) FROM events WHERE instr(frame, ?) > 0;",
                -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, needle, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                found = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return found;
}

int main(void) {
    char directory[] = "/tmp/metalbear-deletion-sweep-XXXXXX";
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
        /* Hold is off, so no background timer runs during the test. */
        .deletion_hold_seconds = 0,
    };
    metalbear_server *server = metalbear_server_start(&config);
    CHECK(server != NULL);
    if (!server) {
        rmtree(directory);
        return 1;
    }

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);

    char *alice_token = NULL, *alice_did = NULL;
    char *bob_token = NULL, *bob_did = NULL;
    char *carol_token = NULL, *carol_did = NULL;
    char *dave_token = NULL, *dave_did = NULL;
    CHECK(create_account_session(client, "alice.example.com", "secret123",
                                 "alice@example.com", &alice_token,
                                 &alice_did));
    CHECK(create_account_session(client, "bob.example.com", "secret123",
                                 "bob@example.com", &bob_token, &bob_did));
    CHECK(create_account_session(client, "carol.example.com", "secret123",
                                 "carol@example.com", &carol_token,
                                 &carol_did));
    CHECK(create_account_session(client, "dave.example.com", "secret123",
                                 "dave@example.com", &dave_token, &dave_did));
    CHECK(alice_did && bob_did && carol_did && dave_did);

    char alice_dir[1024], bob_dir[1024], carol_dir[1024], dave_dir[1024];
    {
        metalbear_account_entry *entry = NULL;
        if (metalbear_account_registry_find_by_did(server->registry, alice_did,
                                                   &entry) == WF_OK) {
            snprintf(alice_dir, sizeof(alice_dir), "%s", entry->data_directory);
            metalbear_account_entry_free(entry);
        }
        entry = NULL;
        if (metalbear_account_registry_find_by_did(server->registry, bob_did,
                                                   &entry) == WF_OK) {
            snprintf(bob_dir, sizeof(bob_dir), "%s", entry->data_directory);
            metalbear_account_entry_free(entry);
        }
        entry = NULL;
        if (metalbear_account_registry_find_by_did(server->registry, carol_did,
                                                   &entry) == WF_OK) {
            snprintf(carol_dir, sizeof(carol_dir), "%s", entry->data_directory);
            metalbear_account_entry_free(entry);
        }
        entry = NULL;
        if (metalbear_account_registry_find_by_did(server->registry, dave_did,
                                                   &entry) == WF_OK) {
            snprintf(dave_dir, sizeof(dave_dir), "%s", entry->data_directory);
            metalbear_account_entry_free(entry);
        }
    }

    /* alice and bob are deactivated; dave is deactivated but has no timestamp
     * (an older database), carol stays active. */
    CHECK(deactivate(client, alice_token));
    CHECK(deactivate(client, bob_token));
    CHECK(deactivate(client, dave_token));
    set_deactivated_at(server, bob_did, "2020-01-01T00:00:00.000Z");
    set_deactivated_at(server, dave_did, NULL);

    int64_t now = (int64_t)time(NULL);
    char seq_path[512];
    snprintf(seq_path, sizeof(seq_path), "%s/sequencer.sqlite3", directory);

    /* Hold disabled: never deletes, however old the deactivation. */
    CHECK(metalbear_deletion_sweep_run(server, 0, now) == 0);
    CHECK(registry_has(server, bob_did));

    /* One forced pass with a one-hour hold: only bob is old enough. */
    CHECK(metalbear_deletion_sweep_run(server, 3600, now) == 1);

    CHECK(registry_has(server, alice_did));
    CHECK(dir_exists(alice_dir));
    CHECK(registry_has(server, carol_did));
    CHECK(dir_exists(carol_dir));
    CHECK(registry_has(server, dave_did));
    CHECK(dir_exists(dave_dir));

    CHECK(!registry_has(server, bob_did));
    CHECK(!dir_exists(bob_dir));

    /* Purge kept only the final `deleted` announcement for bob. */
    CHECK(count_frames_with(seq_path, bob_did) == 1);
    CHECK(count_frames_with(seq_path, "deleted") == 1);
    /* alice's firehose history is untouched by the sweep. */
    CHECK(count_frames_with(seq_path, alice_did) >= 1);
    CHECK(count_frames_with(seq_path, "deactivated") >= 1);

    /* A second pass is a no-op: there is nothing left to delete. */
    CHECK(metalbear_deletion_sweep_run(server, 3600, now) == 0);

    free(alice_token);
    free(alice_did);
    free(bob_token);
    free(bob_did);
    free(carol_token);
    free(carol_did);
    free(dave_token);
    free(dave_did);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_deletion_sweep: OK\n");
    return 0;
}
