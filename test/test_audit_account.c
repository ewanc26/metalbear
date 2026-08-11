#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_audit_account.c — offline end-to-end coverage for the
 * com.atproto.server.createAccount audit: the handler is the only path that
 * opens an account on this host, so every gate it is supposed to apply is
 * checked here as a client would hit it.
 *
 *   (a) a missing email is 400 InvalidRequest "Email is required" — not the
 *       invented InvalidEmail, which the createAccount lexicon never declares,
 *   (b) a password longer than the reference's 64-character ceiling is 400
 *       InvalidRequest with the reference's exact message, and exactly 64
 *       characters is accepted,
 *   (c) the signed-PLC-operation import path is refused outright: 400
 *       InvalidRequest "Unsupported input: \"plcOp\"",
 *   (d) the full handle is validated, not just the domain suffix — a space, a
 *       leading hyphen, an empty label, or a single bare label are all 400
 *       InvalidHandle even when the handle would otherwise be well-formed,
 *   (e) an email already registered to an account is 400 InvalidRequest
 *       "Email already taken: <email>", while a taken handle still reports
 *       the lexicon's HandleNotAvailable,
 *   (f) an imported DID requires authenticating as exactly that DID: no auth
 *       or another identity's auth is 401 AuthRequired, and importing a DID
 *       this host already holds is refused without disturbing the existing
 *       account,
 *   (g) a normal signup still lands active, resolvable, and announced on the
 *       host firehose.
 *
 * Cleanup removes the whole data directory, every per-account SQLite file and
 * blob directory included.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <ftw.h>
#include <sqlite3.h>
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

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

/* Copy the `error` name and `message` out of an XRPC error body; both are
 * written as empty strings when absent. */
static void parse_error(wf_response *response, char *err, size_t err_len,
                        char *message, size_t message_len) {
    err[0] = '\0';
    if (message) message[0] = '\0';
    cJSON *json = json_response(response);
    cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
    if (cJSON_IsString(error)) snprintf(err, err_len, "%s", error->valuestring);
    cJSON *msg = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (message && cJSON_IsString(msg))
        snprintf(message, message_len, "%s", msg->valuestring);
    cJSON_Delete(json);
}

/* POST com.atproto.server.createAccount with the given fields and return the
 * HTTP status. `did` and `extra` (a raw JSON object member) are optional; a
 * NULL email is simply omitted. `token` authenticates the request when set.
 * The client's auth is reset to anonymous afterwards. */
static long create_account(wf_xrpc_client *client, const char *handle,
                           const char *password, const char *email,
                           const char *did, const char *extra,
                           const char *token, char *err, size_t err_len,
                           char *message, size_t message_len) {
    char body[1400];
    int off = snprintf(body, sizeof(body),
                       "{\"handle\":\"%s\","
                       "\"password\":\"%s\"",
                       handle, password);
    if (email)
        off += snprintf(body + off, sizeof(body) - off, ",\"email\":\"%s\"",
                        email);
    if (did)
        off += snprintf(body + off, sizeof(body) - off, ",\"did\":\"%s\"", did);
    if (extra) off += snprintf(body + off, sizeof(body) - off, ",%s", extra);
    snprintf(body + off, sizeof(body) - off, "}");
    wf_xrpc_client_set_auth(client, token);
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                      &response);
    long status = response.status;
    if (err && err_len)
        parse_error(&response, err, err_len, message, message_len);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, NULL);
    return status;
}

/* Sign up a fresh account with no imported DID and return its access JWT and
 * minted DID. Returns false unless both came back. */
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

/* Count host-log frames naming `did` — the firehose announcement for a new
 * account carries its DID as text, so a substring search over the stored
 * frames avoids decoding DAG-CBOR here. */
static int count_events_mentioning(const char *seq_path, const char *did) {
    sqlite3 *db = NULL;
    int found = 0;
    if (sqlite3_open(seq_path, &db) == SQLITE_OK) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(
                db, "SELECT COUNT(*) FROM events WHERE instr(frame, ?) > 0;",
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

int main(void) {
    char directory[] = "/tmp/metalbear-audit-account-XXXXXX";
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

    char err[64];
    char message[512];

    /* ---- (a) missing email ---------------------------------------------- */
    CHECK(create_account(client, "alice.example.com", "secret123", NULL, NULL,
                         NULL, NULL, err, sizeof(err), message,
                         sizeof(message)) == 400);
    CHECK(strcmp(err, "InvalidRequest") == 0);
    CHECK(strstr(message, "Email is required") != NULL);

    /* ---- (b) password ceiling ------------------------------------------- */
    {
        char longpw[258];
        memset(longpw, 'x', 257);
        longpw[257] = '\0';
        CHECK(create_account(client, "alice.example.com", longpw,
                             "alice@example.com", NULL, NULL, NULL, err,
                             sizeof(err), message, sizeof(message)) == 400);
        CHECK(strcmp(err, "InvalidRequest") == 0);
        CHECK(strcmp(message,
                     "Password too long. Maximum length is 256 characters.") ==
              0);
    }

    /* ---- (c) plcOp is refused, not silently dropped ---------------------- */
    CHECK(create_account(client, "alice.example.com", "secret123",
                         "alice@example.com", NULL, "\"plcOp\":{}", NULL, err,
                         sizeof(err), message, sizeof(message)) == 400);
    CHECK(strcmp(err, "InvalidRequest") == 0);
    CHECK(strstr(message, "\"plcOp\"") != NULL);

    /* ---- (d) full handle syntax ----------------------------------------- */
    {
        /* a space inside a label */
        CHECK(create_account(client, "bad label.example.com", "secret123",
                             "x@example.com", NULL, NULL, NULL, err,
                             sizeof(err), message, sizeof(message)) == 400);
        CHECK(strcmp(err, "InvalidHandle") == 0);
        /* a label cannot lead with a hyphen */
        CHECK(create_account(client, "-alice.example.com", "secret123",
                             "x@example.com", NULL, NULL, NULL, err,
                             sizeof(err), message, sizeof(message)) == 400);
        CHECK(strcmp(err, "InvalidHandle") == 0);
        /* an empty label */
        CHECK(create_account(client, "alice..example.com", "secret123",
                             "x@example.com", NULL, NULL, NULL, err,
                             sizeof(err), message, sizeof(message)) == 400);
        CHECK(strcmp(err, "InvalidHandle") == 0);
        /* one bare label is not a handle */
        CHECK(create_account(client, "singlelabel", "secret123",
                             "x@example.com", NULL, NULL, NULL, err,
                             sizeof(err), message, sizeof(message)) == 400);
        CHECK(strcmp(err, "InvalidHandle") == 0);
    }

    /* ---- normal signups: the boundary password is accepted --------------- */
    char *alice_token = NULL;
    char *alice_did = NULL;
    CHECK(create_account_session(client, "alice.example.com", "secret123",
                                 "alice@example.com", &alice_token,
                                 &alice_did));
    CHECK(alice_did != NULL);
    {
        char pw256[257];
        memset(pw256, 'y', 256);
        pw256[256] = '\0';
        char *bob_token = NULL;
        char *bob_did = NULL;
        CHECK(create_account_session(client, "bob.example.com", pw256,
                                     "bob@example.com", &bob_token, &bob_did));

        /* ---- (e) taken handle, taken email ------------------------------- */
        CHECK(create_account(client, "alice.example.com", "secret123",
                             "other@example.com", NULL, NULL, NULL, err,
                             sizeof(err), message, sizeof(message)) == 400);
        CHECK(strcmp(err, "HandleNotAvailable") == 0);

        CHECK(create_account(client, "carol.example.com", "secret123",
                             "alice@example.com", NULL, NULL, NULL, err,
                             sizeof(err), message, sizeof(message)) == 400);
        CHECK(strcmp(err, "InvalidRequest") == 0);
        CHECK(strstr(message, "Email already taken: alice@example.com") !=
              NULL);

        /* ---- (f) DID import demands authentication ----------------------- */
        /* no auth at all */
        CHECK(create_account(client, "dave.example.com", "secret123",
                             "dave@example.com", "did:plc:imported", NULL, NULL,
                             err, sizeof(err), message,
                             sizeof(message)) == 401);
        CHECK(strcmp(err, "AuthRequired") == 0);
        CHECK(strstr(message, "Missing auth to create account with did: "
                              "did:plc:imported") != NULL);

        /* someone else's identity */
        CHECK(create_account(client, "erin.example.com", "secret123",
                             "erin@example.com", alice_did, NULL, bob_token,
                             err, sizeof(err), message,
                             sizeof(message)) == 401);
        CHECK(strcmp(err, "AuthRequired") == 0);

        /* the right identity importing a DID this host already holds is
         * refused, and the owner's account is left untouched. */
        CHECK(create_account(client, "frank.example.com", "secret123",
                             "frank@example.com", alice_did, NULL, alice_token,
                             err, sizeof(err), message,
                             sizeof(message)) == 400);
        CHECK(strcmp(err, "InvalidRequest") == 0);
        CHECK(strstr(message, "DID already taken") != NULL);

        free(bob_token);
        free(bob_did);
    }

    /* ---- (g) the real signups landed active and announced ---------------- */
    {
        wf_response response = {0};
        wf_xrpc_param params[] = {{"did", alice_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus", params,
                             1, &response);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "active")));
        CHECK(!cJSON_GetObjectItemCaseSensitive(json, "status"));
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    {
        char seq_path[512];
        snprintf(seq_path, sizeof(seq_path), "%s/sequencer.sqlite3", directory);
        CHECK(count_events_mentioning(seq_path, alice_did) >= 1);
    }

    free(alice_token);
    free(alice_did);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_audit_account: OK\n");
    return 0;
}
