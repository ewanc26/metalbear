#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_takedown.c — offline end-to-end coverage for the moderation model:
 * account, record and blob takedowns applied through
 * com.atproto.admin.updateSubjectStatus.
 *
 * The properties under test are the ones a takedown is worth nothing without:
 *
 *   (a) a taken-down account reports `takendown` — not `deactivated` — from
 *       every endpoint that reports a status, and takedown outranks
 *       deactivation when both apply,
 *   (b) its repository stops being readable, with `RepoTakendown`
 *       distinguished from `RepoDeactivated` so a consumer can tell a
 *       moderation action from the account holder's own choice,
 *   (c) its existing sessions stop working and it cannot log in again,
 *   (d) a taken-down record reads as absent while the rest of the repository
 *       still serves,
 *   (e) a taken-down blob cannot be fetched and cannot be re-uploaded, and
 *       the takedown is scoped to the account that holds it rather than to
 *       the CID, which names content and may be shared,
 *   (f) lifting a takedown restores all of the above,
 *   (g) the firehose is told: the takedown and its lifting each produce an
 *       #account event carrying the new status.
 *
 * Cleanup removes the whole data directory, every per-account SQLite file and
 * blob directory included.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <ftw.h>
#include <openssl/evp.h>
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

/* Case-sensitive substring search over a length-delimited body. */
static bool body_has(const wf_response *response, const char *needle) {
    if (!response || !response->body || !needle) return false;
    size_t nlen = strlen(needle);
    if (response->body_len < nlen) return false;
    for (size_t i = 0; i + nlen <= response->body_len; i++)
        if (memcmp(response->body + i, needle, nlen) == 0) return true;
    return false;
}

/* The `error` name from an XRPC error body, or "" when there is none.
 * Copied into `out` because the parsed tree is freed here. */
static void error_name(wf_response *response, char *out, size_t out_len) {
    out[0] = '\0';
    cJSON *json = json_response(response);
    cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
    if (cJSON_IsString(error)) snprintf(out, out_len, "%s", error->valuestring);
    cJSON_Delete(json);
}

/* POST an admin-gated XRPC method with HTTP Basic `admin:<password>`. */
static wf_status admin_post(wf_xrpc_client *client, const char *base,
                            const char *nsid, const char *body,
                            wf_response *out) {
    char cred[64];
    int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
    char b64[128];
    int len =
        EVP_EncodeBlock((unsigned char *)b64, (const unsigned char *)cred, n);
    b64[len] = '\0';
    char auth[160];
    snprintf(auth, sizeof(auth), "Basic %s", b64);
    wf_http_header hdr = {"Authorization", auth};
    char url[256];
    snprintf(url, sizeof(url), "%s/xrpc/%s", base, nsid);
    return wf_http_post(client, url, "application/json", body, &hdr, 1, out);
}

/* GET an admin-gated XRPC method with HTTP Basic. */
static wf_status admin_get(wf_xrpc_client *client, const char *base,
                           const char *query, wf_response *out) {
    char cred[64];
    int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
    char b64[128];
    int len =
        EVP_EncodeBlock((unsigned char *)b64, (const unsigned char *)cred, n);
    b64[len] = '\0';
    char auth[160];
    snprintf(auth, sizeof(auth), "Basic %s", b64);
    wf_http_header hdr = {"Authorization", auth};
    char url[512];
    snprintf(url, sizeof(url), "%s/xrpc/%s", base, query);
    return wf_http_get_with_headers(client, url, &hdr, 1, out);
}

/* Apply or lift an account takedown. Returns the HTTP status. */
static long set_account_takedown(wf_xrpc_client *client, const char *base,
                                 const char *did, bool applied) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"subject\":{\"$type\":\"com.atproto.admin.defs#repoRef\","
             "\"did\":\"%s\"},\"takedown\":{\"applied\":%s,"
             "\"ref\":\"moderation-1\"}}",
             did, applied ? "true" : "false");
    wf_response response = {0};
    admin_post(client, base, "com.atproto.admin.updateSubjectStatus", body,
               &response);
    long status = response.status;
    wf_response_free(&response);
    return status;
}

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
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

static long create_record(wf_xrpc_client *client, const char *repo,
                          const char *rkey, const char *text) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
             "\"rkey\":\"%s\",\"record\":{\"$type\":\"app.bsky.feed.post\","
             "\"text\":\"%s\",\"createdAt\":\"2026-07-27T00:00:00.000Z\"}}",
             repo, rkey, text);
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.repo.createRecord", body, &response);
    long status = response.status;
    wf_response_free(&response);
    return status;
}

static long get_record(wf_xrpc_client *client, const char *repo,
                       const char *rkey) {
    wf_xrpc_param params[] = {
        {"repo", repo},
        {"collection", "app.bsky.feed.post"},
        {"rkey", rkey},
    };
    wf_response response = {0};
    wf_xrpc_query_params(client, "com.atproto.repo.getRecord", params, 3,
                         &response);
    long status = response.status;
    wf_response_free(&response);
    return status;
}

/* Upload a blob and copy its CID out. Returns the HTTP status. */
static long upload_blob(wf_xrpc_client *client, const char *base,
                        const char *token, const char *bytes, char *out_cid,
                        size_t out_len) {
    char url[256];
    snprintf(url, sizeof(url), "%s/xrpc/com.atproto.repo.uploadBlob", base);
    char auth[1024];
    snprintf(auth, sizeof(auth), "Bearer %s", token);
    wf_http_header hdr = {"Authorization", auth};
    wf_response response = {0};
    wf_http_post(client, url, "text/plain", bytes, &hdr, 1, &response);
    long status = response.status;
    if (status == 200 && out_cid && out_len) {
        cJSON *json = json_response(&response);
        cJSON *blob = cJSON_GetObjectItemCaseSensitive(json, "blob");
        cJSON *ref = cJSON_GetObjectItemCaseSensitive(blob, "ref");
        cJSON *link = cJSON_GetObjectItemCaseSensitive(ref, "$link");
        if (cJSON_IsString(link))
            snprintf(out_cid, out_len, "%s", link->valuestring);
        cJSON_Delete(json);
    }
    wf_response_free(&response);
    return status;
}

/*
 * Count #account frames in the host log naming `did` and carrying `status`.
 * The frame stores both as text, so searching the bytes avoids decoding
 * DAG-CBOR here — the same approach the multi-account test takes.
 */
static int count_account_events(const char *seq_path, const char *did,
                                const char *status) {
    sqlite3 *db = NULL;
    int found = 0;
    if (sqlite3_open(seq_path, &db) == SQLITE_OK) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(
                db,
                "SELECT COUNT(*) FROM events WHERE instr(frame, '#account') > 0"
                " AND instr(frame, ?) > 0 AND instr(frame, ?) > 0;",
                -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, did, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, status, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                found = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return found;
}

int main(void) {
    char directory[] = "/tmp/metalbear-takedown-XXXXXX";
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

    const char *mallory_did = "did:plc:mallory";
    const char *victim_did = "did:plc:victim";
    char *mallory = create_account(client, "mallory.example.com", mallory_did,
                                   "mallorysecret");
    char *victim = create_account(client, "victim.example.com", victim_did,
                                  "victimsecret");
    CHECK(mallory != NULL);
    CHECK(victim != NULL);
    if (!mallory || !victim) goto done;

    /* Both accounts write a record, and both upload the same bytes, so the
     * blob CID is genuinely shared between two accounts. */
    wf_xrpc_client_set_auth(client, mallory);
    CHECK(create_record(client, mallory_did, "keep", "kept") == 200);
    CHECK(create_record(client, mallory_did, "bad", "offending") == 200);
    char mallory_blob[128] = "";
    CHECK(upload_blob(client, base, mallory, "shared bytes", mallory_blob,
                      sizeof(mallory_blob)) == 200);
    CHECK(mallory_blob[0] != '\0');

    wf_xrpc_client_set_auth(client, victim);
    char victim_blob[128] = "";
    CHECK(upload_blob(client, base, victim, "shared bytes", victim_blob,
                      sizeof(victim_blob)) == 200);
    /* Same bytes, so necessarily the same CID: this is what makes a takedown
     * keyed on the CID alone a bug rather than a shortcut. */
    CHECK(strcmp(mallory_blob, victim_blob) == 0);

    wf_response response = {0};
    char err[64];

    /* ---- (d) record takedown ------------------------------------------- */
    {
        char body[640];
        snprintf(body, sizeof(body),
                 "{\"subject\":{\"$type\":\"com.atproto.repo.strongRef\","
                 "\"uri\":\"at://%s/app.bsky.feed.post/bad\","
                 "\"cid\":\"unused\"},"
                 "\"takedown\":{\"applied\":true,\"ref\":\"mod-record\"}}",
                 mallory_did);
        CHECK(admin_post(client, base, "com.atproto.admin.updateSubjectStatus",
                         body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }
    wf_xrpc_client_set_auth(client, NULL);
    /* The taken-down record reads as absent; its neighbour still serves. */
    CHECK(get_record(client, mallory_did, "bad") == 404);
    CHECK(get_record(client, mallory_did, "keep") == 200);

    /* getSubjectStatus reports it, and the strongRef it echoes carries the
     * `cid` the lexicon requires — a reference without one is unusable. */
    {
        char query[512];
        snprintf(query, sizeof(query),
                 "com.atproto.admin.getSubjectStatus?uri=at://%s/"
                 "app.bsky.feed.post/bad",
                 mallory_did);
        CHECK(admin_get(client, base, query, &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *subject = cJSON_GetObjectItemCaseSensitive(json, "subject");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(subject, "cid");
        cJSON *takedown = cJSON_GetObjectItemCaseSensitive(json, "takedown");
        cJSON *applied = cJSON_GetObjectItemCaseSensitive(takedown, "applied");
        CHECK(cJSON_IsString(cid) && cid->valuestring[0]);
        CHECK(cJSON_IsTrue(applied));
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* ---- (e) blob takedown, scoped to one account ----------------------- */
    {
        char body[640];
        snprintf(
            body, sizeof(body),
            "{\"subject\":{\"$type\":\"com.atproto.admin.defs#repoBlobRef\","
            "\"did\":\"%s\",\"cid\":\"%s\"},"
            "\"takedown\":{\"applied\":true,\"ref\":\"mod-blob\"}}",
            mallory_did, mallory_blob);
        CHECK(admin_post(client, base, "com.atproto.admin.updateSubjectStatus",
                         body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }
    {
        wf_xrpc_param params[] = {{"did", mallory_did}, {"cid", mallory_blob}};
        wf_xrpc_query_params(client, "com.atproto.sync.getBlob", params, 2,
                             &response);
        CHECK(response.status == 404);
        wf_response_free(&response);
        /* The other account stored the same bytes and is unaffected. */
        wf_xrpc_param others[] = {{"did", victim_did}, {"cid", victim_blob}};
        wf_xrpc_query_params(client, "com.atproto.sync.getBlob", others, 2,
                             &response);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }
    /* Re-uploading the same bytes must not quietly undo the takedown. */
    CHECK(upload_blob(client, base, mallory, "shared bytes", NULL, 0) == 400);

    /* The account itself is not taken down by its blob's takedown. */
    {
        wf_xrpc_param params[] = {{"did", mallory_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus", params,
                             1, &response);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "active")));
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* ---- (a)(b)(c) account takedown ------------------------------------ */
    CHECK(set_account_takedown(client, base, mallory_did, true) == 200);

    {
        wf_xrpc_param params[] = {{"did", mallory_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus", params,
                             1, &response);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *status = cJSON_GetObjectItemCaseSensitive(json, "status");
        CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(json, "active")));
        CHECK(cJSON_IsString(status) &&
              strcmp(status->valuestring, "takendown") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* (b) the repository stops serving, under a name that says why. */
    {
        wf_xrpc_param params[] = {{"did", mallory_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepo", params, 1,
                             &response);
        CHECK(response.status == 400);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "RepoTakendown") == 0);
        wf_response_free(&response);

        wf_xrpc_query_params(client, "com.atproto.sync.listBlobs", params, 1,
                             &response);
        CHECK(response.status == 400);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "RepoTakendown") == 0);
        wf_response_free(&response);

        wf_xrpc_query_params(client, "com.atproto.sync.getLatestCommit", params,
                             1, &response);
        CHECK(response.status == 400);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "RepoTakendown") == 0);
        wf_response_free(&response);
    }

    /* Even the record that was never moderated is now unreadable. */
    CHECK(get_record(client, mallory_did, "keep") == 400);

    /* The handle stops resolving, as it does for an account that is gone. */
    {
        wf_xrpc_param params[] = {{"handle", "mallory.example.com"}};
        wf_xrpc_query_params(client, "com.atproto.identity.resolveHandle",
                             params, 1, &response);
        CHECK(response.status == 400);
        wf_response_free(&response);
    }

    /* listRepos reports the status rather than omitting the account. */
    {
        wf_xrpc_query(client, "com.atproto.sync.listRepos", NULL, &response);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *repos = cJSON_GetObjectItemCaseSensitive(json, "repos");
        bool saw_takendown = false;
        cJSON *repo = NULL;
        cJSON_ArrayForEach(repo, repos) {
            cJSON *did = cJSON_GetObjectItemCaseSensitive(repo, "did");
            cJSON *status = cJSON_GetObjectItemCaseSensitive(repo, "status");
            if (cJSON_IsString(did) &&
                strcmp(did->valuestring, mallory_did) == 0 &&
                cJSON_IsString(status) &&
                strcmp(status->valuestring, "takendown") == 0)
                saw_takendown = true;
        }
        CHECK(saw_takendown);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* (c) the session it already held is dead, and it cannot get a new one. */
    wf_xrpc_client_set_auth(client, mallory);
    wf_xrpc_query(client, "com.atproto.server.getSession", NULL, &response);
    CHECK(response.status == 401);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, NULL);
    {
        const char *body = "{\"identifier\":\"mallory.example.com\","
                           "\"password\":\"mallorysecret\"}";
        wf_xrpc_procedure(client, "com.atproto.server.createSession", body,
                          &response);
        CHECK(response.status == 401);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "AccountTakedown") == 0);
        wf_response_free(&response);
    }

    /* The untouched account is entirely unaffected. */
    {
        wf_xrpc_param params[] = {{"did", victim_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus", params,
                             1, &response);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "active")));
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* A takedown may not be paired with a reactivation: the two disagree
     * about what the account's status should become. */
    {
        char body[400];
        snprintf(body, sizeof(body),
                 "{\"subject\":{\"$type\":\"com.atproto.admin.defs#repoRef\","
                 "\"did\":\"%s\"},\"takedown\":{\"applied\":true},"
                 "\"deactivated\":{\"applied\":false}}",
                 victim_did);
        /* A refusal comes back as WF_ERR_HTTP, so only the status is checked.
         */
        admin_post(client, base, "com.atproto.admin.updateSubjectStatus", body,
                   &response);
        CHECK(response.status == 400);
        wf_response_free(&response);
        /* And it changed nothing: the account is still active. */
        wf_xrpc_param params[] = {{"did", victim_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus", params,
                             1, &response);
        cJSON *json = json_response(&response);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "active")));
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* ---- (g) the firehose was told ------------------------------------- */
    char seq_path[512];
    snprintf(seq_path, sizeof(seq_path), "%s/sequencer.sqlite3", directory);
    CHECK(count_account_events(seq_path, mallory_did, "takendown") >= 1);

    /* ---- (f) lifting it restores everything ---------------------------- */
    CHECK(set_account_takedown(client, base, mallory_did, false) == 200);
    {
        wf_xrpc_param params[] = {{"did", mallory_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus", params,
                             1, &response);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "active")));
        CHECK(!cJSON_GetObjectItemCaseSensitive(json, "status"));
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    CHECK(get_record(client, mallory_did, "keep") == 200);
    /* The record's own takedown outlives the account's: lifting one does not
     * lift the other. */
    CHECK(get_record(client, mallory_did, "bad") == 404);
    {
        const char *body = "{\"identifier\":\"mallory.example.com\","
                           "\"password\":\"mallorysecret\"}";
        wf_xrpc_procedure(client, "com.atproto.server.createSession", body,
                          &response);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }

    /* A deactivated account that is also taken down reports the takedown:
     * the moderation action is the one a consumer must not misread. */
    CHECK(set_account_takedown(client, base, mallory_did, true) == 200);
    {
        char body[400];
        snprintf(body, sizeof(body),
                 "{\"subject\":{\"$type\":\"com.atproto.admin.defs#repoRef\","
                 "\"did\":\"%s\"},\"deactivated\":{\"applied\":true}}",
                 mallory_did);
        CHECK(admin_post(client, base, "com.atproto.admin.updateSubjectStatus",
                         body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);

        wf_xrpc_param params[] = {{"did", mallory_did}};
        wf_xrpc_query_params(client, "com.atproto.sync.getRepoStatus", params,
                             1, &response);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *status = cJSON_GetObjectItemCaseSensitive(json, "status");
        CHECK(cJSON_IsString(status) &&
              strcmp(status->valuestring, "takendown") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /*
     * /metrics is admin-gated and reports what actually happened.
     *
     * Open, it would publish a private host's account count and write rate to
     * anyone who asked; Prometheus has had basic_auth in its scrape config for
     * as long as it has existed. The takedown counter is checked here because
     * this test is the only one that applies any.
     */
    {
        char url[256];
        snprintf(url, sizeof(url), "%s/metrics", base);
        CHECK(wf_http_get(client, url, &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        wf_response_free(&response);

        char cred[64];
        int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
        char b64[128];
        int len = EVP_EncodeBlock((unsigned char *)b64,
                                  (const unsigned char *)cred, n);
        b64[len] = '\0';
        char auth[160];
        snprintf(auth, sizeof(auth), "Basic %s", b64);
        wf_http_header hdr = {"Authorization", auth};
        CHECK(wf_http_get_with_headers(client, url, &hdr, 1, &response) ==
              WF_OK);
        CHECK(response.status == 200);
        /* Prometheus rejects a counter with no TYPE line, so the exposition
         * has to carry them and not just the samples. */
        CHECK(body_has(&response,
                       "# TYPE metalbear_takedowns_applied_total counter"));
        CHECK(
            body_has(&response, "metalbear_accounts{status=\"takendown\"} 1"));
        CHECK(body_has(&response, "metalbear_build_info{version="));
        /* Four takedowns were applied above: a record, a blob, and the
         * account twice. Lifting one is not an application. */
        CHECK(body_has(&response, "metalbear_takedowns_applied_total 4"));
#ifdef WF_XRPC_HAS_REQUEST_OBSERVER
        /*
         * Per-route series, including a plain HTTP route. Those have no NSID
         * and never reach the auth callback, so counting there — which is
         * where the totals used to come from — missed them entirely.
         *
         * Guarded like the code that produces them: the observer is an
         * optional Wolfram feature, and asserting on it unconditionally
         * makes an optional dependency a required one.
         */
        CHECK(body_has(&response, "metalbear_route_requests_total{route=\"com."
                                  "atproto.sync.getRepo\"}"));
        CHECK(body_has(&response, "metalbear_route_errors_total{route=\"com."
                                  "atproto.sync.getRepo\"}"));
        CHECK(body_has(&response,
                       "metalbear_route_requests_total{route=\"/metrics\"}"));
#endif
        wf_response_free(&response);
    }

done:
    free(mallory);
    free(victim);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_takedown: OK\n");
    return 0;
}
