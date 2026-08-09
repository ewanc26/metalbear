#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_audit_sync.c — offline end-to-end coverage for three behaviors that
 * audit and sync clients depend on:
 *
 *   (a) com.atproto.sync.listBlobs honors its `since` rev: only blobs whose
 *       first-seen rev sorts after the given repo revision are listed,
 *   (b) com.atproto.server.refreshSession distinguishes an invalid/malformed
 *       refresh token (`InvalidToken`) from a genuine token that was revoked
 *       or expired (`ExpiredToken`), matching the lexicon's error names,
 *   (c) com.atproto.repo.createRecord / putRecord / applyWrites always report
 *       `validationStatus` in their results, even when the client passed
 *       validate:false (which reports "unknown" — nothing was checked).
 *
 * Cleanup removes the whole data directory, every per-account SQLite file and
 * blob directory included.
 */

#include "metalbear/server.h"
#include "wolfram/crypto.h"
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

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
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

static bool json_array_has(const cJSON *arr, const char *s) {
    if (!cJSON_IsArray(arr)) return false;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (cJSON_IsString(item) && strcmp(item->valuestring, s) == 0)
            return true;
    }
    return false;
}

/* Create an account and copy its access and refresh JWTs out. Returns the
 * HTTP status (200 on success). */
static long create_account(wf_xrpc_client *client, const char *handle,
                            const char *password,
                            char *out_access, size_t access_len,
                            char *out_refresh, size_t refresh_len,
                            char *out_did, size_t out_did_len) {
    char body[256];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"%s\","
             "\"email\":\"%s@example.com\"}",
             handle, password, handle);
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                      &response);
    long status = response.status;
    if (status == 200) {
        cJSON *json = json_response(&response);
        cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
        cJSON *refresh = cJSON_GetObjectItemCaseSensitive(json, "refreshJwt");
        cJSON *did_item = cJSON_GetObjectItemCaseSensitive(json, "did");
        if (cJSON_IsString(access) && out_access)
            snprintf(out_access, access_len, "%s", access->valuestring);
        if (cJSON_IsString(refresh) && out_refresh)
            snprintf(out_refresh, refresh_len, "%s", refresh->valuestring);
        if (cJSON_IsString(did_item) && out_did)
            snprintf(out_did, out_did_len, "%s", did_item->valuestring);
        cJSON_Delete(json);
    }
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

/* putRecord for a record whose image embed names blob `cid`. Copies the
 * resulting commit.rev out. Returns the HTTP status. */
static long put_record_with_blob(wf_xrpc_client *client, const char *repo,
                                 const char *rkey, const char *cid,
                                 char *out_rev, size_t out_rev_len) {
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"repo\":\"%s\",\"collection\":\"com.example.audit\","
             "\"rkey\":\"%s\",\"record\":{\"$type\":\"com.example.audit\","
             "\"image\":{\"$type\":\"blob\",\"ref\":{\"$link\":\"%s\"},"
             "\"mimeType\":\"text/plain\",\"size\":16}}}",
             repo, rkey, cid);
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.repo.putRecord", body, &response);
    long status = response.status;
    if (status == 200 && out_rev && out_rev_len) {
        cJSON *json = json_response(&response);
        cJSON *commit = cJSON_GetObjectItemCaseSensitive(json, "commit");
        cJSON *rev = cJSON_GetObjectItemCaseSensitive(commit, "rev");
        if (cJSON_IsString(rev) && rev->valuestring[0])
            snprintf(out_rev, out_rev_len, "%s", rev->valuestring);
        else
            out_rev[0] = '\0';
        cJSON_Delete(json);
    }
    wf_response_free(&response);
    return status;
}

/* Query listBlobs and return the parsed body on success (*out), plus the HTTP
 * status. */
static long list_blobs(wf_xrpc_client *client, const char *did,
                       const char *since, cJSON **out) {
    wf_xrpc_param params[2];
    int n = 0;
    params[n].name = "did";
    params[n].value = did;
    n++;
    if (since) {
        params[n].name = "since";
        params[n].value = since;
        n++;
    }
    wf_response response = {0};
    wf_status st = wf_xrpc_query_params(client, "com.atproto.sync.listBlobs",
                                        params, (size_t)n, &response);
    long status = response.status;
    if (out) *out = st == WF_OK ? json_response(&response) : NULL;
    wf_response_free(&response);
    return status;
}

/* Build a JWT-shaped (but unsigned/unverifiable) bearer token naming `sub`.
 */
static char *build_fake_jwt(const char *sub) {
    char payload_json[256];
    snprintf(payload_json, sizeof(payload_json), "{\"sub\":\"%s\"}", sub);
    char *payload_b64 = NULL;
    if (wf_crypto_base64url_encode((const unsigned char *)payload_json,
                                   strlen(payload_json), &payload_b64) != WF_OK)
        return NULL;
    char *token = malloc(strlen(payload_b64) + 16);
    if (token) sprintf(token, "x.%s.x", payload_b64);
    free(payload_b64);
    return token;
}

/* Assert `validationStatus` is present in the response and carries one of the
 * lexicon's values, returning the value in `out`. */
static void expect_validation_status(wf_response *response, char *out,
                                     size_t out_len) {
    out[0] = '\0';
    cJSON *json = json_response(response);
    cJSON *vs = cJSON_GetObjectItemCaseSensitive(json, "validationStatus");
    CHECK(cJSON_IsString(vs));
    if (cJSON_IsString(vs)) {
        CHECK(strcmp(vs->valuestring, "valid") == 0 ||
              strcmp(vs->valuestring, "unknown") == 0);
        snprintf(out, out_len, "%s", vs->valuestring);
    }
    cJSON_Delete(json);
}

int main(void) {
    char directory[] = "/tmp/metalbear-audit-sync-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
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

    char did_buf[128] = "";
    char access[2048] = "";
    char refresh[2048] = "";
    CHECK(create_account(client, "audit.example.com", "auditsecret",
                         access, sizeof(access), refresh, sizeof(refresh),
                         did_buf, sizeof(did_buf)) == 200);
    const char *did = did_buf;
    CHECK(access[0] != '\0');
    CHECK(refresh[0] != '\0');
    wf_xrpc_client_set_auth(client, access);

    wf_response response = {0};
    char err[64];

    /* ---- (a) listBlobs honors `since` ------------------------------- */
    char cid1[128] = "";
    char cid2[128] = "";
    CHECK(upload_blob(client, base, access, "first blob bytes", cid1,
                      sizeof(cid1)) == 200);
    CHECK(cid1[0] != '\0');

    /* The first record is written while only blob1 exists: the blob store
     * first-saw blob1 (its upload TID) strictly before this commit's rev. */
    char rev1[64] = "";
    CHECK(put_record_with_blob(client, did, "one", cid1, rev1,
                               sizeof(rev1)) == 200);
    CHECK(rev1[0] != '\0');

    /* Blob2 is uploaded after commit 1, so its first-seen TID sorts after
     * rev1 — exactly what `since` filters on. */
    CHECK(upload_blob(client, base, access, "second blob bytes", cid2,
                      sizeof(cid2)) == 200);
    CHECK(cid2[0] != '\0');
    CHECK(strcmp(cid1, cid2) != 0);

    char rev2[64] = "";
    CHECK(put_record_with_blob(client, did, "two", cid2, rev2,
                               sizeof(rev2)) == 200);
    CHECK(rev2[0] != '\0');

    /* Without `since`, both blobs are listed. */
    {
        cJSON *root = NULL;
        CHECK(list_blobs(client, did, NULL, &root) == 200);
        CHECK(root != NULL);
        cJSON *cids = cJSON_GetObjectItemCaseSensitive(root, "cids");
        CHECK(json_array_has(cids, cid1));
        CHECK(json_array_has(cids, cid2));
        cJSON_Delete(root);
    }

    /* Since commit 1, only blob2 has been seen. */
    {
        cJSON *root = NULL;
        CHECK(list_blobs(client, did, rev1, &root) == 200);
        CHECK(root != NULL);
        cJSON *cids = cJSON_GetObjectItemCaseSensitive(root, "cids");
        CHECK(!json_array_has(cids, cid1));
        CHECK(json_array_has(cids, cid2));
        cJSON_Delete(root);
    }

    /* Since commit 2, nothing new has been seen. */
    {
        cJSON *root = NULL;
        CHECK(list_blobs(client, did, rev2, &root) == 200);
        CHECK(root != NULL);
        cJSON *cids = cJSON_GetObjectItemCaseSensitive(root, "cids");
        CHECK(cJSON_IsArray(cids) && cJSON_GetArraySize(cids) == 0);
        cJSON_Delete(root);
    }

    /* ---- (b) refreshSession distinguishes InvalidToken/ExpiredToken ---- */
    /* A genuine refresh token rotates successfully. */
    char rotated[2048] = "";
    {
        wf_xrpc_client_set_auth(client, refresh);
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                "{}", &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *new_refresh =
            cJSON_GetObjectItemCaseSensitive(json, "refreshJwt");
        if (cJSON_IsString(new_refresh))
            snprintf(rotated, sizeof(rotated), "%s", new_refresh->valuestring);
        cJSON_Delete(json);
        wf_response_free(&response);
    }
    CHECK(rotated[0] != '\0' && strcmp(rotated, refresh) != 0);

    /* Revoke the rotated token, then confirm refreshing it is reported as
     * ExpiredToken — the token is genuine, just no longer usable. */
    {
        wf_xrpc_client_set_auth(client, rotated);
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.deleteSession",
                                "{}", &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);

        CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                "{}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "ExpiredToken") == 0);
        wf_response_free(&response);
    }

    /* A token that is not even a JWT fails verification outright. */
    {
        wf_xrpc_client_set_auth(client, "not-a-jwt");
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                "{}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "AuthenticationRequired") == 0);
        wf_response_free(&response);
    }

    /* A JWT-shaped token naming this account but with no valid signature
     * also fails verification: InvalidToken, not ExpiredToken. */
    {
        char *fake = build_fake_jwt(did);
        CHECK(fake != NULL);
        wf_xrpc_client_set_auth(client, fake);
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                "{}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "InvalidToken") == 0);
        wf_response_free(&response);
        free(fake);
    }

    /* A JWT-shaped token naming an account this server never minted is
     * equally unverifiable. */
    {
        char *fake = build_fake_jwt("did:plc:nobodyhome");
        CHECK(fake != NULL);
        wf_xrpc_client_set_auth(client, fake);
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.refreshSession",
                                "{}", &response) == WF_ERR_HTTP);
        CHECK(response.status == 401);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "AuthenticationRequired") == 0);
        wf_response_free(&response);
        free(fake);
    }

    /* ---- (c) validationStatus is always reported on writes ------------ */
    wf_xrpc_client_set_auth(client, access);

    /* createRecord: known-schema collection, no validate input. */
    {
        char body[512];
        snprintf(body, sizeof(body),
            "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
            "\"record\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"hello\","
            "\"createdAt\":\"2026-08-08T00:00:00.000Z\"}}", did);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord", body,
                                &response) == WF_OK);
        CHECK(response.status == 200);
        char vs[16];
        expect_validation_status(&response, vs, sizeof(vs));
        wf_response_free(&response);
    }

    /* createRecord with validate:false still reports the field, as "unknown"
     * (nothing was checked). */
    {
        char body[512];
        snprintf(body, sizeof(body),
            "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
            "\"record\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"hello\","
            "\"createdAt\":\"2026-08-08T00:00:00.000Z\"},\"validate\":false}",
            did);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord", body,
                                &response) == WF_OK);
        CHECK(response.status == 200);
        char vs[16];
        expect_validation_status(&response, vs, sizeof(vs));
        CHECK(strcmp(vs, "unknown") == 0);
        wf_response_free(&response);
    }

    /* putRecord with validate:false. */
    {
        char body[512];
        snprintf(body, sizeof(body),
            "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
            "\"rkey\":\"pv1\",\"record\":{\"$type\":\"app.bsky.feed.post\","
            "\"text\":\"put\",\"createdAt\":\"2026-08-08T00:00:00.000Z\"},"
            "\"validate\":false}", did);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.putRecord", body,
                                &response) == WF_OK);
        CHECK(response.status == 200);
        char vs[16];
        expect_validation_status(&response, vs, sizeof(vs));
        CHECK(strcmp(vs, "unknown") == 0);
        wf_response_free(&response);
    }

    /* applyWrites: every create/update result carries the field. */
    {
        char body[512];
        snprintf(body, sizeof(body),
            "{\"repo\":\"%s\",\"writes\":["
            "{\"$type\":\"com.atproto.repo.applyWrites#create\","
            "\"collection\":\"com.example.audit\",\"rkey\":\"aw1\","
            "\"value\":{\"$type\":\"com.example.audit\",\"note\":\"one\"}}],"
            "\"validate\":false}", did);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.applyWrites", body,
                                &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *results = cJSON_GetObjectItemCaseSensitive(json, "results");
        cJSON *entry = cJSON_GetArrayItem(results, 0);
        cJSON *vs =
            cJSON_GetObjectItemCaseSensitive(entry, "validationStatus");
        CHECK(cJSON_IsString(vs) && strcmp(vs->valuestring, "unknown") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    {
        char body[512];
        snprintf(body, sizeof(body),
            "{\"repo\":\"%s\",\"writes\":["
            "{\"$type\":\"com.atproto.repo.applyWrites#create\","
            "\"collection\":\"app.bsky.feed.post\",\"rkey\":\"aw2\","
            "\"value\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"two\","
            "\"createdAt\":\"2026-08-08T00:00:00.000Z\"}}]}", did);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.applyWrites", body,
                                &response) == WF_OK);
        CHECK(response.status == 200);
        cJSON *json = json_response(&response);
        cJSON *results = cJSON_GetObjectItemCaseSensitive(json, "results");
        cJSON *entry = cJSON_GetArrayItem(results, 0);
        cJSON *vs =
            cJSON_GetObjectItemCaseSensitive(entry, "validationStatus");
        CHECK(cJSON_IsString(vs));
        if (cJSON_IsString(vs))
            CHECK(strcmp(vs->valuestring, "valid") == 0 ||
                  strcmp(vs->valuestring, "unknown") == 0);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

done:
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_audit_sync: OK\n");
    return 0;
}
