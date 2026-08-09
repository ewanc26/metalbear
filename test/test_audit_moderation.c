#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_audit_moderation.c — offline end-to-end coverage for
 * com.atproto.moderation.createReport, the audit/report trail MetalBear
 * records locally in its SQLite report store.
 *
 * The properties under test are the ones a report is worth nothing without:
 *
 *   (a) a repoRef subject (a did) comes back in the response `subject` union
 *       carrying the discriminating `$type` and the did,
 *   (b) a strongRef subject (uri+cid) comes back carrying
 *       `com.atproto.repo.strongRef`,
 *   (c) an unknown reasonType is refused with InvalidRequest rather than
 *       stored,
 *   (d) a body with no reasonType at all is refused with InvalidRequest, and
 *       is run twice — the path that used to double-free the framework-owned
 *       request body, which aborts on the second pass,
 *   (e) an unauthenticated call is refused with 401 and must not free the
 *       framework-owned request body either,
 *   (f) after all of the above the server still serves a normal,
 *       authenticated report, so the error paths did not corrupt it.
 *
 * Cleanup removes the whole data directory, every per-account SQLite file and
 * blob directory included.
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

static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *password,
                            char *out_did, size_t out_did_len) {
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
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
    if (cJSON_IsString(did) && out_did && out_did_len > 0)
        snprintf(out_did, out_did_len, "%s", did->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* POST a createReport body and return the HTTP status, handing `out` back to
 * the caller for parsing (freed there). */
static long create_report(wf_xrpc_client *client, const char *body,
                          wf_response *out) {
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.moderation.createReport", body,
                      &response);
    long status = response.status;
    if (out)
        *out = response;
    else
        wf_response_free(&response);
    return status;
}

int main(void) {
    char directory[] = "/tmp/metalbear-audit-XXXXXX";
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

    char reporter_did[256] = {0};
    char *reporter = create_account(client, "reporter.example.com", "reportersecret",
                                    reporter_did, sizeof(reporter_did));
    CHECK(reporter != NULL);
    if (!reporter) goto done;
    wf_xrpc_client_set_auth(client, reporter);

    wf_response response = {0};
    char err[64];

    /* ---- (a) repoRef subject -------------------------------------------- */
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"reasonType\":\"com.atproto.moderation.defs#reasonSpam\","
                 "\"reason\":\"unsolicited promotion\","
                 "\"subject\":{\"$type\":\"com.atproto.admin.defs#repoRef\","
                 "\"did\":\"%s\"}}",
                 reporter_did);
        CHECK(create_report(client, body, &response) == 200);
        cJSON *json = json_response(&response);
        CHECK(json != NULL);
        cJSON *subject = cJSON_GetObjectItemCaseSensitive(json, "subject");
        cJSON *type = cJSON_GetObjectItemCaseSensitive(subject, "$type");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(subject, "did");
        cJSON *id = cJSON_GetObjectItemCaseSensitive(json, "id");
        cJSON *reason_type =
            cJSON_GetObjectItemCaseSensitive(json, "reasonType");
        cJSON *reason = cJSON_GetObjectItemCaseSensitive(json, "reason");
        cJSON *reported_by =
            cJSON_GetObjectItemCaseSensitive(json, "reportedBy");
        cJSON *created_at = cJSON_GetObjectItemCaseSensitive(json, "createdAt");
        /* The response `subject` is a closed union: a strict client rejects
         * it without the member-discriminating $type. */
        CHECK(cJSON_IsString(type) &&
              strcmp(type->valuestring, "com.atproto.admin.defs#repoRef") == 0);
        CHECK(cJSON_IsString(did) &&
              strcmp(did->valuestring, reporter_did) == 0);
        CHECK(cJSON_IsNumber(id) && id->valuedouble > 0);
        CHECK(cJSON_IsString(reason_type) &&
              strcmp(reason_type->valuestring,
                     "com.atproto.moderation.defs#reasonSpam") == 0);
        CHECK(cJSON_IsString(reason) &&
              strcmp(reason->valuestring, "unsolicited promotion") == 0);
        CHECK(cJSON_IsString(reported_by) &&
              strcmp(reported_by->valuestring, reporter_did) == 0);
        CHECK(cJSON_IsString(created_at) && created_at->valuestring[0]);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* ---- (b) strongRef subject ------------------------------------------ */
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"reasonType\":\"tools.ozone.report.defs#reasonOther\","
                 "\"subject\":{\"$type\":\"com.atproto.repo.strongRef\","
                 "\"uri\":\"at://%s/app.bsky.feed.post/abc\","
                 "\"cid\":\"bafkreitargetcid\"}}",
                 reporter_did);
        CHECK(create_report(client, body, &response) == 200);
        cJSON *json = json_response(&response);
        CHECK(json != NULL);
        cJSON *subject = cJSON_GetObjectItemCaseSensitive(json, "subject");
        cJSON *type = cJSON_GetObjectItemCaseSensitive(subject, "$type");
        cJSON *uri = cJSON_GetObjectItemCaseSensitive(subject, "uri");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(subject, "cid");
        CHECK(cJSON_IsString(type) &&
              strcmp(type->valuestring, "com.atproto.repo.strongRef") == 0);
        CHECK(cJSON_IsString(uri) && uri->valuestring[0]);
        CHECK(cJSON_IsString(cid) && cid->valuestring[0]);
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* ---- (c) unknown reasonType ----------------------------------------- */
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"reasonType\":\"com.atproto.moderation.defs#reasonTotallyFake\","
                 "\"subject\":{\"did\":\"%s\"}}",
                 reporter_did);
        CHECK(create_report(client, body, &response) == 400);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "InvalidRequest") == 0);
        wf_response_free(&response);
    }

    /* ---- (d) missing reasonType, run twice -------------------------------
     * This is the path that used to cJSON_Delete(request->params) — the
     * framework-owned parsed body the server frees itself after the handler
     * returns. A double-free aborts on the second pass (or under a
     * sanitizer), so two identical requests prove the handler no longer
     * touches it. */
    {
        char body[512];
        snprintf(body, sizeof(body), "{\"subject\":{\"did\":\"%s\"}}", reporter_did);
        CHECK(create_report(client, body, &response) == 400);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "InvalidRequest") == 0);
        wf_response_free(&response);
        CHECK(create_report(client, body, &response) == 400);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "InvalidRequest") == 0);
        wf_response_free(&response);
    }

    /* ---- (e) unauthenticated, run twice ----------------------------------
     * The auth callback (server.c authenticate_request) answers a missing
     * bearer token with WF_ERR_PERMISSION before the handler runs, and the
     * framework turns that into 401 AuthenticationRequired. What matters here
     * is the 401, that it is a real XRPC error envelope, and that a repeat
     * request does not crash — the handler's own 401 guard, which must never
     * free request->params either, stays as defense in depth. */
    wf_xrpc_client_set_auth(client, NULL);
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"reasonType\":\"com.atproto.moderation.defs#reasonSpam\","
                 "\"subject\":{\"did\":\"%s\"}}",
                 reporter_did);
        CHECK(create_report(client, body, &response) == 401);
        error_name(&response, err, sizeof(err));
        CHECK(err[0] != '\0');
        wf_response_free(&response);
        CHECK(create_report(client, body, &response) == 401);
        error_name(&response, err, sizeof(err));
        CHECK(err[0] != '\0');
        wf_response_free(&response);
    }

    /* ---- (f) the server survived all of the above ----------------------- */
    wf_xrpc_client_set_auth(client, reporter);
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"reasonType\":\"com.atproto.moderation.defs#reasonOther\","
                 "\"subject\":{\"did\":\"%s\"}}",
                 reporter_did);
        CHECK(create_report(client, body, &response) == 200);
        wf_response_free(&response);
    }

done:
    free(reporter);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_audit_moderation: OK\n");
    return 0;
}
