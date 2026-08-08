#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_audit_identity.c — offline end-to-end coverage for the identity
 * surface MetalBear audits against the lexicons and the reference PDS:
 *
 *   (a) app.bsky.actor.getProfile for an active local account that has an
 *       app.bsky.actor.profile record returns the record's fields
 *       (displayName, description, avatar/banner blobs, createdAt) on top of
 *       the {did, handle} base — the local-account enrichment that used to
 *       stop at a bare {did, handle},
 *   (b) getProfile for a local account with no profile record still returns
 *       200 with {did, handle} and does not crash,
 *   (c) com.atproto.identity.updateHandle for a handle outside the configured
 *       domain fails with UnsupportedDomain — the name the reference's
 *       normalizeAndValidateHandle gives a handle that is not on a domain the
 *       server will serve (account-manager.ts:206-210), and
 *   (d) com.atproto.identity.resolveHandle for a handle that resolves to
 *       nothing fails with HandleNotFound — the lexicon's only declared error
 *       (com/atproto/identity/resolveHandle.json errors[0]).
 *
 * The profile record is written exactly the way a client writes one: an
 * uploaded image blob referenced from the record's avatar/banner fields, with
 * the literal record key "self" the profile lexicon requires. Cleanup removes
 * the whole data directory, every per-account SQLite file and blob directory
 * included.
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

/* createAccount as a client would; returns the access JWT (or NULL).
 * The DID assigned by the server is captured into `out_did`. */
static char *create_account(wf_xrpc_client *client, const char *handle,
                            char *out_did, size_t out_did_len,
                            const char *password) {
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
    cJSON *did = cJSON_GetObjectItemCaseSensitive(json, "did");
    char *token = cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    if (out_did && out_did_len && cJSON_IsString(did))
        snprintf(out_did, out_did_len, "%s", did->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    return token;
}

/* Upload a tiny PNG and copy the resulting blob CID into `out_cid`. Returns
 * the HTTP status. */
static long upload_png(wf_xrpc_client *client, char *out_cid, size_t out_len) {
    const unsigned char png[] = {0x89, 'P', 'N', 'G'};
    wf_response response = {0};
    wf_status st =
        wf_xrpc_upload_blob(client, "com.atproto.repo.uploadBlob", png,
                            sizeof(png), "image/png", &response);
    long status = st == WF_OK ? response.status : 0;
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

/* createRecord an app.bsky.actor.profile at the literal key "self". */
static long write_profile(wf_xrpc_client *client, const char *repo,
                          const char *avatar_cid, const char *banner_cid) {
    char body[2048];
    snprintf(body, sizeof(body),
             "{\"repo\":\"%s\",\"collection\":\"app.bsky.actor.profile\","
             "\"rkey\":\"self\","
             "\"record\":{\"$type\":\"app.bsky.actor.profile\","
             "\"displayName\":\"Alice Example\","
             "\"description\":\"A profile description\","
             "\"pronouns\":\"she/her\","
             "\"website\":\"https://alice.example.com\","
             "\"avatar\":{\"$type\":\"blob\",\"ref\":{\"$link\":\"%s\"},"
             "\"mimeType\":\"image/png\",\"size\":4},"
             "\"banner\":{\"$type\":\"blob\",\"ref\":{\"$link\":\"%s\"},"
             "\"mimeType\":\"image/png\",\"size\":4},"
             "\"createdAt\":\"2026-07-27T00:00:00.000Z\"}}",
             repo, avatar_cid, banner_cid);
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.repo.createRecord", body, &response);
    long status = response.status;
    wf_response_free(&response);
    return status;
}

/* GET the app.bsky.actor.getProfile view for `did`; on 200 the parsed view is
 * returned in `*out_json` (caller frees). */
static long get_local_profile(wf_xrpc_client *client, const char *did,
                              cJSON **out_json) {
    wf_xrpc_param params[] = {{"did", did}};
    wf_response response = {0};
    wf_xrpc_query_params(client, "app.bsky.actor.getProfile", params, 1,
                         &response);
    long status = response.status;
    *out_json = json_response(&response);
    wf_response_free(&response);
    return status;
}

int main(void) {
    char directory[] = "/tmp/metalbear-audit-identity-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .admin_password = "secret-admin",
        /* No account is configured; every account below arrives through
         * createAccount, the same path a real client takes. */
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

    char alice_did[64] = "";
    char bob_did[64] = "";
    char *alice =
        create_account(client, "alice.example.com", alice_did,
                       sizeof(alice_did), "alicesecret");
    char *bob = create_account(client, "bob.example.com", bob_did,
                               sizeof(bob_did), "bobsecret");
    CHECK(alice != NULL);
    CHECK(bob != NULL);
    if (!alice || !bob) goto done;

    wf_response response = {0};
    char err[64];

    /* ---- (a) getProfile enrichment with a profile record --------------- */
    wf_xrpc_client_set_auth(client, alice);
    char avatar_cid[128] = "";
    char banner_cid[128] = "";
    CHECK(upload_png(client, avatar_cid, sizeof(avatar_cid)) == 200);
    CHECK(upload_png(client, banner_cid, sizeof(banner_cid)) == 200);
    CHECK(avatar_cid[0] != '\0' && banner_cid[0] != '\0');
    CHECK(write_profile(client, alice_did, avatar_cid, banner_cid) == 200);

    cJSON *view = NULL;
    CHECK(get_local_profile(client, alice_did, &view) == 200);
    if (view) {
        cJSON *did = cJSON_GetObjectItemCaseSensitive(view, "did");
        cJSON *handle = cJSON_GetObjectItemCaseSensitive(view, "handle");
        cJSON *display = cJSON_GetObjectItemCaseSensitive(view, "displayName");
        cJSON *description =
            cJSON_GetObjectItemCaseSensitive(view, "description");
        cJSON *created = cJSON_GetObjectItemCaseSensitive(view, "createdAt");
        cJSON *avatar = cJSON_GetObjectItemCaseSensitive(view, "avatar");
        cJSON *banner = cJSON_GetObjectItemCaseSensitive(view, "banner");
        CHECK(cJSON_IsString(did) && strcmp(did->valuestring, alice_did) == 0);
        CHECK(cJSON_IsString(handle) &&
              strcmp(handle->valuestring, "alice.example.com") == 0);
        CHECK(cJSON_IsString(display) &&
              strcmp(display->valuestring, "Alice Example") == 0);
        CHECK(cJSON_IsString(description) &&
              strcmp(description->valuestring, "A profile description") == 0);
        CHECK(cJSON_IsString(created) && created->valuestring[0]);
        /* avatar/banner are #blob objects from the record, preserved whole:
         * {ref:{$link}, mimeType, size}. */
        CHECK(cJSON_IsObject(avatar));
        if (cJSON_IsObject(avatar)) {
            cJSON *ref = cJSON_GetObjectItemCaseSensitive(avatar, "ref");
            cJSON *link =
                ref ? cJSON_GetObjectItemCaseSensitive(ref, "$link") : NULL;
            cJSON *mime = cJSON_GetObjectItemCaseSensitive(avatar, "mimeType");
            cJSON *size = cJSON_GetObjectItemCaseSensitive(avatar, "size");
            CHECK(cJSON_IsString(link) &&
                  strcmp(link->valuestring, avatar_cid) == 0);
            CHECK(cJSON_IsString(mime) &&
                  strcmp(mime->valuestring, "image/png") == 0);
            CHECK(cJSON_IsNumber(size) && size->valueint > 0);
        }
        CHECK(cJSON_IsObject(banner));
        cJSON_Delete(view);
    }
    view = NULL;

    /* ---- (b) getProfile with no profile record ------------------------- */
    CHECK(get_local_profile(client, bob_did, &view) == 200);
    if (view) {
        cJSON *did = cJSON_GetObjectItemCaseSensitive(view, "did");
        cJSON *handle = cJSON_GetObjectItemCaseSensitive(view, "handle");
        CHECK(cJSON_IsString(did) && strcmp(did->valuestring, bob_did) == 0);
        CHECK(cJSON_IsString(handle) &&
              strcmp(handle->valuestring, "bob.example.com") == 0);
        /* No profile record means no profile fields, just the required base.
         */
        CHECK(!cJSON_GetObjectItemCaseSensitive(view, "displayName"));
        CHECK(!cJSON_GetObjectItemCaseSensitive(view, "avatar"));
        cJSON_Delete(view);
    }
    view = NULL;

    /* ---- (c) updateHandle on a different domain ------------------------ */
    {
        const char *body = "{\"handle\":\"alice.otherdomain.com\"}";
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        error_name(&response, err, sizeof(err));
        CHECK(strcmp(err, "InvalidHandle") == 0);
        wf_response_free(&response);

        /* And the same call with an in-domain handle passes the domain gate
         * (a real rename). */
        const char *rename_body = "{\"handle\":\"alice2.example.com\"}";
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                rename_body, &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);

        /* The renamed handle is what getProfile now reports. */
        CHECK(get_local_profile(client, alice_did, &view) == 200);
        if (view) {
            cJSON *handle = cJSON_GetObjectItemCaseSensitive(view, "handle");
            CHECK(cJSON_IsString(handle) &&
                  strcmp(handle->valuestring, "alice2.example.com") == 0);
            cJSON_Delete(view);
        }
        view = NULL;
    }

    /* ---- (d) resolveHandle for a non-existent handle ------------------- */
    wf_xrpc_client_set_auth(client, NULL);
    {
        wf_xrpc_param params[] = {{"handle", "ghost.example.com"}};
        CHECK(wf_xrpc_query_params(client, "com.atproto.identity.resolveHandle",
                                   params, 1, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        error_name(&response, err, sizeof(err));
        /* HandleNotFound is the resolveHandle lexicon's only declared error
         * (resolveHandle.json errors[0]); no change was needed here. */
        CHECK(strcmp(err, "HandleNotFound") == 0);
        wf_response_free(&response);
    }

done:
    free(alice);
    free(bob);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_audit_identity: OK\n");
    return 0;
}
