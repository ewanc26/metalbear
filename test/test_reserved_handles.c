#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
/*
 * test_reserved_handles.c -- offline coverage for the reserved-handle
 * blocklist ported from the reference PDS (handle/reserved.ts).
 *
 * Two layers:
 *   1. Direct checks of the label matcher: atproto terms, common service
 *      labels, famous accounts, case folding, domain and dotted-prefix
 *      boundaries.
 *   2. An in-process PDS, driven by the same XRPC calls a client makes:
 *      createAccount and updateHandle reject reserved labels with
 *      HandleNotAvailable, ordinary handles still work, the admin handle
 *      override cannot bypass the list, and explicit-slur rejection on
 *      record keys remains in force.
 */

#include "metalbear/handle/reserved.h"
#include "metalbear/repo/explicit_slurs.h"
#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <openssl/evp.h>
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

static char base[80];

static cJSON *json_response(wf_response *response) {
    return cJSON_ParseWithLength(response->body ? response->body : "",
                                 response->body_len);
}

static void error_name(wf_response *response, char *out, size_t out_len) {
    out[0] = '\0';
    cJSON *json = json_response(response);
    cJSON *error = cJSON_GetObjectItemCaseSensitive(json, "error");
    if (cJSON_IsString(error)) snprintf(out, out_len, "%s", error->valuestring);
    cJSON_Delete(json);
}

static void check_rejected(wf_response *response, long expected_status,
                           const char *expected_error, const char *context) {
    if (response->status != expected_status) {
        fprintf(stderr, "FAIL %s: HTTP %ld, expected %ld\n", context,
                response->status, expected_status);
        failures++;
    }
    char err[64];
    error_name(response, err, sizeof(err));
    if (strcmp(err, expected_error) != 0) {
        fprintf(stderr, "FAIL %s: error '%s', expected '%s'\n", context, err,
                expected_error);
        failures++;
    }
}

/* POST with optional extra headers; used for the admin-gated route, which
 * authenticates with HTTP Basic the way the reference does. */
static wf_status post(wf_xrpc_client *client, const char *nsid,
                      const char *body, const wf_http_header *headers,
                      size_t header_count, wf_response *out) {
    char url[256];
    snprintf(url, sizeof(url), "%s/xrpc/%s", base, nsid);
    return wf_http_post(client, url, "application/json", body, headers,
                        header_count, out);
}

static char *create_account(wf_xrpc_client *client, const char *handle,
                            char *out_did, size_t out_did_len) {
    char body[512];
    snprintf(body, sizeof(body),
             "{\"handle\":\"%s\",\"password\":\"secret123\","
             "\"email\":\"%s@example.com\"}",
             handle, handle);
    wf_response response = {0};
    if (wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                          &response) != WF_OK ||
        response.status != 200) {
        fprintf(stderr, "FAIL createAccount %s: HTTP %ld\n", handle,
                response.status);
        failures++;
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

static void test_matcher(void) {
    const char *reserved[] = {
        "admin.example.com", "at.example.com",      "atp.example.com",
        "plc.example.com",   "pds.example.com",     "did.example.com",
        "repo.example.com",  "tid.example.com",     "nsid.example.com",
        "xrpc.example.com",  "lex.example.com",     "lexicon.example.com",
        "bsky.example.com",  "bluesky.example.com", "handle.example.com",
        "api.example.com",   "www.example.com",     "nasa.example.com",
        "ADMIN.EXAMPLE.COM",
    };
    for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
        CHECK(metalbear_handle_is_reserved(reserved[i], ".example.com") == 1);
    }
    const char *ordinary[] = {
        "alice.example.com",
        "ewan.example.com",
        "administrator2.example.com",
        "admin.other.com",
        "admin.foo.example.com",
        "example.com",
        "",
    };
    for (size_t i = 0; i < sizeof(ordinary) / sizeof(ordinary[0]); i++) {
        CHECK(metalbear_handle_is_reserved(ordinary[i], ".example.com") == 0);
    }
    CHECK(metalbear_handle_is_reserved(NULL, ".example.com") == 0);
    CHECK(metalbear_handle_is_reserved("admin.example.com", NULL) == 0);
    CHECK(metalbear_handle_is_reserved("admin.example.com", "") == 0);
}

int main(void) {
    test_matcher();

    char directory[] = "/tmp/metalbear-reserved-XXXXXX";
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
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);

    wf_response response = {0};

    /* Signup: reserved labels are refused, ordinary ones pass. */
    /* `at` is in the reference list but is only two characters, so signup
     * rejects it earlier with InvalidHandle; use three-plus-character labels
     * here to assert the reserved-handle boundary specifically. */
    const char *reserved_signups[] = {"admin.example.com", "bsky.example.com",
                                      "atp.example.com", "nasa.example.com"};
    for (size_t i = 0;
         i < sizeof(reserved_signups) / sizeof(reserved_signups[0]); i++) {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"handle\":\"%s\",\"password\":\"secret123\","
                 "\"email\":\"r%zu@example.com\"}",
                 reserved_signups[i], i);
        CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                                body, &response) == WF_ERR_HTTP);
        check_rejected(&response, 400, "HandleNotAvailable",
                       reserved_signups[i]);
        wf_response_free(&response);
    }

    char alice_did[64] = "";
    char *token = create_account(client, "alice.example.com", alice_did,
                                 sizeof(alice_did));
    CHECK(token != NULL);
    CHECK(alice_did[0] != '\0');

    /* The slur check on record keys still fires independently. */
    if (token) {
        wf_xrpc_client_set_auth(client, token);
        char slur_body[512];
        snprintf(slur_body, sizeof(slur_body),
                 "{\"repo\":\"%s\",\"collection\":\"app.bsky.feed.post\","
                 "\"rkey\":\"chink\",\"record\":{\"$type\":"
                 "\"app.bsky.feed.post\",\"text\":\"hi\",\"createdAt\":"
                 "\"2026-07-27T00:00:00.000Z\"}}",
                 alice_did);
        CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                slur_body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        cJSON *json = json_response(&response);
        cJSON *message =
            json ? cJSON_GetObjectItemCaseSensitive(json, "message") : NULL;
        CHECK(cJSON_IsString(message) &&
              strstr(message->valuestring, "Unacceptable slur") != NULL);
        cJSON_Delete(json);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, NULL);
    }

    /* Self-service handle update: reserved rejected, ordinary accepted. */
    if (token) {
        wf_xrpc_client_set_auth(client, token);
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                "{\"handle\":\"api.example.com\"}",
                                &response) == WF_ERR_HTTP);
        check_rejected(&response, 400, "HandleNotAvailable",
                       "updateHandle api");
        wf_response_free(&response);

        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.updateHandle",
                                "{\"handle\":\"carol.example.com\"}",
                                &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
        wf_xrpc_client_set_auth(client, NULL);
    }

    /* The admin override uses the same shared constraint check. */
    {
        char cred[64];
        int n = snprintf(cred, sizeof(cred), "admin:%s", "secret-admin");
        char b64[128];
        int len = EVP_EncodeBlock((unsigned char *)b64,
                                  (const unsigned char *)cred, n);
        b64[len] = '\0';
        char auth[160];
        snprintf(auth, sizeof(auth), "Basic %s", b64);
        wf_http_header hdr = {"Authorization", auth};
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"did\":\"%s\",\"handle\":\"admin.example.com\"}",
                 alice_did);
        CHECK(post(client, "com.atproto.admin.updateAccountHandle", body, &hdr,
                   1, &response) == WF_ERR_HTTP);
        check_rejected(&response, 400, "HandleNotAvailable",
                       "admin updateAccountHandle");
        wf_response_free(&response);
    }

    free(token);
    if (client) wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_reserved_handles: OK\n");
    return 0;
}
