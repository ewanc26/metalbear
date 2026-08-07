/*
 * test_identity_plc_operation.c — offline coverage for
 * com.atproto.identity.submitPlcOperation.
 *
 * Regression coverage for two bugs found while testing a live cross-server
 * migration: submitPlcOperation's rotationKeys check compared against
 * server->service_did (a did:web string, e.g. "did:web:pds.example.com")
 * instead of the server's actual PLC rotation key (a did:key derived from
 * server->plc_rotation, the same value getRecommendedDidCredentials
 * advertises) -- so it rejected every operation a real PLC client would ever
 * submit. And the handler never actually submitted anything to a PLC
 * directory at all; it validated structure and silently "acknowledged".
 *
 * Both are tested here without a real PLC directory: the rotationKeys check
 * runs (and is asserted) before any network call, and the submission
 * attempt itself is pointed at a closed local port so its failure is fast,
 * deterministic, and proves the handler now actually attempts a real
 * network submission instead of silently succeeding.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include "metalbear/server.h"
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

int main(void) {
    printf("submitPlcOperation Tests\n");
    printf("=========================\n\n");

    char directory[] = "/tmp/metalbear-plcop-XXXXXX";
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
        /* A closed local port: any submission attempt fails fast with a
         * connection error rather than hanging or reaching a real PLC
         * directory, while still proving a network call was attempted. */
        .plc_url = "http://127.0.0.1:1",
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
    wf_response response = {0};

    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                            "{\"handle\":\"alice.example.com\","
                            "\"password\":\"correct horse battery staple\","
                            "\"did\":\"did:plc:migrationplctest\","
                            "\"email\":\"alice@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    char *access_token = strdup(
        cJSON_GetObjectItemCaseSensitive(json, "accessJwt")->valuestring);
    cJSON_Delete(json);
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, access_token);

    /* getRecommendedDidCredentials names the server's actual PLC rotation
     * key -- the value a real migration client would (correctly) put in
     * rotationKeys, and the value submitPlcOperation must actually check
     * against. */
    CHECK(wf_xrpc_query_params(client,
                               "com.atproto.identity.getRecommendedDidCredentials",
                               NULL, 0, &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *recommended = json_response(&response);
    cJSON *rotation_keys_arr =
        cJSON_GetObjectItemCaseSensitive(recommended, "rotationKeys");
    char *server_rotation_didkey =
        strdup(cJSON_GetArrayItem(rotation_keys_arr, 0)->valuestring);
    CHECK(server_rotation_didkey != NULL);
    wf_response_free(&response);

    /* Bug #1 regression: an operation whose rotationKeys names the
     * server's service DID (a did:web string) rather than its actual
     * rotation key must still be refused -- proving the check compares
     * against a real key, not something that would spuriously accept a
     * did:web string too. */
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"operation\":{\"type\":\"plc_operation\","
                 "\"rotationKeys\":[\"%s\"]}}",
                 config.service_did);
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.submitPlcOperation",
                                body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 400);
        cJSON *err = json_response(&response);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(err, "error")->valuestring,
                     "InvalidRequest") == 0);
        CHECK(strstr(cJSON_GetObjectItemCaseSensitive(err, "message")
                         ->valuestring,
                     "rotation key") != NULL);
        cJSON_Delete(err);
        wf_response_free(&response);
    }

    /* Bug #1 fixed + bug #2 regression: an operation whose rotationKeys
     * correctly names the server's own rotation key passes that check (no
     * "do not include" refusal) and the handler actually attempts to
     * submit it over the network -- which fails against the closed port
     * above, proving it is a real attempt rather than a silent
     * acknowledgment. */
    {
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"operation\":{\"type\":\"plc_operation\","
                 "\"rotationKeys\":[\"%s\"]}}",
                 server_rotation_didkey);
        CHECK(wf_xrpc_procedure(client, "com.atproto.identity.submitPlcOperation",
                                body, &response) == WF_ERR_HTTP);
        CHECK(response.status == 502);
        cJSON *err = json_response(&response);
        CHECK(cJSON_GetObjectItemCaseSensitive(err, "error") != NULL);
        CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(err, "error")->valuestring,
                     "InvalidRequest") != 0);
        cJSON_Delete(err);
        wf_response_free(&response);
    }

    free(server_rotation_didkey);
    free(access_token);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);

    printf("\n");
    if (failures)
        fprintf(stderr, "%d submitPlcOperation test(s) failed\n", failures);
    return failures ? 1 : 0;
}
