#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

/*
 * test_account_email_send_failure.c — regression coverage for
 * request_email_confirmation and request_email_update silently reporting
 * success when the actual SMTP send failed (src/account/account_routes.c).
 *
 * Both used to call metalbear_email_send_verification and discard its
 * return value outright, always answering {"success":true} /
 * {"tokenRequired":true} regardless of whether an email went anywhere --
 * unlike com.atproto.admin.sendEmail (admin_routes.c), which has always
 * correctly reported {"sent": false} on failure. A client (or a user
 * staring at "check your email") had no way to learn the confirmation
 * email never sent.
 *
 * request_password_reset is NOT covered here: it's unauthenticated and
 * deliberately always reports success even for a real account, to avoid
 * email enumeration (see its own comment in account_routes.c) -- that
 * endpoint's fix is a server-side log line, not an observable response
 * change, so there's nothing at the HTTP layer to assert on.
 *
 * Points server->email at a closed local port (smtp_starttls left at its
 * struct-literal default of false, i.e. smtps://, which fails fast on
 * connection refused without needing a real TLS handshake) so the send
 * genuinely fails, then confirms both endpoints report that failure
 * instead of claiming success.
 */

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    char directory[] = "/tmp/metalbear-email-fail-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    metalbear_config config = {
        .listen_address = "127.0.0.1",
        .port = 0,
        .thread_count = 2,
        .data_directory = directory,
        .service_did = "did:web:pds.example.com",
        .user_domain = ".example.com",
        .invite_required = false,
        /* Port 1 (a privileged port nothing listens on): connection
         * refused immediately, no real mail server needed to prove the
         * send fails. */
        .smtp_host = "127.0.0.1",
        .smtp_port = 1,
        .from_address = "pds@example.com",
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

    wf_response response = {0};
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.createAccount",
                            "{\"handle\":\"alice.example.com\","
                            "\"password\":\"correct horse battery staple\","
                            "\"email\":\"alice@example.com\"}",
                            &response) == WF_OK);
    CHECK(response.status == 200);
    cJSON *json = json_response(&response);
    cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
    char *access_token =
        cJSON_IsString(access) ? strdup(access->valuestring) : NULL;
    cJSON_Delete(json);
    wf_response_free(&response);
    CHECK(access_token != NULL);
    if (!access_token) {
        wf_xrpc_client_free(client);
        metalbear_server_free(server);
        rmtree(directory);
        return failures ? 1 : 0;
    }
    wf_xrpc_client_set_auth(client, access_token);

    /* ---- requestEmailConfirmation: must report the send failure, not a
     * fabricated success -------------------------------------------------*/
    CHECK(wf_xrpc_procedure(client,
                            "com.atproto.server.requestEmailConfirmation", "{}",
                            &response) == WF_ERR_HTTP);
    CHECK(response.status == 500);
    json = json_response(&response);
    CHECK(cJSON_GetObjectItemCaseSensitive(json, "error") != NULL);
    /* Never the fabricated success this used to always return. */
    cJSON *success = cJSON_GetObjectItemCaseSensitive(json, "success");
    CHECK(!success || !cJSON_IsTrue(success));
    cJSON_Delete(json);
    wf_response_free(&response);

    /* ---- requestEmailUpdate: same bug, same fix ------------------------*/
    CHECK(wf_xrpc_procedure(client, "com.atproto.server.requestEmailUpdate",
                            "{}", &response) == WF_ERR_HTTP);
    CHECK(response.status == 500);
    json = json_response(&response);
    CHECK(cJSON_GetObjectItemCaseSensitive(json, "error") != NULL);
    cJSON *token_required =
        cJSON_GetObjectItemCaseSensitive(json, "tokenRequired");
    CHECK(!token_required || !cJSON_IsTrue(token_required));
    cJSON_Delete(json);
    wf_response_free(&response);

    free(access_token);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    rmtree(directory);
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_account_email_send_failure: OK\n");
    return 0;
}
