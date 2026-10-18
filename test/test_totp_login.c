/*
 * Two-factor login end to end over XRPC: enrolment, confirmation with a wrong
 * and then a right code, a login with and without the factor, a replayed code,
 * a backup code used once, an app password that skips the factor, and disable.
 */
#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "metalbear/server.h"
#include "metalbear/twofactor/totp.h"
#include "wolfram/xrpc.h"
#include "wolfram/xrpc_server.h"

static int failures = 0;

#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static cJSON *json_of(wf_response *response) {
    if (!response->body || response->body_len == 0) return NULL;
    return cJSON_ParseWithLength((const char *)response->body,
                                 response->body_len);
}

/* Creates an account and returns its access token. */
static char *create_account(wf_xrpc_client *client, const char *handle,
                            const char *password) {
    char body[512];
    snprintf(
        body, sizeof(body),
        "{\"handle\":\"%s\",\"password\":\"%s\",\"email\":\"%s@example.com\"}",
        handle, password, handle);
    wf_response response = {0};
    char *token = NULL;
    if (wf_xrpc_procedure(client, "com.atproto.server.createAccount", body,
                          &response) == WF_OK &&
        response.status == 200) {
        cJSON *json = json_of(&response);
        cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
        if (cJSON_IsString(access)) token = strdup(access->valuestring);
        cJSON_Delete(json);
    }
    wf_response_free(&response);
    return token;
}

/* Logs in with an optional authFactorToken. Returns the HTTP status and, on
 * success, the access token in *token (caller frees). */
static long login(wf_xrpc_client *client, const char *handle,
                  const char *password, const char *factor, char **token) {
    char body[512];
    if (factor)
        snprintf(body, sizeof(body),
                 "{\"identifier\":\"%s\",\"password\":\"%s\","
                 "\"authFactorToken\":\"%s\"}",
                 handle, password, factor);
    else
        snprintf(body, sizeof(body),
                 "{\"identifier\":\"%s\",\"password\":\"%s\"}", handle,
                 password);
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.server.createSession", body,
                      &response);
    long status = response.status;
    if (token) *token = NULL;
    if (status == 200 && token) {
        cJSON *json = json_of(&response);
        cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
        if (cJSON_IsString(access)) *token = strdup(access->valuestring);
        cJSON_Delete(json);
    }
    wf_response_free(&response);
    return status;
}

/* Calls a procedure with an optional JSON body. Returns the status and the
 * parsed body (caller deletes). */
static long call(wf_xrpc_client *client, const char *nsid, const char *body,
                 cJSON **out) {
    wf_response response = {0};
    wf_xrpc_procedure(client, nsid, body, &response);
    long status = response.status;
    if (out) *out = json_of(&response);
    wf_response_free(&response);
    return status;
}

int main(void) {
    char directory[] = "/tmp/metalbear-totp-login-XXXXXX";
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
        return 1;
    }

    char base[80];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u",
             (unsigned)metalbear_server_port(server));
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    CHECK(client != NULL);

    char *token = create_account(client, "alice.example.com", "alicesecret");
    CHECK(token != NULL);
    if (!token) goto done;
    wf_xrpc_client_set_auth(client, token);

    /* Enrolment: a secret comes back, and login is unchanged until confirmed.
     */
    cJSON *json = NULL;
    CHECK(call(client, "uk.ewancroft.totp.enrol", NULL, &json) == 200);
    cJSON *secret_json =
        json ? cJSON_GetObjectItemCaseSensitive(json, "secret") : NULL;
    CHECK(cJSON_IsString(secret_json));
    unsigned char secret[64];
    size_t secret_len = 0;
    if (cJSON_IsString(secret_json))
        CHECK(metalbear_base32_decode(secret_json->valuestring, secret,
                                      sizeof(secret), &secret_len) == WF_OK);
    cJSON_Delete(json);
    CHECK(secret_len == 20);
    char *before = NULL;
    CHECK(login(client, "alice.example.com", "alicesecret", NULL, &before) ==
          200);
    free(before);

    /* A wrong code does not turn the factor on. */
    CHECK(call(client, "uk.ewancroft.totp.confirm", "{\"code\":\"000000\"}",
               NULL) == 400);

    /* The right code does, and returns ten backup codes, shown once. */
    int64_t now = (int64_t)time(NULL);
    uint32_t code = 0;
    CHECK(metalbear_totp_code(secret, secret_len, now / 30, &code) == WF_OK);
    char right[8];
    snprintf(right, sizeof(right), "%06u", (unsigned)code);
    char confirm[64];
    snprintf(confirm, sizeof(confirm), "{\"code\":\"%s\"}", right);
    CHECK(call(client, "uk.ewancroft.totp.confirm", confirm, &json) == 200);
    char backup[16][24];
    int backup_count = 0;
    cJSON *codes =
        json ? cJSON_GetObjectItemCaseSensitive(json, "backupCodes") : NULL;
    if (cJSON_IsArray(codes)) {
        backup_count = cJSON_GetArraySize(codes);
        for (int i = 0; i < backup_count && i < 16; i++) {
            cJSON *c = cJSON_GetArrayItem(codes, i);
            if (cJSON_IsString(c))
                snprintf(backup[i], sizeof(backup[i]), "%s", c->valuestring);
        }
    }
    CHECK(backup_count == 10);
    cJSON_Delete(json);

    /* Now the factor is on: a password alone is refused, a wrong code too. */
    CHECK(login(client, "alice.example.com", "alicesecret", NULL, NULL) == 401);
    CHECK(login(client, "alice.example.com", "alicesecret", "000000", NULL) ==
          401);

    /* The confirming code's step is spent. A code for the next step is fresh,
     * and it logs in once: replaying it is refused. */
    char next[8];
    CHECK(metalbear_totp_code(secret, secret_len, now / 30 + 1, &code) ==
          WF_OK);
    snprintf(next, sizeof(next), "%06u", (unsigned)code);
    CHECK(login(client, "alice.example.com", "alicesecret", right, NULL) ==
          401);
    char *session = NULL;
    CHECK(login(client, "alice.example.com", "alicesecret", next, &session) ==
          200);
    free(session);
    CHECK(login(client, "alice.example.com", "alicesecret", next, NULL) == 401);

    /* A backup code logs in once. */
    CHECK(login(client, "alice.example.com", "alicesecret", backup[0],
                &session) == 200);
    free(session);
    CHECK(login(client, "alice.example.com", "alicesecret", backup[0], NULL) ==
          401);

    /* An app password skips the factor, as the design records. */
    wf_xrpc_client_set_auth(client, NULL);
    cJSON *app = NULL;
    wf_xrpc_client_set_auth(client, token);
    CHECK(call(client, "com.atproto.server.createAppPassword",
               "{\"name\":\"phone\"}", &app) == 200);
    char *app_password = NULL;
    cJSON *app_pw =
        app ? cJSON_GetObjectItemCaseSensitive(app, "password") : NULL;
    if (cJSON_IsString(app_pw)) app_password = strdup(app_pw->valuestring);
    cJSON_Delete(app);
    CHECK(app_password != NULL);
    if (app_password) {
        CHECK(login(client, "alice.example.com", app_password, NULL,
                    &session) == 200);
        free(session);
        free(app_password);
    }

    /* Disable needs the password and a current code. A wrong password is
     * refused. */
    char disable_bad[160];
    snprintf(disable_bad, sizeof(disable_bad),
             "{\"password\":\"wrongpass\",\"code\":\"%s\"}", backup[1]);
    CHECK(call(client, "uk.ewancroft.totp.disable", disable_bad, NULL) == 401);
    char disable_ok[160];
    snprintf(disable_ok, sizeof(disable_ok),
             "{\"password\":\"alicesecret\",\"code\":\"%s\"}", backup[1]);
    CHECK(call(client, "uk.ewancroft.totp.disable", disable_ok, NULL) == 200);
    CHECK(login(client, "alice.example.com", "alicesecret", NULL, &session) ==
          200);
    free(session);

done:
    free(token);
    wf_xrpc_client_free(client);
    metalbear_server_free(server);
    if (failures == 0) {
        printf("PASS: two-factor login\n");
        return 0;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
