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

/* Logs in with an optional authFactorToken and trustedDeviceToken. Returns the
 * HTTP status and, on success, the access token in *token and the newly issued
 * trusted device token in *device_token (either may be NULL). */
static long login_full(wf_xrpc_client *client, const char *handle,
                       const char *password, const char *factor,
                       const char *device, char **token, char **device_token,
                       cJSON **out_json) {
    char body[1024];
    size_t off = snprintf(body, sizeof(body),
                          "{\"identifier\":\"%s\",\"password\":\"%s\"", handle,
                          password);
    if (factor && off < sizeof(body))
        off += snprintf(body + off, sizeof(body) - off,
                        ",\"authFactorToken\":\"%s\"", factor);
    if (device && off < sizeof(body))
        off += snprintf(body + off, sizeof(body) - off,
                        ",\"trustedDeviceToken\":\"%s\"", device);
    if (off < sizeof(body)) snprintf(body + off, sizeof(body) - off, "}");
    wf_response response = {0};
    wf_xrpc_procedure(client, "com.atproto.server.createSession", body,
                      &response);
    long status = response.status;
    if (token) *token = NULL;
    if (device_token) *device_token = NULL;
    if (out_json) *out_json = NULL;
    if (status == 200) {
        cJSON *json = json_of(&response);
        if (json && token) {
            cJSON *access = cJSON_GetObjectItemCaseSensitive(json, "accessJwt");
            if (cJSON_IsString(access)) *token = strdup(access->valuestring);
        }
        if (json && device_token) {
            cJSON *issued =
                cJSON_GetObjectItemCaseSensitive(json, "trustedDeviceToken");
            if (cJSON_IsString(issued))
                *device_token = strdup(issued->valuestring);
        }
        if (out_json)
            *out_json = json;
        else
            cJSON_Delete(json);
    }
    wf_response_free(&response);
    return status;
}

/* Logs in with an optional authFactorToken. Returns the HTTP status and, on
 * success, the access token in *token (caller frees). */
static long login(wf_xrpc_client *client, const char *handle,
                  const char *password, const char *factor, char **token) {
    return login_full(client, handle, password, factor, NULL, token, NULL,
                      NULL);
}

/* Calls an XRPC query and returns the status and parsed body. */
static long query(wf_xrpc_client *client, const char *nsid, cJSON **out) {
    wf_response response = {0};
    wf_xrpc_query(client, nsid, NULL, &response);
    long status = response.status;
    if (out) *out = json_of(&response);
    wf_response_free(&response);
    return status;
}

/* Reads the signed-in account's DID. */
static void session_did(wf_xrpc_client *client, char *out, size_t out_len) {
    out[0] = '\0';
    wf_response response = {0};
    if (wf_xrpc_query(client, "com.atproto.server.getSession", NULL,
                      &response) == WF_OK &&
        response.status == 200) {
        cJSON *json = json_of(&response);
        cJSON *did =
            json ? cJSON_GetObjectItemCaseSensitive(json, "did") : NULL;
        if (cJSON_IsString(did)) snprintf(out, out_len, "%s", did->valuestring);
        cJSON_Delete(json);
    }
    wf_response_free(&response);
}

/* Changes a password through the admin route, using a fresh client so the
 * bearer token does not override the Basic header. */
static long admin_set_password(const char *base, const char *did,
                               const char *password) {
    wf_xrpc_client *admin = wf_xrpc_client_new(base);
    if (!admin) return -1;
    char url[256];
    snprintf(url, sizeof(url),
             "%s/xrpc/com.atproto.admin.updateAccountPassword", base);
    char body[512];
    snprintf(body, sizeof(body), "{\"did\":\"%s\",\"password\":\"%s\"}", did,
             password);
    wf_http_header auth = {"Authorization", "Basic YWRtaW46c2VjcmV0LWFkbWlu"};
    wf_response response = {0};
    wf_http_post(admin, url, "application/json", body, &auth, 1, &response);
    long status = response.status;
    wf_response_free(&response);
    wf_xrpc_client_free(admin);
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

    /* A successful factor check issues a trusted device token, shown once in
     * the session response (issue #131). */
    char *trusted = NULL;
    cJSON *trusted_json = NULL;
    CHECK(login_full(client, "alice.example.com", "alicesecret", backup[2],
                     NULL, &session, &trusted, &trusted_json) == 200);
    CHECK(session != NULL);
    CHECK(trusted != NULL && strlen(trusted) == 52);
    if (trusted_json && trusted) {
        cJSON *issued = cJSON_GetObjectItemCaseSensitive(trusted_json,
                                                         "trustedDeviceToken");
        CHECK(cJSON_IsString(issued) &&
              strcmp(issued->valuestring, trusted) == 0);
    }
    cJSON_Delete(trusted_json);
    free(session);

    /* It appears in the account's list with a 30-day expiry, and lets the next
     * full-password login skip the factor without issuing another token.
     * Earlier factor logins in this test also issued devices, so revoke every
     * listed one below rather than assuming this is the only row. */
    json = NULL;
    CHECK(query(client, "uk.ewancroft.totp.listTrustedDevices", &json) == 200);
    cJSON *devices =
        json ? cJSON_GetObjectItemCaseSensitive(json, "devices") : NULL;
    CHECK(cJSON_IsArray(devices) && cJSON_GetArraySize(devices) >= 1);
    char device_ids[16][64];
    int device_count = 0;
    if (cJSON_IsArray(devices)) {
        int listed = cJSON_GetArraySize(devices);
        for (int i = 0; i < listed && i < 16; i++) {
            cJSON *item = cJSON_GetArrayItem(devices, i);
            cJSON *id = cJSON_GetObjectItemCaseSensitive(item, "id");
            cJSON *created =
                cJSON_GetObjectItemCaseSensitive(item, "createdAt");
            cJSON *expires =
                cJSON_GetObjectItemCaseSensitive(item, "expiresAt");
            CHECK(cJSON_IsString(id) && strlen(id->valuestring) == 16);
            CHECK(cJSON_IsNumber(created) && cJSON_IsNumber(expires));
            if (cJSON_IsNumber(created) && cJSON_IsNumber(expires))
                CHECK((int64_t)expires->valuedouble -
                          (int64_t)created->valuedouble ==
                      30 * 24 * 60 * 60);
            if (cJSON_IsString(id))
                snprintf(device_ids[device_count++], sizeof(device_ids[0]),
                         "%s", id->valuestring);
        }
    }
    cJSON_Delete(json);

    char *trusted_session = NULL;
    char *reissued = NULL;
    CHECK(login_full(client, "alice.example.com", "alicesecret", NULL, trusted,
                     &trusted_session, &reissued, &trusted_json) == 200);
    CHECK(trusted_session != NULL);
    CHECK(reissued == NULL);
    if (trusted_json)
        CHECK(cJSON_GetObjectItemCaseSensitive(trusted_json,
                                               "trustedDeviceToken") == NULL);
    cJSON_Delete(trusted_json);
    free(trusted_session);
    CHECK(login_full(client, "alice.example.com", "alicesecret", NULL,
                     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                     NULL, NULL, NULL) == 401);

    /* Revocation takes effect on the next login. */
    CHECK(device_count >= 1);
    for (int i = 0; i < device_count; i++) {
        char revoke[96];
        snprintf(revoke, sizeof(revoke), "{\"id\":\"%s\"}", device_ids[i]);
        CHECK(call(client, "uk.ewancroft.totp.revokeTrustedDevice", revoke,
                   &json) == 200);
        cJSON_Delete(json);
    }
    CHECK(login_full(client, "alice.example.com", "alicesecret", NULL, trusted,
                     NULL, NULL, NULL) == 401);
    CHECK(query(client, "uk.ewancroft.totp.listTrustedDevices", &json) == 200);
    devices = json ? cJSON_GetObjectItemCaseSensitive(json, "devices") : NULL;
    CHECK(cJSON_IsArray(devices) && cJSON_GetArraySize(devices) == 0);
    cJSON_Delete(json);
    free(trusted);
    trusted = NULL;

    /* Changing the password drops trust too: the next login needs a code even
     * with the old device token and the new password. */
    CHECK(login_full(client, "alice.example.com", "alicesecret", backup[3],
                     NULL, &session, &trusted, NULL) == 200);
    free(session);
    CHECK(trusted != NULL);
    char did[128] = "";
    session_did(client, did, sizeof(did));
    CHECK(did[0] != '\0');
    CHECK(admin_set_password(base, did, "newsecret") == 200);
    CHECK(login_full(client, "alice.example.com", "newsecret", NULL, trusted,
                     NULL, NULL, NULL) == 401);
    free(trusted);
    trusted = NULL;

    /* The factor itself still works with the new password; re-authenticate for
     * the disable step. */
    char *fresh = NULL;
    CHECK(login_full(client, "alice.example.com", "newsecret", backup[4], NULL,
                     &fresh, NULL, NULL) == 200);
    CHECK(fresh != NULL);
    wf_xrpc_client_set_auth(client, fresh);
    free(fresh);

    /* Disable needs the password and a current code. A wrong password is
     * refused. */
    char disable_bad[160];
    snprintf(disable_bad, sizeof(disable_bad),
             "{\"password\":\"wrongpass\",\"code\":\"%s\"}", backup[6]);
    CHECK(call(client, "uk.ewancroft.totp.disable", disable_bad, NULL) == 401);
    char disable_ok[160];
    snprintf(disable_ok, sizeof(disable_ok),
             "{\"password\":\"newsecret\",\"code\":\"%s\"}", backup[5]);
    CHECK(call(client, "uk.ewancroft.totp.disable", disable_ok, NULL) == 200);
    CHECK(login(client, "alice.example.com", "newsecret", NULL, &session) ==
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
