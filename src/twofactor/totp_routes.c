#include "totp_routes.h"

#include "metalbear/log.h"
#include "metalbear/oauth/auth.h"
#include "metalbear/twofactor/totp.h"

#include <cJSON.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BACKUP_CODE_COUNT 10

static bool all_digits(const char *s, size_t n) {
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)s[i])) return false;
    return true;
}

/* A six-digit TOTP code, as a number, or false if the token is not one. */
static bool parse_totp_code(const char *token, uint32_t *out) {
    size_t n = strlen(token);
    if (n != 6 || !all_digits(token, n)) return false;
    *out = (uint32_t)strtoul(token, NULL, 10);
    return true;
}

/* Opens the account's sealed secret. The caller frees *secret. */
static wf_status load_secret(metalbear_server *server,
                             const metalbear_auth_totp *record,
                             unsigned char **secret, size_t *secret_len) {
    return metalbear_twofactor_open(server->totp_key, record->secret,
                                    record->secret_len, secret, secret_len);
}

/* Checks a TOTP code against the stored secret and records the step it matched,
 * so the same step cannot be used again. */
static wf_status check_totp(metalbear_server *server,
                            metalbear_auth_store *auth,
                            const metalbear_auth_totp *record, uint32_t code,
                            bool *accepted) {
    *accepted = false;
    unsigned char *secret = NULL;
    size_t secret_len = 0;
    wf_status st = load_secret(server, record, &secret, &secret_len);
    if (st != WF_OK) return st;
    int64_t step = -1;
    bool matched =
        metalbear_totp_verify(secret, secret_len, code, (int64_t)time(NULL),
                              record->last_step, &step);
    OPENSSL_cleanse(secret, secret_len);
    free(secret);
    if (!matched) return WF_OK;
    bool recorded = false;
    st = metalbear_auth_totp_use_step(auth, step, &recorded);
    *accepted = st == WF_OK && recorded;
    return st;
}

/* Checks a backup code. Its stored form is keyed, so this needs the server key.
 */
static wf_status check_backup(metalbear_server *server,
                              metalbear_auth_store *auth, const char *token,
                              bool *accepted) {
    unsigned char hash[32];
    wf_status st = metalbear_backup_code_hash(server->totp_key, token, hash);
    if (st != WF_OK) {
        *accepted = false;
        return WF_OK;
    }
    return metalbear_auth_totp_consume_backup(auth, hash, accepted);
}

static bool key_ready(metalbear_server *server, wf_xrpc_response *response) {
    if (server->totp_key_ready) return true;
    wf_xrpc_response_set_error(
        response, 500, "InternalError",
        "Two-factor login is not configured on this server");
    return false;
}

static wf_status respond_error(wf_xrpc_response *response, int status,
                               const char *name, const char *message) {
    wf_xrpc_response_set_error(response, status, name, message);
    return WF_OK;
}

static const char *param_string(const wf_xrpc_request *request,
                                const char *name) {
    const cJSON *p =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, name)
            : NULL;
    return cJSON_IsString(p) ? p->valuestring : NULL;
}

wf_status totp_enrol(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct)
        return respond_error(response, 401, "InvalidToken",
                             "Invalid access token");
    if (!key_ready(server, response)) return WF_OK;

    metalbear_auth_totp record;
    if (metalbear_auth_totp_get(acct->auth, &record) != WF_OK)
        return respond_error(response, 500, "InternalError",
                             "Could not read two-factor state");
    bool active = record.active;
    metalbear_auth_totp_free(&record);
    if (active)
        return respond_error(
            response, 400, "InvalidRequest",
            "Two-factor login is already on; disable it first");

    unsigned char secret[METALBEAR_TOTP_SECRET_BYTES];
    if (metalbear_totp_secret_new(secret) != WF_OK)
        return respond_error(response, 500, "InternalError",
                             "Could not create a secret");
    unsigned char *sealed = NULL;
    size_t sealed_len = 0;
    wf_status st = metalbear_twofactor_seal(
        server->totp_key, secret, sizeof(secret), &sealed, &sealed_len);
    if (st == WF_OK)
        st = metalbear_auth_totp_put_pending(acct->auth, sealed, sealed_len);
    free(sealed);
    if (st != WF_OK) {
        OPENSSL_cleanse(secret, sizeof(secret));
        return respond_error(response, 500, "InternalError",
                             "Could not store the secret");
    }

    char b32[64];
    if (metalbear_base32_encode(secret, sizeof(secret), b32, sizeof(b32)) !=
        WF_OK) {
        OPENSSL_cleanse(secret, sizeof(secret));
        return respond_error(response, 500, "InternalError",
                             "Could not encode the secret");
    }
    OPENSSL_cleanse(secret, sizeof(secret));

    char uri[512];
    snprintf(uri, sizeof(uri),
             "otpauth://totp/MetalBear:%s?secret=%s&issuer=MetalBear"
             "&algorithm=SHA1&digits=6&period=30",
             acct->did, b32);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "secret", b32);
    cJSON_AddStringToObject(root, "uri", uri);
    return set_json(response, root);
}

wf_status totp_confirm(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct)
        return respond_error(response, 401, "InvalidToken",
                             "Invalid access token");
    if (!key_ready(server, response)) return WF_OK;

    const char *code_text = param_string(request, "code");
    uint32_t code = 0;
    if (!code_text || !parse_totp_code(code_text, &code))
        return respond_error(response, 400, "InvalidRequest",
                             "code must be six digits");

    metalbear_auth_totp record;
    if (metalbear_auth_totp_get(acct->auth, &record) != WF_OK)
        return respond_error(response, 500, "InternalError",
                             "Could not read two-factor state");
    if (!record.found || !record.secret) {
        metalbear_auth_totp_free(&record);
        return respond_error(
            response, 400, "InvalidRequest",
            "No pending two-factor setup; start with uk.ewancroft.totp.enrol");
    }
    if (record.active) {
        metalbear_auth_totp_free(&record);
        return respond_error(response, 400, "InvalidRequest",
                             "Two-factor login is already on");
    }

    unsigned char *secret = NULL;
    size_t secret_len = 0;
    wf_status st = load_secret(server, &record, &secret, &secret_len);
    if (st != WF_OK) {
        metalbear_auth_totp_free(&record);
        return respond_error(response, 500, "InternalError",
                             "Could not open the secret");
    }
    int64_t step = -1;
    bool matched = metalbear_totp_verify(secret, secret_len, code,
                                         (int64_t)time(NULL), -1, &step);
    OPENSSL_cleanse(secret, secret_len);
    free(secret);
    metalbear_auth_totp_free(&record);
    if (!matched)
        return respond_error(response, 400, "InvalidCode",
                             "That code does not match");

    char codes[BACKUP_CODE_COUNT][METALBEAR_BACKUP_CODE_CHARS + 1];
    unsigned char hashes[BACKUP_CODE_COUNT][32];
    for (int i = 0; i < BACKUP_CODE_COUNT; i++) {
        if (metalbear_backup_code_new(codes[i]) != WF_OK ||
            metalbear_backup_code_hash(server->totp_key, codes[i], hashes[i]) !=
                WF_OK)
            return respond_error(response, 500, "InternalError",
                                 "Could not create backup codes");
    }
    st = metalbear_auth_totp_activate(acct->auth,
                                      (const unsigned char(*)[32])hashes,
                                      BACKUP_CODE_COUNT, step);
    if (st == WF_ERR_CONFLICT)
        return respond_error(response, 400, "InvalidRequest",
                             "Two-factor login is already on");
    if (st != WF_OK)
        return respond_error(response, 500, "InternalError",
                             "Could not turn two-factor login on");

    LOG_INFO("totp: two-factor login turned on for did=%s", acct->did);
    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();
    if (!root || !list) {
        cJSON_Delete(root);
        cJSON_Delete(list);
        return WF_ERR_ALLOC;
    }
    for (int i = 0; i < BACKUP_CODE_COUNT; i++)
        cJSON_AddItemToArray(list, cJSON_CreateString(codes[i]));
    cJSON_AddItemToObject(root, "backupCodes", list);
    return set_json(response, root);
}

wf_status totp_disable(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct)
        return respond_error(response, 401, "InvalidToken",
                             "Invalid access token");

    /* Turning the factor off needs the password, not only a session: a stolen
     * session token alone must not remove the second factor. An app password
     * is refused here, because it is a narrower credential. */
    const char *password = param_string(request, "password");
    if (!password)
        return respond_error(response, 400, "InvalidRequest",
                             "password is required");
    char *app_name = NULL;
    metalbear_credential_kind kind =
        metalbear_account_verify_credential(acct->account, password, &app_name);
    free(app_name);
    if (kind != METALBEAR_CREDENTIAL_ACCOUNT)
        return respond_error(response, 401, "AuthenticationRequired",
                             "Invalid password");

    metalbear_auth_totp record;
    if (metalbear_auth_totp_get(acct->auth, &record) != WF_OK)
        return respond_error(response, 500, "InternalError",
                             "Could not read two-factor state");
    bool active = record.active;
    metalbear_auth_totp_free(&record);
    if (!active)
        return respond_error(response, 400, "InvalidRequest",
                             "Two-factor login is not on");

    if (!key_ready(server, response)) return WF_OK;
    const char *token = param_string(request, "code");
    if (!token)
        return respond_error(response, 400, "InvalidRequest",
                             "code (a TOTP code or a backup code) is required");
    if (!metalbear_totp_login_required(server, acct) ||
        metalbear_totp_check_login_token(server, acct, token, &active) !=
            WF_OK ||
        !active)
        return respond_error(response, 401, "AuthFactorTokenRequired",
                             "That code does not match");

    if (metalbear_auth_totp_disable(acct->auth) != WF_OK)
        return respond_error(response, 500, "InternalError",
                             "Could not turn two-factor login off");
    LOG_INFO("totp: two-factor login turned off for did=%s", acct->did);
    return WF_OK;
}

bool metalbear_totp_login_required(metalbear_server *server,
                                   metalbear_account_context *acct) {
    (void)server;
    if (!acct || !acct->auth) return false;
    metalbear_auth_totp record;
    if (metalbear_auth_totp_get(acct->auth, &record) != WF_OK) return true;
    bool active = record.active;
    metalbear_auth_totp_free(&record);
    return active;
}

wf_status metalbear_totp_check_login_token(metalbear_server *server,
                                           metalbear_account_context *acct,
                                           const char *token, bool *accepted) {
    if (!accepted) return WF_ERR_INVALID_ARG;
    *accepted = false;
    if (!server->totp_key_ready || !acct || !token || !*token) return WF_OK;
    uint32_t code = 0;
    if (parse_totp_code(token, &code)) {
        metalbear_auth_totp record;
        wf_status st = metalbear_auth_totp_get(acct->auth, &record);
        if (st != WF_OK) return st;
        if (record.active && record.secret)
            st = check_totp(server, acct->auth, &record, code, accepted);
        metalbear_auth_totp_free(&record);
        return st;
    }
    return check_backup(server, acct->auth, token, accepted);
}
