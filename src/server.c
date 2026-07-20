#define _POSIX_C_SOURCE 200809L

#include "metalbear/server.h"
#include "metalbear/account.h"
#include "metalbear/account_registry.h"
#include "metalbear/auth.h"
#include "metalbear/backup.h"
#include "metalbear/email.h"
#include "metalbear/key_rotation.h"
#include "metalbear/oauth.h"
#include "metalbear/oauth_routes.h"
#include "metalbear/sequencer.h"

#include "wolfram/blob_store.h"
#include "wolfram/repo_store.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef enum metalbear_log_level {
    METALBEAR_LOG_DEBUG = 0,
    METALBEAR_LOG_INFO,
    METALBEAR_LOG_WARN,
    METALBEAR_LOG_ERROR,
} metalbear_log_level;

static metalbear_log_level log_level = METALBEAR_LOG_INFO;

static void metalbear_log(metalbear_log_level level, const char *fmt, ...) {
    if (level < log_level) return;
    static const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    va_list args;
    fprintf(stderr, "MetalBear [%s] ", level_names[level]);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

#define LOG_DEBUG(...) metalbear_log(METALBEAR_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) metalbear_log(METALBEAR_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...) metalbear_log(METALBEAR_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) metalbear_log(METALBEAR_LOG_ERROR, __VA_ARGS__)

static char *join_path(const char *directory, const char *name);

struct metalbear_server {
    wf_xrpc_server *xrpc;
    wf_repo_store *repo;
    wf_blob_store *blobs;
    metalbear_auth_store *auth;
    metalbear_account_store *account;
    metalbear_sequencer *sequencer;
    metalbear_oauth_store *oauth;
    metalbear_key_rotation *key_rotation;
    metalbear_account_registry *registry;
    wf_rate_limiter *rate_limiter;
    metalbear_email *email;
    char *service_did;
    char *public_url;
    char *account_did;
    char *account_handle;
    char *user_domain;
    char *account_email;
    int64_t retention_max_age;
    int64_t retention_min_events;
};

static bool constant_time_equal(const char *a, const char *b) {
    if (!a || !b) return false;
    size_t an = strlen(a), bn = strlen(b);
    return an == bn && CRYPTO_memcmp(a, b, an) == 0;
}

static bool is_public_route(const char *nsid) {
    static const char *const public_routes[] = {
        "com.atproto.server.describeServer",
        "_health",
        "com.atproto.server.createSession",
        "com.atproto.server.createAccount",
        "com.atproto.identity.resolveHandle",
        "com.atproto.repo.getRecord",
        "com.atproto.repo.describeRepo",
        "com.atproto.repo.listRecords",
        "com.atproto.sync.getLatestCommit",
        "com.atproto.sync.getBlob",
        "com.atproto.sync.getRepo",
        "com.atproto.sync.getBlocks",
        "com.atproto.sync.getRepoStatus",
        "com.atproto.sync.listRepos",
        "com.atproto.sync.subscribeRepos",
    };
    for (size_t i = 0; i < sizeof(public_routes) / sizeof(public_routes[0]); i++)
        if (strcmp(nsid, public_routes[i]) == 0) return true;
    return false;
}

static const char *bearer_token(const char *header) {
    static const char prefix[] = "Bearer ";
    if (!header || strncmp(header, prefix, sizeof(prefix) - 1) != 0)
        return NULL;
    return header + sizeof(prefix) - 1;
}

static bool inactive_route_allowed(const char *nsid) {
    return strcmp(nsid, "com.atproto.server.getSession") == 0 ||
           strcmp(nsid, "com.atproto.server.activateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.deactivateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.refreshSession") == 0 ||
           strcmp(nsid, "com.atproto.server.deleteSession") == 0;
}

static bool full_access_route(const char *nsid) {
    return strcmp(nsid, "com.atproto.server.createAppPassword") == 0 ||
           strcmp(nsid, "com.atproto.server.activateAccount") == 0 ||
           strcmp(nsid, "com.atproto.server.deactivateAccount") == 0;
}

static wf_status authenticate(wf_xrpc_request *req, void *ctx) {
    metalbear_server *server = ctx;
    if (is_public_route(req->nsid)) {
        if (!metalbear_account_is_active(server->account) &&
            (strncmp(req->nsid, "com.atproto.repo.", 17) == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getLatestCommit") == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getBlob") == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getRepo") == 0 ||
             strcmp(req->nsid, "com.atproto.sync.getBlocks") == 0))
            return WF_ERR_CONFLICT;
        return WF_OK;
    }
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *repo = cJSON_GetObjectItemCaseSensitive(req->params, "repo");
        cJSON *did = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        cJSON *target = cJSON_IsString(repo) ? repo :
                        (cJSON_IsString(did) ? did : NULL);
        if (target) {
            metalbear_account_entry *entry = NULL;
            wf_status lookup = metalbear_account_registry_find_by_did(
                server->registry, target->valuestring, &entry);
            bool known = lookup == WF_OK && entry;
            metalbear_account_entry_free(entry);
            if (!known)
                return WF_ERR_PERMISSION;
        }
    }

    const char *provided = bearer_token(req->auth_header);
    bool refresh_route = strcmp(req->nsid,
                                "com.atproto.server.refreshSession") == 0 ||
                         strcmp(req->nsid,
                                "com.atproto.server.deleteSession") == 0;
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    wf_status status = refresh_route
        ? (provided ? WF_OK : WF_ERR_PERMISSION)
        : metalbear_auth_verify_access_scope(server->auth, provided, &scope);
    if (status != WF_OK) return status;
    if (!refresh_route && full_access_route(req->nsid) &&
        scope != METALBEAR_ACCESS_FULL)
        return WF_ERR_PERMISSION;
    if (!metalbear_account_is_active(server->account) &&
        !inactive_route_allowed(req->nsid))
        return WF_ERR_CONFLICT;

    req->authed_subject = strdup(server->account_did);
    if (!req->authed_subject) return WF_ERR_ALLOC;
    req->authed_principal_kind = WF_XRPC_PRINCIPAL_USER;
    return WF_OK;
}

static wf_status set_json(wf_xrpc_response *response, cJSON *root) {
    if (!root) return WF_ERR_ALLOC;
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(response, json, strlen(json));
    free(json);
    return WF_OK;
}

static wf_status request_account_delete(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    /* Generate a random deletion token */
    unsigned char random_bytes[16];
    static const char hex[] = "0123456789abcdef";
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1)
        return WF_ERR_INTERNAL;
    char token[33];
    for (size_t i = 0; i < sizeof(random_bytes); i++) {
        token[i * 2] = hex[random_bytes[i] >> 4];
        token[i * 2 + 1] = hex[random_bytes[i] & 15];
    }
    token[32] = '\0';
    /* Send confirmation email if configured */
    if (server->email && server->account_email && server->account_email[0]) {
        metalbear_email_send_account_deletion(
            server->email, server->account_email, token);
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "token", token);
    return set_json(response, root);
}

static wf_status delete_account(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *password = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "password") : NULL;
    cJSON *token = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    if (!cJSON_IsString(password) || !cJSON_IsString(token)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "password and token are required");
        return WF_OK;
    }
    if (!metalbear_account_verify_password(server->account,
                                           password->valuestring)) {
        wf_xrpc_response_set_error(response, 401, "AuthenticationRequired",
                                   "Invalid password");
        return WF_OK;
    }
    /* Revoke all sessions */
    metalbear_auth_delete_all(server->auth);
    /* Delete all app passwords and credentials */
    metalbear_account_delete(server->account);
    /* Deactivate the account */
    metalbear_account_deactivate(server->account, NULL);
    /* Remove from the account registry */
    metalbear_account_registry_remove(server->registry, server->account_did);
    /* Emit deactivation event to firehose */
    metalbear_sequencer_account_status(
        server->sequencer, server->account_did, 0, "deleted");
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status describe_server(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    cJSON *root = cJSON_CreateObject();
    cJSON *domains = cJSON_CreateArray();
    if (!root || !domains) {
        cJSON_Delete(root);
        cJSON_Delete(domains);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", server->service_did);
    cJSON_AddItemToArray(domains, cJSON_CreateString(server->user_domain));
    cJSON_AddItemToObject(root, "availableUserDomains", domains);
    cJSON_AddBoolToObject(root, "inviteCodeRequired", true);
    return set_json(response, root);
}

static wf_status health(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response) {
    (void)ctx;
    (void)request;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "version", METALBEAR_VERSION);
    return set_json(response, root);
}

static wf_status resolve_handle(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *handle = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "handle") : NULL;
    if (!cJSON_IsString(handle) ||
        !wf_syntax_handle_is_valid(handle->valuestring) ||
        strcmp(handle->valuestring, server->account_handle) != 0 ||
        !metalbear_account_is_active(server->account)) {
        wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "did", server->account_did);
    return set_json(response, root);
}

static metalbear_credential_kind valid_login(metalbear_server *server,
                                             cJSON *body,
                                             char **out_app_password_name) {
    if (out_app_password_name) *out_app_password_name = NULL;
    cJSON *identifier = body ? cJSON_GetObjectItemCaseSensitive(body, "identifier") : NULL;
    cJSON *password = body ? cJSON_GetObjectItemCaseSensitive(body, "password") : NULL;
    if (!cJSON_IsString(identifier) || !cJSON_IsString(password))
        return METALBEAR_CREDENTIAL_INVALID;
    bool correct_id = constant_time_equal(identifier->valuestring,
                                          server->account_handle) ||
                      constant_time_equal(identifier->valuestring,
                                          server->account_did);
    return correct_id ? metalbear_account_verify_credential(
                            server->account, password->valuestring,
                            out_app_password_name)
                      : METALBEAR_CREDENTIAL_INVALID;
}

static cJSON *session_json(metalbear_server *server,
                           const metalbear_session_tokens *tokens) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    if (tokens) {
        cJSON_AddStringToObject(root, "accessJwt", tokens->access_jwt);
        cJSON_AddStringToObject(root, "refreshJwt", tokens->refresh_jwt);
    }
    cJSON_AddStringToObject(root, "handle", server->account_handle);
    cJSON_AddStringToObject(root, "did", server->account_did);
    bool active = metalbear_account_is_active(server->account);
    cJSON_AddBoolToObject(root, "active", active);
    if (!active) cJSON_AddStringToObject(root, "status", "deactivated");
    return root;
}

static wf_status create_session(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    char *app_password_name = NULL;
    metalbear_credential_kind credential = valid_login(
        server, request->params, &app_password_name);
    if (credential == METALBEAR_CREDENTIAL_INVALID) {
        wf_xrpc_response_set_error(response, 401, "AuthenticationRequired",
                                   "Invalid identifier or password");
        return WF_OK;
    }
    metalbear_access_scope scope = credential == METALBEAR_CREDENTIAL_ACCOUNT
        ? METALBEAR_ACCESS_FULL
        : credential == METALBEAR_CREDENTIAL_APP_PASSWORD_PRIVILEGED
            ? METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED
            : METALBEAR_ACCESS_APP_PASSWORD;
    metalbear_session_tokens tokens = {0};
    if (metalbear_auth_create_scoped_session(server->auth, scope,
            app_password_name, &tokens) != WF_OK) {
        free(app_password_name);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create session");
        return WF_OK;
    }
    free(app_password_name);
    wf_status status = set_json(response, session_json(server, &tokens));
    metalbear_session_tokens_free(&tokens);
    return status;
}

static wf_status get_session(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    (void)request;
    return set_json(response, session_json(ctx, NULL));
}

static wf_status refresh_session(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const char *token = bearer_token(request->auth_header);
    metalbear_session_tokens tokens = {0};
    if (metalbear_auth_rotate_refresh(server->auth, token, &tokens) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "ExpiredToken",
                                   "Refresh token is expired or revoked");
        return WF_OK;
    }
    wf_status status = set_json(response, session_json(server, &tokens));
    metalbear_session_tokens_free(&tokens);
    return status;
}

static wf_status delete_session(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const char *token = bearer_token(request->auth_header);
    if (metalbear_auth_revoke_refresh(server->auth, token) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Refresh token is invalid or revoked");
        return WF_OK;
    }
    (void)response;
    return WF_OK;
}

static wf_status create_app_password(void *ctx,
                                     const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *name = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "name") : NULL;
    cJSON *privileged = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "privileged") : NULL;
    if (!cJSON_IsString(name) || !name->valuestring[0] ||
        (privileged && !cJSON_IsBool(privileged))) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty name is required");
        return WF_OK;
    }
    char *password = NULL, *created_at = NULL;
    wf_status status = metalbear_account_create_app_password(
        server->account, name->valuestring, cJSON_IsTrue(privileged),
        &password, &created_at);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response,
            status == WF_ERR_CONFLICT || status == WF_ERR_INVALID_ARG ? 400 : 500,
            status == WF_ERR_CONFLICT || status == WF_ERR_INVALID_ARG
                ? "InvalidRequest" : "InternalError",
            status == WF_ERR_CONFLICT ? "App password name already exists" :
                                        "Could not create app password");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) { free(password); free(created_at); return WF_ERR_ALLOC; }
    cJSON_AddStringToObject(root, "name", name->valuestring);
    cJSON_AddStringToObject(root, "password", password);
    cJSON_AddStringToObject(root, "createdAt", created_at);
    cJSON_AddBoolToObject(root, "privileged", cJSON_IsTrue(privileged));
    free(password);
    free(created_at);
    return set_json(response, root);
}

static wf_status list_app_passwords(void *ctx,
                                    const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    metalbear_app_password *passwords = NULL;
    size_t count = 0;
    if (metalbear_account_list_app_passwords(server->account, &passwords,
                                             &count) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not list app passwords");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *items = cJSON_CreateArray();
    if (!root || !items) {
        cJSON_Delete(root); cJSON_Delete(items);
        metalbear_app_passwords_free(passwords, count);
        return WF_ERR_ALLOC;
    }
    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        if (!item) {
            cJSON_Delete(root); cJSON_Delete(items);
            metalbear_app_passwords_free(passwords, count);
            return WF_ERR_ALLOC;
        }
        cJSON_AddStringToObject(item, "name", passwords[i].name);
        cJSON_AddStringToObject(item, "createdAt", passwords[i].created_at);
        cJSON_AddBoolToObject(item, "privileged", passwords[i].privileged);
        cJSON_AddItemToArray(items, item);
    }
    metalbear_app_passwords_free(passwords, count);
    cJSON_AddItemToObject(root, "passwords", items);
    return set_json(response, root);
}

static wf_status revoke_app_password(void *ctx,
                                     const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *name = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "name") : NULL;
    if (!cJSON_IsString(name) || !name->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty name is required");
        return WF_OK;
    }
    if (metalbear_account_revoke_app_password(server->account,
                                               name->valuestring) != WF_OK ||
        metalbear_auth_revoke_app_password_sessions(server->auth,
                                                     name->valuestring) != WF_OK)
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not revoke app password");
    return WF_OK;
}

static wf_status deactivate_account(void *ctx,
                                    const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *delete_after = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "deleteAfter")
        : NULL;
    if (delete_after && !cJSON_IsString(delete_after)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "deleteAfter must be a datetime string");
        return WF_OK;
    }
    wf_status status = metalbear_account_deactivate(
        server->account,
        cJSON_IsString(delete_after) ? delete_after->valuestring : NULL);
    if (status == WF_OK)
        status = metalbear_sequencer_account_status(
            server->sequencer, server->account_did, 0, "deactivated");
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not deactivate account");
    }
    return WF_OK;
}

static wf_status activate_account(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    wf_status status = metalbear_account_activate(server->account);
    if (status == WF_OK)
        status = metalbear_sequencer_account_activation(
            server->sequencer, server->account_did, server->account_handle,
            server->repo);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not activate account");
    }
    return WF_OK;
}

static bool valid_service_audience(const char *audience) {
    if (!audience || strlen(audience) > 2048) return false;
    const char *fragment = strchr(audience, '#');
    if (!fragment) return wf_syntax_did_is_valid(audience);
    if (fragment == audience || !fragment[1] || strchr(fragment + 1, '#'))
        return false;
    size_t length = (size_t)(fragment - audience);
    char *did = malloc(length + 1);
    if (!did) return false;
    memcpy(did, audience, length);
    did[length] = '\0';
    bool valid = wf_syntax_did_is_valid(did);
    free(did);
    return valid;
}

static bool protected_service_method(const char *lxm) {
    static const char *const methods[] = {
        "com.atproto.admin.sendEmail",
        "com.atproto.identity.requestPlcOperationSignature",
        "com.atproto.identity.signPlcOperation",
        "com.atproto.identity.updateHandle",
        "com.atproto.server.activateAccount",
        "com.atproto.server.confirmEmail",
        "com.atproto.server.createAppPassword",
        "com.atproto.server.deactivateAccount",
        "com.atproto.server.getAccountInviteCodes",
        "com.atproto.server.getSession",
        "com.atproto.server.listAppPasswords",
        "com.atproto.server.requestAccountDelete",
        "com.atproto.server.requestEmailConfirmation",
        "com.atproto.server.requestEmailUpdate",
        "com.atproto.server.revokeAppPassword",
        "com.atproto.server.updateEmail",
    };
    if (!lxm) return false;
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
        if (strcmp(lxm, methods[i]) == 0) return true;
    return false;
}

static bool privileged_service_method(const char *lxm) {
    return lxm && (strncmp(lxm, "chat.bsky.", 10) == 0 ||
                   strcmp(lxm, "com.atproto.server.createAccount") == 0);
}

static wf_status get_service_auth(void *ctx,
                                  const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *aud = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "aud") : NULL;
    cJSON *exp_item = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "exp") : NULL;
    cJSON *lxm_item = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "lxm") : NULL;
    const char *lxm = cJSON_IsString(lxm_item) ? lxm_item->valuestring : NULL;
    if (!cJSON_IsString(aud) || !valid_service_audience(aud->valuestring) ||
        (lxm_item && (!cJSON_IsString(lxm_item) ||
                      !wf_syntax_nsid_is_valid(lxm))) ||
        protected_service_method(lxm)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Invalid service auth audience or method");
        return WF_OK;
    }
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    if (metalbear_auth_verify_access_scope(server->auth,
            bearer_token(request->auth_header), &scope) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (scope == METALBEAR_ACCESS_APP_PASSWORD &&
        privileged_service_method(lxm)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
            "Insufficient access for privileged service method");
        return WF_OK;
    }
    int64_t expiration = 0;
    if (exp_item) {
        if (!cJSON_IsString(exp_item)) {
            wf_xrpc_response_set_error(response, 400, "BadExpiration",
                                       "Expiration must be an integer");
            return WF_OK;
        }
        char *end = NULL;
        errno = 0;
        long long parsed = strtoll(exp_item->valuestring, &end, 10);
        if (errno || !end || *end) parsed = 0;
        int64_t now = (int64_t)time(NULL);
        if (parsed < now || parsed - now > 3600 ||
            (!lxm && parsed - now > 60)) {
            wf_xrpc_response_set_error(response, 400, "BadExpiration",
                                       "Expiration is outside allowed bounds");
            return WF_OK;
        }
        expiration = (int64_t)parsed;
    }
    char *token = NULL;
    if (wf_repo_store_create_service_auth(server->repo, aud->valuestring,
                                           expiration, lxm, &token) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create service token");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(token);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "token", token);
    free(token);
    return set_json(response, root);
}

static wf_status set_car_response(wf_xrpc_response *response,
                                  unsigned char *data, size_t length) {
    wf_xrpc_response_set_body(response, (const char *)data, length);
    wf_xrpc_response_set_content_type(response, "application/vnd.ipld.car");
    free(data);
    return response->body || length == 0 ? WF_OK : WF_ERR_ALLOC;
}

static wf_status get_repo(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *since = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "since") : NULL;
    if (!cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    unsigned char *data = NULL;
    size_t length = 0;
    wf_status status = wf_repo_store_export(
        server->repo, cJSON_IsString(since) ? since->valuestring : NULL,
        &data, &length);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is empty or unavailable");
        return WF_OK;
    }
    return set_car_response(response, data, length);
}

static wf_status get_blocks(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    if (!cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    const char **cids = NULL;
    size_t cid_count = 0;
    for (cJSON *item = request->params->child; item; item = item->next) {
        if (!item->string || strcmp(item->string, "cids") != 0 ||
            !cJSON_IsString(item))
            continue;
        const char **grown = realloc(cids, (cid_count + 1) * sizeof(*grown));
        if (!grown) {
            free(cids);
            return WF_ERR_ALLOC;
        }
        cids = grown;
        cids[cid_count++] = item->valuestring;
    }
    if (cid_count == 0) {
        free(cids);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "at least one cid is required");
        return WF_OK;
    }
    unsigned char *data = NULL;
    size_t length = 0;
    wf_status status = wf_repo_store_get_blocks(server->repo, cids, cid_count,
                                                &data, &length);
    free(cids);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "BlockNotFound",
                                   "One or more blocks were not found");
        return WF_OK;
    }
    return set_car_response(response, data, length);
}

static wf_status get_repo_status(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    if (!cJSON_IsString(did) ||
        strcmp(did->valuestring, server->account_did) != 0) {
        wf_xrpc_response_set_error(response, 400, "RepoNotFound",
                                   "Repository is not hosted here");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "did", server->account_did);
    bool active = metalbear_account_is_active(server->account);
    cJSON_AddBoolToObject(root, "active", active);
    if (!active) cJSON_AddStringToObject(root, "status", "deactivated");
    char *rev = NULL, *cid = NULL;
    if (active && wf_repo_store_get_head(server->repo, &rev, &cid) == WF_OK)
        cJSON_AddStringToObject(root, "rev", rev);
    free(rev);
    free(cid);
    return set_json(response, root);
}

static wf_status create_account(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *identifier = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "identifier") : NULL;
    cJSON *password = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "password") : NULL;
    cJSON *did = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "did") : NULL;
    cJSON *invite_code = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "inviteCode") : NULL;
    if (!cJSON_IsString(identifier) || !cJSON_IsString(password) ||
        !cJSON_IsString(did)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "identifier, password, and did are required");
        return WF_OK;
    }
    (void)invite_code;
    /* Check if the handle is already registered */
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_handle(
            server->registry, identifier->valuestring,
            &existing) == WF_OK) {
        metalbear_account_entry_free(existing);
        wf_xrpc_response_set_error(response, 400, "AccountAlreadyExists",
                                   "Handle is already taken");
        return WF_OK;
    }
    /* Hash the password */
    char *hash = metalbear_account_hash_password(password->valuestring);
    if (!hash) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not hash password");
        return WF_OK;
    }
    /* Build data directory for the new account */
    char *data_dir = join_path(server->user_domain,
                               identifier->valuestring);
    free(hash);
    if (!data_dir) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not build data directory");
        return WF_OK;
    }
    wf_status status = metalbear_account_registry_add(
        server->registry, did->valuestring, identifier->valuestring,
        "", data_dir);
    free(data_dir);
    if (status == WF_ERR_CONFLICT) {
        wf_xrpc_response_set_error(response, 400, "AccountAlreadyExists",
                                   "Handle is already taken");
        return WF_OK;
    }
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create account");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "did", did->valuestring);
    cJSON_AddStringToObject(root, "handle", identifier->valuestring);
    return set_json(response, root);
}

static wf_status request_email_confirmation(void *ctx,
                                            const wf_xrpc_request *request,
                                            wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    char *email = NULL;
    int confirmed = 0;
    if (metalbear_account_get_email(server->account, &email, &confirmed) !=
            WF_OK || !email) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "No email address on file");
        free(email);
        return WF_OK;
    }
    if (confirmed) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Email is already confirmed");
        free(email);
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(server->account, "confirm",
                                             token, sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create confirmation token");
        return WF_OK;
    }
    if (server->email)
        metalbear_email_send_verification(server->email, email, token);
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status confirm_email(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *token = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "token is required");
        return WF_OK;
    }
    wf_status status = metalbear_account_verify_email_token(
        server->account, "confirm", token->valuestring);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired confirmation token");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status request_email_update(void *ctx,
                                      const wf_xrpc_request *request,
                                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *email = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "email") : NULL;
    if (!cJSON_IsString(email) || !email->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "email is required");
        return WF_OK;
    }
    /* Store the new email address */
    if (metalbear_account_store_email(server->account,
                                      email->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not store email address");
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(server->account, "update",
                                             token, sizeof(token)) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create update token");
        return WF_OK;
    }
    if (server->email)
        metalbear_email_send_verification(server->email, email->valuestring,
                                          token);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status update_email(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *token = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "token") : NULL;
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "token is required");
        return WF_OK;
    }
    wf_status status = metalbear_account_verify_email_token(
        server->account, "update", token->valuestring);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired update token");
        return WF_OK;
    }
    /* Mark the stored email as confirmed */
    char *email = NULL;
    int confirmed = 0;
    metalbear_account_get_email(server->account, &email, &confirmed);
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status request_password_reset(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *identifier = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "identifier")
        : NULL;
    if (!cJSON_IsString(identifier) || !identifier->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "identifier is required");
        return WF_OK;
    }
    char *email = NULL;
    metalbear_account_get_email(server->account, &email, NULL);
    if (!email || !email[0]) {
        free(email);
        /* Always return success to avoid email enumeration */
        cJSON *root = cJSON_CreateObject();
        if (!root) return WF_ERR_ALLOC;
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(response, root);
    }
    char token[33];
    if (metalbear_account_create_email_token(server->account, "reset",
                                             token, sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create reset token");
        return WF_OK;
    }
    if (server->email)
        metalbear_email_send_password_reset(server->email, email, token);
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

static wf_status get_account_invite_codes(void *ctx,
                                          const wf_xrpc_request *request,
                                          wf_xrpc_response *response) {
    (void)request;
    (void)ctx;
    /* Single-account PDS: return empty invite codes */
    cJSON *root = cJSON_CreateObject();
    cJSON *codes = cJSON_CreateArray();
    if (!root || !codes) {
        cJSON_Delete(root);
        cJSON_Delete(codes);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToObject(root, "inviteCodes", codes);
    return set_json(response, root);
}

static wf_status list_repos(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    cJSON *root = cJSON_CreateObject();
    cJSON *repos = cJSON_CreateArray();
    if (!root || !repos) {
        cJSON_Delete(root);
        cJSON_Delete(repos);
        return WF_ERR_ALLOC;
    }
    char *rev = NULL, *cid = NULL;
    if (wf_repo_store_get_head(server->repo, &rev, &cid) == WF_OK) {
        cJSON *repo = cJSON_CreateObject();
        if (!repo) {
            free(rev);
            free(cid);
            cJSON_Delete(root);
            cJSON_Delete(repos);
            return WF_ERR_ALLOC;
        }
        cJSON_AddStringToObject(repo, "did", server->account_did);
        cJSON_AddStringToObject(repo, "head", cid);
        cJSON_AddStringToObject(repo, "rev", rev);
        bool active = metalbear_account_is_active(server->account);
        cJSON_AddBoolToObject(repo, "active", active);
        if (!active)
            cJSON_AddStringToObject(repo, "status", "deactivated");
        cJSON_AddItemToArray(repos, repo);
    }
    free(rev);
    free(cid);
    cJSON_AddItemToObject(root, "repos", repos);
    return set_json(response, root);
}

static bool make_directory(const char *path) {
    if (mkdir(path, 0700) == 0) return true;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static char *join_path(const char *directory, const char *name) {
    size_t dn = strlen(directory), nn = strlen(name);
    bool slash = dn > 0 && directory[dn - 1] == '/';
    char *path = malloc(dn + nn + (slash ? 1 : 2));
    if (!path) return NULL;
    snprintf(path, dn + nn + (slash ? 1 : 2), "%s%s%s", directory,
             slash ? "" : "/", name);
    return path;
}

static bool copy_config(metalbear_server *server,
                        const metalbear_config *config) {
    server->service_did = strdup(config->service_did);
    if (config->public_url) server->public_url = strdup(config->public_url);
    server->account_did = strdup(config->account_did);
    server->account_handle = strdup(config->account_handle);
    server->user_domain = strdup(config->user_domain);
    return server->service_did && (!config->public_url || server->public_url) &&
           server->account_did &&
           server->account_handle && server->user_domain;
}

static char *public_url_from_service_did(const char *did) {
    static const char prefix[] = "did:web:";
    if (!did || strncmp(did, prefix, sizeof(prefix) - 1) != 0) return NULL;
    const char *source = did + sizeof(prefix) - 1;
    size_t capacity = strlen(source) + strlen("https://") + 1;
    char *url = malloc(capacity);
    if (!url) return NULL;
    char *output = url;
    memcpy(output, "https://", strlen("https://"));
    output += strlen("https://");
    while (*source) {
        if (source[0] == '%' && source[1] == '3' &&
            (source[2] == 'A' || source[2] == 'a')) {
            *output++ = ':';
            source += 3;
        } else {
            *output++ = *source == ':' ? '/' : *source;
            source++;
        }
    }
    *output = '\0';
    return url;
}

static wf_status register_identity_documents(metalbear_server *server) {
    if (!server->public_url)
        server->public_url = public_url_from_service_did(server->service_did);
    if (!server->public_url) return WF_ERR_INVALID_ARG;
    cJSON *document = cJSON_CreateObject();
    cJSON *context = cJSON_CreateArray();
    cJSON *services = cJSON_CreateArray();
    cJSON *service = cJSON_CreateObject();
    if (!document || !context || !services || !service) {
        cJSON_Delete(document);
        cJSON_Delete(context);
        cJSON_Delete(services);
        cJSON_Delete(service);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToArray(context,
                         cJSON_CreateString("https://www.w3.org/ns/did/v1"));
    cJSON_AddItemToObject(document, "@context", context);
    cJSON_AddStringToObject(document, "id", server->service_did);
    cJSON_AddStringToObject(service, "id", "#atproto_pds");
    cJSON_AddStringToObject(service, "type", "AtprotoPersonalDataServer");
    cJSON_AddStringToObject(service, "serviceEndpoint", server->public_url);
    cJSON_AddItemToArray(services, service);
    cJSON_AddItemToObject(document, "service", services);
    char *json = cJSON_PrintUnformatted(document);
    cJSON_Delete(document);
    if (!json) return WF_ERR_ALLOC;
    wf_status status = wf_xrpc_server_register_static_get(server->xrpc,
        "/.well-known/did.json", "application/did+ld+json", json,
        strlen(json));
    free(json);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_static_get(server->xrpc,
        "/.well-known/atproto-did", "text/plain; charset=utf-8",
        server->account_did, strlen(server->account_did));
    if (status != WF_OK) return status;
    static const char landing[] =
        "MetalBear AT Protocol Personal Data Server\n"
        "API routes are available under /xrpc/.\n";
    status = wf_xrpc_server_register_static_get(
        server->xrpc, "/", "text/plain; charset=utf-8", landing,
        sizeof(landing) - 1);
    if (status != WF_OK) return status;
    static const char robots[] =
        "User-agent: *\nAllow: /\n";
    return wf_xrpc_server_register_static_get(
        server->xrpc, "/robots.txt", "text/plain; charset=utf-8", robots,
        sizeof(robots) - 1);
}

static bool valid_config(const metalbear_config *config) {
    return config && config->listen_address && config->data_directory &&
           config->service_did && config->account_did &&
           config->account_handle && config->user_domain && config->password &&
           config->password[0];
}

metalbear_server *metalbear_server_start(const metalbear_config *config) {
    if (!valid_config(config)) {
        LOG_ERROR("invalid server configuration");
        return NULL;
    }
    if (!make_directory(config->data_directory)) {
        LOG_ERROR("cannot create data directory: %s", config->data_directory);
        return NULL;
    }

    metalbear_server *server = calloc(1, sizeof(*server));
    char *repo_path = join_path(config->data_directory, "repo.sqlite3");
    char *blob_path = join_path(config->data_directory, "blobs");
    char *auth_path = join_path(config->data_directory, "auth.sqlite3");
    char *account_path = join_path(config->data_directory, "account.sqlite3");
    char *sequence_path = join_path(config->data_directory, "sequencer.sqlite3");
    if (!server || !repo_path || !blob_path || !auth_path || !account_path ||
        !sequence_path ||
        !copy_config(server, config) ||
        !make_directory(blob_path)) {
        LOG_ERROR("cannot initialise server paths");
        goto fail;
    }

    if (wf_repo_store_open(repo_path, config->account_did,
                           config->account_handle, &server->repo) != WF_OK) {
        LOG_ERROR("cannot open repository store");
        goto fail;
    }
    server->blobs = wf_blob_store_new(blob_path);
    if (!server->blobs) {
        LOG_ERROR("cannot open blob store");
        goto fail;
    }
    if (metalbear_auth_store_open(auth_path, config->service_did,
                                  config->account_did, &server->auth) != WF_OK) {
        LOG_ERROR("cannot open authentication store");
        goto fail;
    }
    if (metalbear_account_store_open(account_path, config->password,
                                     &server->account) != WF_OK) {
        LOG_ERROR("cannot open account state store");
        goto fail;
    }
    if (metalbear_sequencer_open(sequence_path, config->account_did,
                                 config->account_handle,
                                 &server->sequencer) != WF_OK) {
        LOG_ERROR("cannot open event sequencer");
        goto fail;
    }

    /* Open OAuth store */
    char *oauth_path = join_path(config->data_directory, "oauth.sqlite3");
    if (!oauth_path ||
        metalbear_oauth_store_open(oauth_path, config->public_url
                                    ? config->public_url : "",
                                   config->account_did,
                                   &server->oauth) != WF_OK) {
        LOG_ERROR("cannot open OAuth store");
        free(oauth_path);
        goto fail;
    }
    free(oauth_path);

    /* Open key rotation store */
    char *key_path = join_path(config->data_directory, "keys.sqlite3");
    if (!key_path ||
        metalbear_key_rotation_open(key_path,
                                    &server->key_rotation) != WF_OK) {
        LOG_ERROR("cannot open key rotation store");
        free(key_path);
        goto fail;
    }
    free(key_path);

    /* Open account registry */
    char *registry_path = join_path(config->data_directory, "accounts.sqlite3");
    if (!registry_path ||
        metalbear_account_registry_open(registry_path,
                                        &server->registry) != WF_OK) {
        LOG_ERROR("cannot open account registry");
        free(registry_path);
        goto fail;
    }
    free(registry_path);
    /* Seed the registry with the primary account if not already present */
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, config->account_did, &existing) != WF_OK) {
        char *primary_dir = join_path(config->data_directory, "primary");
        if (primary_dir) {
            metalbear_account_registry_add(server->registry,
                                           config->account_did,
                                           config->account_handle,
                                           "", primary_dir);
            free(primary_dir);
        }
    } else {
        metalbear_account_entry_free(existing);
    }

    /* Create rate limiter: 100 requests per 60 seconds */
    server->rate_limiter = wf_rate_limiter_new(100, 60, 0);
    wf_repo_store_set_event_callback(server->repo,
                                     metalbear_sequencer_repo_event,
                                     server->sequencer);
    if (metalbear_sequencer_reconcile_account(
            server->sequencer, server->account_did,
            metalbear_account_is_active(server->account)) != WF_OK) {
        LOG_ERROR("cannot reconcile account sequence");
        goto fail;
    }
    if (metalbear_sequencer_reconcile_repo(server->sequencer,
                                           server->repo) != WF_OK) {
        LOG_ERROR("cannot reconcile repository sequence");
        goto fail;
    }
    server->xrpc = wf_xrpc_server_start(config->listen_address, config->port,
                                        config->thread_count);
    if (!server->xrpc) {
        LOG_ERROR("cannot start XRPC listener");
        goto fail;
    }
    if (register_identity_documents(server) != WF_OK) {
        LOG_ERROR("cannot register identity documents");
        goto fail;
    }

    if (wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.describeServer", describe_server, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "_health", health, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createAccount", create_account, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.identity.resolveHandle", resolve_handle, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createSession", create_session, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.getSession", get_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.refreshSession", refresh_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.deleteSession", delete_session, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.createAppPassword", create_app_password,
            server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.listAppPasswords", list_app_passwords,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.revokeAppPassword", revoke_app_password,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.deactivateAccount", deactivate_account,
            server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.activateAccount", activate_account,
            server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.getServiceAuth", get_service_auth,
            server) != WF_OK ||
        wf_xrpc_server_register_pds_repo(server->xrpc, server->repo) != WF_OK ||
        wf_xrpc_server_register_blob_store(server->xrpc, server->blobs) != WF_OK) {
        LOG_ERROR("cannot register XRPC routes");
        goto fail;
    }
    if (wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getRepo", get_repo, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getBlocks", get_blocks, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.getRepoStatus", get_repo_status, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.sync.listRepos", list_repos, server) != WF_OK ||
        metalbear_sequencer_register(server->sequencer,
                                     server->xrpc) != WF_OK) {
        LOG_ERROR("cannot register sync export routes");
        goto fail;
    }

    wf_xrpc_server_set_auth_callback(server->xrpc, authenticate, server);

    /* Register OAuth HTTP routes (bypass XRPC auth) */
    if (metalbear_oauth_routes_register(server->xrpc, server->oauth,
                                         server->public_url,
                                         server->service_did,
                                         server->account_did) != WF_OK) {
        LOG_ERROR("cannot register OAuth routes");
        goto fail;
    }

    /* Register account deletion routes */
    if (wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestAccountDelete",
            request_account_delete, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.deleteAccount",
            delete_account, server) != WF_OK) {
        LOG_ERROR("cannot register deletion routes");
        goto fail;
    }

    /* Register email flow routes */
    if (wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestEmailConfirmation",
            request_email_confirmation, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.confirmEmail",
            confirm_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestEmailUpdate",
            request_email_update, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.updateEmail",
            update_email, server) != WF_OK ||
        wf_xrpc_server_register_procedure(server->xrpc,
            "com.atproto.server.requestPasswordReset",
            request_password_reset, server) != WF_OK ||
        wf_xrpc_server_register_query(server->xrpc,
            "com.atproto.server.getAccountInviteCodes",
            get_account_invite_codes, server) != WF_OK) {
        LOG_ERROR("cannot register email/invite routes");
        goto fail;
    }

    /* Apply rate limiting */
    if (server->rate_limiter)
        wf_xrpc_server_set_rate_limiter(server->xrpc, server->rate_limiter);

    /* Initialize email module if configured */
    if (config->smtp_host && config->smtp_host[0] &&
        config->from_address && config->from_address[0]) {
        metalbear_email_config email_cfg = {
            .smtp_host = config->smtp_host,
            .smtp_port = config->smtp_port ? config->smtp_port : 587,
            .smtp_username = config->smtp_username,
            .smtp_password = config->smtp_password,
            .from_address = config->from_address,
            .from_name = config->from_name,
            .smtp_starttls = config->smtp_starttls,
        };
        metalbear_email_open(&email_cfg, &server->email);
    }
    if (config->account_email && config->account_email[0])
        server->account_email = strdup(config->account_email);

    /* Configure firehose retention */
    server->retention_max_age = config->retention_max_age_seconds > 0
                                    ? config->retention_max_age_seconds
                                    : 30 * 24 * 60 * 60; /* 30 days */
    server->retention_min_events = config->retention_min_events > 0
                                      ? config->retention_min_events
                                      : 1000;

    /* Apply initial retention */
    metalbear_sequencer_retain(server->sequencer,
                               server->retention_max_age,
                               server->retention_min_events);

    free(repo_path);
    free(blob_path);
    free(auth_path);
    free(account_path);
    free(sequence_path);
    return server;

fail:
    free(repo_path);
    free(blob_path);
    free(auth_path);
    free(account_path);
    free(sequence_path);
    metalbear_server_free(server);
    return NULL;
}

uint16_t metalbear_server_port(const metalbear_server *server) {
    return server ? wf_xrpc_server_port(server->xrpc) : 0;
}

void metalbear_server_free(metalbear_server *server) {
    if (!server) return;
    wf_xrpc_server_free(server->xrpc);
    wf_repo_store_set_event_callback(server->repo, NULL, NULL);
    metalbear_sequencer_free(server->sequencer);
    metalbear_account_store_free(server->account);
    metalbear_auth_store_free(server->auth);
    metalbear_oauth_store_free(server->oauth);
    metalbear_key_rotation_free(server->key_rotation);
    metalbear_account_registry_free(server->registry);
    metalbear_email_free(server->email);
    wf_rate_limiter_free(server->rate_limiter);
    wf_blob_store_free(server->blobs);
    wf_repo_store_free(server->repo);
    free(server->service_did);
    free(server->public_url);
    free(server->account_did);
    free(server->account_handle);
    free(server->user_domain);
    free(server->account_email);
    free(server);
}
