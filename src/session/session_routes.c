#include "session_routes.h"
#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/oauth/auth.h"
#include "metalbear/ops/metrics.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static metalbear_credential_kind
valid_login(metalbear_server *server, cJSON *body,
            metalbear_account_context **out_account,
            char **out_app_password_name) {
    if (out_account) *out_account = NULL;
    if (out_app_password_name) *out_app_password_name = NULL;
    cJSON *identifier =
        body ? cJSON_GetObjectItemCaseSensitive(body, "identifier") : NULL;
    cJSON *password =
        body ? cJSON_GetObjectItemCaseSensitive(body, "password") : NULL;
    if (!cJSON_IsString(identifier) || !cJSON_IsString(password))
        return METALBEAR_CREDENTIAL_INVALID;
    metalbear_account_context *acct =
        context_for_identifier(server, identifier->valuestring);
    if (!acct) return METALBEAR_CREDENTIAL_INVALID;
    metalbear_credential_kind credential = metalbear_account_verify_credential(
        acct->account, password->valuestring, out_app_password_name);
    if (credential != METALBEAR_CREDENTIAL_INVALID && out_account)
        *out_account = acct;
    return credential;
}

static cJSON *session_json(metalbear_server *server,
                           metalbear_account_context *acct,
                           const metalbear_session_tokens *tokens) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    if (tokens) {
        cJSON_AddStringToObject(root, "accessJwt", tokens->access_jwt);
        cJSON_AddStringToObject(root, "refreshJwt", tokens->refresh_jwt);
    }
    cJSON_AddStringToObject(root, "handle", acct->handle);
    cJSON_AddStringToObject(root, "did", acct->did);
    bool active = false;
    const char *status = account_status_string(server, acct, &active);
    cJSON_AddBoolToObject(root, "active", active);
    if (status) cJSON_AddStringToObject(root, "status", status);
    char *email = NULL;
    int confirmed = 0;
    bool email_auth_factor = false;
    if (metalbear_account_get_email(acct->account, &email, &confirmed) ==
            WF_OK &&
        email) {
        cJSON_AddStringToObject(root, "email", email);
        cJSON_AddBoolToObject(root, "emailConfirmed", confirmed != 0);
        if (confirmed != 0) {
            email_auth_factor = true;
        }
    }
    free(email);
    if (server->public_url) {
        cJSON *did_doc = build_did_doc(server, acct);
        if (did_doc) cJSON_AddItemToObject(root, "didDoc", did_doc);
    }
    cJSON_AddBoolToObject(root, "emailAuthFactor", email_auth_factor);
    return root;
}

wf_status create_session(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = NULL;
    char *app_password_name = NULL;

    /* Keyed by identifier+IP so this can't be used either to lock a
     * legitimate user out (an attacker hammering their identifier from many
     * IPs) or to brute-force many identifiers from one IP while staying
     * under any single per-identifier budget. */
    {
        const cJSON *identifier =
            request->params ? cJSON_GetObjectItemCaseSensitive(request->params,
                                                               "identifier")
                            : NULL;
        const char *id_str =
            cJSON_IsString(identifier) ? identifier->valuestring : "";
        char key[320];
        snprintf(key, sizeof(key), "%s-%s", id_str,
                 request->client_ip ? request->client_ip : "unknown");
        if (!check_endpoint_rate_limit(server->rl_create_session_day,
                                       server->rl_create_session_5min, key, 1,
                                       response)) {
            return WF_OK;
        }
    }

    /* Matches the reference's OLD_PASSWORD_MAX_LENGTH check (createSession.ts):
     * reject an implausibly long password before it is ever hashed, rather
     * than paying scrypt's cost (proportional to input size) for an input no
     * real password reaches. */
    {
        const cJSON *password_check =
            request->params
                ? cJSON_GetObjectItemCaseSensitive(request->params, "password")
                : NULL;
        if (cJSON_IsString(password_check) &&
            strlen(password_check->valuestring) > 512) {
            wf_xrpc_response_set_error(
                response, 401, "AuthenticationRequired",
                "Password too long. Consider resetting your password.");
            return WF_OK;
        }
    }

    metalbear_credential_kind credential =
        valid_login(server, request->params, &acct, &app_password_name);
    if (credential == METALBEAR_CREDENTIAL_INVALID || !acct) {
        LOG_WARN("create_session: invalid credentials for host=%s",
                 request->host_header ? request->host_header : "(unknown)");
        metalbear_metrics_inc(METALBEAR_METRIC_LOGIN_FAILURES);
        wf_xrpc_response_set_error(response, 401, "AuthenticationRequired",
                                   "Invalid identifier or password");
        return WF_OK;
    }
    /*
     * Credentials are checked before the takedown so the error does not
     * distinguish a taken-down account from a wrong password to anyone who
     * does not already hold the password.
     *
     * `allowTakendown` (com.atproto.server.createSession lexicon) lets the
     * caller opt into a session anyway, narrowly scoped to
     * METALBEAR_ACCESS_TAKENDOWN rather than refused outright -- matching
     * the reference's `formatScope(appPassword, isSoftDeleted)`, which
     * checks the takedown before the credential kind and returns
     * AuthScope.Takendown regardless of whether an app password was used.
     */
    bool taken_down = account_is_taken_down(server, acct->did);
    if (taken_down) {
        const cJSON *allow_takendown =
            request->params ? cJSON_GetObjectItemCaseSensitive(request->params,
                                                               "allowTakendown")
                            : NULL;
        if (!cJSON_IsTrue(allow_takendown)) {
            free(app_password_name);
            metalbear_metrics_inc(METALBEAR_METRIC_LOGIN_FAILURES);
            LOG_WARN("create_session: refused taken-down account did=%s",
                     acct->did);
            wf_xrpc_response_set_error(response, 401, "AccountTakedown",
                                       "Account has been taken down");
            return WF_OK;
        }
    }
    metalbear_access_scope scope =
        taken_down ? METALBEAR_ACCESS_TAKENDOWN
        : credential == METALBEAR_CREDENTIAL_ACCOUNT ? METALBEAR_ACCESS_FULL
        : credential == METALBEAR_CREDENTIAL_APP_PASSWORD_PRIVILEGED
            ? METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED
            : METALBEAR_ACCESS_APP_PASSWORD;
    metalbear_session_tokens tokens = {0};
    if (metalbear_auth_create_scoped_session(
            acct->auth, scope, app_password_name, &tokens) != WF_OK) {
        free(app_password_name);
        LOG_ERROR("create_session: failed to create session for did=%s",
                  acct->did);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create session");
        return WF_OK;
    }
    free(app_password_name);
    metalbear_metrics_inc(METALBEAR_METRIC_SESSIONS_CREATED);
    LOG_INFO("create_session: issued session for did=%s scope=%d", acct->did,
             scope);
    wf_status status = set_json(response, session_json(server, acct, &tokens));
    metalbear_session_tokens_free(&tokens);
    return status;
}

wf_status get_session(void *ctx, const wf_xrpc_request *request,
                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    return set_json(response, session_json(server, acct, NULL));
}

wf_status refresh_session(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    const char *token = bearer_token(request->auth_header);
    if (acct && account_is_taken_down(server, acct->did)) {
        wf_xrpc_response_set_error(response, 401, "AccountTakedown",
                                   "Account has been taken down");
        return WF_OK;
    }
    metalbear_session_tokens tokens = {0};
    if (!acct ||
        metalbear_auth_rotate_refresh(acct->auth, token, &tokens) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "ExpiredToken",
                                   "Refresh token is expired or revoked");
        return WF_OK;
    }
    wf_status status = set_json(response, session_json(server, acct, &tokens));
    metalbear_session_tokens_free(&tokens);
    return status;
}

wf_status delete_session(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    const char *token = bearer_token(request->auth_header);
    if (!acct || metalbear_auth_revoke_refresh(acct->auth, token) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Refresh token is invalid or revoked");
        return WF_OK;
    }
    (void)response;
    return WF_OK;
}

wf_status create_app_password(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *name =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "name")
            : NULL;
    cJSON *privileged =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "privileged")
            : NULL;
    if (!cJSON_IsString(name) || !name->valuestring[0] ||
        (privileged && !cJSON_IsBool(privileged))) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty name is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    char *password = NULL, *created_at = NULL;
    wf_status status = metalbear_account_create_app_password(
        acct->account, name->valuestring, cJSON_IsTrue(privileged), &password,
        &created_at);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(
            response,
            status == WF_ERR_CONFLICT || status == WF_ERR_INVALID_ARG ? 400
                                                                      : 500,
            status == WF_ERR_CONFLICT || status == WF_ERR_INVALID_ARG
                ? "InvalidRequest"
                : "InternalError",
            status == WF_ERR_CONFLICT ? "App password name already exists"
                                      : "Could not create app password");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(password);
        free(created_at);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "name", name->valuestring);
    cJSON_AddStringToObject(root, "password", password);
    cJSON_AddStringToObject(root, "createdAt", created_at);
    cJSON_AddBoolToObject(root, "privileged", cJSON_IsTrue(privileged));
    free(password);
    free(created_at);
    return set_json(response, root);
}

wf_status list_app_passwords(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    metalbear_app_password *passwords = NULL;
    size_t count = 0;
    if (metalbear_account_list_app_passwords(acct->account, &passwords,
                                             &count) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not list app passwords");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *items = cJSON_CreateArray();
    if (!root || !items) {
        cJSON_Delete(root);
        cJSON_Delete(items);
        metalbear_app_passwords_free(passwords, count);
        return WF_ERR_ALLOC;
    }
    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        if (!item) {
            cJSON_Delete(root);
            cJSON_Delete(items);
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

wf_status revoke_app_password(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *name =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "name")
            : NULL;
    if (!cJSON_IsString(name) || !name->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty name is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (metalbear_account_revoke_app_password(acct->account,
                                              name->valuestring) != WF_OK ||
        metalbear_auth_revoke_app_password_sessions(acct->auth,
                                                    name->valuestring) != WF_OK)
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not revoke app password");
    return WF_OK;
}

wf_status deactivate_account(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *delete_after =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "deleteAfter")
            : NULL;
    if (delete_after && !cJSON_IsString(delete_after)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "deleteAfter must be a datetime string");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    wf_status status = metalbear_account_deactivate(
        acct->account,
        cJSON_IsString(delete_after) ? delete_after->valuestring : NULL);
    if (status == WF_OK)
        status = metalbear_sequencer_account_status(acct->sequencer, acct->did,
                                                    0, "deactivated");
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not deactivate account");
    }
    return WF_OK;
}

wf_status activate_account(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    wf_status status = metalbear_account_activate(acct->account);
    if (status == WF_OK)
        status = metalbear_sequencer_account_activation(
            acct->sequencer, acct->did, acct->handle, acct->repo);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not activate account");
    }
    return WF_OK;
}
