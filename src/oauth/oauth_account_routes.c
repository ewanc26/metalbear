#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth/oauth_account_routes.h"

#include "../server_internal.h"

#include "metalbear/oauth/oauth.h"

#include <cJSON.h>
#include <string.h>

/* ---- com.metalbear.oauth.listDevices (query) ----
 * Every device session (browser signed in as this account, see
 * oauth_signin) still valid for the caller's own account. */
wf_status oauth_list_devices(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    metalbear_oauth_device_session_info *items = NULL;
    size_t count = 0;
    if (metalbear_oauth_device_session_list(server->oauth, acct->did, &items,
                                            &count) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not list device sessions");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_oauth_device_session_info_list_free(items, count);
        return WF_ERR_ALLOC;
    }
    cJSON *devices = cJSON_CreateArray();
    if (!devices) {
        cJSON_Delete(root);
        metalbear_oauth_device_session_info_list_free(items, count);
        return WF_ERR_ALLOC;
    }
    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        if (!item) continue;
        cJSON_AddStringToObject(item, "sessionId", items[i].session_id);
        cJSON_AddNumberToObject(item, "expiresAt", (double)items[i].expires_at);
        cJSON_AddItemToArray(devices, item);
    }
    cJSON_AddItemToObject(root, "devices", devices);
    metalbear_oauth_device_session_info_list_free(items, count);
    return set_json(response, root);
}

/* ---- com.metalbear.oauth.revokeDevice (procedure) ----
 * Sign a single device (by the sessionId listDevices returned) out of the
 * caller's own account, without touching any other device's session. */
wf_status oauth_revoke_device(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *session_id =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "sessionId")
            : NULL;
    if (!cJSON_IsString(session_id) || !session_id->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty sessionId is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    wf_status status = metalbear_oauth_device_session_revoke_by_id(
        server->oauth, acct->did, session_id->valuestring);
    if (status == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No such device session");
        return WF_OK;
    }
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not revoke device session");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.metalbear.oauth.listGrants (query) ----
 * Every OAuth client currently holding a live grant (refresh token) for the
 * caller's own account -- one entry per distinct client, regardless of how
 * many times it re-authorized. */
wf_status oauth_list_grants(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    metalbear_oauth_grant_info *items = NULL;
    size_t count = 0;
    if (metalbear_oauth_grants_list(server->oauth, acct->did, &items, &count) !=
        WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not list connected apps");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_oauth_grant_info_list_free(items, count);
        return WF_ERR_ALLOC;
    }
    cJSON *grants = cJSON_CreateArray();
    if (!grants) {
        cJSON_Delete(root);
        metalbear_oauth_grant_info_list_free(items, count);
        return WF_ERR_ALLOC;
    }
    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        if (!item) continue;
        cJSON_AddStringToObject(item, "clientId", items[i].client_id);
        cJSON_AddStringToObject(item, "scope", items[i].scope);
        cJSON_AddNumberToObject(item, "expiresAt", (double)items[i].expires_at);
        cJSON_AddItemToArray(grants, item);
    }
    cJSON_AddItemToObject(root, "grants", grants);
    metalbear_oauth_grant_info_list_free(items, count);
    return set_json(response, root);
}

/* ---- com.metalbear.oauth.revokeGrant (procedure) ----
 * Disconnect one OAuth client from the caller's own account outright,
 * ending its access rather than waiting for its current token to expire. */
wf_status oauth_revoke_grant(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *client_id =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "clientId")
            : NULL;
    if (!cJSON_IsString(client_id) || !client_id->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "A non-empty clientId is required");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (metalbear_oauth_grants_revoke(server->oauth, acct->did,
                                      client_id->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not revoke connected app");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}
