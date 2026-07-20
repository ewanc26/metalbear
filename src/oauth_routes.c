#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth_routes.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct oauth_route_ctx {
    metalbear_oauth_store *store;
    char *public_url;
} oauth_route_ctx;

static wf_status json_response(wf_xrpc_response *resp, cJSON *root,
                                const char *cache_control) {
    if (!root) return WF_ERR_ALLOC;
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(resp, json, strlen(json));
    free(json);
    if (cache_control)
        wf_xrpc_response_add_header(resp, "Cache-Control", cache_control);
    return WF_OK;
}

static wf_status oauth_metadata(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    (void)req;
    oauth_route_ctx *rctx = ctx;
    const char *issuer = rctx->public_url;
    if (!issuer || !issuer[0]) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Server public URL not configured");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;

    cJSON_AddStringToObject(root, "issuer", issuer);

    size_t base_len = strlen(issuer);
    char *endpoint = NULL;

    endpoint = malloc(base_len + sizeof("/oauth/authorize"));
    if (endpoint) {
        snprintf(endpoint, base_len + sizeof("/oauth/authorize"),
                 "%s/oauth/authorize", issuer);
        cJSON_AddStringToObject(root, "authorization_endpoint", endpoint);
        free(endpoint);
    }

    endpoint = malloc(base_len + sizeof("/oauth/token"));
    if (endpoint) {
        snprintf(endpoint, base_len + sizeof("/oauth/token"),
                 "%s/oauth/token", issuer);
        cJSON_AddStringToObject(root, "token_endpoint", endpoint);
        free(endpoint);
    }

    endpoint = malloc(base_len + sizeof("/oauth/jwks"));
    if (endpoint) {
        snprintf(endpoint, base_len + sizeof("/oauth/jwks"),
                 "%s/oauth/jwks", issuer);
        cJSON_AddStringToObject(root, "jwks_uri", endpoint);
        free(endpoint);
    }

    endpoint = malloc(base_len + sizeof("/oauth/par"));
    if (endpoint) {
        snprintf(endpoint, base_len + sizeof("/oauth/par"),
                 "%s/oauth/par", issuer);
        cJSON_AddStringToObject(root,
                                "pushed_authorization_request_endpoint",
                                endpoint);
        free(endpoint);
    }

    endpoint = malloc(base_len + sizeof("/oauth/revoke"));
    if (endpoint) {
        snprintf(endpoint, base_len + sizeof("/oauth/revoke"),
                 "%s/oauth/revoke", issuer);
        cJSON_AddStringToObject(root, "revocation_endpoint", endpoint);
        free(endpoint);
    }

    cJSON_AddBoolToObject(root, "require_pushed_authorization_requests", true);

    cJSON *scopes = cJSON_CreateArray();
    cJSON_AddItemToArray(scopes, cJSON_CreateString("atproto"));
    cJSON_AddItemToArray(scopes, cJSON_CreateString("transition:generic"));
    cJSON_AddItemToArray(scopes, cJSON_CreateString("transition:email"));
    cJSON_AddItemToArray(scopes, cJSON_CreateString("transition:chat.bsky"));
    cJSON_AddItemToObject(root, "scopes_supported", scopes);

    cJSON *subjects = cJSON_CreateArray();
    cJSON_AddItemToArray(subjects, cJSON_CreateString("public"));
    cJSON_AddItemToObject(root, "subject_types_supported", subjects);

    cJSON *response_types = cJSON_CreateArray();
    cJSON_AddItemToArray(response_types, cJSON_CreateString("code"));
    cJSON_AddItemToObject(root, "response_types_supported", response_types);

    cJSON *response_modes = cJSON_CreateArray();
    cJSON_AddItemToArray(response_modes, cJSON_CreateString("query"));
    cJSON_AddItemToArray(response_modes, cJSON_CreateString("fragment"));
    cJSON_AddItemToArray(response_modes, cJSON_CreateString("form_post"));
    cJSON_AddItemToObject(root, "response_modes_supported", response_modes);

    cJSON *grant_types = cJSON_CreateArray();
    cJSON_AddItemToArray(grant_types, cJSON_CreateString("authorization_code"));
    cJSON_AddItemToArray(grant_types, cJSON_CreateString("refresh_token"));
    cJSON_AddItemToObject(root, "grant_types_supported", grant_types);

    cJSON *methods = cJSON_CreateArray();
    cJSON_AddItemToArray(methods, cJSON_CreateString("S256"));
    cJSON_AddItemToObject(root, "code_challenge_methods_supported", methods);

    cJSON *dpop_algs = cJSON_CreateArray();
    cJSON_AddItemToArray(dpop_algs, cJSON_CreateString("ES256"));
    cJSON_AddItemToObject(root, "dpop_signing_alg_values_supported",
                          dpop_algs);

    cJSON *token_methods = cJSON_CreateArray();
    cJSON_AddItemToArray(token_methods, cJSON_CreateString("none"));
    cJSON_AddItemToArray(token_methods,
                         cJSON_CreateString("private_key_jwt"));
    cJSON_AddItemToObject(root, "token_endpoint_auth_methods_supported",
                          token_methods);

    cJSON *locales = cJSON_CreateArray();
    cJSON_AddItemToArray(locales, cJSON_CreateString("en-US"));
    cJSON_AddItemToObject(root, "ui_locales_supported", locales);

    cJSON_AddBoolToObject(root, "request_parameter_supported", true);
    cJSON_AddBoolToObject(root, "request_uri_parameter_supported", true);
    cJSON_AddBoolToObject(root, "require_request_uri_registration", true);
    cJSON_AddBoolToObject(root,
                          "authorization_response_iss_parameter_supported",
                          true);
    cJSON_AddBoolToObject(root, "client_id_metadata_document_supported",
                          true);

    return json_response(resp, root, "max-age=300");
}

static wf_status protected_resource_metadata(void *ctx,
                                             const wf_xrpc_request *req,
                                             wf_xrpc_response *resp) {
    (void)req;
    oauth_route_ctx *rctx = ctx;
    const char *resource = rctx->public_url;
    if (!resource || !resource[0]) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Server public URL not configured");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;

    cJSON_AddStringToObject(root, "resource", resource);

    cJSON *auth_servers = cJSON_CreateArray();
    cJSON_AddItemToArray(auth_servers, cJSON_CreateString(resource));
    cJSON_AddItemToObject(root, "authorization_servers", auth_servers);

    cJSON *scopes = cJSON_CreateArray();
    cJSON_AddItemToArray(scopes, cJSON_CreateString("atproto"));
    cJSON_AddItemToObject(root, "scopes_supported", scopes);

    cJSON *methods = cJSON_CreateArray();
    cJSON_AddItemToArray(methods, cJSON_CreateString("header"));
    cJSON_AddItemToObject(root, "bearer_methods_supported", methods);

    return json_response(resp, root, "max-age=300");
}

static wf_status oauth_jwks(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    (void)req;
    oauth_route_ctx *rctx = ctx;
    char *jwks = NULL;
    if (metalbear_oauth_jwks(rctx->store, &jwks) != WF_OK || !jwks)
        return WF_ERR_INTERNAL;
    wf_xrpc_response_set_body(resp, jwks, strlen(jwks));
    free(jwks);
    wf_xrpc_response_add_header(resp, "Cache-Control", "max-age=300");
    return WF_OK;
}

static wf_status oauth_par(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    if (!req->params || !cJSON_IsObject(req->params)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }

    cJSON *client_id = cJSON_GetObjectItemCaseSensitive(req->params,
                                                        "client_id");
    cJSON *redirect_uri = cJSON_GetObjectItemCaseSensitive(req->params,
                                                           "redirect_uri");
    cJSON *scope = cJSON_GetObjectItemCaseSensitive(req->params, "scope");
    cJSON *state = cJSON_GetObjectItemCaseSensitive(req->params, "state");
    cJSON *code_challenge = cJSON_GetObjectItemCaseSensitive(req->params,
                                                            "code_challenge");
    cJSON *dpop_jkt = cJSON_GetObjectItemCaseSensitive(req->params,
                                                       "dpop_jkt");

    if (!cJSON_IsString(client_id) || !cJSON_IsString(redirect_uri) ||
        !cJSON_IsString(scope) || !cJSON_IsString(code_challenge) ||
        !cJSON_IsString(dpop_jkt)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing required parameters");
        return WF_OK;
    }

    if (!strstr(scope->valuestring, "atproto")) {
        wf_xrpc_response_set_error(resp, 400, "invalid_scope",
                                   "Scope must include 'atproto'");
        return WF_OK;
    }

    metalbear_oauth_request request = {
        .client_id = client_id->valuestring,
        .redirect_uri = redirect_uri->valuestring,
        .scope = scope->valuestring,
        .state = cJSON_IsString(state) ? state->valuestring : NULL,
        .code_challenge = code_challenge->valuestring,
        .dpop_jkt = dpop_jkt->valuestring,
    };

    char *request_uri = NULL;
    int64_t expires_in = 0;
    wf_status status = metalbear_oauth_create_par(rctx->store, &request,
                                                   &request_uri,
                                                   &expires_in);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Could not create PAR");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) { free(request_uri); return WF_ERR_ALLOC; }
    cJSON_AddStringToObject(root, "request_uri", request_uri);
    cJSON_AddNumberToObject(root, "expires_in", (double)expires_in);
    free(request_uri);

    wf_xrpc_response_set_content_type(resp, "application/json");
    return json_response(resp, root, "no-store");
}

static wf_status oauth_authorize(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    const char *request_uri = NULL;
    const char *client_id = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *ru = cJSON_GetObjectItemCaseSensitive(req->params,
                                                     "request_uri");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(req->params,
                                                      "client_id");
        if (cJSON_IsString(ru)) request_uri = ru->valuestring;
        if (cJSON_IsString(cid)) client_id = cid->valuestring;
    }

    if (!request_uri || !client_id) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing request_uri or client_id");
        return WF_OK;
    }

    char *code = NULL;
    char *redirect_uri = NULL;
    char *state = NULL;
    wf_status status = metalbear_oauth_authorize(rctx->store, request_uri,
                                                  client_id, &code,
                                                  &redirect_uri, &state);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Authorization failed");
        return WF_OK;
    }

    size_t url_len = strlen(redirect_uri) + strlen(code) +
                     (state ? strlen(state) : 0) + 64;
    char *url = malloc(url_len);
    if (!url) {
        free(code); free(redirect_uri); free(state);
        return WF_ERR_ALLOC;
    }
    snprintf(url, url_len, "%s?code=%s", redirect_uri, code);
    if (state) {
        size_t len = strlen(url);
        snprintf(url + len, url_len - len, "&state=%s", state);
    }

    wf_xrpc_response_set_content_type(resp, "text/html");
    wf_xrpc_response_add_header(resp, "Location", url);
    resp->http_status = 302;

    free(code);
    free(redirect_uri);
    free(state);
    free(url);
    return WF_OK;
}

static wf_status parse_form_body(const wf_xrpc_request *req, cJSON **out) {
    *out = NULL;
    if (!req->body || req->body_len == 0) return WF_ERR_INVALID_ARG;

    if (req->content_type && strstr(req->content_type, "application/json")) {
        *out = cJSON_ParseWithLength((const char *)req->body, req->body_len);
        return *out ? WF_OK : WF_ERR_INVALID_ARG;
    }

    char *body = strndup((const char *)req->body, req->body_len);
    if (!body) return WF_ERR_ALLOC;

    *out = cJSON_CreateObject();
    if (!*out) { free(body); return WF_ERR_ALLOC; }

    char *saveptr = NULL;
    char *pair = strtok_r(body, "&", &saveptr);
    while (pair) {
        char *eq = strchr(pair, '=');
        if (eq) {
            *eq = '\0';
            cJSON_AddStringToObject(*out, pair, eq + 1);
        }
        pair = strtok_r(NULL, "&", &saveptr);
    }
    free(body);
    return *out ? WF_OK : WF_ERR_ALLOC;
}

static wf_status oauth_token(void *ctx, const wf_xrpc_request *req,
                             wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;

    cJSON *body = NULL;
    if (parse_form_body(req, &body) != WF_OK || !body) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }

    cJSON *grant_type = cJSON_GetObjectItemCaseSensitive(body, "grant_type");
    if (!cJSON_IsString(grant_type)) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "grant_type is required");
        return WF_OK;
    }

    metalbear_oauth_grant grant = {0};
    wf_status status = WF_ERR_INVALID_ARG;

    if (strcmp(grant_type->valuestring, "authorization_code") == 0) {
        cJSON *code = cJSON_GetObjectItemCaseSensitive(body, "code");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(body, "client_id");
        cJSON *redir = cJSON_GetObjectItemCaseSensitive(body, "redirect_uri");
        cJSON *verifier = cJSON_GetObjectItemCaseSensitive(body,
                                                           "code_verifier");
        cJSON *jkt = cJSON_GetObjectItemCaseSensitive(body, "dpop_jkt");

        if (!cJSON_IsString(code) || !cJSON_IsString(cid) ||
            !cJSON_IsString(redir) || !cJSON_IsString(verifier) ||
            !cJSON_IsString(jkt)) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                       "Missing required parameters");
            return WF_OK;
        }
        status = metalbear_oauth_exchange_code(rctx->store, code->valuestring,
                                                cid->valuestring,
                                                redir->valuestring,
                                                verifier->valuestring,
                                                jkt->valuestring, &grant);
    } else if (strcmp(grant_type->valuestring, "refresh_token") == 0) {
        cJSON *refresh = cJSON_GetObjectItemCaseSensitive(body,
                                                          "refresh_token");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(body, "client_id");
        cJSON *jkt = cJSON_GetObjectItemCaseSensitive(body, "dpop_jkt");

        if (!cJSON_IsString(refresh) || !cJSON_IsString(cid) ||
            !cJSON_IsString(jkt)) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                       "Missing required parameters");
            return WF_OK;
        }
        status = metalbear_oauth_refresh(rctx->store, refresh->valuestring,
                                          cid->valuestring, jkt->valuestring,
                                          &grant);
    }

    cJSON_Delete(body);

    if (status != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_grant",
                                   "Token request failed");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) { metalbear_oauth_grant_free(&grant); return WF_ERR_ALLOC; }
    cJSON_AddStringToObject(root, "access_token", grant.access_token);
    cJSON_AddStringToObject(root, "token_type", "DPoP");
    cJSON_AddNumberToObject(root, "expires_in", (double)grant.expires_in);
    if (grant.refresh_token)
        cJSON_AddStringToObject(root, "refresh_token", grant.refresh_token);
    metalbear_oauth_grant_free(&grant);

    wf_xrpc_response_set_content_type(resp, "application/json");
    wf_xrpc_response_add_header(resp, "Cache-Control", "no-store");
    wf_xrpc_response_add_header(resp, "Pragma", "no-cache");
    return json_response(resp, root, NULL);
}

static wf_status oauth_revoke(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;

    cJSON *body = NULL;
    if (parse_form_body(req, &body) != WF_OK || !body) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }

    cJSON *token = cJSON_GetObjectItemCaseSensitive(body, "token");
    if (!cJSON_IsString(token)) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "token is required");
        return WF_OK;
    }

    metalbear_oauth_revoke(rctx->store, token->valuestring);
    cJSON_Delete(body);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return json_response(resp, root, "no-store");
}

wf_status metalbear_oauth_routes_register(wf_xrpc_server *server,
                                          metalbear_oauth_store *store,
                                          const char *public_url,
                                          const char *service_did,
                                          const char *account_did) {
    (void)service_did;
    (void)account_did;

    if (!server || !store) return WF_ERR_INVALID_ARG;

    oauth_route_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return WF_ERR_ALLOC;
    ctx->store = store;
    ctx->public_url = public_url ? strdup(public_url) : NULL;

    if (wf_xrpc_server_register_http_route(server, "GET",
            "/.well-known/oauth-authorization-server",
            oauth_metadata, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "GET",
            "/.well-known/oauth-protected-resource",
            protected_resource_metadata, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "GET",
            "/oauth/jwks", oauth_jwks, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST",
            "/oauth/par", oauth_par, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST",
            "/oauth/token", oauth_token, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST",
            "/oauth/revoke", oauth_revoke, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "GET",
            "/oauth/authorize", oauth_authorize, ctx) != WF_OK) {
        free(ctx->public_url);
        free(ctx);
        return WF_ERR_INTERNAL;
    }

    return WF_OK;
}
