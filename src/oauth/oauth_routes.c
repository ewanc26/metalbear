#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth_routes.h"

#include <cJSON.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* The device-session cookie name and attributes. HttpOnly so a script on the
 * page cannot read it (there is nothing legitimate for one to do with it, and
 * XSS is the threat this defends against); SameSite=Lax rather than Strict so
 * the cookie is still sent on the top-level navigation back from a sign-in
 * redirect; Secure because the only real deployment is behind the reverse
 * proxy the README already requires, terminating HTTPS. */
#define MB_DEVICE_COOKIE "mb_device"

typedef struct oauth_route_ctx {
    metalbear_oauth_store *store;
    char *public_url;
    metalbear_oauth_subject_resolver resolve_subject;
    metalbear_oauth_credential_verifier verify_credential;
    void *resolver_ctx;
} oauth_route_ctx;

/* Percent-encode one query value. Caller frees with curl_free. */
static char *url_escape(const char *value) {
    return curl_easy_escape(NULL, value, 0);
}

/*
 * Find `name=value` in a raw `Cookie` header (`name1=value1; name2=value2`,
 * per RFC 6265) and return a copy of the value, or NULL if absent. MHD (and
 * the shim) hand this over unparsed, the same way they hand over the rest of
 * the request's headers.
 */
static char *find_cookie(const char *cookie_header, const char *name) {
    if (!cookie_header) return NULL;
    size_t name_len = strlen(name);
    const char *p = cookie_header;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        const char *eq = strchr(p, '=');
        const char *semi = strchr(p, ';');
        if (!eq || (semi && eq > semi)) {
            if (!semi) break;
            p = semi + 1;
            continue;
        }
        const char *value_start = eq + 1;
        const char *value_end = semi ? semi : value_start + strlen(value_start);
        if ((size_t)(eq - p) == name_len && strncmp(p, name, name_len) == 0) {
            size_t value_len = (size_t)(value_end - value_start);
            char *out = malloc(value_len + 1);
            if (!out) return NULL;
            memcpy(out, value_start, value_len);
            out[value_len] = '\0';
            return out;
        }
        if (!semi) break;
        p = semi + 1;
    }
    return NULL;
}

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
        snprintf(endpoint, base_len + sizeof("/oauth/token"), "%s/oauth/token",
                 issuer);
        cJSON_AddStringToObject(root, "token_endpoint", endpoint);
        free(endpoint);
    }

    endpoint = malloc(base_len + sizeof("/oauth/jwks"));
    if (endpoint) {
        snprintf(endpoint, base_len + sizeof("/oauth/jwks"), "%s/oauth/jwks",
                 issuer);
        cJSON_AddStringToObject(root, "jwks_uri", endpoint);
        free(endpoint);
    }

    endpoint = malloc(base_len + sizeof("/oauth/par"));
    if (endpoint) {
        snprintf(endpoint, base_len + sizeof("/oauth/par"), "%s/oauth/par",
                 issuer);
        cJSON_AddStringToObject(root, "pushed_authorization_request_endpoint",
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

    /* ES256 only: wf_oauth_verify_dpop (wolfram's oauth/verify.c) hardcodes
     * `alg == "ES256"` and rejects everything else, so that is the only
     * algorithm this server can actually verify a DPoP proof with. */
    cJSON *dpop_algs = cJSON_CreateArray();
    cJSON_AddItemToArray(dpop_algs, cJSON_CreateString("ES256"));
    cJSON_AddItemToObject(root, "dpop_signing_alg_values_supported", dpop_algs);

    /* Both "none" (public clients) and "private_key_jwt" (confidential
     * clients) are honored by the token endpoint: oauth_token verifies an
     * RFC 7523 client_assertion JWT against the client's published JWKS
     * (see client_jwks_resolve + oauth_token below). Mirrors the reference
     * PDS's Client.AUTH_METHODS_SUPPORTED. */
    cJSON *token_methods = cJSON_CreateArray();
    cJSON_AddItemToArray(token_methods, cJSON_CreateString("none"));
    cJSON_AddItemToArray(token_methods, cJSON_CreateString("private_key_jwt"));
    cJSON_AddItemToObject(root, "token_endpoint_auth_methods_supported",
                          token_methods);

    /* ES256 only: wf_oauth_verify_client_assertion (wolfram's oauth/verify.c)
     * accepts ES256 and rejects every other algorithm. */
    cJSON *token_algs = cJSON_CreateArray();
    cJSON_AddItemToArray(token_algs, cJSON_CreateString("ES256"));
    cJSON_AddItemToObject(
        root, "token_endpoint_auth_signing_alg_values_supported", token_algs);

    cJSON *locales = cJSON_CreateArray();
    cJSON_AddItemToArray(locales, cJSON_CreateString("en-US"));
    cJSON_AddItemToObject(root, "ui_locales_supported", locales);

    cJSON_AddBoolToObject(root, "request_parameter_supported", true);
    cJSON_AddBoolToObject(root, "request_uri_parameter_supported", true);
    cJSON_AddBoolToObject(root, "require_request_uri_registration", true);
    cJSON_AddBoolToObject(
        root, "authorization_response_iss_parameter_supported", true);
    cJSON_AddBoolToObject(root, "client_id_metadata_document_supported", true);

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

    /* Matches the reference PDS's auth-routes.ts verbatim. */
    cJSON_AddStringToObject(root, "resource_documentation",
                            "https://atproto.com");

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

static int hex_value(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Decode one application/x-www-form-urlencoded component.  Decode '+'
 * before percent escapes so an encoded literal plus (%2B) remains a plus. */
static wf_status form_decode(const char *value, size_t len, char **out) {
    char *decoded = malloc(len + 1);
    if (!decoded) return WF_ERR_ALLOC;
    size_t write = 0;
    for (size_t read = 0; read < len; read++) {
        unsigned char ch = (unsigned char)value[read];
        if (ch == '+') {
            decoded[write++] = ' ';
        } else if (ch == '%') {
            if (read + 2 >= len) {
                free(decoded);
                return WF_ERR_INVALID_ARG;
            }
            int high = hex_value((unsigned char)value[++read]);
            int low = hex_value((unsigned char)value[++read]);
            if (high < 0 || low < 0) {
                free(decoded);
                return WF_ERR_INVALID_ARG;
            }
            ch = (unsigned char)((high << 4) | low);
            /* cJSON values are C strings; embedded NUL cannot be preserved. */
            if (ch == '\0') {
                free(decoded);
                return WF_ERR_INVALID_ARG;
            }
            decoded[write++] = (char)ch;
        } else {
            decoded[write++] = (char)ch;
        }
    }
    decoded[write] = '\0';
    *out = decoded;
    return WF_OK;
}

static bool media_type_is(const char *value, const char *media_type) {
    if (!value) return false;
    size_t length = strlen(media_type);
    return strncasecmp(value, media_type, length) == 0 &&
           (value[length] == '\0' || value[length] == ';' ||
            value[length] == ' ' || value[length] == '\t');
}

/* OAuth PAR and token requests are commonly application/x-www-form-urlencoded.
 * Keep JSON accepted for the existing JSON API clients, but parse form values
 * before they reach the exact client/redirect-uri comparisons in the store. */
static wf_status parse_form_body(const wf_xrpc_request *req, cJSON **out) {
    *out = NULL;
    if (!req->body || req->body_len == 0) return WF_ERR_INVALID_ARG;

    if (media_type_is(req->content_type, "application/json")) {
        cJSON *json =
            cJSON_ParseWithLength((const char *)req->body, req->body_len);
        if (!json || !cJSON_IsObject(json)) {
            cJSON_Delete(json);
            return WF_ERR_INVALID_ARG;
        }
        *out = json;
        return WF_OK;
    }
    if (!media_type_is(req->content_type, "application/x-www-form-urlencoded"))
        return WF_ERR_INVALID_ARG;

    cJSON *form = cJSON_CreateObject();
    if (!form) return WF_ERR_ALLOC;
    size_t offset = 0;
    while (offset < req->body_len) {
        const char *start = (const char *)req->body + offset;
        const char *end = memchr(start, '&', req->body_len - offset);
        size_t pair_len = end ? (size_t)(end - start) : req->body_len - offset;
        const char *equals = memchr(start, '=', pair_len);
        char *key = NULL, *value = NULL;
        wf_status status = WF_ERR_INVALID_ARG;
        if (!equals || equals == start ||
            (status = form_decode(start, (size_t)(equals - start), &key)) !=
                WF_OK ||
            !key[0] || cJSON_GetObjectItemCaseSensitive(form, key) ||
            (status = form_decode(equals + 1,
                                  pair_len - (size_t)(equals - start) - 1,
                                  &value)) != WF_OK ||
            !cJSON_AddStringToObject(form, key, value)) {
            if (status == WF_OK) status = WF_ERR_ALLOC;
            free(key);
            free(value);
            cJSON_Delete(form);
            return status;
        }
        free(key);
        free(value);
        offset += pair_len + (end ? 1 : 0);
    }
    *out = form;
    return WF_OK;
}

static wf_status oauth_par(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    cJSON *body = NULL;
    if (parse_form_body(req, &body) != WF_OK || !body) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }

    cJSON *client_id = cJSON_GetObjectItemCaseSensitive(body, "client_id");
    cJSON *redirect_uri =
        cJSON_GetObjectItemCaseSensitive(body, "redirect_uri");
    cJSON *scope = cJSON_GetObjectItemCaseSensitive(body, "scope");
    cJSON *state = cJSON_GetObjectItemCaseSensitive(body, "state");
    cJSON *code_challenge =
        cJSON_GetObjectItemCaseSensitive(body, "code_challenge");
    cJSON *dpop_jkt = cJSON_GetObjectItemCaseSensitive(body, "dpop_jkt");

    if (!cJSON_IsString(client_id) || !cJSON_IsString(redirect_uri) ||
        !cJSON_IsString(scope) || !cJSON_IsString(code_challenge) ||
        !cJSON_IsString(dpop_jkt)) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing required parameters");
        return WF_OK;
    }

    /* The "atproto" scope token is required for all OAuth flows.
     * Check for it as a space-separated token, not a substring. */
    {
        const char *scope_str = scope->valuestring;
        bool has_atproto = false;
        const char *p = scope_str;
        while (*p) {
            const char *end = strchr(p, ' ');
            size_t len = end ? (size_t)(end - p) : strlen(p);
            if (len == 7 && strncmp(p, "atproto", 7) == 0) {
                has_atproto = true;
                break;
            }
            p = end ? end + 1 : p + len;
        }
        if (!has_atproto) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(resp, 400, "invalid_scope",
                                       "The \"atproto\" scope is required");
            return WF_OK;
        }
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
                                                  &request_uri, &expires_in);
    cJSON_Delete(body);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Could not create PAR");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(request_uri);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "request_uri", request_uri);
    cJSON_AddNumberToObject(root, "expires_in", (double)expires_in);
    free(request_uri);

    wf_xrpc_response_set_content_type(resp, "application/json");
    resp->http_status = 201;
    return json_response(resp, root, "no-store");
}

static wf_status oauth_authorize(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    const char *request_uri = NULL;
    const char *client_id = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *ru =
            cJSON_GetObjectItemCaseSensitive(req->params, "request_uri");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(req->params, "client_id");
        if (cJSON_IsString(ru)) request_uri = ru->valuestring;
        if (cJSON_IsString(cid)) client_id = cid->valuestring;
    }

    if (!request_uri || !client_id) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing request_uri or client_id");
        return WF_OK;
    }

    /*
     * Which account is being authorized must be stated, not assumed. The
     * subject used to come from a single DID baked into the store, so every
     * token this endpoint issued spoke for that one account no matter who
     * asked — on a multi-account host that hands the client the wrong
     * session entirely.
     */
    const char *hint = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *lh = cJSON_GetObjectItemCaseSensitive(req->params, "login_hint");
        if (cJSON_IsString(lh)) hint = lh->valuestring;
    }
    char subject[256];
    if (!hint || !hint[0]) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "login_hint is required to identify the "
                                   "account being authorized");
        return WF_OK;
    }
    if (!rctx->resolve_subject ||
        !rctx->resolve_subject(rctx->resolver_ctx, hint, subject,
                               sizeof(subject))) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Unknown account");
        return WF_OK;
    }

    /*
     * login_hint names the account, but it is not proof of anything: a
     * handle is a public identifier, resolvable by anyone. What used to
     * happen here is exactly the bug that made that a problem — a code was
     * minted for whichever account login_hint named, no matter who was
     * asking, which is an unauthenticated path to a valid token for any
     * account on the host.
     *
     * The browser must additionally hold a device-session cookie proving it
     * already presented that account's password once, in this browser,
     * within the last 30 days. Absent one — first visit, expired, or one
     * that names a different account than login_hint — no code is issued.
     * The browser is redirected to sign in and land back here instead, with
     * the same request_uri/client_id/login_hint it arrived with, so it can
     * retry once the cookie is set.
     */
    char *device_token = find_cookie(req->cookie_header, MB_DEVICE_COOKIE);
    char verified_subject[256];
    bool authenticated = device_token &&
                         metalbear_oauth_device_session_verify(
                             rctx->store, device_token, verified_subject,
                             sizeof(verified_subject)) == WF_OK &&
                         strcmp(verified_subject, subject) == 0;
    free(device_token);

    if (!authenticated) {
        char *enc_ru = url_escape(request_uri);
        char *enc_cid = url_escape(client_id);
        char *enc_hint = url_escape(hint);
        if (!enc_ru || !enc_cid || !enc_hint) {
            curl_free(enc_ru);
            curl_free(enc_cid);
            curl_free(enc_hint);
            return WF_ERR_ALLOC;
        }
        char redirect[1024];
        int n =
            snprintf(redirect, sizeof(redirect),
                     "/oauth/consent?request_uri=%s&client_id=%s&login_hint=%s",
                     enc_ru, enc_cid, enc_hint);
        curl_free(enc_ru);
        curl_free(enc_cid);
        curl_free(enc_hint);
        if (n < 0 || (size_t)n >= sizeof(redirect)) {
            wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                       "Request too large to continue");
            return WF_OK;
        }
        wf_xrpc_response_set_content_type(resp, "text/html");
        wf_xrpc_response_add_header(resp, "Location", redirect);
        resp->http_status = 302;
        return WF_OK;
    }

    char *code = NULL;
    char *redirect_uri = NULL;
    char *state = NULL;
    wf_status status =
        metalbear_oauth_authorize(rctx->store, request_uri, client_id, subject,
                                  &code, &redirect_uri, &state);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Authorization failed");
        return WF_OK;
    }

    char *escaped_code = url_escape(code);
    char *escaped_state = state ? url_escape(state) : NULL;
    char *escaped_issuer = url_escape(rctx->public_url);
    if (!escaped_code || (state && !escaped_state) || !escaped_issuer) {
        curl_free(escaped_code);
        curl_free(escaped_state);
        curl_free(escaped_issuer);
        free(code);
        free(redirect_uri);
        free(state);
        return WF_ERR_ALLOC;
    }
    const char separator = strchr(redirect_uri, '?') ? '&' : '?';
    size_t url_len = strlen(redirect_uri) + strlen(escaped_code) +
                     strlen(escaped_issuer) +
                     (escaped_state ? strlen(escaped_state) : 0) + 32;
    char *url = malloc(url_len);
    if (!url) {
        curl_free(escaped_code);
        curl_free(escaped_state);
        curl_free(escaped_issuer);
        free(code);
        free(redirect_uri);
        free(state);
        return WF_ERR_ALLOC;
    }
    snprintf(url, url_len, "%s%ccode=%s%s%s&iss=%s", redirect_uri, separator,
             escaped_code, escaped_state ? "&state=" : "",
             escaped_state ? escaped_state : "", escaped_issuer);

    wf_xrpc_response_set_content_type(resp, "text/html");
    wf_xrpc_response_add_header(resp, "Location", url);
    resp->http_status = 302;

    free(code);
    free(redirect_uri);
    free(state);
    free(url);
    curl_free(escaped_code);
    curl_free(escaped_state);
    curl_free(escaped_issuer);
    return WF_OK;
}

/* ------------------------------------------------------------------ */
/* private_key_jwt client authentication                               */
/*                                                                     */
/* A confidential client identifies itself at the token endpoint with  */
/* an RFC 7523 client_assertion JWT signed by a key it publishes in    */
/* its metadata document (client_id is that document's URL). We fetch  */
/* the metadata, take its `jwks` (or `jwks_uri`), and verify the       */
/* assertion against it with wolfram's wf_oauth_verify_client_assertion. */
/* ------------------------------------------------------------------ */

typedef struct http_buf {
    char *data;
    size_t len;
    size_t cap;
} http_buf;

static size_t http_write_cb(char *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    http_buf *buf = (http_buf *)userdata;
    size_t total = size * nmemb;
    if (buf->len + total + 1 > buf->cap) {
        size_t newcap = (buf->cap + total) * 2;
        char *grown = realloc(buf->data, newcap);
        if (!grown) return 0;
        buf->data = grown;
        buf->cap = newcap;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/* Fetch `url` and parse it as JSON. */
static wf_status http_get_json(const char *url, cJSON **out_json) {
    CURL *curl = NULL;
    http_buf body = {0};
    CURLcode rc;
    cJSON *json = NULL;
    wf_status status = WF_ERR_NETWORK;

    if (!url || !out_json) return WF_ERR_INVALID_ARG;
    *out_json = NULL;

    curl = curl_easy_init();
    if (!curl) return WF_ERR_ALLOC;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "application/json");
    rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || !body.data) goto done;

    json = cJSON_ParseWithLength(body.data, body.len);
    if (!json) {
        status = WF_ERR_PARSE;
        goto done;
    }
    *out_json = json;
    json = NULL;
    status = WF_OK;
done:
    free(body.data);
    cJSON_Delete(json);
    return status;
}

/* Does `host` equal `name`, optionally followed by a port? Guards the
 * loopback carve-out below against prefix tricks like
 * `127.0.0.1.evil.example`. */
static bool host_is(const char *host, const char *name) {
    size_t n = strlen(name);
    if (strncasecmp(host, name, n) != 0) return false;
    char c = host[n];
    return c == '\0' || c == ':';
}

/* A client_id is a URL the token endpoint fetches on every request, and the
 * client chooses it — so it is an SSRF surface. Only https is acceptable in
 * production; loopback http is allowed so offline tests and local
 * deployments can serve a metadata document without TLS. */
static bool client_id_fetchable(const char *client_id) {
    if (!client_id || !client_id[0]) return false;
    if (strncasecmp(client_id, "https://", 8) == 0) return true;
    if (strncasecmp(client_id, "http://", 7) == 0) {
        const char *host = client_id + 7;
        return host_is(host, "127.0.0.1") || host_is(host, "localhost") ||
               host_is(host, "[::1]");
    }
    return false;
}

/* Resolve a client's signing JWKS from its metadata document. `client_id`
 * is the metadata document URL. On success *out_jwks is the JWKS JSON (an
 * object with a `keys` array); the caller must free it with cJSON_Delete.
 * WF_ERR_NOT_FOUND if the metadata declares token_endpoint_auth_method
 * "none"; WF_ERR_PARSE on an unresolvable/invalid document. */
static wf_status client_jwks_resolve(const char *client_id, cJSON **out_jwks) {
    cJSON *metadata = NULL, *jwks = NULL, *jwks_uri = NULL;
    const cJSON *auth_method;
    wf_status status;

    if (!client_id || !client_id[0] || !out_jwks) return WF_ERR_INVALID_ARG;
    *out_jwks = NULL;

    if (!client_id_fetchable(client_id)) return WF_ERR_INVALID_ARG;

    status = http_get_json(client_id, &metadata);
    if (status != WF_OK) return status;

    /* A public client must not present a client_assertion; the reference
     * provider routes on this field and would ignore the assertion. */
    auth_method = cJSON_GetObjectItemCaseSensitive(
        metadata, "token_endpoint_auth_method");
    if (cJSON_IsString(auth_method) &&
        strcmp(auth_method->valuestring, "none") == 0) {
        status = WF_ERR_NOT_FOUND;
        goto done;
    }

    jwks = cJSON_GetObjectItemCaseSensitive(metadata, "jwks");
    if (cJSON_IsObject(jwks)) {
        *out_jwks = cJSON_Duplicate(jwks, 1);
        if (!*out_jwks) {
            status = WF_ERR_ALLOC;
            goto done;
        }
        status = WF_OK;
        goto done;
    }

    /* Metadata that only points at a jwks_uri is equally valid. */
    jwks_uri = cJSON_GetObjectItemCaseSensitive(metadata, "jwks_uri");
    if (cJSON_IsString(jwks_uri) && jwks_uri->valuestring[0]) {
        status = http_get_json(jwks_uri->valuestring, out_jwks);
        goto done;
    }

    status = WF_ERR_PARSE; /* metadata carries neither jwks nor jwks_uri */
done:
    cJSON_Delete(metadata);
    return status;
}

/* Verify an RFC 7523 client assertion against the client's published JWKS.
 * On success *out_client_id is a heap copy of the authenticated client_id
 * (the assertion's iss/sub, which must equal the presented client_id);
 * the caller frees it. */
static wf_status client_assertion_authenticate(oauth_route_ctx *rctx,
                                               const char *client_id,
                                               const char *assertion,
                                               char **out_client_id) {
    cJSON *jwks = NULL;
    cJSON *keys_arr = NULL;
    wf_oauth_trusted_keys *keys = NULL;
    wf_oauth_client_assertion_verified *verified = NULL;
    wf_status status;

    if (!out_client_id) return WF_ERR_INVALID_ARG;
    *out_client_id = NULL;

    status = client_jwks_resolve(client_id, &jwks);
    if (status != WF_OK) return status;

    keys_arr = cJSON_GetObjectItemCaseSensitive(jwks, "keys");
    if (!cJSON_IsArray(keys_arr) || cJSON_GetArraySize(keys_arr) == 0) {
        status = WF_ERR_PARSE;
        goto done;
    }
    status = wf_oauth_trusted_keys_new(&keys);
    if (status != WF_OK) goto done;
    {
        cJSON *key;
        cJSON_ArrayForEach(key, keys_arr) {
            char *jwk_json;
            wf_status add;
            if (!cJSON_IsObject(key)) continue;
            jwk_json = cJSON_PrintUnformatted(key);
            if (!jwk_json) {
                status = WF_ERR_ALLOC;
                goto done;
            }
            add = wf_oauth_trusted_keys_add_jwk(keys, jwk_json);
            free(jwk_json);
            if (add != WF_OK) {
                status = add;
                goto done;
            }
        }
    }
    status = wf_oauth_verify_client_assertion(
        assertion, client_id, rctx->public_url, keys, &verified);
    if (status != WF_OK) goto done;
    *out_client_id = strdup(verified->client_id);
    if (!*out_client_id) {
        status = WF_ERR_ALLOC;
        goto done;
    }
    status = WF_OK;
done:
    wf_oauth_client_assertion_verified_free(verified);
    wf_oauth_trusted_keys_free(keys);
    cJSON_Delete(jwks);
    return status;
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

    /* private_key_jwt client authentication (RFC 7523). When a
     * client_assertion is present it authenticates the client; the verified
     * client_id is the authority, not the untrusted form field alone. */
    cJSON *client_assertion =
        cJSON_GetObjectItemCaseSensitive(body, "client_assertion");
    char *auth_client_id = NULL;
    if (cJSON_IsString(client_assertion) && client_assertion->valuestring[0]) {
        cJSON *assertion_type =
            cJSON_GetObjectItemCaseSensitive(body, "client_assertion_type");
        cJSON *form_cid = cJSON_GetObjectItemCaseSensitive(body, "client_id");
        if (!cJSON_IsString(assertion_type) ||
            strcmp(assertion_type->valuestring,
                   "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") !=
                0 ||
            !cJSON_IsString(form_cid) || !form_cid->valuestring[0]) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(
                resp, 400, "invalid_client",
                "Invalid client_assertion_type or missing client_id");
            return WF_OK;
        }
        wf_status ast = client_assertion_authenticate(
            rctx, form_cid->valuestring, client_assertion->valuestring,
            &auth_client_id);
        if (ast != WF_OK) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(resp, 400, "invalid_client",
                                       "Client authentication failed");
            return WF_OK;
        }
    }

    metalbear_oauth_grant grant = {0};
    wf_status status = WF_ERR_INVALID_ARG;

    if (strcmp(grant_type->valuestring, "authorization_code") == 0) {
        cJSON *code = cJSON_GetObjectItemCaseSensitive(body, "code");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(body, "client_id");
        cJSON *redir = cJSON_GetObjectItemCaseSensitive(body, "redirect_uri");
        cJSON *verifier =
            cJSON_GetObjectItemCaseSensitive(body, "code_verifier");
        cJSON *jkt = cJSON_GetObjectItemCaseSensitive(body, "dpop_jkt");

        if (!cJSON_IsString(code) || !cJSON_IsString(cid) ||
            !cJSON_IsString(redir) || !cJSON_IsString(verifier) ||
            !cJSON_IsString(jkt)) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                       "Missing required parameters");
            return WF_OK;
        }
        status = metalbear_oauth_exchange_code(
            rctx->store, code->valuestring,
            auth_client_id ? auth_client_id : cid->valuestring,
            redir->valuestring, verifier->valuestring, jkt->valuestring,
            &grant);
    } else if (strcmp(grant_type->valuestring, "refresh_token") == 0) {
        cJSON *refresh =
            cJSON_GetObjectItemCaseSensitive(body, "refresh_token");
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
                                         auth_client_id ? auth_client_id
                                                        : cid->valuestring,
                                         jkt->valuestring, &grant);
    }

    cJSON_Delete(body);
    free(auth_client_id);

    if (status != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_grant",
                                   "Token request failed");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_oauth_grant_free(&grant);
        return WF_ERR_ALLOC;
    }
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

/* Build a `Set-Cookie` value for the device session and add it to `resp`.
 * `max_age_seconds` of 0 clears the cookie, per RFC 6265. */
static void set_device_cookie(wf_xrpc_response *resp, const char *token,
                              int64_t max_age_seconds) {
    char cookie[512];
    snprintf(cookie, sizeof(cookie),
             MB_DEVICE_COOKIE "=%s; Path=/; HttpOnly; Secure; SameSite=Lax; "
                              "Max-Age=%lld",
             token ? token : "", (long long)max_age_seconds);
    wf_xrpc_response_add_header(resp, "Set-Cookie", cookie);
}

/*
 * POST /oauth/signin (not part of the OAuth spec) — the primitive both the
 * plain account-login page and the OAuth consent page sign in through.
 * Verifies an account password and, on success, sets the device-session
 * cookie that `/oauth/authorize` requires.
 *
 * Account password only, never an app password. An app password is meant to
 * carry restricted scope to one third-party client; if it could open a
 * device session it could authorize this endpoint to grant OTHER OAuth
 * clients access, or open the web UI to create further app passwords — a
 * scoped credential escalating itself to full account control. That check
 * lives in the verify_credential callback the caller supplies, not here:
 * whether a given kind of credential counts as "the account's own" is an
 * account-model question, not an OAuth-routing one.
 */
static wf_status oauth_signin(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    if (!req->params || !cJSON_IsObject(req->params)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }
    cJSON *identifier =
        cJSON_GetObjectItemCaseSensitive(req->params, "identifier");
    cJSON *password = cJSON_GetObjectItemCaseSensitive(req->params, "password");
    if (!cJSON_IsString(identifier) || !cJSON_IsString(password)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "identifier and password are required");
        return WF_OK;
    }

    char subject[256];
    if (!rctx->verify_credential ||
        !rctx->verify_credential(rctx->resolver_ctx, identifier->valuestring,
                                 password->valuestring, subject,
                                 sizeof(subject))) {
        /* Timing here is not constant, unlike com.atproto.server.createSession
         * (which pads to 350ms). This endpoint is reached by a human typing
         * into a form, not scriptable at a rate where that matters, and
         * account_verify_credential's scrypt work already dominates any
         * timing signal an unknown-vs-wrong-password branch could leak. */
        wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                   "Invalid identifier or password");
        return WF_OK;
    }

    char *token = NULL;
    if (metalbear_oauth_device_session_create(rctx->store, subject, &token) !=
        WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "internal_error",
                                   "Could not create a session");
        return WF_OK;
    }
    set_device_cookie(resp, token, METALBEAR_DEVICE_SESSION_LIFETIME_SECONDS);
    free(token);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "did", subject);
    return json_response(resp, root, "no-store");
}

/* POST /oauth/signout (not part of the OAuth spec). Revokes the presented
 * device session, if any, and clears the cookie either way — the desired
 * end state (signed out) holds whether or not there was a session to
 * revoke. */
static wf_status oauth_signout(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    char *token = find_cookie(req->cookie_header, MB_DEVICE_COOKIE);
    if (token) metalbear_oauth_device_session_revoke(rctx->store, token);
    free(token);
    set_device_cookie(resp, NULL, 0);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return json_response(resp, root, "no-store");
}

wf_status metalbear_oauth_routes_register(
    wf_xrpc_server *server, metalbear_oauth_store *store,
    const char *public_url, const char *service_did,
    metalbear_oauth_subject_resolver resolve_subject,
    metalbear_oauth_credential_verifier verify_credential, void *resolver_ctx) {
    (void)service_did;

    if (!server || !store) return WF_ERR_INVALID_ARG;

    oauth_route_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return WF_ERR_ALLOC;
    ctx->store = store;
    ctx->public_url = public_url ? strdup(public_url) : NULL;
    ctx->resolve_subject = resolve_subject;
    ctx->verify_credential = verify_credential;
    ctx->resolver_ctx = resolver_ctx;

    if (wf_xrpc_server_register_http_route(
            server, "GET", "/.well-known/oauth-authorization-server",
            oauth_metadata, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(
            server, "GET", "/.well-known/oauth-protected-resource",
            protected_resource_metadata, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "GET", "/oauth/jwks",
                                           oauth_jwks, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST", "/oauth/par",
                                           oauth_par, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST", "/oauth/token",
                                           oauth_token, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST", "/oauth/revoke",
                                           oauth_revoke, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "GET", "/oauth/authorize",
                                           oauth_authorize, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST", "/oauth/signin",
                                           oauth_signin, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST", "/oauth/signout",
                                           oauth_signout, ctx) != WF_OK) {
        free(ctx->public_url);
        free(ctx);
        return WF_ERR_INTERNAL;
    }

    return WF_OK;
}
