#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth/oauth_routes.h"

#include "metalbear/oauth/webauthn.h"
#include "wolfram/crypto.h"

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

/*
 * A browser can hold more than one signed-in account at once (MetalBear is a
 * multi-account host): `mb_device`'s value is up to MB_DEVICE_MAX_SESSIONS
 * session tokens joined by '.', one per account. '.' never appears in a
 * token itself -- tokens are base64url (wf_crypto_base64url_encode), whose
 * alphabet excludes it -- so no escaping is needed. The cap bounds both
 * cookie size and the per-request verification work; signing into a new
 * account past it evicts the oldest.
 */
#define MB_DEVICE_MAX_SESSIONS 5
#define MB_DEVICE_TOKEN_SEP '.'

/* One verified device session: its token (owned, for revocation/cookie
 * rebuilding) and the account DID it authenticates. */
typedef struct device_session_entry {
    char *token;
    char subject[256];
} device_session_entry;

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

/* Extract just the host from rctx->public_url (e.g. "bear1.croft.click" from
 * "https://bear1.croft.click") -- WebAuthn's RP ID is a bare hostname, no
 * scheme or port, unlike the origin check further down which wants the
 * whole public_url. Caller frees with free(). */
static char *rp_id_from_public_url(const char *public_url) {
    if (!public_url) return NULL;
    CURLU *parsed = curl_url();
    if (!parsed) return NULL;
    char *host = NULL, *result = NULL;
    if (curl_url_set(parsed, CURLUPART_URL, public_url, 0) == CURLUE_OK &&
        curl_url_get(parsed, CURLUPART_HOST, &host, 0) == CURLUE_OK && host) {
        result = strdup(host);
    }
    if (host) curl_free(host);
    curl_url_cleanup(parsed);
    return result;
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

/* Split a device-session cookie value ('.'-joined tokens) into up to
 * MB_DEVICE_MAX_SESSIONS strdup'd tokens, written into `out`. Returns the
 * count. Extra tokens beyond the cap are ignored -- this server never
 * writes more than the cap, so seeing more only means a cookie value this
 * server didn't produce, not something worth failing on. */
static size_t split_device_tokens(const char *value,
                                  char *out[MB_DEVICE_MAX_SESSIONS]) {
    size_t n = 0;
    if (!value) return 0;
    const char *p = value;
    while (*p && n < MB_DEVICE_MAX_SESSIONS) {
        const char *sep = strchr(p, MB_DEVICE_TOKEN_SEP);
        size_t len = sep ? (size_t)(sep - p) : strlen(p);
        if (len > 0) {
            char *tok = malloc(len + 1);
            if (tok) {
                memcpy(tok, p, len);
                tok[len] = '\0';
                out[n++] = tok;
            }
        }
        if (!sep) break;
        p = sep + 1;
    }
    return n;
}

/* Join up to MB_DEVICE_MAX_SESSIONS tokens into one '.'-separated cookie
 * value. Caller frees the result. */
static char *join_device_tokens(char *const tokens[], size_t count) {
    size_t total = 1;
    for (size_t i = 0; i < count; i++) total += strlen(tokens[i]) + 1;
    char *out = malloc(total);
    if (!out) return NULL;
    out[0] = '\0';
    for (size_t i = 0; i < count; i++) {
        if (i > 0) strcat(out, ".");
        strcat(out, tokens[i]);
    }
    return out;
}

static void free_device_sessions(device_session_entry entries[], size_t count) {
    for (size_t i = 0; i < count; i++) free(entries[i].token);
}

/*
 * Read the mb_device cookie and verify every token it carries against
 * `store`, returning the still-valid ones (token + subject) in `out`. An
 * expired or otherwise invalid token is silently dropped rather than
 * surfaced as an error -- whatever survives is what the caller should
 * persist back into the cookie on its next write, which self-heals a stale
 * cookie over time with no separate cleanup pass needed.
 */
static size_t
read_device_sessions(metalbear_oauth_store *store, const char *cookie_header,
                     device_session_entry out[MB_DEVICE_MAX_SESSIONS]) {
    char *value = find_cookie(cookie_header, MB_DEVICE_COOKIE);
    if (!value) return 0;
    char *tokens[MB_DEVICE_MAX_SESSIONS];
    size_t token_count = split_device_tokens(value, tokens);
    free(value);
    size_t n = 0;
    for (size_t i = 0; i < token_count; i++) {
        char subject[256];
        if (metalbear_oauth_device_session_verify(store, tokens[i], subject,
                                                  sizeof(subject)) == WF_OK) {
            out[n].token = tokens[i];
            snprintf(out[n].subject, sizeof(out[n].subject), "%s", subject);
            n++;
        } else {
            free(tokens[i]);
        }
    }
    return n;
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

    /* Fields matching the reference oauth-provider's buildMetadata(): */
    cJSON *display_values = cJSON_CreateArray();
    cJSON_AddItemToArray(display_values, cJSON_CreateString("page"));
    cJSON_AddItemToArray(display_values, cJSON_CreateString("popup"));
    cJSON_AddItemToArray(display_values, cJSON_CreateString("touch"));
    cJSON_AddItemToObject(root, "display_values_supported", display_values);

    cJSON *prompt_values = cJSON_CreateArray();
    cJSON_AddItemToArray(prompt_values, cJSON_CreateString("none"));
    cJSON_AddItemToArray(prompt_values, cJSON_CreateString("login"));
    cJSON_AddItemToArray(prompt_values, cJSON_CreateString("consent"));
    cJSON_AddItemToArray(prompt_values, cJSON_CreateString("select_account"));
    cJSON_AddItemToArray(prompt_values, cJSON_CreateString("create"));
    cJSON_AddItemToObject(root, "prompt_values_supported", prompt_values);

    /* Request object signing: ES256 (what Wolfram verifies) + "none"
     * (unsigned request objects), matching the reference's
     * [...VERIFY_ALGOS, "none"] pattern. Only ES256 is listed because
     * Wolfram's verify.c only accepts ES256; advertising algorithms we
     * cannot verify would break interop. */
    cJSON *req_obj_algs = cJSON_CreateArray();
    cJSON_AddItemToArray(req_obj_algs, cJSON_CreateString("ES256"));
    cJSON_AddItemToArray(req_obj_algs, cJSON_CreateString("none"));
    cJSON_AddItemToObject(root, "request_object_signing_alg_values_supported",
                          req_obj_algs);

    /* No request object encryption is supported (matches reference). */
    cJSON *req_obj_enc_algs = cJSON_CreateArray();
    cJSON_AddItemToObject(root,
                          "request_object_encryption_alg_values_supported",
                          req_obj_enc_algs);

    cJSON *req_obj_enc_enc = cJSON_CreateArray();
    cJSON_AddItemToObject(root,
                          "request_object_encryption_enc_values_supported",
                          req_obj_enc_enc);

    /* Protected resources: this server is its own resource server. */
    cJSON *protected_resources = cJSON_CreateArray();
    cJSON_AddItemToArray(protected_resources, cJSON_CreateString(issuer));
    cJSON_AddItemToObject(root, "protected_resources", protected_resources);

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

    /* Empty array matches the reference PDS's auth-routes.ts
     * (scopes_supported: []). The "atproto" scope is advertised in the
     * authorization server metadata instead. */
    cJSON *scopes = cJSON_CreateArray();
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
            !key[0] ||
            (status = form_decode(equals + 1,
                                  pair_len - (size_t)(equals - start) - 1,
                                  &value)) != WF_OK) {
            free(key);
            free(value);
            cJSON_Delete(form);
            return status;
        }
        cJSON *existing = cJSON_GetObjectItemCaseSensitive(form, key);
        if (existing) cJSON_DeleteItemFromObject(form, key);
        if (!cJSON_AddStringToObject(form, key, value)) {
            free(key);
            free(value);
            cJSON_Delete(form);
            return WF_ERR_ALLOC;
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
        !cJSON_IsString(scope) || !cJSON_IsString(code_challenge)) {
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

    char parsed_dpop_jkt[64] = {0};
    if (!cJSON_IsString(dpop_jkt) || !dpop_jkt->valuestring[0]) {
        if (req->dpop_header) {
            char htu[512];
            int n = snprintf(htu, sizeof(htu), "%s/oauth/par",
                             rctx->public_url ? rctx->public_url : "");
            if (n > 0 && (size_t)n < sizeof(htu)) {
                wf_oauth_verified_token *dpop_verified = NULL;
                wf_status dpop_st = wf_oauth_verify_dpop(
                    req->dpop_header, NULL, "POST", htu, NULL, &dpop_verified);
                if (dpop_st == WF_OK && dpop_verified &&
                    dpop_verified->dpop_jkt) {
                    strncpy(parsed_dpop_jkt, dpop_verified->dpop_jkt,
                            sizeof(parsed_dpop_jkt) - 1);
                }
                wf_oauth_verified_token_free(dpop_verified);
            }
        }
    } else {
        strncpy(parsed_dpop_jkt, dpop_jkt->valuestring,
                sizeof(parsed_dpop_jkt) - 1);
    }

    metalbear_oauth_request request = {
        .client_id = client_id->valuestring,
        .redirect_uri = redirect_uri->valuestring,
        .scope = scope->valuestring,
        .state = cJSON_IsString(state) ? state->valuestring : NULL,
        .code_challenge = code_challenge->valuestring,
        .dpop_jkt = parsed_dpop_jkt[0] ? parsed_dpop_jkt : NULL,
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

/* Redirects the browser to the consent page, carrying whatever of
 * request_uri/client_id/login_hint it already has -- `login_hint` may be
 * NULL (asking the consent page to prompt for an identifier itself) or
 * empty. Returns WF_ERR_ALLOC only on allocation failure; the redirect
 * itself is always a successful response (302), never an XRPC error, since
 * the browser still has somewhere useful to go either way. */
static wf_status redirect_to_consent(wf_xrpc_response *resp,
                                     const char *request_uri,
                                     const char *client_id,
                                     const char *login_hint) {
    char *enc_ru = url_escape(request_uri);
    char *enc_cid = url_escape(client_id);
    char *enc_hint =
        login_hint && login_hint[0] ? url_escape(login_hint) : NULL;
    if (!enc_ru || !enc_cid || (login_hint && login_hint[0] && !enc_hint)) {
        curl_free(enc_ru);
        curl_free(enc_cid);
        curl_free(enc_hint);
        return WF_ERR_ALLOC;
    }
    char redirect[1024];
    int n = enc_hint
                ? snprintf(redirect, sizeof(redirect),
                           "/oauth/consent?request_uri=%s&client_id=%s&login_"
                           "hint=%s",
                           enc_ru, enc_cid, enc_hint)
                : snprintf(redirect, sizeof(redirect),
                           "/oauth/consent?request_uri=%s&client_id=%s", enc_ru,
                           enc_cid);
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
     *
     * A client that omits login_hint (some do, expecting the provider itself
     * to ask "who are you?") is not an error: send the browser to the
     * consent page without one, and let it collect an identifier there
     * before coming back here with login_hint filled in. Only a login_hint
     * that fails to resolve to a real account is a hard failure — the
     * consent page has already done what it can at that point.
     */
    const char *hint = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *lh = cJSON_GetObjectItemCaseSensitive(req->params, "login_hint");
        if (cJSON_IsString(lh)) hint = lh->valuestring;
    }
    if (!hint || !hint[0]) {
        return redirect_to_consent(resp, request_uri, client_id, NULL);
    }
    char subject[256];
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
     * within the last 30 days -- one of possibly several, since a browser
     * can be signed into more than one account at once (see
     * MB_DEVICE_MAX_SESSIONS). Absent one for THIS account — first visit,
     * expired, or only other accounts signed in — no code is issued. The
     * browser is redirected to sign in and land back here instead, with the
     * same request_uri/client_id/login_hint it arrived with, so it can
     * retry once that account's session is set -- without disturbing
     * whatever other accounts are already signed in.
     */
    device_session_entry sessions[MB_DEVICE_MAX_SESSIONS];
    size_t session_count =
        read_device_sessions(rctx->store, req->cookie_header, sessions);
    bool authenticated = false;
    for (size_t i = 0; i < session_count; i++) {
        if (strcmp(sessions[i].subject, subject) == 0) {
            authenticated = true;
            break;
        }
    }
    free_device_sessions(sessions, session_count);

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

/*
 * Best-effort fetch of a client's display fields (client_name, client_uri,
 * logo_uri) from its metadata document, for the consent screen -- so a user
 * approves a named, recognizable app rather than a bare client_id URL.
 * Unlike client_jwks_resolve, failure here is never fatal to the flow: a
 * client whose metadata document is slow, unreachable, or missing these
 * optional fields still gets a consent screen, just with the raw client_id
 * shown instead of a friendly name. All three out params are NULL (not an
 * error) when the corresponding field is absent or the fetch fails
 * entirely; only allocation failure returns non-WF_OK.
 */
static wf_status fetch_client_display_metadata(const char *client_id,
                                               char **out_name, char **out_uri,
                                               char **out_logo) {
    *out_name = NULL;
    *out_uri = NULL;
    *out_logo = NULL;
    if (!client_id_fetchable(client_id)) return WF_OK;

    cJSON *metadata = NULL;
    if (http_get_json(client_id, &metadata) != WF_OK || !metadata) return WF_OK;

    cJSON *name = cJSON_GetObjectItemCaseSensitive(metadata, "client_name");
    cJSON *uri = cJSON_GetObjectItemCaseSensitive(metadata, "client_uri");
    cJSON *logo = cJSON_GetObjectItemCaseSensitive(metadata, "logo_uri");
    wf_status status = WF_OK;
    if (cJSON_IsString(name) && name->valuestring[0]) {
        *out_name = strdup(name->valuestring);
        if (!*out_name) status = WF_ERR_ALLOC;
    }
    /* Only offer client_uri/logo_uri onward as https (or loopback http, for
     * local dev/test) -- the same fetchability rule as the client_id itself,
     * so the consent page never gets handed a javascript: or data: URI to
     * put in an href/src. */
    if (status == WF_OK && cJSON_IsString(uri) &&
        client_id_fetchable(uri->valuestring)) {
        *out_uri = strdup(uri->valuestring);
        if (!*out_uri) status = WF_ERR_ALLOC;
    }
    if (status == WF_OK && cJSON_IsString(logo) &&
        client_id_fetchable(logo->valuestring)) {
        *out_logo = strdup(logo->valuestring);
        if (!*out_logo) status = WF_ERR_ALLOC;
    }
    cJSON_Delete(metadata);
    if (status != WF_OK) {
        free(*out_name);
        free(*out_uri);
        free(*out_logo);
        *out_name = *out_uri = *out_logo = NULL;
    }
    return status;
}

/* ---- GET /oauth/authorize/info ----
 * Read-only counterpart to /oauth/authorize: lets the consent page show
 * what is actually being requested (scope, and the requesting client's
 * display name/logo when its metadata document offers them) before the
 * user decides, without consuming the PAR the way approval does. */
static wf_status oauth_authorize_info(void *ctx, const wf_xrpc_request *req,
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
     * Distinct `error` codes per failure, not one generic
     * "invalid_request" for everything -- the consent page uses this to
     * show an explanation that actually matches what went wrong (retry vs.
     * go back to the app vs. "this isn't fixable by refreshing") instead of
     * one message covering three unrelated causes. See #26 item 3.
     */
    char *scope = NULL, *redirect_uri = NULL;
    wf_status status = metalbear_oauth_par_peek(
        rctx->store, request_uri, client_id, &scope, &redirect_uri);
    if (status == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(resp, 400, "expired",
                                   "This authorization request has expired "
                                   "or is unknown");
        return WF_OK;
    }
    if (status != WF_OK) {
        wf_xrpc_response_set_error(
            resp, 400, "client_mismatch",
            "This authorization request does not match the application "
            "that started it");
        return WF_OK;
    }
    free(redirect_uri); /* not part of this response */

    char *name = NULL, *uri = NULL, *logo = NULL;
    fetch_client_display_metadata(client_id, &name, &uri, &logo);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(scope);
        free(name);
        free(uri);
        free(logo);
        wf_xrpc_response_set_error(resp, 500, "server_error",
                                   "Could not build authorization info");
        return WF_OK;
    }
    bool ok = cJSON_AddStringToObject(root, "client_id", client_id) &&
              cJSON_AddStringToObject(root, "scope", scope);
    if (ok && name) ok = cJSON_AddStringToObject(root, "client_name", name);
    if (ok && uri) ok = cJSON_AddStringToObject(root, "client_uri", uri);
    if (ok && logo) ok = cJSON_AddStringToObject(root, "logo_uri", logo);
    free(scope);
    free(name);
    free(uri);
    free(logo);
    if (!ok) {
        cJSON_Delete(root);
        wf_xrpc_response_set_error(resp, 500, "server_error",
                                   "Could not build authorization info");
        return WF_OK;
    }
    return json_response(resp, root, "no-store");
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
            !cJSON_IsString(redir) || !cJSON_IsString(verifier)) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                       "Missing required parameters");
            return WF_OK;
        }
        status = metalbear_oauth_exchange_code(
            rctx->store, code->valuestring,
            auth_client_id ? auth_client_id : cid->valuestring,
            redir->valuestring, verifier->valuestring,
            cJSON_IsString(jkt) ? jkt->valuestring : NULL, &grant);
    } else if (strcmp(grant_type->valuestring, "refresh_token") == 0) {
        cJSON *refresh =
            cJSON_GetObjectItemCaseSensitive(body, "refresh_token");
        cJSON *cid = cJSON_GetObjectItemCaseSensitive(body, "client_id");
        cJSON *jkt = cJSON_GetObjectItemCaseSensitive(body, "dpop_jkt");

        if (!cJSON_IsString(refresh) || !cJSON_IsString(cid)) {
            cJSON_Delete(body);
            wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                       "Missing required parameters");
            return WF_OK;
        }
        status = metalbear_oauth_refresh(
            rctx->store, refresh->valuestring,
            auth_client_id ? auth_client_id : cid->valuestring,
            cJSON_IsString(jkt) ? jkt->valuestring : NULL, &grant);
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
 * `value` is the full cookie value -- one token, or MB_DEVICE_MAX_SESSIONS
 * of them joined by '.' (see join_device_tokens) -- not just a single
 * session's token. `max_age_seconds` of 0 clears the cookie, per RFC 6265. */
static void set_device_cookie(wf_xrpc_response *resp, const char *value,
                              int64_t max_age_seconds) {
    char cookie[512];
    snprintf(cookie, sizeof(cookie),
             MB_DEVICE_COOKIE "=%s; Path=/; HttpOnly; Secure; SameSite=Lax; "
                              "Max-Age=%lld",
             value ? value : "", (long long)max_age_seconds);
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
/*
 * Common tail of every path that ends in "the browser is now signed in as
 * `subject`" -- password sign-in and passkey authentication alike: mint a
 * device session, fold it into whatever sessions the cookie already carries
 * (replacing subject's own stale one, evicting the oldest past the cap,
 * keeping every other account's session untouched so a multi-account
 * browser doesn't get signed out of accounts it didn't just sign into), set
 * the cookie, and respond with {"did": subject}.
 */
static wf_status finish_device_signin(oauth_route_ctx *rctx,
                                      const wf_xrpc_request *req,
                                      wf_xrpc_response *resp,
                                      const char *subject) {
    device_session_entry existing[MB_DEVICE_MAX_SESSIONS];
    size_t existing_count =
        read_device_sessions(rctx->store, req->cookie_header, existing);
    char *keep[MB_DEVICE_MAX_SESSIONS];
    size_t keep_count = 0;
    for (size_t i = 0; i < existing_count; i++) {
        if (strcmp(existing[i].subject, subject) == 0) {
            metalbear_oauth_device_session_revoke(rctx->store,
                                                  existing[i].token);
            free(existing[i].token);
        } else {
            keep[keep_count++] = existing[i].token;
        }
    }
    while (keep_count >= MB_DEVICE_MAX_SESSIONS) {
        metalbear_oauth_device_session_revoke(rctx->store, keep[0]);
        free(keep[0]);
        memmove(keep, keep + 1, (keep_count - 1) * sizeof(*keep));
        keep_count--;
    }

    char *token = NULL;
    if (metalbear_oauth_device_session_create(rctx->store, subject, &token) !=
        WF_OK) {
        for (size_t i = 0; i < keep_count; i++) free(keep[i]);
        wf_xrpc_response_set_error(resp, 500, "internal_error",
                                   "Could not create a session");
        return WF_OK;
    }
    keep[keep_count++] = token;

    char *cookie_value = join_device_tokens(keep, keep_count);
    for (size_t i = 0; i < keep_count; i++) free(keep[i]);
    if (!cookie_value) return WF_ERR_ALLOC;
    set_device_cookie(resp, cookie_value,
                      METALBEAR_DEVICE_SESSION_LIFETIME_SECONDS);
    free(cookie_value);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "did", subject);
    return json_response(resp, root, "no-store");
}

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

    return finish_device_signin(rctx, req, resp, subject);
}

/* True if `subject` is among the accounts the presented device-session
 * cookie is currently signed into. Every passkey account-management route
 * below (register, list, remove) uses this as its authorization check --
 * the same "already proved a password once" bar oauth_signin's cookie sets,
 * not a separate credential. */
static bool device_session_authorizes(oauth_route_ctx *rctx,
                                      const wf_xrpc_request *req,
                                      const char *subject) {
    device_session_entry sessions[MB_DEVICE_MAX_SESSIONS];
    size_t count =
        read_device_sessions(rctx->store, req->cookie_header, sessions);
    bool authorized = false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(sessions[i].subject, subject) == 0) authorized = true;
    }
    free_device_sessions(sessions, count);
    return authorized;
}

/*
 * POST /oauth/passkey/register/options (not part of the OAuth spec).
 * Requires an existing device session for the account named by `did` in
 * the request body -- registering a passkey is an account-management
 * action, reached only from an already-authenticated account/security
 * page, never pre-login.
 */
static wf_status passkey_register_options(void *ctx, const wf_xrpc_request *req,
                                          wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    if (!req->params || !cJSON_IsObject(req->params)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }
    cJSON *did_item = cJSON_GetObjectItemCaseSensitive(req->params, "did");
    if (!cJSON_IsString(did_item) || !did_item->valuestring[0]) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "did is required");
        return WF_OK;
    }
    const char *subject = did_item->valuestring;
    if (!device_session_authorizes(rctx, req, subject)) {
        wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                   "No device session for this account");
        return WF_OK;
    }

    char *rp_id = rp_id_from_public_url(rctx->public_url);
    if (!rp_id) return WF_ERR_INTERNAL;

    char *challenge = NULL;
    if (metalbear_oauth_passkey_challenge_create(
            rctx->store, METALBEAR_WEBAUTHN_CEREMONY_REGISTRATION, subject,
            &challenge) != WF_OK) {
        free(rp_id);
        wf_xrpc_response_set_error(resp, 500, "internal_error",
                                   "Could not start registration");
        return WF_OK;
    }

    metalbear_oauth_passkey_info *existing = NULL;
    size_t existing_count = 0;
    metalbear_oauth_passkey_list(rctx->store, subject, &existing,
                                 &existing_count);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(rp_id);
        free(challenge);
        metalbear_oauth_passkey_info_list_free(existing, existing_count);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "challenge", challenge);

    cJSON *rp = cJSON_CreateObject();
    cJSON_AddStringToObject(rp, "id", rp_id);
    cJSON_AddStringToObject(rp, "name", "MetalBear");
    cJSON_AddItemToObject(root, "rp", rp);

    /* WebAuthn user.id just needs to be an opaque, non-secret handle -- the
     * challenge's own random bytes serve fine, sparing this endpoint a
     * separate RNG call. */
    cJSON *user = cJSON_CreateObject();
    cJSON_AddStringToObject(user, "id", challenge);
    cJSON_AddStringToObject(user, "name", subject);
    cJSON_AddStringToObject(user, "displayName", subject);
    cJSON_AddItemToObject(root, "user", user);

    cJSON *params = cJSON_CreateArray();
    cJSON *es256 = cJSON_CreateObject();
    cJSON_AddStringToObject(es256, "type", "public-key");
    cJSON_AddNumberToObject(es256, "alg", -7);
    cJSON_AddItemToArray(params, es256);
    cJSON_AddItemToObject(root, "pubKeyCredParams", params);

    cJSON_AddStringToObject(root, "attestation", "none");

    /* "preferred", not "required": a resident/discoverable credential is
     * only useful for usernameless login, which this implementation never
     * does -- passkey_authenticate_options always requires an identifier
     * and supplies allowCredentials explicitly. Requiring one here would
     * reject registration outright on authenticators that support WebAuthn
     * but not resident keys, for no benefit this server actually uses. */
    cJSON *selection = cJSON_CreateObject();
    cJSON_AddStringToObject(selection, "residentKey", "preferred");
    cJSON_AddStringToObject(selection, "userVerification", "preferred");
    cJSON_AddItemToObject(root, "authenticatorSelection", selection);

    cJSON *exclude = cJSON_CreateArray();
    for (size_t i = 0; i < existing_count; i++) {
        cJSON *cred = cJSON_CreateObject();
        cJSON_AddStringToObject(cred, "type", "public-key");
        cJSON_AddStringToObject(cred, "id", existing[i].id);
        cJSON_AddItemToArray(exclude, cred);
    }
    cJSON_AddItemToObject(root, "excludeCredentials", exclude);

    metalbear_oauth_passkey_info_list_free(existing, existing_count);
    free(rp_id);
    free(challenge);
    return json_response(resp, root, "no-store");
}

/*
 * POST /oauth/passkey/register/verify (not part of the OAuth spec). Same
 * device-session requirement as .../register/options. Verifies the
 * WebAuthn registration ceremony -- challenge, origin, RP ID hash -- under
 * "none" attestation, so there is no attestation statement signature to
 * check, only that the ceremony itself came from this origin with a
 * challenge this server actually issued -- and stores the new credential.
 */
static wf_status passkey_register_verify(void *ctx, const wf_xrpc_request *req,
                                         wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    unsigned char *client_data = NULL, *attestation_object = NULL;
    size_t client_data_len = 0, attestation_object_len = 0;
    char *rp_id = NULL;
    cJSON *client_data_json = NULL;
    metalbear_webauthn_attested_credential cred;
    memset(&cred, 0, sizeof(cred));

    if (!req->params || !cJSON_IsObject(req->params)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }
    cJSON *did_item = cJSON_GetObjectItemCaseSensitive(req->params, "did");
    cJSON *response_item =
        cJSON_GetObjectItemCaseSensitive(req->params, "response");
    cJSON *name_item = cJSON_GetObjectItemCaseSensitive(req->params, "name");
    if (!cJSON_IsString(did_item) || !did_item->valuestring[0] ||
        !cJSON_IsObject(response_item)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "did and response are required");
        return WF_OK;
    }
    const char *subject = did_item->valuestring;
    const char *name = cJSON_IsString(name_item) && name_item->valuestring[0]
                           ? name_item->valuestring
                           : NULL;
    if (!device_session_authorizes(rctx, req, subject)) {
        wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                   "No device session for this account");
        return WF_OK;
    }

    cJSON *client_data_b64 =
        cJSON_GetObjectItemCaseSensitive(response_item, "clientDataJSON");
    cJSON *attestation_b64 =
        cJSON_GetObjectItemCaseSensitive(response_item, "attestationObject");
    if (!cJSON_IsString(client_data_b64) || !cJSON_IsString(attestation_b64) ||
        wf_crypto_base64url_decode(client_data_b64->valuestring, &client_data,
                                   &client_data_len) != WF_OK ||
        wf_crypto_base64url_decode(attestation_b64->valuestring,
                                   &attestation_object,
                                   &attestation_object_len) != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Malformed registration response");
        goto fail;
    }

    client_data_json =
        cJSON_ParseWithLength((const char *)client_data, client_data_len);
    {
        cJSON *type =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "type");
        cJSON *origin =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "origin");
        cJSON *challenge =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "challenge");
        /* crossOrigin is optional per spec (older clients omit it), so only
         * reject when a client explicitly says the ceremony ran inside a
         * cross-origin iframe -- e.g. this login page framed on another
         * site to clickjack a passkey ceremony -- not merely absent. */
        cJSON *cross_origin =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "crossOrigin");
        if (!cJSON_IsObject(client_data_json) || !cJSON_IsString(type) ||
            strcmp(type->valuestring, "webauthn.create") != 0 ||
            !cJSON_IsString(origin) || !rctx->public_url ||
            strcmp(origin->valuestring, rctx->public_url) != 0 ||
            !cJSON_IsString(challenge) ||
            (cJSON_IsBool(cross_origin) && cJSON_IsTrue(cross_origin))) {
            wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                       "Registration ceremony did not verify");
            goto fail;
        }

        char challenge_subject[256];
        if (metalbear_oauth_passkey_challenge_consume(
                rctx->store, challenge->valuestring,
                METALBEAR_WEBAUTHN_CEREMONY_REGISTRATION, challenge_subject,
                sizeof(challenge_subject)) != WF_OK ||
            strcmp(challenge_subject, subject) != 0) {
            wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                       "Registration ceremony did not verify");
            goto fail;
        }
    }

    rp_id = rp_id_from_public_url(rctx->public_url);
    if (!rp_id) {
        wf_xrpc_response_set_error(resp, 500, "internal_error",
                                   "Could not verify registration");
        goto fail;
    }
    {
        const unsigned char *auth_data = NULL;
        size_t auth_data_len = 0;
        unsigned char expected_rp_id_hash[32];
        if (metalbear_webauthn_parse_attestation_object(
                attestation_object, attestation_object_len, &auth_data,
                &auth_data_len) != WF_OK ||
            metalbear_webauthn_parse_registration_auth_data(
                auth_data, auth_data_len, &cred) != WF_OK ||
            wf_crypto_sha256((const unsigned char *)rp_id, strlen(rp_id),
                             expected_rp_id_hash) != WF_OK ||
            memcmp(cred.rp_id_hash, expected_rp_id_hash, 32) != 0 ||
            !(cred.flags & METALBEAR_WEBAUTHN_FLAG_UP)) {
            wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                       "Registration ceremony did not verify");
            goto fail;
        }
    }

    {
        wf_status add_status = metalbear_oauth_passkey_add(
            rctx->store, subject, cred.credential_id, cred.credential_id_len,
            cred.public_key.x, cred.public_key.y, name);
        if (add_status == WF_ERR_DUPLICATE) {
            wf_xrpc_response_set_error(resp, 409, "invalid_request",
                                       "This passkey is already registered");
            goto fail;
        }
        if (add_status != WF_OK) {
            wf_xrpc_response_set_error(resp, 500, "internal_error",
                                       "Could not save the passkey");
            goto fail;
        }
    }

    {
        cJSON *root = cJSON_CreateObject();
        free(client_data);
        free(attestation_object);
        free(rp_id);
        cJSON_Delete(client_data_json);
        metalbear_webauthn_attested_credential_free(&cred);
        if (!root) return WF_ERR_ALLOC;
        cJSON_AddBoolToObject(root, "ok", true);
        return json_response(resp, root, "no-store");
    }

fail:
    free(client_data);
    free(attestation_object);
    free(rp_id);
    cJSON_Delete(client_data_json);
    metalbear_webauthn_attested_credential_free(&cred);
    return WF_OK;
}

/*
 * POST /oauth/passkey/authenticate/options (not part of the OAuth spec).
 * Unauthenticated -- reached pre-login, from the same place the password
 * form lives. Resolves `identifier` the way oauth_signin's password path
 * resolves one internally, but never distinguishes "unknown account" from
 * "no passkeys registered" in the response: both look identical
 * ({"available": false}), so this endpoint cannot be used to enumerate
 * which handles exist.
 */
static wf_status passkey_authenticate_options(void *ctx,
                                              const wf_xrpc_request *req,
                                              wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    if (!req->params || !cJSON_IsObject(req->params)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }
    cJSON *identifier_item =
        cJSON_GetObjectItemCaseSensitive(req->params, "identifier");
    if (!cJSON_IsString(identifier_item) || !identifier_item->valuestring[0]) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "identifier is required");
        return WF_OK;
    }

    char subject[256] = "";
    bool resolved =
        rctx->resolve_subject &&
        rctx->resolve_subject(rctx->resolver_ctx, identifier_item->valuestring,
                              subject, sizeof(subject));
    int has_passkeys = 0;
    if (resolved)
        metalbear_oauth_passkey_exists(rctx->store, subject, &has_passkeys);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    if (!resolved || !has_passkeys) {
        cJSON_AddBoolToObject(root, "available", false);
        return json_response(resp, root, "no-store");
    }

    metalbear_oauth_passkey_info *items = NULL;
    size_t item_count = 0;
    char *challenge = NULL;
    char *rp_id = NULL;
    if (metalbear_oauth_passkey_list(rctx->store, subject, &items,
                                     &item_count) != WF_OK ||
        metalbear_oauth_passkey_challenge_create(
            rctx->store, METALBEAR_WEBAUTHN_CEREMONY_AUTHENTICATION, subject,
            &challenge) != WF_OK ||
        !(rp_id = rp_id_from_public_url(rctx->public_url))) {
        metalbear_oauth_passkey_info_list_free(items, item_count);
        free(challenge);
        free(rp_id);
        cJSON_Delete(root);
        wf_xrpc_response_set_error(resp, 500, "internal_error",
                                   "Could not start authentication");
        return WF_OK;
    }

    cJSON_AddBoolToObject(root, "available", true);
    cJSON_AddStringToObject(root, "challenge", challenge);
    cJSON_AddStringToObject(root, "rpId", rp_id);
    cJSON_AddStringToObject(root, "userVerification", "preferred");
    cJSON *allow = cJSON_CreateArray();
    for (size_t i = 0; i < item_count; i++) {
        cJSON *cred = cJSON_CreateObject();
        cJSON_AddStringToObject(cred, "type", "public-key");
        cJSON_AddStringToObject(cred, "id", items[i].id);
        cJSON_AddItemToArray(allow, cred);
    }
    cJSON_AddItemToObject(root, "allowCredentials", allow);

    metalbear_oauth_passkey_info_list_free(items, item_count);
    free(challenge);
    free(rp_id);
    return json_response(resp, root, "no-store");
}

/*
 * POST /oauth/passkey/authenticate/verify (not part of the OAuth spec).
 * Unauthenticated. Verifies a WebAuthn assertion -- challenge, origin, RP ID
 * hash, and (unlike registration) the ES256 signature itself, over
 * authenticatorData || SHA256(clientDataJSON), using the P-256 public key
 * stored at registration -- and on success ends the same way password
 * sign-in does.
 */
static wf_status passkey_authenticate_verify(void *ctx,
                                             const wf_xrpc_request *req,
                                             wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    unsigned char *credential_id = NULL, *client_data = NULL,
                  *authenticator_data = NULL, *signature_der = NULL;
    size_t credential_id_len = 0, client_data_len = 0,
           authenticator_data_len = 0, signature_der_len = 0;
    char *rp_id = NULL;
    cJSON *client_data_json = NULL;

    if (!req->params || !cJSON_IsObject(req->params)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }
    cJSON *id_item = cJSON_GetObjectItemCaseSensitive(req->params, "id");
    cJSON *response_item =
        cJSON_GetObjectItemCaseSensitive(req->params, "response");
    if (!cJSON_IsString(id_item) || !cJSON_IsObject(response_item) ||
        wf_crypto_base64url_decode(id_item->valuestring, &credential_id,
                                   &credential_id_len) != WF_OK) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Malformed authentication response");
        goto fail;
    }
    {
        cJSON *client_data_b64 =
            cJSON_GetObjectItemCaseSensitive(response_item, "clientDataJSON");
        cJSON *auth_data_b64 = cJSON_GetObjectItemCaseSensitive(
            response_item, "authenticatorData");
        cJSON *signature_b64 =
            cJSON_GetObjectItemCaseSensitive(response_item, "signature");
        if (!cJSON_IsString(client_data_b64) ||
            !cJSON_IsString(auth_data_b64) || !cJSON_IsString(signature_b64) ||
            wf_crypto_base64url_decode(client_data_b64->valuestring,
                                       &client_data,
                                       &client_data_len) != WF_OK ||
            wf_crypto_base64url_decode(auth_data_b64->valuestring,
                                       &authenticator_data,
                                       &authenticator_data_len) != WF_OK ||
            wf_crypto_base64url_decode(signature_b64->valuestring,
                                       &signature_der,
                                       &signature_der_len) != WF_OK) {
            wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                       "Malformed authentication response");
            goto fail;
        }
    }

    char subject[256];
    unsigned char stored_x[32], stored_y[32];
    uint32_t stored_sign_count = 0;
    if (metalbear_oauth_passkey_lookup(
            rctx->store, credential_id, credential_id_len, subject,
            sizeof(subject), stored_x, stored_y, &stored_sign_count) != WF_OK) {
        wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                   "Unknown passkey");
        goto fail;
    }

    client_data_json =
        cJSON_ParseWithLength((const char *)client_data, client_data_len);
    {
        cJSON *type =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "type");
        cJSON *origin =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "origin");
        cJSON *challenge =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "challenge");
        cJSON *cross_origin =
            cJSON_GetObjectItemCaseSensitive(client_data_json, "crossOrigin");
        if (!cJSON_IsObject(client_data_json) || !cJSON_IsString(type) ||
            strcmp(type->valuestring, "webauthn.get") != 0 ||
            !cJSON_IsString(origin) || !rctx->public_url ||
            strcmp(origin->valuestring, rctx->public_url) != 0 ||
            !cJSON_IsString(challenge) ||
            (cJSON_IsBool(cross_origin) && cJSON_IsTrue(cross_origin))) {
            wf_xrpc_response_set_error(
                resp, 401, "invalid_grant",
                "Authentication ceremony did not verify");
            goto fail;
        }

        char challenge_subject[256];
        if (metalbear_oauth_passkey_challenge_consume(
                rctx->store, challenge->valuestring,
                METALBEAR_WEBAUTHN_CEREMONY_AUTHENTICATION, challenge_subject,
                sizeof(challenge_subject)) != WF_OK ||
            strcmp(challenge_subject, subject) != 0) {
            wf_xrpc_response_set_error(
                resp, 401, "invalid_grant",
                "Authentication ceremony did not verify");
            goto fail;
        }
    }

    rp_id = rp_id_from_public_url(rctx->public_url);
    unsigned char flags = 0;
    uint32_t new_sign_count = 0;
    {
        unsigned char rp_id_hash[32], expected_rp_id_hash[32];
        if (!rp_id ||
            metalbear_webauthn_parse_assertion_auth_data(
                authenticator_data, authenticator_data_len, rp_id_hash, &flags,
                &new_sign_count) != WF_OK ||
            wf_crypto_sha256((const unsigned char *)rp_id, strlen(rp_id),
                             expected_rp_id_hash) != WF_OK ||
            memcmp(rp_id_hash, expected_rp_id_hash, 32) != 0 ||
            !(flags & METALBEAR_WEBAUTHN_FLAG_UP)) {
            wf_xrpc_response_set_error(
                resp, 401, "invalid_grant",
                "Authentication ceremony did not verify");
            goto fail;
        }
    }

    /* WebAuthn assertion signatures cover authenticatorData ||
     * SHA256(clientDataJSON) (§7.2 step 21) and are DER-encoded -- convert
     * to the raw r||s form wf_crypto_p256_verify_allow_malleable expects. */
    {
        unsigned char client_data_hash[32];
        if (wf_crypto_sha256(client_data, client_data_len, client_data_hash) !=
            WF_OK) {
            wf_xrpc_response_set_error(resp, 500, "internal_error",
                                       "Could not verify authentication");
            goto fail;
        }
        size_t signed_data_len =
            authenticator_data_len + sizeof(client_data_hash);
        unsigned char *signed_data = malloc(signed_data_len);
        if (!signed_data) {
            free(credential_id);
            free(client_data);
            free(authenticator_data);
            free(signature_der);
            free(rp_id);
            cJSON_Delete(client_data_json);
            return WF_ERR_ALLOC;
        }
        memcpy(signed_data, authenticator_data, authenticator_data_len);
        memcpy(signed_data + authenticator_data_len, client_data_hash,
               sizeof(client_data_hash));

        unsigned char signature_raw[64];
        wf_status sig_status = wf_crypto_ecdsa_der_to_raw(
            signature_der, signature_der_len, signature_raw);
        bool signature_valid =
            sig_status == WF_OK &&
            wf_crypto_p256_verify_allow_malleable(
                stored_x, stored_y, signed_data, signed_data_len, signature_raw,
                sizeof(signature_raw)) == WF_OK;
        free(signed_data);

        /* WebAuthn explicitly allows an authenticator to never increment its
         * counter at all (many resident-key/passkey providers, e.g. a
         * platform passkey synced across devices, always report 0) -- that
         * is not itself a cloning signal, so a counter that has ALWAYS been
         * 0 is exempted. But a counter that WAS incrementing and then drops
         * back to 0, or repeats/decreases a nonzero value, is exactly the
         * signal this check exists to catch, and must still fail. */
        bool counter_ok = (new_sign_count == 0 && stored_sign_count == 0) ||
                          new_sign_count > stored_sign_count;
        if (!signature_valid || !counter_ok) {
            wf_xrpc_response_set_error(
                resp, 401, "invalid_grant",
                "Authentication ceremony did not verify");
            goto fail;
        }
    }

    metalbear_oauth_passkey_touch(rctx->store, credential_id, credential_id_len,
                                  new_sign_count);

    free(credential_id);
    free(client_data);
    free(authenticator_data);
    free(signature_der);
    free(rp_id);
    cJSON_Delete(client_data_json);
    return finish_device_signin(rctx, req, resp, subject);

fail:
    free(credential_id);
    free(client_data);
    free(authenticator_data);
    free(signature_der);
    free(rp_id);
    cJSON_Delete(client_data_json);
    return WF_OK;
}

/*
 * GET /oauth/passkey/list?did=... (not part of the OAuth spec). Same
 * device-session requirement as registration.
 */
static wf_status passkey_list(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    const char *subject = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *did_item = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        if (cJSON_IsString(did_item) && did_item->valuestring[0])
            subject = did_item->valuestring;
    }
    if (!subject || !device_session_authorizes(rctx, req, subject)) {
        wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                   "No device session for this account");
        return WF_OK;
    }

    metalbear_oauth_passkey_info *items = NULL;
    size_t item_count = 0;
    if (metalbear_oauth_passkey_list(rctx->store, subject, &items,
                                     &item_count) != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "internal_error",
                                   "Could not list passkeys");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_oauth_passkey_info_list_free(items, item_count);
        return WF_ERR_ALLOC;
    }
    cJSON *list = cJSON_CreateArray();
    for (size_t i = 0; i < item_count; i++) {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "id", items[i].id);
        if (items[i].name)
            cJSON_AddStringToObject(entry, "name", items[i].name);
        cJSON_AddNumberToObject(entry, "createdAt",
                                (double)items[i].created_at);
        if (items[i].last_used_at > 0)
            cJSON_AddNumberToObject(entry, "lastUsedAt",
                                    (double)items[i].last_used_at);
        cJSON_AddItemToArray(list, entry);
    }
    cJSON_AddItemToObject(root, "passkeys", list);
    metalbear_oauth_passkey_info_list_free(items, item_count);
    return json_response(resp, root, "no-store");
}

/*
 * POST /oauth/passkey/remove (not part of the OAuth spec). `id` is one of
 * the credential IDs GET /oauth/passkey/list returned. Same device-session
 * requirement as registration.
 */
static wf_status passkey_remove(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    if (!req->params || !cJSON_IsObject(req->params)) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "Missing or invalid request body");
        return WF_OK;
    }
    cJSON *did_item = cJSON_GetObjectItemCaseSensitive(req->params, "did");
    cJSON *id_item = cJSON_GetObjectItemCaseSensitive(req->params, "id");
    if (!cJSON_IsString(did_item) || !did_item->valuestring[0] ||
        !cJSON_IsString(id_item) || !id_item->valuestring[0]) {
        wf_xrpc_response_set_error(resp, 400, "invalid_request",
                                   "did and id are required");
        return WF_OK;
    }
    const char *subject = did_item->valuestring;
    if (!device_session_authorizes(rctx, req, subject)) {
        wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                   "No device session for this account");
        return WF_OK;
    }

    wf_status status = metalbear_oauth_passkey_remove(rctx->store, subject,
                                                      id_item->valuestring);
    if (status == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(resp, 404, "not_found", "Unknown passkey");
        return WF_OK;
    }
    if (status != WF_OK) {
        wf_xrpc_response_set_error(resp, 500, "internal_error",
                                   "Could not remove the passkey");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return json_response(resp, root, "no-store");
}

/*
 * GET /oauth/session (not part of the OAuth spec). Read-only check of every
 * device session the presented cookie carries -- the same check
 * `oauth_authorize`'s approval step makes, exposed ahead of time so the
 * consent page can send a user to sign in *before* showing a consent screen
 * it cannot actually finish, rather than after: a regular JWT session (the
 * `auth` store) is not proof of a device session, since nothing establishes
 * one but POST /oauth/signin, and a returning user with only a JWT session
 * would otherwise reach "Approve" and loop back to this same consent page
 * with nothing having happened.
 *
 * `subjects` lists every account currently signed in on this browser (a
 * multi-account host can have more than one at once), letting the consent
 * page offer an account picker instead of just the single most-recent
 * signed-in account. `did` names that most-recent one, for a caller that
 * only wants a single answer -- the same subject this endpoint always
 * returned back when a browser could only ever hold one session.
 *
 * An optional `login_hint` query param asks specifically whether THAT
 * account is among the signed-in ones, resolved the same way
 * `oauth_authorize` resolves it (rctx->resolve_subject) so a handle and a
 * DID naming the same account agree. `matches_hint` answers that directly
 * rather than making the caller resolve and compare a handle against a
 * list of DIDs itself -- this is exactly the check that used to be missing
 * client-side: without it, a consent page that only asked "is ANY session
 * present" would treat a session for a DIFFERENT account as satisfying
 * `login_hint` and loop forever retrying an authorize call that keeps
 * failing for the actual requested account.
 */
static wf_status oauth_session(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    device_session_entry sessions[MB_DEVICE_MAX_SESSIONS];
    size_t count =
        read_device_sessions(rctx->store, req->cookie_header, sessions);
    if (count == 0) {
        wf_xrpc_response_set_error(resp, 401, "invalid_grant",
                                   "No device session");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free_device_sessions(sessions, count);
        return WF_ERR_ALLOC;
    }
    cJSON *subjects = cJSON_CreateArray();
    if (!subjects) {
        cJSON_Delete(root);
        free_device_sessions(sessions, count);
        return WF_ERR_ALLOC;
    }
    for (size_t i = 0; i < count; i++)
        cJSON_AddItemToArray(subjects, cJSON_CreateString(sessions[i].subject));
    cJSON_AddItemToObject(root, "subjects", subjects);
    cJSON_AddStringToObject(root, "did", sessions[count - 1].subject);

    const char *hint = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *lh = cJSON_GetObjectItemCaseSensitive(req->params, "login_hint");
        if (cJSON_IsString(lh) && lh->valuestring[0]) hint = lh->valuestring;
    }
    if (hint) {
        char hint_subject[256] = "";
        bool resolved =
            rctx->resolve_subject &&
            rctx->resolve_subject(rctx->resolver_ctx, hint, hint_subject,
                                  sizeof(hint_subject));
        bool matches = false;
        for (size_t i = 0; resolved && i < count; i++) {
            if (strcmp(sessions[i].subject, hint_subject) == 0) {
                matches = true;
                break;
            }
        }
        cJSON_AddBoolToObject(root, "matches_hint", matches);
    }

    free_device_sessions(sessions, count);
    return json_response(resp, root, "no-store");
}

/*
 * POST /oauth/signout (not part of the OAuth spec). With no body (or a
 * body naming no `did`), revokes every device session the cookie carries
 * and clears it entirely — the desired end state (signed out of
 * everything) holds whether or not there was anything to revoke. With
 * `{"did": "..."}`, revokes only that one account's session and rewrites
 * the cookie with whatever others remain, so switching away from one
 * signed-in account on a multi-account browser doesn't sign the others
 * out too.
 */
static wf_status oauth_signout(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    oauth_route_ctx *rctx = ctx;
    const char *only_subject = NULL;
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *did = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        if (cJSON_IsString(did) && did->valuestring[0])
            only_subject = did->valuestring;
    }

    device_session_entry sessions[MB_DEVICE_MAX_SESSIONS];
    size_t count =
        read_device_sessions(rctx->store, req->cookie_header, sessions);

    char *keep[MB_DEVICE_MAX_SESSIONS];
    size_t keep_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (!only_subject || strcmp(sessions[i].subject, only_subject) == 0) {
            metalbear_oauth_device_session_revoke(rctx->store,
                                                  sessions[i].token);
            free(sessions[i].token);
        } else {
            keep[keep_count++] = sessions[i].token;
        }
    }

    if (keep_count == 0) {
        set_device_cookie(resp, NULL, 0);
    } else {
        char *cookie_value = join_device_tokens(keep, keep_count);
        if (cookie_value) {
            set_device_cookie(resp, cookie_value,
                              METALBEAR_DEVICE_SESSION_LIFETIME_SECONDS);
            free(cookie_value);
        }
    }
    for (size_t i = 0; i < keep_count; i++) free(keep[i]);

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
        wf_xrpc_server_register_http_route(
            server, "GET", "/oauth/authorize/info", oauth_authorize_info,
            ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST", "/oauth/signin",
                                           oauth_signin, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "GET", "/oauth/session",
                                           oauth_session, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST", "/oauth/signout",
                                           oauth_signout, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(
            server, "POST", "/oauth/passkey/register/options",
            passkey_register_options, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(
            server, "POST", "/oauth/passkey/register/verify",
            passkey_register_verify, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(
            server, "POST", "/oauth/passkey/authenticate/options",
            passkey_authenticate_options, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(
            server, "POST", "/oauth/passkey/authenticate/verify",
            passkey_authenticate_verify, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "GET", "/oauth/passkey/list",
                                           passkey_list, ctx) != WF_OK ||
        wf_xrpc_server_register_http_route(server, "POST",
                                           "/oauth/passkey/remove",
                                           passkey_remove, ctx) != WF_OK) {
        free(ctx->public_url);
        free(ctx);
        return WF_ERR_INTERNAL;
    }

    return WF_OK;
}
