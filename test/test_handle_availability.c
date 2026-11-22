/*
 * test_handle_availability.c -- offline coverage for the temporary signup
 * helpers com.atproto.temp.checkHandleAvailability and
 * com.atproto.temp.addReservedHandle.
 *
 * Everything runs through wf_xrpc_set_handler: the client builds a real XRPC
 * URL/body, the seam turns that back into a wf_xrpc_request, and the test
 * calls MetalBear's actual auth callback before dispatching to the route
 * handlers. That way the public/admin boundary is exercised on the same
 * request path as the happy responses, without opening a socket.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "../src/account/account_routes.h"
#include "../src/server_internal.h"

#include "metalbear/account/account_registry.h"
#include "wolfram/temp_typed.h"
#include "wolfram/xrpc.h"

#include "test.h"

#include <cJSON.h>

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* XRPC encodes query values with curl_easy_escape; decode the ones the seam
 * sees back into the cJSON object a server dispatcher would have built. */
static char *url_decode(const char *in, size_t len) {
    char *out = malloc(len + 1);
    if (!out) return NULL;
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        if (in[i] == '%' && i + 2 < len && hex_value(in[i + 1]) >= 0 &&
            hex_value(in[i + 2]) >= 0) {
            out[n++] = (char)(hex_value(in[i + 1]) * 16 + hex_value(in[i + 2]));
            i += 2;
        } else if (in[i] == '+') {
            out[n++] = ' ';
        } else {
            out[n++] = in[i];
        }
    }
    out[n] = '\0';
    return out;
}

static cJSON *query_params(const char *url) {
    cJSON *params = cJSON_CreateObject();
    WF_CHECK(params != NULL);
    const char *query = strchr(url, '?');
    if (!query) return params;
    query++;

    while (*query) {
        const char *end = strchr(query, '&');
        if (!end) end = query + strlen(query);
        const char *equals = memchr(query, '=', (size_t)(end - query));
        if (equals && equals != query && equals + 1 != end) {
            char *name = url_decode(query, (size_t)(equals - query));
            char *value = url_decode(equals + 1, (size_t)(end - equals - 1));
            WF_CHECK(name != NULL && value != NULL);
            if (name && value) cJSON_AddStringToObject(params, name, value);
            free(name);
            free(value);
        }
        query = *end ? end + 1 : end;
    }
    return params;
}

static const char *find_header(const wf_http_header *headers, size_t count,
                               const char *name) {
    for (size_t i = 0; i < count; i++) {
        if (headers[i].name && strcasecmp(headers[i].name, name) == 0)
            return headers[i].value;
    }
    return NULL;
}

typedef struct {
    metalbear_server *server;
} seam_ctx;

static wf_status dispatch(void *userdata, const char *nsid, cJSON *params,
                          wf_xrpc_response *response) {
    seam_ctx *ctx = userdata;
    if (strcmp(nsid, "com.atproto.temp.checkHandleAvailability") == 0)
        return check_handle_availability(ctx->server,
                                         &(wf_xrpc_request){
                                             .params = params,
                                         },
                                         response);
    if (strcmp(nsid, "com.atproto.temp.addReservedHandle") == 0)
        return add_reserved_handle(ctx->server,
                                   &(wf_xrpc_request){
                                       .params = params,
                                   },
                                   response);
    wf_xrpc_response_set_error(response, 404, "InvalidRequest",
                               "unknown seam route");
    return WF_OK;
}

static wf_status seam_handler(void *userdata, const char *method,
                              const char *url, const char *content_type,
                              const char *body, size_t body_len,
                              const wf_http_header *headers,
                              size_t header_count, wf_response *out) {
    seam_ctx *ctx = userdata;
    const char *start = strstr(url, "/xrpc/");
    if (!start) return WF_ERR_INVALID_ARG;
    start += strlen("/xrpc/");
    const char *end = strchr(start, '?');
    if (!end) end = start + strlen(start);
    char nsid[256];
    size_t nsid_len = (size_t)(end - start);
    if (nsid_len == 0 || nsid_len >= sizeof(nsid)) return WF_ERR_INVALID_ARG;
    memcpy(nsid, start, nsid_len);
    nsid[nsid_len] = '\0';

    cJSON *params = strcmp(method, "POST") == 0
                        ? cJSON_ParseWithLength(body ? body : "", body_len)
                        : query_params(url);
    if (!params) params = cJSON_CreateObject();
    WF_CHECK(params != NULL);

    wf_xrpc_request req;
    memset(&req, 0, sizeof(req));
    req.nsid = nsid;
    req.path = url;
    req.method = method;
    req.auth_header = find_header(headers, header_count, "Authorization");
    req.params = params;
    req.content_type = content_type;
    req.body = (const unsigned char *)body;
    req.body_len = body_len;

    wf_xrpc_response response = WF_XRPC_RESPONSE_INIT;
    wf_status status = metalbear_authenticate(&req, ctx->server);
    if (status == WF_OK) status = dispatch(userdata, nsid, params, &response);
    if (status == WF_ERR_PERMISSION) {
        wf_xrpc_response_set_error(&response, 401, "AuthenticationRequired",
                                   "Authentication required");
        status = WF_ERR_HTTP;
    } else if (status == WF_OK &&
               (response.http_status < 200 || response.http_status >= 300)) {
        status = WF_ERR_HTTP;
    }
    cJSON_Delete(params);

    out->status = response.http_status;
    if (response.body && response.body_len) {
        out->body = malloc(response.body_len + 1);
        WF_CHECK(out->body != NULL);
        if (!out->body) {
            free(response.body);
            free(response.content_type);
            return WF_ERR_ALLOC;
        }
        memcpy(out->body, response.body, response.body_len);
        out->body[response.body_len] = '\0';
        out->body_len = response.body_len;
    }
    free(response.body);
    free(response.content_type);
    return (response.http_status >= 200 && response.http_status < 300)
               ? WF_OK
               : WF_ERR_HTTP;
}

static void check_error(wf_response *response, long status,
                        const char *expected) {
    WF_CHECK(response->status == status);
    cJSON *json = cJSON_ParseWithLength(response->body ? response->body : "",
                                        response->body_len);
    WF_CHECK(json != NULL);
    cJSON *error =
        json ? cJSON_GetObjectItemCaseSensitive(json, "error") : NULL;
    WF_CHECK(cJSON_IsString(error) &&
             strcmp(error->valuestring, expected) == 0);
    cJSON_Delete(json);
}

static void check_availability(wf_response *response, const char *handle,
                               int available) {
    WF_CHECK(response->status == 200);
    wf_temp_check_handle_availability parsed;
    WF_CHECK(wf_temp_check_handle_availability_parse(
                 response->body, response->body_len, &parsed) == WF_OK);
    WF_CHECK(parsed.handle && strcmp(parsed.handle, handle) == 0);
    WF_CHECK(parsed.available == available);
    WF_CHECK(parsed.raw_result != NULL);
    cJSON *type =
        parsed.raw_result
            ? cJSON_GetObjectItemCaseSensitive(parsed.raw_result, "$type")
            : NULL;
    WF_CHECK(cJSON_IsString(type));
    if (type) {
        const char *expected =
            available
                ? "com.atproto.temp.checkHandleAvailability#resultAvailable"
                : "com.atproto.temp.checkHandleAvailability#resultUnavailable";
        WF_CHECK(strcmp(type->valuestring, expected) == 0);
    }
    if (!available) {
        WF_CHECK(parsed.suggestion_count > 0);
        for (size_t i = 0; i < parsed.suggestion_count; i++) {
            WF_CHECK(parsed.suggestions[i].handle &&
                     strstr(parsed.suggestions[i].handle, ".example.com"));
            WF_CHECK(parsed.suggestions[i].method &&
                     strcmp(parsed.suggestions[i].method, "random_digits") ==
                         0);
        }
    }
    wf_temp_check_handle_availability_free(&parsed);
}

static wf_status query(wf_xrpc_client *client, const char *handle,
                       const char *email, wf_response *out) {
    wf_xrpc_param params[2] = {{"handle", handle}, {"email", email}};
    return wf_xrpc_query_params(client,
                                "com.atproto.temp.checkHandleAvailability",
                                params, email ? 2 : 1, out);
}

static wf_status reserve(wf_xrpc_client *client, const char *handle,
                         const wf_http_header *headers, size_t header_count,
                         wf_response *out) {
    char body[256];
    snprintf(body, sizeof(body), "{\"handle\":\"%s\"}", handle);
    return wf_http_post(client,
                        "http://seam.test/xrpc/com.atproto.temp."
                        "addReservedHandle",
                        "application/json", body, headers, header_count, out);
}

int main(void) {
    char directory[] = "/tmp/metalbear-handle-availability-XXXXXX";
    int directory_fd = mkstemp(directory);
    WF_CHECK(directory_fd >= 0);
    close(directory_fd);
    WF_CHECK(unlink(directory) == 0);
    WF_CHECK(mkdir(directory, 0700) == 0);
    char registry_path[sizeof(directory) + 32];
    snprintf(registry_path, sizeof(registry_path), "%s/account.sqlite3",
             directory);

    metalbear_account_registry *registry = NULL;
    WF_CHECK(metalbear_account_registry_open(registry_path, &registry) ==
             WF_OK);
    WF_CHECK(metalbear_account_registry_add(
                 registry, "did:plc:taken0000000000000000000",
                 "taken.example.com", "hash", directory) == WF_OK);

    metalbear_server server;
    memset(&server, 0, sizeof(server));
    server.registry = registry;
    server.user_domain = ".example.com";
    server.admin_password = "secret-admin";
    seam_ctx ctx = {.server = &server};

    wf_xrpc_client *client = wf_xrpc_client_new("http://seam.test");
    WF_CHECK(client != NULL);
    wf_xrpc_set_handler(client, seam_handler, &ctx);
    wf_response response = {0};

    /* Public route: available, taken and reserved answers use the lexicon's
     * result union. */
    WF_CHECK(query(client, "fresh.example.com", NULL, &response) == WF_OK);
    check_availability(&response, "fresh.example.com", 1);
    wf_response_free(&response);

    WF_CHECK(query(client, "taken.example.com", NULL, &response) == WF_OK);
    check_availability(&response, "taken.example.com", 0);
    wf_response_free(&response);

    WF_CHECK(query(client, "admin.example.com", NULL, &response) == WF_OK);
    check_availability(&response, "admin.example.com", 0);
    wf_response_free(&response);

    /* format:email's declared error. */
    WF_CHECK(query(client, "fresh.example.com", "not-an-email", &response) ==
             WF_ERR_HTTP);
    check_error(&response, 400, "InvalidEmail");
    wf_response_free(&response);

    /* Admin route boundary: no credential and a bearer token are not the
     * configured HTTP Basic admin credential. */
    WF_CHECK(reserve(client, "held.example.com", NULL, 0, &response) ==
             WF_ERR_HTTP);
    check_error(&response, 401, "AuthenticationRequired");
    wf_response_free(&response);

    wf_xrpc_client_set_auth(client, "not-admin");
    WF_CHECK(reserve(client, "held.example.com", NULL, 0, &response) ==
             WF_ERR_HTTP);
    check_error(&response, 401, "AuthenticationRequired");
    wf_response_free(&response);
    wf_xrpc_client_set_auth(client, NULL);

    char credential[64];
    int credential_len =
        snprintf(credential, sizeof(credential), "admin:%s", "secret-admin");
    char encoded[128];
    int encoded_len =
        EVP_EncodeBlock((unsigned char *)encoded,
                        (const unsigned char *)credential, credential_len);
    encoded[encoded_len] = '\0';
    char authorization[192];
    snprintf(authorization, sizeof(authorization), "Basic %s", encoded);
    wf_http_header admin_header = {"Authorization", authorization};

    WF_CHECK(reserve(client, "held.example.com", &admin_header, 1, &response) ==
             WF_OK);
    WF_CHECK(response.status == 200);
    wf_temp_add_reserved_handle_result added;
    WF_CHECK(wf_temp_add_reserved_handle_parse(response.body, response.body_len,
                                               &added) == WF_OK);
    WF_CHECK(added.ok == 1);
    wf_temp_add_reserved_handle_result_free(&added);
    wf_response_free(&response);

    WF_CHECK(query(client, "held.example.com", NULL, &response) == WF_OK);
    check_availability(&response, "held.example.com", 0);
    wf_response_free(&response);

    /* A reservation written with an already-expired TTL is pruned on the next
     * availability check, so the handle becomes bookable again. */
    bool expired_reserved = true;
    WF_CHECK(metalbear_account_registry_reserve_handle(
                 registry, "expired.example.com", -1, &expired_reserved) ==
             WF_OK);
    WF_CHECK(expired_reserved == false);
    WF_CHECK(query(client, "expired.example.com", NULL, &response) == WF_OK);
    check_availability(&response, "expired.example.com", 1);
    wf_response_free(&response);

    bool live_reserved = false;
    WF_CHECK(metalbear_account_registry_reserve_handle(
                 registry, "live.example.com", 60, &live_reserved) == WF_OK);
    WF_CHECK(live_reserved == true);
    bool is_reserved = false;
    WF_CHECK(metalbear_account_registry_is_handle_reserved(
                 registry, "LIVE.EXAMPLE.COM", &is_reserved) == WF_OK);
    WF_CHECK(is_reserved == true);
    is_reserved = false;
    WF_CHECK(metalbear_account_registry_is_handle_reserved(
                 registry, "expired.example.com", &is_reserved) == WF_OK);
    WF_CHECK(is_reserved == false);

    wf_xrpc_set_handler(client, NULL, NULL);
    wf_xrpc_client_free(client);
    metalbear_account_registry_free(registry);

    WF_TEST_SUMMARY();
}
