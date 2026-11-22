/*
 * test_admin_audit.c — offline end-to-end coverage for the operator-visible
 * admin audit trail (issue #160).
 *
 * Every com.atproto.admin.* call goes through the wf_xrpc_set_handler seam:
 * an authenticated call writes an `ok` row with its target DID, a refused
 * call writes a `denied` row before the handler, and the admin-only
 * /_ops/audit route pages through them newest-first with a numeric cursor.
 * A caller without the Basic admin credential cannot read the log.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "../src/admin/admin_routes.h"
#include "../src/ops/status.h"
#include "../src/server_internal.h"

#include "metalbear/account/account_registry.h"
#include "metalbear/admin/audit.h"

#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)
#define WF_CHECK CHECK

typedef struct {
    metalbear_server *server;
} seam_ctx;

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
            char name[128];
            char value[256];
            size_t name_len = (size_t)(equals - query);
            size_t value_len = (size_t)(end - equals - 1);
            if (name_len < sizeof(name) && value_len < sizeof(value)) {
                memcpy(name, query, name_len);
                name[name_len] = '\0';
                memcpy(value, equals + 1, value_len);
                value[value_len] = '\0';
                cJSON_AddStringToObject(params, name, value);
            }
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

static void finish_response(wf_xrpc_response *response, wf_response *out) {
    out->status = response->http_status;
    if (response->body && response->body_len) {
        out->body = malloc(response->body_len + 1);
        WF_CHECK(out->body != NULL);
        if (!out->body) {
            free(response->body);
            free(response->content_type);
            return;
        }
        memcpy(out->body, response->body, response->body_len);
        out->body[response->body_len] = '\0';
        out->body_len = response->body_len;
    }
    free(response->body);
    free(response->content_type);
}

static wf_status seam_handler(void *userdata, const char *method,
                              const char *url, const char *content_type,
                              const char *body, size_t body_len,
                              const wf_http_header *headers,
                              size_t header_count, wf_response *out) {
    (void)method;
    (void)content_type;
    (void)body;
    (void)body_len;
    seam_ctx *ctx = userdata;
    cJSON *params = query_params(url);
    WF_CHECK(params != NULL);

    wf_xrpc_request req;
    memset(&req, 0, sizeof(req));
    req.path = url;
    req.method = "GET";
    req.auth_header = find_header(headers, header_count, "Authorization");
    req.params = params;

    wf_xrpc_response response = WF_XRPC_RESPONSE_INIT;
    if (strstr(url, "/_ops/audit")) {
        /* HTTP routes bypass the XRPC auth callback: the handler guards
         * itself, exactly as /_debug/health does. */
        (void)admin_audit_handler(ctx->server, &req, &response);
    } else if (strstr(url, "/xrpc/com.atproto.admin.getInviteCodes")) {
        req.nsid = "com.atproto.admin.getInviteCodes";
        wf_status auth = metalbear_authenticate(&req, ctx->server);
        if (auth == WF_OK)
            (void)admin_get_invite_codes_audited(ctx->server, &req, &response);
        else
            wf_xrpc_response_set_error(&response, 401, "AuthenticationRequired",
                                       "Authentication required");
    } else {
        wf_xrpc_response_set_error(&response, 404, "InvalidRequest",
                                   "unknown seam route");
    }
    cJSON_Delete(params);
    finish_response(&response, out);
    return (response.http_status >= 200 && response.http_status < 300)
               ? WF_OK
               : WF_ERR_HTTP;
}

static void basic_header(char *buf, size_t size) {
    char credential[128];
    int n =
        snprintf(credential, sizeof(credential), "admin:%s", "secret-admin");
    char encoded[256];
    int elen = EVP_EncodeBlock((unsigned char *)encoded,
                               (const unsigned char *)credential, n);
    encoded[elen] = '\0';
    snprintf(buf, size, "Basic %s", encoded);
}

static cJSON *parse_body(wf_response *response) {
    CHECK(response->status == 200);
    cJSON *json = cJSON_ParseWithLength(response->body ? response->body : "",
                                        response->body_len);
    CHECK(json != NULL);
    return json;
}

int main(void) {
    char directory[] = "/tmp/metalbear-admin-audit-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char registry_path[512];
    char audit_path[512];
    snprintf(registry_path, sizeof(registry_path), "%s/account.sqlite3",
             directory);
    snprintf(audit_path, sizeof(audit_path), "%s/admin_audit.sqlite3",
             directory);

    metalbear_account_registry *registry = NULL;
    CHECK(metalbear_account_registry_open(registry_path, &registry) == WF_OK);
    metalbear_admin_audit *audit = NULL;
    CHECK(metalbear_admin_audit_open(audit_path, &audit) == WF_OK);
    CHECK(metalbear_admin_audit_count(audit) == 0);

    metalbear_server server;
    memset(&server, 0, sizeof(server));
    server.registry = registry;
    server.audit = audit;
    server.admin_password = "secret-admin";
    server.user_domain = ".example.com";
    seam_ctx ctx = {.server = &server};

    char authorization[384];
    basic_header(authorization, sizeof(authorization));
    wf_http_header admin_header = {"Authorization", authorization};

    wf_xrpc_client *client = wf_xrpc_client_new("http://seam.test");
    CHECK(client != NULL);
    wf_xrpc_set_handler(client, seam_handler, &ctx);
    wf_response response = {0};

    /* A refused admin call is audited even though no handler runs. */
    CHECK(wf_http_get_with_headers(
              client, "http://seam.test/xrpc/com.atproto.admin.getInviteCodes",
              NULL, 0, &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);
    CHECK(metalbear_admin_audit_count(audit) == 1);

    /* Three successful calls, each with a target DID. */
    for (int i = 1; i <= 3; i++) {
        char url[384];
        snprintf(url, sizeof(url),
                 "http://seam.test/xrpc/com.atproto.admin.getInviteCodes"
                 "?did=did:plc:target%d",
                 i);
        CHECK(wf_http_get_with_headers(client, url, &admin_header, 1,
                                       &response) == WF_OK);
        CHECK(response.status == 200);
        wf_response_free(&response);
    }
    CHECK(metalbear_admin_audit_count(audit) == 4);

    /* Non-admins cannot read the trail at all. */
    CHECK(wf_http_get_with_headers(client,
                                   "http://seam.test/_ops/audit?limit=1", NULL,
                                   0, &response) == WF_ERR_HTTP);
    CHECK(response.status == 401);
    wf_response_free(&response);

    /* Pagination: newest first, one row per page, opaque numeric cursor. */
    char url[512];
    char cursor[32] = {0};
    const char *expected_target[] = {"did:plc:target3", "did:plc:target2",
                                     "did:plc:target1", NULL};
    for (int page = 0; page < 4; page++) {
        if (page == 0)
            snprintf(url, sizeof(url), "http://seam.test/_ops/audit?limit=1");
        else
            snprintf(url, sizeof(url),
                     "http://seam.test/_ops/audit?limit=1&cursor=%s", cursor);
        CHECK(wf_http_get_with_headers(client, url, &admin_header, 1,
                                       &response) == WF_OK);
        cJSON *json = parse_body(&response);
        cJSON *rows =
            json ? cJSON_GetObjectItemCaseSensitive(json, "audit") : NULL;
        CHECK(cJSON_IsArray(rows) && cJSON_GetArraySize(rows) == 1);
        cJSON *row = cJSON_IsArray(rows) ? cJSON_GetArrayItem(rows, 0) : NULL;
        cJSON *action =
            row ? cJSON_GetObjectItemCaseSensitive(row, "action") : NULL;
        cJSON *outcome =
            row ? cJSON_GetObjectItemCaseSensitive(row, "outcome") : NULL;
        cJSON *target =
            row ? cJSON_GetObjectItemCaseSensitive(row, "targetDid") : NULL;
        CHECK(cJSON_IsString(action) &&
              strcmp(action->valuestring, "com.atproto.admin.getInviteCodes") ==
                  0);
        if (expected_target[page]) {
            CHECK(cJSON_IsString(outcome) &&
                  strcmp(outcome->valuestring, "ok") == 0);
            CHECK(cJSON_IsString(target) &&
                  strcmp(target->valuestring, expected_target[page]) == 0);
        } else {
            CHECK(cJSON_IsString(outcome) &&
                  strcmp(outcome->valuestring, "denied") == 0);
        }
        const cJSON *next =
            json ? cJSON_GetObjectItemCaseSensitive(json, "cursor") : NULL;
        if (page < 3) {
            CHECK(cJSON_IsString(next));
            if (cJSON_IsString(next))
                snprintf(cursor, sizeof(cursor), "%s", next->valuestring);
        } else {
            CHECK(!cJSON_IsString(next));
        }
        cJSON_Delete(json);
        wf_response_free(&response);
    }

    /* Malformed cursors are refused rather than silently ignored. */
    CHECK(wf_http_get_with_headers(
              client, "http://seam.test/_ops/audit?cursor=not-a-number",
              &admin_header, 1, &response) == WF_ERR_HTTP);
    CHECK(response.status == 400);
    wf_response_free(&response);

    wf_xrpc_set_handler(client, NULL, NULL);
    wf_xrpc_client_free(client);
    metalbear_admin_audit_free(audit);
    metalbear_account_registry_free(registry);
    unlink(audit_path);
    unlink(registry_path);
    rmdir(directory);

    if (failures) {
        fprintf(stderr, "test_admin_audit: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_admin_audit: all checks passed\n");
    return 0;
}
