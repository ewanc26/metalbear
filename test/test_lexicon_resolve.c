/*
 * test_lexicon_resolve.c — offline tests for the
 * com.atproto.lexicon.resolveLexicon route (src/lexicon_routes.c), served
 * from Wolfram's vendored lexicon corpus (METALBEAR_TEST_LEXICON_DIR).
 *
 * Two layers, both offline:
 *   1. Direct handler calls with a fabricated wf_xrpc_request: known NSID
 *      serves the exact vendored document, unknown NSID is a 400
 *      InvalidRequest, a missing nsid parameter is a 400, and a server with
 *      no corpus loaded is a 500.
 *   2. The wf_xrpc_set_handler client seam: wf_xrpc_query_params against a
 *      client whose transport dispatches to the route handler, so the full
 *      URL -> params -> handler -> response path is exercised without a
 *      socket.
 */

#define _POSIX_C_SOURCE 200809L

#include "../src/lexicon_routes.h"
#include "../src/server_internal.h"

#include "wolfram/validate.h"
#include "wolfram/xrpc.h"

#include "test.h"

#include <cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef METALBEAR_TEST_LEXICON_DIR
#define METALBEAR_TEST_LEXICON_DIR "lexicons"
#endif

/* Builds a request carrying one query param, the way the server's dispatch
 * does for GET /xrpc/<nsid>?nsid=<value>. */
static wf_xrpc_request make_request(const char *nsid_param) {
    wf_xrpc_request req;
    memset(&req, 0, sizeof(req));
    req.nsid = "com.atproto.lexicon.resolveLexicon";
    req.method = "GET";
    if (nsid_param) {
        req.params = cJSON_CreateObject();
        cJSON_AddStringToObject(req.params, "nsid", nsid_param);
    }
    return req;
}

static void free_request(wf_xrpc_request *req) {
    cJSON_Delete(req->params);
}

static wf_xrpc_response call(metalbear_server *server, const char *nsid) {
    wf_xrpc_request req = make_request(nsid);
    wf_xrpc_response resp = WF_XRPC_RESPONSE_INIT;
    wf_status st = resolve_lexicon(server, &req, &resp);
    WF_CHECK(st == WF_OK);
    free_request(&req);
    return resp;
}

/* Client-seam handler: parses ?nsid= out of the URL and dispatches to the
 * route handler, translating the wf_xrpc_response into a wf_response. */
static wf_status seam_handler(void *userdata, const char *method,
                              const char *url, const char *content_type,
                              const char *body, size_t body_len,
                              const wf_http_header *headers,
                              size_t header_count, wf_response *out) {
    metalbear_server *server = userdata;
    const char *q = strchr(url, '?');
    const char *nsid_value = NULL;
    char *decoded = NULL;
    wf_xrpc_request req;
    wf_xrpc_response resp = WF_XRPC_RESPONSE_INIT;
    wf_status st;

    (void)method;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)headers;
    (void)header_count;

    if (q && strncmp(q + 1, "nsid=", 5) == 0) {
        const char *amp = strchr(q + 6, '&');
        size_t n = amp ? (size_t)(amp - (q + 6)) : strlen(q + 6);
        decoded = malloc(n + 1);
        if (!decoded) return WF_ERR_ALLOC;
        memcpy(decoded, q + 6, n);
        decoded[n] = '\0';
        nsid_value = decoded;
    }

    req = make_request(nsid_value);
    st = resolve_lexicon(server, &req, &resp);
    free_request(&req);
    free(decoded);
    if (st != WF_OK) return st;

    out->status = resp.http_status;
    if (resp.body && resp.body_len) {
        out->body = malloc(resp.body_len + 1);
        if (!out->body) {
            free(resp.body);
            free(resp.content_type);
            return WF_ERR_ALLOC;
        }
        memcpy(out->body, resp.body, resp.body_len);
        out->body[resp.body_len] = '\0';
        out->body_len = resp.body_len;
    }
    free(resp.body);
    free(resp.content_type);
    return (resp.http_status >= 200 && resp.http_status < 300) ? WF_OK
                                                               : WF_ERR_HTTP;
}

int main(void) {
    wf_lexicon_registry *registry = wf_lexicon_registry_new();
    WF_CHECK(registry != NULL);
    WF_CHECK(wf_lexicon_registry_load_dir(registry,
                                          METALBEAR_TEST_LEXICON_DIR) == WF_OK);

    metalbear_server server;
    memset(&server, 0, sizeof(server));
    server.lexicons = registry;

    /* --- known NSID serves the exact vendored document --- */
    {
        wf_xrpc_response resp = call(&server, "app.bsky.feed.post");
        WF_CHECK(resp.http_status == 200);
        WF_CHECK(resp.content_type &&
                 strcmp(resp.content_type, "application/json") == 0);
        char *expected = NULL;
        size_t expected_len = 0;
        WF_CHECK(wf_lexicon_resolve("app.bsky.feed.post",
                                    METALBEAR_TEST_LEXICON_DIR, &expected,
                                    &expected_len) == WF_OK);
        WF_CHECK(resp.body_len == expected_len);
        WF_CHECK(resp.body && memcmp(resp.body, expected, expected_len) == 0);
        cJSON *doc = cJSON_ParseWithLength(resp.body, resp.body_len);
        WF_CHECK(doc && cJSON_IsObject(doc));
        cJSON *id = cJSON_GetObjectItemCaseSensitive(doc, "id");
        WF_CHECK(cJSON_IsString(id) &&
                 strcmp(id->valuestring, "app.bsky.feed.post") == 0);
        cJSON_Delete(doc);
        free(expected);
        free(resp.body);
        free(resp.content_type);
    }

    /* --- unknown NSID is a 400 InvalidRequest --- */
    {
        wf_xrpc_response resp = call(&server, "com.example.does-not-exist");
        WF_CHECK(resp.http_status == 400);
        cJSON *err =
            resp.body ? cJSON_ParseWithLength(resp.body, resp.body_len) : NULL;
        WF_CHECK(err && cJSON_IsString(
                            cJSON_GetObjectItemCaseSensitive(err, "error")));
        WF_CHECK(
            strcmp(cJSON_GetObjectItemCaseSensitive(err, "error")->valuestring,
                   "InvalidRequest") == 0);
        cJSON_Delete(err);
        free(resp.body);
        free(resp.content_type);
    }

    /* --- missing nsid parameter is a 400 --- */
    {
        wf_xrpc_response resp = call(&server, NULL);
        WF_CHECK(resp.http_status == 400);
        free(resp.body);
        free(resp.content_type);
    }

    /* --- no corpus loaded is a 500, not a silent 400 --- */
    {
        metalbear_server bare;
        memset(&bare, 0, sizeof(bare));
        wf_xrpc_response resp = call(&bare, "app.bsky.feed.post");
        WF_CHECK(resp.http_status == 500);
        free(resp.body);
        free(resp.content_type);
    }

    /* --- full client path through the wf_xrpc_set_handler seam --- */
    {
        wf_xrpc_client *client = wf_xrpc_client_new("http://lexicon.test");
        WF_CHECK(client != NULL);
        wf_xrpc_set_handler(client, seam_handler, &server);

        wf_xrpc_param params[] = {{"nsid", "com.atproto.lexicon.schema"}};
        wf_response resp;
        WF_CHECK(wf_xrpc_query_params(client,
                                      "com.atproto.lexicon.resolveLexicon",
                                      params, 1, &resp) == WF_OK);
        WF_CHECK(resp.status == 200);
        cJSON *doc = cJSON_ParseWithLength(resp.body, resp.body_len);
        WF_CHECK(doc &&
                 cJSON_IsString(cJSON_GetObjectItemCaseSensitive(doc, "id")));
        WF_CHECK(
            strcmp(cJSON_GetObjectItemCaseSensitive(doc, "id")->valuestring,
                   "com.atproto.lexicon.schema") == 0);
        cJSON_Delete(doc);
        wf_response_free(&resp);

        wf_xrpc_param bad[] = {{"nsid", "com.example.nope"}};
        WF_CHECK(wf_xrpc_query_params(client,
                                      "com.atproto.lexicon.resolveLexicon", bad,
                                      1, &resp) == WF_ERR_HTTP);
        WF_CHECK(resp.status == 400);
        wf_response_free(&resp);

        wf_xrpc_set_handler(client, NULL, NULL);
        wf_xrpc_client_free(client);
    }

    wf_lexicon_registry_free(registry);
    WF_TEST_SUMMARY();
}
