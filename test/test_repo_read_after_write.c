/*
 * test_repo_read_after_write.c -- offline coverage for issue #158.
 *
 * A write must be visible to every read route immediately after it returns.
 * The routes are driven through wf_xrpc_set_handler so the client builds the
 * real XRPC URL/body, the seam turns that back into a wf_xrpc_request, and
 * MetalBear's own repo route handlers answer it against one live store.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "../src/server_internal.h"

#include "metalbear/repo/repo_store.h"
#include "wolfram/xrpc.h"

#include "test.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void temp_path(char *buf, size_t n, const char *tag) {
    snprintf(buf, n, "/tmp/metalbear_repo_raw_%s_XXXXXX", tag);
    int fd = mkstemp(buf);
    if (fd >= 0) close(fd);
    unlink(buf);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* The Wolfram client escapes query values with curl_easy_escape; decode the
 * ones the seam sees back into the cJSON object a server dispatcher builds. */
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

typedef struct {
    metalbear_repo_store *store;
    const char *did;
    const char *public_url;
} seam_ctx;

static wf_status seam_handler(void *userdata, const char *method,
                              const char *url, const char *content_type,
                              const char *body, size_t body_len,
                              const wf_http_header *headers,
                              size_t header_count, wf_response *out) {
    (void)headers;
    (void)header_count;
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
    if (!params) return WF_ERR_INVALID_ARG;

    wf_xrpc_request req;
    memset(&req, 0, sizeof(req));
    req.nsid = nsid;
    req.path = url;
    req.method = method;
    req.params = params;
    req.content_type = content_type;
    req.body = (const unsigned char *)body;
    req.body_len = body_len;

    wf_xrpc_response response = WF_XRPC_RESPONSE_INIT;
    wf_status status = metalbear_repo_routes_dispatch(
        ctx->store, ctx->did, ctx->public_url, nsid, &req, &response);
    cJSON_Delete(params);
    if (status != WF_OK) return status;

    out->status = response.http_status;
    if (response.body && response.body_len) {
        out->body = malloc(response.body_len + 1);
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

static cJSON *parse_ok(wf_response *res) {
    WF_CHECK(res->status == 200);
    cJSON *json =
        cJSON_ParseWithLength(res->body ? res->body : "", res->body_len);
    WF_CHECK(json != NULL);
    return json;
}

static void query(wf_xrpc_client *client, const char *nsid,
                  const wf_xrpc_param *params, size_t count, wf_response *out) {
    WF_CHECK(wf_xrpc_query_params(client, nsid, params, count, out) == WF_OK);
}

/* Every read route must show exactly the just-written state. Called twice in
 * a row by the caller so repeated reads are pinned as stable too. */
static void check_reads(wf_xrpc_client *client, const char *collection,
                        const char *rkey, const char *text, const char *uri,
                        const char *record_cid, const char *commit_cid,
                        const char *commit_rev, int expected_count) {
    wf_response res;

    query(client, "com.atproto.repo.getRecord",
          (wf_xrpc_param[]){{"collection", collection}, {"rkey", rkey}}, 2,
          &res);
    cJSON *got = parse_ok(&res);
    cJSON *juri = cJSON_GetObjectItemCaseSensitive(got, "uri");
    cJSON *jcid = cJSON_GetObjectItemCaseSensitive(got, "cid");
    cJSON *value = cJSON_GetObjectItemCaseSensitive(got, "value");
    cJSON *jtext =
        value ? cJSON_GetObjectItemCaseSensitive(value, "text") : NULL;
    WF_CHECK(cJSON_IsString(juri) && strcmp(juri->valuestring, uri) == 0);
    WF_CHECK(cJSON_IsString(jcid) &&
             strcmp(jcid->valuestring, record_cid) == 0);
    WF_CHECK(cJSON_IsString(jtext) && strcmp(jtext->valuestring, text) == 0);
    cJSON_Delete(got);
    wf_response_free(&res);

    query(client, "com.atproto.repo.listRecords",
          (wf_xrpc_param[]){{"collection", collection}}, 1, &res);
    cJSON *list = parse_ok(&res);
    cJSON *records = cJSON_GetObjectItemCaseSensitive(list, "records");
    WF_CHECK(cJSON_IsArray(records) &&
             cJSON_GetArraySize(records) == expected_count);
    int found = 0;
    for (int i = 0; records && i < cJSON_GetArraySize(records); i++) {
        cJSON *entry = cJSON_GetArrayItem(records, i);
        cJSON *euri =
            entry ? cJSON_GetObjectItemCaseSensitive(entry, "uri") : NULL;
        if (cJSON_IsString(euri) && strcmp(euri->valuestring, uri) == 0)
            found = 1;
    }
    WF_CHECK(found);
    cJSON_Delete(list);
    wf_response_free(&res);

    query(client, "com.atproto.repo.describeRepo", NULL, 0, &res);
    cJSON *desc = parse_ok(&res);
    cJSON *rev = cJSON_GetObjectItemCaseSensitive(desc, "rev");
    cJSON *cols = cJSON_GetObjectItemCaseSensitive(desc, "collections");
    WF_CHECK(cJSON_IsString(rev) && strcmp(rev->valuestring, commit_rev) == 0);
    WF_CHECK(cJSON_IsArray(cols));
    int has_collection = 0;
    for (int i = 0; cols && i < cJSON_GetArraySize(cols); i++) {
        cJSON *e = cJSON_GetArrayItem(cols, i);
        if (cJSON_IsString(e) && strcmp(e->valuestring, collection) == 0)
            has_collection = 1;
    }
    WF_CHECK(has_collection);
    cJSON_Delete(desc);
    wf_response_free(&res);

    query(client, "com.atproto.sync.getLatestCommit", NULL, 0, &res);
    cJSON *head = parse_ok(&res);
    cJSON *hcid = cJSON_GetObjectItemCaseSensitive(head, "cid");
    cJSON *hrev = cJSON_GetObjectItemCaseSensitive(head, "rev");
    WF_CHECK(cJSON_IsString(hcid) &&
             strcmp(hcid->valuestring, commit_cid) == 0);
    WF_CHECK(cJSON_IsString(hrev) &&
             strcmp(hrev->valuestring, commit_rev) == 0);
    cJSON_Delete(head);
    wf_response_free(&res);
}

int main(void) {
    char path[256];
    temp_path(path, sizeof(path), "raw");

    metalbear_repo_store *store = NULL;
    wf_status s = metalbear_repo_store_open(path, "did:plc:rawtest",
                                            "raw.example.com", &store);
    WF_CHECK(s == WF_OK && store != NULL);
    if (s != WF_OK || !store) {
        unlink(path);
        WF_TEST_SUMMARY();
    }

    wf_xrpc_client *client = wf_xrpc_client_new("http://repo.test");
    WF_CHECK(client != NULL);
    seam_ctx ctx = {store, "did:plc:rawtest", "https://raw.example.com"};
    wf_xrpc_set_handler(client, seam_handler, &ctx);

    const char *collection = "com.example.post";
    char previous_cid[256] = {0};
    char previous_rev[128] = {0};
    for (int i = 0; i < 3; i++) {
        char text[64];
        snprintf(text, sizeof(text), "post-%d", i);
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"collection\":\"%s\","
                 "\"record\":{\"$type\":\"%s\",\"text\":\"%s\"},"
                 "\"validate\":false}",
                 collection, collection, text);

        wf_response res;
        WF_CHECK(wf_xrpc_procedure(client, "com.atproto.repo.createRecord",
                                   body, &res) == WF_OK);
        cJSON *created = parse_ok(&res);
        cJSON *juri = cJSON_GetObjectItemCaseSensitive(created, "uri");
        cJSON *jcid = cJSON_GetObjectItemCaseSensitive(created, "cid");
        cJSON *commit = cJSON_GetObjectItemCaseSensitive(created, "commit");
        cJSON *ccid =
            commit ? cJSON_GetObjectItemCaseSensitive(commit, "cid") : NULL;
        cJSON *crev =
            commit ? cJSON_GetObjectItemCaseSensitive(commit, "rev") : NULL;
        WF_CHECK(cJSON_IsString(juri) && cJSON_IsString(jcid) &&
                 cJSON_IsString(ccid) && cJSON_IsString(crev));
        if (!(cJSON_IsString(juri) && cJSON_IsString(jcid) &&
              cJSON_IsString(ccid) && cJSON_IsString(crev))) {
            cJSON_Delete(created);
            wf_response_free(&res);
            break;
        }
        char uri[512], record_cid[256], commit_cid[256], commit_rev[128];
        snprintf(uri, sizeof(uri), "%s", juri->valuestring);
        snprintf(record_cid, sizeof(record_cid), "%s", jcid->valuestring);
        snprintf(commit_cid, sizeof(commit_cid), "%s", ccid->valuestring);
        snprintf(commit_rev, sizeof(commit_rev), "%s", crev->valuestring);
        cJSON_Delete(created);
        wf_response_free(&res);

        const char *rkey = strrchr(uri, '/');
        WF_CHECK(rkey != NULL);
        if (!rkey) break;
        rkey++;

        if (i > 0) {
            WF_CHECK(strcmp(commit_cid, previous_cid) != 0);
            WF_CHECK(strcmp(commit_rev, previous_rev) != 0);
        }

        for (int pass = 0; pass < 2; pass++) {
            check_reads(client, collection, rkey, text, uri, record_cid,
                        commit_cid, commit_rev, i + 1);
        }

        snprintf(previous_cid, sizeof(previous_cid), "%s", commit_cid);
        snprintf(previous_rev, sizeof(previous_rev), "%s", commit_rev);
    }

    wf_xrpc_set_handler(client, NULL, NULL);
    wf_xrpc_client_free(client);
    metalbear_repo_store_free(store);
    unlink(path);
    WF_TEST_SUMMARY();
}
