/*
 * test_account_quotas.c -- offline coverage for issue #152.
 *
 * Repo writes are driven through wf_xrpc_set_handler so the client builds a
 * real applyWrites request and MetalBear's own route handler answers it. The
 * account store is the single source of truth for both stores' usage; blob
 * puts go through the same central store the upload route uses.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "../src/server_internal.h"

#include "metalbear/account/account.h"
#include "metalbear/repo/blob_store.h"
#include "wolfram/xrpc.h"

#include "test.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DID "did:plc:quotatest"
#define COLLECTION "com.example.note"

static int event_count;

static void temp_path(char *buf, size_t n, const char *tag) {
    snprintf(buf, n, "/tmp/metalbear_quota_%s_XXXXXX", tag);
    int fd = mkstemp(buf);
    if (fd >= 0) close(fd);
    unlink(buf);
}

static void count_events(const metalbear_repo_store_event *event, void *ctx) {
    (void)event;
    (void)ctx;
    event_count++;
}

static wf_status seam_handler(void *userdata, const char *method,
                              const char *url, const char *content_type,
                              const char *body, size_t body_len,
                              const wf_http_header *headers,
                              size_t header_count, wf_response *out) {
    (void)method;
    (void)content_type;
    (void)headers;
    (void)header_count;
    metalbear_repo_store *store = userdata;
    const char *start = strstr(url, "/xrpc/");
    if (!start) return WF_ERR_INVALID_ARG;
    start += strlen("/xrpc/");
    const char *end = strchr(start, '?');
    if (!end) end = start + strlen(start);
    char nsid[256];
    size_t nsid_len = (size_t)(end - start);
    if (!nsid_len || nsid_len >= sizeof(nsid)) return WF_ERR_INVALID_ARG;
    memcpy(nsid, start, nsid_len);
    nsid[nsid_len] = '\0';

    cJSON *params = cJSON_ParseWithLength(body ? body : "", body_len);
    if (!params) return WF_ERR_INVALID_ARG;
    wf_xrpc_request req;
    memset(&req, 0, sizeof(req));
    req.nsid = nsid;
    req.path = url;
    req.method = "POST";
    req.params = params;
    req.body = (const unsigned char *)body;
    req.body_len = body_len;

    wf_xrpc_response resp = WF_XRPC_RESPONSE_INIT;
    wf_status status = metalbear_repo_routes_dispatch(
        store, DID, "https://quota.example.com", nsid, &req, &resp);
    cJSON_Delete(params);
    if (status != WF_OK) return status;
    out->status = resp.http_status;
    if (resp.body && resp.body_len) {
        out->body = malloc(resp.body_len + 1);
        if (!out->body) return WF_ERR_ALLOC;
        memcpy(out->body, resp.body, resp.body_len);
        out->body[resp.body_len] = '\0';
        out->body_len = resp.body_len;
    }
    free(resp.body);
    free(resp.content_type);
    return WF_OK;
}

/* One create write with a payload of `text_len` filler bytes. */
static wf_status apply_create(wf_xrpc_client *client, size_t text_len,
                              wf_response *out) {
    char *text = malloc(text_len + 1);
    if (!text) return WF_ERR_ALLOC;
    memset(text, 'x', text_len);
    text[text_len] = '\0';
    static const char fmt[] =
        "{\"repo\":\"" DID "\",\"writes\":[{\"$type\":"
        "\"com.atproto.repo.applyWrites#create\","
        "\"collection\":\"" COLLECTION "\","
        "\"value\":{\"$type\":\"" COLLECTION "\",\"text\":\"%s\"}}],"
        "\"validate\":false}";
    int needed = snprintf(NULL, 0, fmt, text);
    char *body = needed > 0 ? malloc((size_t)needed + 1) : NULL;
    if (!body || snprintf(body, (size_t)needed + 1, fmt, text) != needed) {
        free(body);
        free(text);
        return WF_ERR_ALLOC;
    }
    free(text);
    wf_status st =
        wf_xrpc_procedure(client, "com.atproto.repo.applyWrites", body, out);
    free(body);
    return st;
}

static void free_response(wf_response *res) {
    free(res->body);
    memset(res, 0, sizeof(*res));
}

static void check_blob_quotas(metalbear_account_store *account) {
    metalbear_blob_store *blobs = metalbear_blob_store_new(NULL);
    WF_CHECK(blobs != NULL);
    if (!blobs) return;
    metalbear_blob_store_set_quota_account(blobs, account);

    unsigned char first[40], second[80];
    memset(first, 1, sizeof(first));
    memset(second, 2, sizeof(second));
    wf_cid cid1, cid2;
    WF_CHECK(wf_cid_of_bytes(first, sizeof(first), &cid1) == WF_OK);
    WF_CHECK(wf_cid_of_bytes(second, sizeof(second), &cid2) == WF_OK);
    char *cid1s = wf_cid_to_string(&cid1);
    char *cid2s = wf_cid_to_string(&cid2);
    WF_CHECK(cid1s && cid2s);
    if (!cid1s || !cid2s) {
        free(cid1s);
        free(cid2s);
        metalbear_blob_store_free(blobs);
        return;
    }

    WF_CHECK(metalbear_account_set_quotas(account, 0, 100) == WF_OK);
    WF_CHECK(metalbear_blob_store_put(blobs, cid1s, "image/png", first,
                                      sizeof(first)) == WF_OK);
    uint64_t repo_used = 0, blob_used = 0;
    WF_CHECK(metalbear_account_get_usage(account, &repo_used, &blob_used) ==
             WF_OK);
    WF_CHECK(blob_used == sizeof(first));

    /* Re-uploading the same CID is deduplicated: no second charge. */
    WF_CHECK(metalbear_blob_store_put(blobs, cid1s, "image/png", first,
                                      sizeof(first)) == WF_OK);
    WF_CHECK(metalbear_account_get_usage(account, &repo_used, &blob_used) ==
             WF_OK);
    WF_CHECK(blob_used == sizeof(first));

    WF_CHECK(metalbear_blob_store_put(blobs, cid2s, "image/png", second,
                                      sizeof(second)) == WF_ERR_RATE_LIMIT);
    WF_CHECK(metalbear_account_get_usage(account, &repo_used, &blob_used) ==
             WF_OK);
    WF_CHECK(blob_used == sizeof(first));

    /* 0 means unlimited, and a delete releases the accounted bytes. */
    WF_CHECK(metalbear_account_set_quotas(account, 0, 0) == WF_OK);
    WF_CHECK(metalbear_blob_store_put(blobs, cid2s, "image/png", second,
                                      sizeof(second)) == WF_OK);
    WF_CHECK(metalbear_account_get_usage(account, &repo_used, &blob_used) ==
             WF_OK);
    WF_CHECK(blob_used == sizeof(first) + sizeof(second));
    WF_CHECK(metalbear_blob_store_delete(blobs, cid1s) == WF_OK);
    WF_CHECK(metalbear_account_get_usage(account, &repo_used, &blob_used) ==
             WF_OK);
    WF_CHECK(blob_used == sizeof(second));

    free(cid1s);
    free(cid2s);
    metalbear_blob_store_free(blobs);
}

static void check_migration(void) {
    char path[256];
    temp_path(path, sizeof(path), "v5");
    sqlite3 *db = NULL;
    WF_CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    if (db) {
        char *err = NULL;
        const char *old_schema =
            "PRAGMA user_version=5;"
            "CREATE TABLE account_state("
            "id INTEGER PRIMARY KEY CHECK(id=0),"
            "active INTEGER NOT NULL CHECK(active IN(0,1)));"
            "INSERT OR IGNORE INTO account_state(id,active) VALUES(0,1);";
        WF_CHECK(sqlite3_exec(db, old_schema, NULL, NULL, &err) == SQLITE_OK);
        if (err) fprintf(stderr, "migration setup: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
    }

    metalbear_account_store *account = NULL;
    WF_CHECK(metalbear_account_store_open(path, "bootstrap-password",
                                          &account) == WF_OK);
    if (account) {
        uint64_t repo_quota = 1, blob_quota = 1, repo_used = 1, blob_used = 1;
        WF_CHECK(metalbear_account_get_quotas(account, &repo_quota,
                                              &blob_quota) == WF_OK);
        WF_CHECK(metalbear_account_get_usage(account, &repo_used, &blob_used) ==
                 WF_OK);
        WF_CHECK(repo_quota == 0 && blob_quota == 0);
        WF_CHECK(repo_used == 0 && blob_used == 0);
        metalbear_account_store_free(account);
    }
    unlink(path);
}

int main(void) {
    char repo_path[256], account_path[256];
    temp_path(repo_path, sizeof(repo_path), "repo");
    temp_path(account_path, sizeof(account_path), "account");

    metalbear_account_store *account = NULL;
    wf_status st =
        metalbear_account_store_open(account_path, "bootstrap", &account);
    WF_CHECK(st == WF_OK && account != NULL);
    if (st != WF_OK || !account) {
        unlink(repo_path);
        unlink(account_path);
        WF_TEST_SUMMARY();
    }

    metalbear_repo_store *repo = NULL;
    st = metalbear_repo_store_open(repo_path, DID, "quota.example.com", &repo);
    WF_CHECK(st == WF_OK && repo != NULL);
    if (st != WF_OK || !repo) {
        metalbear_account_store_free(account);
        unlink(repo_path);
        unlink(account_path);
        WF_TEST_SUMMARY();
    }
    metalbear_repo_store_set_quota_account(repo, account);
    metalbear_repo_store_set_event_callback(repo, count_events, NULL);

    wf_xrpc_client *client = wf_xrpc_client_new("http://quota.test");
    WF_CHECK(client != NULL);
    wf_xrpc_set_handler(client, seam_handler, repo);

    /* Quota 0: unlimited, and the accepted write emits exactly one event. */
    WF_CHECK(metalbear_account_set_quotas(account, 0, 0) == WF_OK);
    wf_response res = {0};
    WF_CHECK(apply_create(client, 16, &res) == WF_OK);
    WF_CHECK(res.status == 200);
    free_response(&res);
    uint64_t repo_used = 0, blob_used = 0;
    WF_CHECK(metalbear_account_get_usage(account, &repo_used, &blob_used) ==
             WF_OK);
    WF_CHECK(repo_used > 0);
    WF_CHECK(event_count == 1);

    /* A configured budget that comfortably fits one write still allows it. */
    WF_CHECK(metalbear_account_set_quotas(account, repo_used + 32768, 0) ==
             WF_OK);
    WF_CHECK(apply_create(client, 2048, &res) == WF_OK);
    WF_CHECK(res.status == 200);
    free_response(&res);
    WF_CHECK(event_count == 2);
    uint64_t after_ok = 0;
    WF_CHECK(metalbear_account_get_usage(account, &after_ok, &blob_used) ==
             WF_OK);
    WF_CHECK(after_ok > repo_used);

    /* The next write cannot fit: refuse it without a commit or a firehose
     * event, and leave the usage counter where it was. */
    char head_before[256] = {0};
    char *cid_before = NULL, *rev_before = NULL;
    WF_CHECK(metalbear_repo_store_get_head(repo, &rev_before, &cid_before) ==
             WF_OK);
    if (cid_before)
        snprintf(head_before, sizeof(head_before), "%s", cid_before);
    free(cid_before);
    free(rev_before);
    WF_CHECK(metalbear_account_set_quotas(account, after_ok + 16, 0) == WF_OK);
    WF_CHECK(apply_create(client, 2048, &res) == WF_OK);
    WF_CHECK(res.status == 400);
    if (res.body) WF_CHECK(strstr(res.body, "account storage quota exceeded"));
    free_response(&res);
    WF_CHECK(event_count == 2);
    uint64_t after_reject = 0;
    WF_CHECK(metalbear_account_get_usage(account, &after_reject, &blob_used) ==
             WF_OK);
    WF_CHECK(after_reject == after_ok);
    char *cid_after = NULL, *rev_after = NULL;
    WF_CHECK(metalbear_repo_store_get_head(repo, &rev_after, &cid_after) ==
             WF_OK);
    if (cid_after && head_before[0])
        WF_CHECK(strcmp(cid_after, head_before) == 0);
    free(cid_after);
    free(rev_after);

    /* Removing the quota makes the very same write succeed. */
    WF_CHECK(metalbear_account_set_quotas(account, 0, 0) == WF_OK);
    WF_CHECK(apply_create(client, 2048, &res) == WF_OK);
    WF_CHECK(res.status == 200);
    free_response(&res);
    WF_CHECK(event_count == 3);

    check_blob_quotas(account);
    check_migration();

    wf_xrpc_set_handler(client, NULL, NULL);
    wf_xrpc_client_free(client);
    metalbear_repo_store_free(repo);
    metalbear_account_store_free(account);
    unlink(repo_path);
    unlink(account_path);
    WF_TEST_SUMMARY();
}
