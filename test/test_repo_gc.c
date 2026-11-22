/*
 * test_repo_gc.c — offline tests for repo-store garbage collection.
 *
 * Covers metalbear_repo_store_gc: blocks unreachable from the current head
 * are removed from both the durable block table and the in-memory CAR,
 * reachable blocks (including the head commit) survive, exports still
 * round-trip, the pass is idempotent, the store reopens cleanly, and a
 * com.atproto.sync.getRepo call through the wf_xrpc_set_handler seam still
 * returns a CAR that replays after GC.
 *
 * Requires WOLFRAM_BUILD_SERVER.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "../src/server_internal.h"

#include "metalbear/repo/repo_store.h"
#include "repo_store_internal.h"

#include "wolfram/repo/car.h"
#include "wolfram/repo/cid.h"
#include "wolfram/xrpc.h"

#include "test.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void temp_path(char *buf, size_t n, const char *tag) {
    snprintf(buf, n, "/tmp/metalbear_repo_gc_%s_XXXXXX", tag);
    int fd = mkstemp(buf);
    if (fd >= 0) close(fd);
    unlink(buf);
}

static wf_status stats_of(metalbear_repo_store *store, size_t *out) {
    metalbear_repo_store_stats st;
    memset(&st, 0, sizeof(st));
    wf_status s = metalbear_repo_store_get_stats(store, &st);
    *out = st.repo_blocks;
    return s;
}

/* Fill a store with `count` records, returning the rkeys in out_rkeys (which
 * must have room for `count` pointers; caller frees each). */
static wf_status seed(metalbear_repo_store *store, int count, char **out_rkeys,
                      char **out_cids) {
    for (int i = 0; i < count; i++) {
        char rkey[64];
        snprintf(rkey, sizeof(rkey), "rkey%02d", i);
        char json[160];
        snprintf(json, sizeof(json),
                 "{\"$type\":\"app.bsky.feed.post\",\"text\":\"post %d\","
                 "\"createdAt\":\"2026-11-22T00:00:00Z\"}",
                 i);
        char *uri = NULL;
        wf_status s = metalbear_repo_store_create_record(
            store, "app.bsky.feed.post", rkey, json, NULL, &uri, &out_cids[i]);
        free(uri);
        if (s != WF_OK) return s;
        out_rkeys[i] = strdup(rkey);
        if (!out_rkeys[i]) return WF_ERR_ALLOC;
    }
    return WF_OK;
}

static void free_seed(int count, char **rkeys, char **cids) {
    for (int i = 0; i < count; i++) {
        free(rkeys[i]);
        free(cids[i]);
    }
}

static int run_gc_basic(void) {
    int failures = 0;
    char path[256];
    temp_path(path, sizeof(path), "basic");

    metalbear_repo_store *store = NULL;
    wf_status s = metalbear_repo_store_open(path, "did:plc:repogc",
                                            "gc.example.com", &store);
    WF_CHECK(s == WF_OK && store != NULL);
    if (s != WF_OK || !store) {
        unlink(path);
        return failures + 1;
    }

    /* GC on an empty repo is a no-op, not an error. */
    size_t removed = 999;
    WF_CHECK(metalbear_repo_store_gc(store, &removed) == WF_OK);
    WF_CHECK(removed == 0);

    enum { N = 6 };
    char *rkeys[N] = {0}, *cids[N] = {0};
    s = seed(store, N, rkeys, cids);
    WF_CHECK(s == WF_OK);

    size_t before = 0;
    WF_CHECK(stats_of(store, &before) == WF_OK);
    WF_CHECK(before > (size_t)N);

    /* Delete half the records: their value blocks and the old MST nodes
     * become unreachable from the new head, but are still stored. */
    const int deleted[] = {0, 2, 4};
    for (size_t i = 0; i < sizeof(deleted) / sizeof(deleted[0]); i++) {
        WF_CHECK(metalbear_repo_store_delete_record(store, "app.bsky.feed.post",
                                                    rkeys[deleted[i]], NULL,
                                                    NULL) == WF_OK);
    }
    size_t after_deletes = 0;
    WF_CHECK(stats_of(store, &after_deletes) == WF_OK);
    WF_CHECK(after_deletes >= before); /* new commits added blocks */

    /* Collect. */
    removed = 0;
    WF_CHECK(metalbear_repo_store_gc(store, &removed) == WF_OK);
    WF_CHECK(removed > 0);

    size_t after_gc = 0;
    WF_CHECK(stats_of(store, &after_gc) == WF_OK);
    WF_CHECK(after_gc == after_deletes - removed);
    WF_CHECK(after_gc < after_deletes);

    /* Surviving records still read back. */
    char *json = NULL, *cid = NULL;
    WF_CHECK(metalbear_repo_store_get_record(store, "app.bsky.feed.post",
                                             rkeys[1], &json, &cid) == WF_OK);
    free(json);
    free(cid);
    json = cid = NULL;
    WF_CHECK(metalbear_repo_store_get_record(store, "app.bsky.feed.post",
                                             rkeys[5], &json, &cid) == WF_OK);
    free(json);
    free(cid);
    json = cid = NULL;

    /* Deleted records stay gone. */
    WF_CHECK(metalbear_repo_store_get_record(store, "app.bsky.feed.post",
                                             rkeys[0], &json,
                                             &cid) == WF_ERR_NOT_FOUND);

    /* Their old value blocks are no longer retrievable through getBlocks. */
    unsigned char *car = NULL;
    size_t car_len = 0;
    const char *gone[] = {cids[0], cids[2], cids[4]};
    for (size_t i = 0; i < 3; i++) {
        WF_CHECK(metalbear_repo_store_get_blocks(store, &gone[i], 1, &car,
                                                 &car_len) == WF_ERR_NOT_FOUND);
        free(car);
        car = NULL;
    }

    /* The head still verifies and a full CAR export round-trips. */
    int verified = 0;
    WF_CHECK(metalbear_repo_store_verify_head(store, &verified, NULL) == WF_OK);
    WF_CHECK(verified == 1);
    WF_CHECK(metalbear_repo_store_export(store, NULL, &car, &car_len) == WF_OK);
    wf_car parsed = {0};
    WF_CHECK(wf_car_parse(car, car_len, &parsed) == WF_OK);
    WF_CHECK(parsed.root_count == 1 && parsed.block_count == after_gc);
    wf_car_free(&parsed);
    free(car);
    car = NULL;

    /* A second pass has nothing left to remove. */
    removed = 999;
    WF_CHECK(metalbear_repo_store_gc(store, &removed) == WF_OK);
    WF_CHECK(removed == 0);

    /* Surviving writes still advance the head after a GC. */
    char *post_uri = NULL, *post_cid = NULL;
    WF_CHECK(metalbear_repo_store_create_record(
                 store, "app.bsky.feed.post", "after-gc",
                 "{\"$type\":\"app.bsky.feed.post\",\"text\":\"after\","
                 "\"createdAt\":\"2026-11-22T00:00:01Z\"}",
                 NULL, &post_uri, &post_cid) == WF_OK);
    free(post_uri);
    free(post_cid);
    verified = 0;
    WF_CHECK(metalbear_repo_store_verify_head(store, &verified, NULL) == WF_OK);
    WF_CHECK(verified == 1);

    metalbear_repo_store_free(store);

    /* Durability: reopen and check the compacted block count and reads. */
    store = NULL;
    WF_CHECK(metalbear_repo_store_open(path, "did:plc:repogc", "gc.example.com",
                                       &store) == WF_OK);
    if (store) {
        size_t reopened = 0;
        WF_CHECK(stats_of(store, &reopened) == WF_OK);
        /* A write adds the record, new MST nodes and a new commit block. */
        WF_CHECK(reopened > after_gc);
        WF_CHECK(metalbear_repo_store_get_record(store, "app.bsky.feed.post",
                                                 rkeys[1], &json,
                                                 &cid) == WF_OK);
        free(json);
        free(cid);
        metalbear_repo_store_free(store);
    }

    free_seed(N, rkeys, cids);
    unlink(path);
    return failures;
}

/* GC must refuse to touch a repo whose in-memory CAR cannot be traversed,
 * rather than deleting blocks it cannot prove are unreachable. */
static int run_gc_unsafe(void) {
    int failures = 0;
    char path[256];
    temp_path(path, sizeof(path), "unsafe");

    metalbear_repo_store *store = NULL;
    WF_CHECK(metalbear_repo_store_open(path, "did:plc:repogcunsafe",
                                       "unsafe.example.com", &store) == WF_OK);
    if (!store) {
        unlink(path);
        return failures + 1;
    }
    char *uri = NULL, *cid = NULL;
    WF_CHECK(metalbear_repo_store_create_record(
                 store, "app.bsky.feed.post", "only",
                 "{\"$type\":\"app.bsky.feed.post\",\"text\":\"x\","
                 "\"createdAt\":\"2026-11-22T00:00:00Z\"}",
                 NULL, &uri, &cid) == WF_OK);
    free(uri);
    free(cid);

    size_t before = 0, removed = 999;
    WF_CHECK(stats_of(store, &before) == WF_OK);

    /* Point the in-memory head at a CID that is not in the CAR. GC must
     * refuse rather than delete blocks it cannot prove are unreachable. */
    wf_cid saved = store->head;
    memset(&store->head, 0, sizeof(store->head));
    store->head.len = sizeof(store->head.bytes);
    memset(store->head.bytes, 0xAB, sizeof(store->head.bytes));
    WF_CHECK(metalbear_repo_store_gc(store, &removed) == WF_ERR_NOT_FOUND);
    WF_CHECK(removed == 0);
    store->head = saved;

    size_t after = 0;
    WF_CHECK(stats_of(store, &after) == WF_OK);
    WF_CHECK(after == before);

    metalbear_repo_store_free(store);
    unlink(path);
    return failures;
}

/* The public getRepo route (src/sync/sync_routes.c) answers with the CAR from
 * metalbear_repo_store_export. Drive that same call through the
 * wf_xrpc_set_handler seam so the client builds a real getRepo request and the
 * returned CAR is parsed back: after GC it must still contain the live head and
 * reachable blocks, and must not contain the blocks we deleted. */
typedef struct {
    metalbear_repo_store *store;
} gc_seam_ctx;

static wf_status gc_seam_handler(void *userdata, const char *method,
                                 const char *url, const char *content_type,
                                 const char *body, size_t body_len,
                                 const wf_http_header *headers,
                                 size_t header_count, wf_response *out) {
    (void)method;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)headers;
    (void)header_count;
    gc_seam_ctx *ctx = userdata;
    const char *start = strstr(url, "/xrpc/");
    if (!start) return WF_ERR_INVALID_ARG;
    start += strlen("/xrpc/");
    const char *end = strchr(start, '?');
    if (!end) end = start + strlen(start);
    size_t nsid_len = (size_t)(end - start);
    const char *getrepo = "com.atproto.sync.getRepo";
    if (nsid_len != strlen(getrepo) || strncmp(start, getrepo, nsid_len) != 0)
        return WF_ERR_INVALID_ARG;

    unsigned char *car = NULL;
    size_t car_len = 0;
    wf_status st =
        metalbear_repo_store_export(ctx->store, NULL, &car, &car_len);
    if (st != WF_OK) return st;
    out->status = 200;
    out->body = (char *)car;
    out->body_len = car_len;
    return WF_OK;
}

static int run_gc_getrepo_seam(void) {
    char path[256];
    temp_path(path, sizeof(path), "seam");

    metalbear_repo_store *store = NULL;
    WF_CHECK(metalbear_repo_store_open(path, "did:plc:repogcseam",
                                       "seam.example.com", &store) == WF_OK);
    if (!store) {
        unlink(path);
        return 1;
    }

    enum { N = 4 };
    char *rkeys[N] = {0}, *cids[N] = {0};
    WF_CHECK(seed(store, N, rkeys, cids) == WF_OK);
    WF_CHECK(metalbear_repo_store_delete_record(store, "app.bsky.feed.post",
                                                rkeys[1], NULL, NULL) == WF_OK);
    WF_CHECK(metalbear_repo_store_delete_record(store, "app.bsky.feed.post",
                                                rkeys[3], NULL, NULL) == WF_OK);

    size_t removed = 0;
    WF_CHECK(metalbear_repo_store_gc(store, &removed) == WF_OK);
    WF_CHECK(removed > 0);

    wf_xrpc_client *client = wf_xrpc_client_new("http://repo.test");
    WF_CHECK(client != NULL);
    if (!client) {
        metalbear_repo_store_free(store);
        unlink(path);
        free_seed(N, rkeys, cids);
        return 1;
    }
    gc_seam_ctx ctx = {store};
    wf_xrpc_set_handler(client, gc_seam_handler, &ctx);

    wf_response res = {0};
    WF_CHECK(
        wf_xrpc_query_params(client, "com.atproto.sync.getRepo",
                             (wf_xrpc_param[]){{"did", "did:plc:repogcseam"}},
                             1, &res) == WF_OK);
    WF_CHECK(res.status == 200);
    WF_CHECK(res.body && res.body_len > 0);

    wf_car parsed = {0};
    WF_CHECK(wf_car_parse((const unsigned char *)res.body, res.body_len,
                          &parsed) == WF_OK);
    WF_CHECK(parsed.root_count == 1);
    size_t after_gc = 0;
    WF_CHECK(stats_of(store, &after_gc) == WF_OK);
    WF_CHECK(parsed.block_count == after_gc);

    /* The deleted records' value CIDs are absent; the surviving ones remain. */
    wf_cid gone = {0};
    WF_CHECK(wf_cid_from_string(cids[1], &gone) == WF_OK);
    WF_CHECK(wf_car_find_block(&parsed, &gone) == NULL);
    WF_CHECK(wf_cid_from_string(cids[3], &gone) == WF_OK);
    WF_CHECK(wf_car_find_block(&parsed, &gone) == NULL);
    wf_cid kept = {0};
    WF_CHECK(wf_cid_from_string(cids[0], &kept) == WF_OK);
    WF_CHECK(wf_car_find_block(&parsed, &kept) != NULL);
    WF_CHECK(wf_cid_from_string(cids[2], &kept) == WF_OK);
    WF_CHECK(wf_car_find_block(&parsed, &kept) != NULL);

    wf_car_free(&parsed);
    wf_response_free(&res);
    wf_xrpc_set_handler(client, NULL, NULL);
    wf_xrpc_client_free(client);
    metalbear_repo_store_free(store);
    unlink(path);
    free_seed(N, rkeys, cids);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += run_gc_basic();
    failures += run_gc_unsafe();
    failures += run_gc_getrepo_seam();
    WF_TEST_SUMMARY();
}
