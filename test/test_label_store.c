/*
 * The label store's insert and query, against a real database file: exact and
 * prefix URI patterns, the source filter, pagination, negation, and a pattern
 * that carries SQL and must match nothing.
 */
#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "metalbear/label/label_store.h"

static int failures = 0;

#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static const char *const SRC_A = "did:plc:labelerone";
static const char *const SRC_B = "did:plc:labelertwo";
static const char *const POST_X1 = "at://did:plc:xaccount/app.bsky.feed.post/1";
static const char *const POST_X3 = "at://did:plc:xaccount/app.bsky.feed.post/3";
static const char *const POST_Y2 = "at://did:plc:yaccount/app.bsky.feed.post/2";

/* Run a query and return the parsed body. The caller deletes it. */
static cJSON *run_query(metalbear_label_store *store,
                        const metalbear_label_query *q) {
    char *js = NULL;
    if (metalbear_label_store_query(store, q, &js) != WF_OK || !js) {
        CHECK(0);
        return NULL;
    }
    cJSON *root = cJSON_Parse(js);
    free(js);
    CHECK(root != NULL);
    return root;
}

static size_t label_count(const cJSON *root) {
    const cJSON *labels = cJSON_GetObjectItemCaseSensitive(root, "labels");
    return cJSON_IsArray(labels) ? (size_t)cJSON_GetArraySize(labels) : 0;
}

static int has_cursor(const cJSON *root) {
    return cJSON_GetObjectItemCaseSensitive(root, "cursor") != NULL;
}

int main(void) {
    char dir[] = "/tmp/metalbear-label-store-XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp\n");
        return 1;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/labels.sqlite3", dir);

    metalbear_label_store *store = NULL;
    CHECK(metalbear_label_store_open(path, &store) == WF_OK && store != NULL);
    if (!store) {
        rmdir(dir);
        return 1;
    }

    /* Four labels: a takedown, a plain label, a label from another labeler,
     * and the takedown's negation. */
    CHECK(metalbear_label_store_insert(store, SRC_A, POST_X1, "!takedown",
                                       false,
                                       "2026-10-01T00:00:00.000Z") == WF_OK);
    CHECK(metalbear_label_store_insert(store, SRC_A, POST_Y2, "spam", false,
                                       "2026-10-01T00:01:00.000Z") == WF_OK);
    CHECK(metalbear_label_store_insert(store, SRC_B, POST_X3, "adult", false,
                                       "2026-10-01T00:02:00.000Z") == WF_OK);
    CHECK(metalbear_label_store_insert(store, SRC_A, POST_X1, "!takedown", true,
                                       "2026-10-01T00:03:00.000Z") == WF_OK);

    /* Invalid inputs are refused before anything is written. */
    CHECK(metalbear_label_store_insert(store, NULL, POST_X1, "x", false,
                                       NULL) == WF_ERR_INVALID_ARG);
    CHECK(metalbear_label_store_insert(store, SRC_A, "", "x", false, NULL) ==
          WF_ERR_INVALID_ARG);

    /* Exact URI: the takedown and its negation, in insert order, with neg only
     * on the negation. */
    {
        const char *pat[] = {POST_X1};
        metalbear_label_query q = {
            .uri_patterns = pat, .uri_pattern_count = 1, .limit = 50};
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 2);
        const cJSON *labels = cJSON_GetObjectItemCaseSensitive(root, "labels");
        const cJSON *first = cJSON_GetArrayItem(labels, 0);
        const cJSON *second = cJSON_GetArrayItem(labels, 1);
        CHECK(cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(first, "ver")));
        CHECK(cJSON_GetObjectItemCaseSensitive(first, "neg") == NULL);
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(second, "neg")));
        CHECK(
            strcmp(cJSON_GetObjectItemCaseSensitive(first, "val")->valuestring,
                   "!takedown") == 0);
        CHECK(!has_cursor(root));
        cJSON_Delete(root);
    }

    /* Prefix: everything under one account, including the negation. */
    {
        const char *pat[] = {"at://did:plc:xaccount/*"};
        metalbear_label_query q = {
            .uri_patterns = pat, .uri_pattern_count = 1, .limit = 50};
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 3);
        cJSON_Delete(root);
    }

    /* A bare '*' matches every URI. */
    {
        const char *pat[] = {"*"};
        metalbear_label_query q = {
            .uri_patterns = pat, .uri_pattern_count = 1, .limit = 50};
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 4);
        cJSON_Delete(root);
    }

    /* Source filter: only labels from the named labeler. */
    {
        const char *pat[] = {"*"};
        const char *src[] = {SRC_A};
        metalbear_label_query q = {
            .uri_patterns = pat,
            .uri_pattern_count = 1,
            .sources = src,
            .source_count = 1,
            .sources_present = true,
            .limit = 50,
        };
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 3);
        cJSON_Delete(root);
    }

    /* Sources asked for but empty match nothing. */
    {
        const char *pat[] = {"*"};
        metalbear_label_query q = {.uri_patterns = pat,
                                   .uri_pattern_count = 1,
                                   .sources_present = true,
                                   .limit = 50};
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 0);
        cJSON_Delete(root);
    }

    /* Pagination: two pages of two, the cursor carried from the first page. */
    {
        const char *pat[] = {"*"};
        metalbear_label_query q = {
            .uri_patterns = pat, .uri_pattern_count = 1, .limit = 2};
        cJSON *page1 = run_query(store, &q);
        CHECK(label_count(page1) == 2);
        CHECK(has_cursor(page1));
        const cJSON *cursor = cJSON_GetObjectItemCaseSensitive(page1, "cursor");
        CHECK(cJSON_IsString(cursor));
        int64_t after = cursor && cJSON_IsString(cursor)
                            ? (int64_t)atoll(cursor->valuestring)
                            : 0;
        cJSON_Delete(page1);

        q.after_id = after;
        cJSON *page2 = run_query(store, &q);
        CHECK(label_count(page2) == 2);
        CHECK(!has_cursor(page2));
        cJSON_Delete(page2);
    }

    /* A pattern that is not in the store matches nothing and is not an error.
     */
    {
        const char *pat[] = {"at://did:plc:nobody/*"};
        metalbear_label_query q = {
            .uri_patterns = pat, .uri_pattern_count = 1, .limit = 50};
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 0);
        cJSON_Delete(root);
    }

    /* A pattern carrying SQL is text, not SQL: it matches nothing, and the
     * table is still there afterwards. */
    {
        const char *pat[] = {"x' OR '1'='1"};
        metalbear_label_query q = {
            .uri_patterns = pat, .uri_pattern_count = 1, .limit = 50};
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 0);
        cJSON_Delete(root);

        const char *all[] = {"*"};
        metalbear_label_query check = {
            .uri_patterns = all, .uri_pattern_count = 1, .limit = 50};
        cJSON *still = run_query(store, &check);
        CHECK(label_count(still) == 4);
        cJSON_Delete(still);
    }

    /* Labels survive a reopen. */
    metalbear_label_store_free(store);
    store = NULL;
    CHECK(metalbear_label_store_open(path, &store) == WF_OK && store != NULL);
    if (store) {
        const char *pat[] = {"*"};
        metalbear_label_query q = {
            .uri_patterns = pat, .uri_pattern_count = 1, .limit = 50};
        cJSON *root = run_query(store, &q);
        CHECK(label_count(root) == 4);
        cJSON_Delete(root);
        metalbear_label_store_free(store);
    }

    char sidecar[560];
    snprintf(sidecar, sizeof(sidecar), "%s-wal", path);
    unlink(sidecar);
    snprintf(sidecar, sizeof(sidecar), "%s-shm", path);
    unlink(sidecar);
    unlink(path);
    rmdir(dir);

    if (failures == 0) {
        printf("PASS: label store insert and query\n");
        return 0;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
