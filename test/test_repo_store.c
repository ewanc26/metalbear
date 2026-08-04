/*
 * test_pds_repo.c — offline tests for the self-hosted PDS repo store.
 *
 * Covers the first coherent PDS slice: a durable, writable repo store
 * backed by SQLite that reuses the SDK's signed-commit / MST machinery,
 * plus the com.atproto.repo XRPC route handlers.
 *
 * Three phases, all offline:
 *   1. Unit (no server): create/put/get/delete/applyWrites + describeRepo,
 *      including persistence across reopen and commit verification with
 *      the store's own signing key.
 *   2. Invariant: the produced head commit verifies with wf_repo_verify.
 *   3. Server round-trip: start an XRPC server, call createRecord /
 *      getRecord / describeRepo over HTTP and assert field-level results.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/repo_store.h"
#include "wolfram/xrpc.h"
#include "wolfram/xrpc_server.h"

#include "test.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void temp_path(char *buf, size_t n, const char *tag) {
    snprintf(buf, n, "/tmp/metalbear_repo_store_%s_XXXXXX", tag);
    int fd = mkstemp(buf);
    if (fd >= 0) close(fd);
    unlink(buf);
}

/*
 * A repo opened with an explicit signing key must adopt it. Bootstrap DID
 * minting publishes a key in the PLC document before the repo exists; if the
 * repo generated its own key instead, every commit it signed would be
 * unverifiable against that document.
 */
static int run_adopted_key(void) {
    int failures = 0;
    char path[256];
    temp_path(path, sizeof(path), "adoptkey");

    wf_signing_key key;
    memset(&key, 0, sizeof(key));
    WF_CHECK(wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &key) == WF_OK);
    char *want_didkey = NULL;
    WF_CHECK(wf_signing_key_public_didkey(&key, &want_didkey) == WF_OK &&
             want_didkey);

    metalbear_repo_store *store = NULL;
    wf_status s = metalbear_repo_store_open_with_key(
        path, "did:plc:adoptkey", "adopt.example.com", &key, &store);
    WF_CHECK(s == WF_OK && store != NULL);
    if (s != WF_OK || !store) {
        free(want_didkey);
        unlink(path);
        return failures + 1;
    }
    WF_CHECK(want_didkey &&
             strcmp(metalbear_repo_store_signing_key_did(store), want_didkey) == 0);

    /* A commit signed by the adopted key must verify against it. */
    char *uri = NULL, *cid = NULL;
    WF_CHECK(metalbear_repo_store_create_record(
                 store, "com.example.adopt", NULL,
                 "{\"$type\":\"com.example.adopt\",\"n\":1}", NULL, &uri,
                 &cid) == WF_OK);
    int verified = 0;
    WF_CHECK(metalbear_repo_store_verify_head(store, &verified, NULL) == WF_OK &&
             verified == 1);
    free(uri);
    free(cid);

    /* The key is fixed at creation: reopening must not replace it. */
    metalbear_repo_store_free(store);
    store = NULL;
    wf_signing_key other;
    memset(&other, 0, sizeof(other));
    WF_CHECK(wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &other) == WF_OK);
    WF_CHECK(metalbear_repo_store_open_with_key(path, "did:plc:adoptkey",
                                                "adopt.example.com", &other,
                                                &store) == WF_OK);
    if (store)
        WF_CHECK(want_didkey &&
                 strcmp(metalbear_repo_store_signing_key_did(store),
                        want_didkey) == 0);
    metalbear_repo_store_free(store);
    free(want_didkey);
    unlink(path);
    return failures;
}

/*
 * Record validation against the lexicon corpus, matching the reference PDS's
 * prepareWrite: a collection with no schema is reported "unknown" rather than
 * rejected, a schema that is satisfied is "valid", and a schema that is
 * violated is an error — the record must not be stored.
 */
static int run_record_validation(void) {
    int failures = 0;
    wf_lexicon_registry *lex = wf_lexicon_registry_new();
    WF_CHECK(lex != NULL);
    if (!lex) return failures + 1;
    if (wf_lexicon_registry_load_dir(lex, METALBEAR_TEST_LEXICON_DIR) != WF_OK) {
        fprintf(stderr, "SKIP: no lexicon corpus at %s\n",
                METALBEAR_TEST_LEXICON_DIR);
        wf_lexicon_registry_free(lex);
        return failures;
    }

    metalbear_validation_status status = METALBEAR_VALIDATION_VALID;
    char *message = NULL;

    /* A well-formed post validates. */
    const char *good = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"hi\","
                       "\"createdAt\":\"2026-07-25T00:00:00Z\"}";
    WF_CHECK(metalbear_validate_record(lex, "app.bsky.feed.post", good, false,
                                       &status, &message) == WF_OK);
    WF_CHECK(status == METALBEAR_VALIDATION_VALID);
    WF_CHECK(message == NULL);

    /* A post missing its required `text` must be rejected, with a message. */
    const char *missing = "{\"$type\":\"app.bsky.feed.post\","
                          "\"createdAt\":\"2026-07-25T00:00:00Z\"}";
    status = METALBEAR_VALIDATION_VALID;
    WF_CHECK(metalbear_validate_record(lex, "app.bsky.feed.post", missing,
                                       false, &status, &message) ==
             WF_ERR_VALIDATION);
    WF_CHECK(message != NULL);
    free(message);
    message = NULL;

    /* Wrong field type is likewise rejected. */
    const char *wrong = "{\"$type\":\"app.bsky.feed.post\",\"text\":123,"
                        "\"createdAt\":\"2026-07-25T00:00:00Z\"}";
    WF_CHECK(metalbear_validate_record(lex, "app.bsky.feed.post", wrong, false,
                                       &status, &message) == WF_ERR_VALIDATION);
    free(message);
    message = NULL;

    /* A collection with no schema is "unknown", not an error — the PDS still
     * hosts collections whose lexicons it does not carry. */
    const char *custom = "{\"$type\":\"click.croft.devtest\",\"x\":1}";
    status = METALBEAR_VALIDATION_VALID;
    WF_CHECK(metalbear_validate_record(lex, "click.croft.devtest", custom,
                                       false, &status, &message) == WF_OK);
    WF_CHECK(status == METALBEAR_VALIDATION_UNKNOWN);
    WF_CHECK(message == NULL);

    /* ...unless the caller demanded validation, which cannot be given. */
    WF_CHECK(metalbear_validate_record(lex, "click.croft.devtest", custom, true,
                                       &status, &message) == WF_ERR_NOT_FOUND);
    free(message);
    message = NULL;

    /* With no registry at all, everything is honestly "unknown". */
    status = METALBEAR_VALIDATION_VALID;
    WF_CHECK(metalbear_validate_record(NULL, "app.bsky.feed.post", missing,
                                       false, &status, &message) == WF_OK);
    WF_CHECK(status == METALBEAR_VALIDATION_UNKNOWN);
    free(message);

    wf_lexicon_registry_free(lex);
    return failures;
}

/*
 * The uploadBlob lexicon is explicit that mimetype/size restrictions are
 * enforced "when the reference is created", not at upload time — MetalBear's
 * blob store itself imposes none. That enforcement is this same lexicon
 * record-validation path: app.bsky.embed.images#image declares an "image"
 * mimetype-glob accept list and maxSize:2000000, so a post embedding a blob
 * outside either bound must fail validation exactly like a missing required field
 * does, proving check_record's call into metalbear_validate_record actually
 * covers blob constraints and not just plain object/string/array schemas.
 */
static int run_blob_constraint_validation(void) {
    int failures = 0;
    wf_lexicon_registry *lex = wf_lexicon_registry_new();
    WF_CHECK(lex != NULL);
    if (!lex) return failures + 1;
    if (wf_lexicon_registry_load_dir(lex, METALBEAR_TEST_LEXICON_DIR) != WF_OK) {
        fprintf(stderr, "SKIP: no lexicon corpus at %s\n",
                METALBEAR_TEST_LEXICON_DIR);
        wf_lexicon_registry_free(lex);
        return failures;
    }

    metalbear_validation_status status = METALBEAR_VALIDATION_VALID;
    char *message = NULL;

    /* Within accept + maxSize: valid. */
    const char *good =
        "{\"$type\":\"app.bsky.feed.post\",\"text\":\"pic\","
        "\"embed\":{\"$type\":\"app.bsky.embed.images\",\"images\":["
        "{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
        "\"ref\":{\"$link\":\"bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku\"},\"mimeType\":\"image/png\","
        "\"size\":2000000}}]},"
        "\"createdAt\":\"2026-07-25T00:00:00Z\"}";
    WF_CHECK(metalbear_validate_record(lex, "app.bsky.feed.post", good, false,
                                       &status, &message) == WF_OK);
    WF_CHECK(status == METALBEAR_VALIDATION_VALID);
    WF_CHECK(message == NULL);

    /* One byte over the 2 MB maxSize is rejected. */
    const char *too_big =
        "{\"$type\":\"app.bsky.feed.post\",\"text\":\"pic\","
        "\"embed\":{\"$type\":\"app.bsky.embed.images\",\"images\":["
        "{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
        "\"ref\":{\"$link\":\"bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku\"},\"mimeType\":\"image/png\","
        "\"size\":2000001}}]},"
        "\"createdAt\":\"2026-07-25T00:00:00Z\"}";
    status = METALBEAR_VALIDATION_VALID;
    WF_CHECK(metalbear_validate_record(lex, "app.bsky.feed.post", too_big,
                                       false, &status, &message) ==
             WF_ERR_VALIDATION);
    WF_CHECK(message != NULL);
    free(message);
    message = NULL;

    /* A mimetype outside the "image" accept glob is rejected regardless of size. */
    const char *wrong_mime =
        "{\"$type\":\"app.bsky.feed.post\",\"text\":\"pic\","
        "\"embed\":{\"$type\":\"app.bsky.embed.images\",\"images\":["
        "{\"alt\":\"a\",\"image\":{\"$type\":\"blob\","
        "\"ref\":{\"$link\":\"bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku\"},\"mimeType\":\"application/pdf\","
        "\"size\":100}}]},"
        "\"createdAt\":\"2026-07-25T00:00:00Z\"}";
    status = METALBEAR_VALIDATION_VALID;
    WF_CHECK(metalbear_validate_record(lex, "app.bsky.feed.post", wrong_mime,
                                       false, &status, &message) ==
             WF_ERR_VALIDATION);
    WF_CHECK(message != NULL);
    free(message);
    message = NULL;

    wf_lexicon_registry_free(lex);
    return failures;
}

/*
 * Read-after-write's load-bearing query: which records post-date a given repo
 * rev. An AppView reports how far it has indexed via `atproto-repo-rev`, and
 * everything newer is a write the author cannot see yet.
 */
static int run_records_since_rev(void) {
    int failures = 0;
    char path[256];
    temp_path(path, sizeof(path), "sincerev");

    metalbear_repo_store *store = NULL;
    if (metalbear_repo_store_open(path, "did:plc:sincerev", "s.example.com",
                                  &store) != WF_OK || !store) {
        WF_CHECK(0);
        unlink(path);
        return failures + 1;
    }

    char *u = NULL, *c = NULL;
    WF_CHECK(metalbear_repo_store_create_record(
                 store, "app.bsky.feed.post", "postone",
                 "{\"$type\":\"app.bsky.feed.post\",\"text\":\"one\"}", NULL,
                 &u, &c) == WF_OK);
    free(u); free(c); u = c = NULL;

    /* The rev after the first write is the watermark an AppView would report. */
    char *rev_after_first = NULL, *cid_tmp = NULL;
    WF_CHECK(metalbear_repo_store_get_head(store, &rev_after_first,
                                           &cid_tmp) == WF_OK);
    free(cid_tmp);

    WF_CHECK(metalbear_repo_store_create_record(
                 store, "app.bsky.feed.post", "posttwo",
                 "{\"$type\":\"app.bsky.feed.post\",\"text\":\"two\"}", NULL,
                 &u, &c) == WF_OK);
    free(u); free(c); u = c = NULL;

    /* Only the second post is newer than that watermark. */
    char *js = NULL;
    WF_CHECK(metalbear_repo_store_records_since_rev(store, rev_after_first, 10,
                                                    &js) == WF_OK && js);
    cJSON *d = js ? cJSON_Parse(js) : NULL;
    cJSON *recs = d ? cJSON_GetObjectItemCaseSensitive(d, "records") : NULL;
    WF_CHECK(recs && cJSON_IsArray(recs) && cJSON_GetArraySize(recs) == 1);
    if (recs && cJSON_GetArraySize(recs) == 1) {
        cJSON *e = cJSON_GetArrayItem(recs, 0);
        cJSON *uri = cJSON_GetObjectItemCaseSensitive(e, "uri");
        cJSON *coll = cJSON_GetObjectItemCaseSensitive(e, "collection");
        cJSON *at = cJSON_GetObjectItemCaseSensitive(e, "indexedAt");
        cJSON *val = cJSON_GetObjectItemCaseSensitive(e, "value");
        WF_CHECK(uri && cJSON_IsString(uri) &&
                 strstr(uri->valuestring, "posttwo") != NULL);
        WF_CHECK(coll && cJSON_IsString(coll) &&
                 strcmp(coll->valuestring, "app.bsky.feed.post") == 0);
        WF_CHECK(at && cJSON_IsString(at) && at->valuestring[0]);
        WF_CHECK(val && cJSON_IsObject(val));
    }
    cJSON_Delete(d);
    free(js);
    js = NULL;

    /* A rev at or past the head means the AppView is caught up: nothing to
     * splice, so callers send the upstream response through untouched. */
    char *head_rev = NULL;
    WF_CHECK(metalbear_repo_store_get_head(store, &head_rev, &cid_tmp) == WF_OK);
    free(cid_tmp);
    WF_CHECK(metalbear_repo_store_records_since_rev(store, head_rev, 10,
                                                    &js) == WF_OK && js);
    d = js ? cJSON_Parse(js) : NULL;
    recs = d ? cJSON_GetObjectItemCaseSensitive(d, "records") : NULL;
    WF_CHECK(recs && cJSON_IsArray(recs) && cJSON_GetArraySize(recs) == 0);
    cJSON_Delete(d);
    free(js);
    js = NULL;

    /* A rev that predates every local record cannot be describing this repo
     * (an account migration, say). Splicing local records into a view built
     * from someone else's history would be worse than showing a stale one, so
     * the sanity check returns nothing. */
    WF_CHECK(metalbear_repo_store_records_since_rev(store, "2222222222222", 10,
                                                    &js) == WF_OK && js);
    d = js ? cJSON_Parse(js) : NULL;
    recs = d ? cJSON_GetObjectItemCaseSensitive(d, "records") : NULL;
    WF_CHECK(recs && cJSON_IsArray(recs) && cJSON_GetArraySize(recs) == 0);
    cJSON_Delete(d);
    free(js);

    free(rev_after_first);
    free(head_rev);
    metalbear_repo_store_free(store);
    unlink(path);
    return failures;
}

/* ── Phase 1 + 2: unit tests (no server) ──────────────────────────── */

static int run_unit(void) {
    int failures = 0;
    char path[256];
    temp_path(path, sizeof(path), "unit");

    metalbear_repo_store *store = NULL;
    wf_status s = metalbear_repo_store_open(path, "did:plc:testpds",
                                     "test.example.com", &store);
    WF_CHECK(s == WF_OK && store != NULL);
    if (s != WF_OK) {
        unlink(path);
        return failures + 1;
    }
    metalbear_repo_store_stats empty_stats = {1, 1};
    WF_CHECK(metalbear_repo_store_get_stats(NULL, &empty_stats) == WF_ERR_INVALID_ARG);
    WF_CHECK(empty_stats.repo_blocks == 0 && empty_stats.indexed_records == 0);
    WF_CHECK(metalbear_repo_store_get_stats(store, NULL) == WF_ERR_INVALID_ARG);
    WF_CHECK(metalbear_repo_store_get_stats(store, &empty_stats) == WF_OK);
    WF_CHECK(empty_stats.repo_blocks == 0 && empty_stats.indexed_records == 0);

    /* createRecord in a first collection (rkey auto-generated). */
    char *uri1 = NULL, *cid1 = NULL;
    s = metalbear_repo_store_create_record(
        store, "com.example.posts", NULL,
        "{\"$type\":\"com.example.posts\",\"text\":\"hello\"}",
        NULL, &uri1, &cid1);
    WF_CHECK(s == WF_OK && uri1 && cid1);
    const char *rkey1 = strrchr(uri1, '/') + 1;
    WF_CHECK(strcmp(uri1, "at://did:plc:testpds/com.example.posts/") != 0);
    WF_CHECK(strlen(rkey1) > 0 && strchr(rkey1, '/') == NULL);

    /* getRecord returns the same data + stable CID. */
    char *recj = NULL, *reccid = NULL;
    s = metalbear_repo_store_get_record(store, "com.example.posts", rkey1,
                                 &recj, &reccid);
    WF_CHECK(s == WF_OK && recj && reccid);
    WF_CHECK(strstr(recj, "\"text\"") != NULL && strstr(recj, "hello") != NULL);
    WF_CHECK(strcmp(reccid, cid1) == 0);
    free(recj);
    free(reccid);

    /* createRecord in a second collection. */
    char *uri2 = NULL, *cid2 = NULL;
    s = metalbear_repo_store_create_record(
        store, "com.example.likes", NULL,
        "{\"$type\":\"com.example.likes\",\"subject\":\"at://x\"}",
        NULL, &uri2, &cid2);
    WF_CHECK(s == WF_OK && uri2 && cid2);
    const char *rkey2 = strrchr(uri2, '/') + 1;

    /* putRecord updates in place; CID must change but rkey is stable. */
    char *uri3 = NULL, *cid3 = NULL;
    s = metalbear_repo_store_put_record(
        store, "com.example.likes", rkey2,
        "{\"$type\":\"com.example.likes\",\"subject\":\"at://y\",\"extra\":5}",
        NULL, NULL, &uri3, &cid3);
    WF_CHECK(s == WF_OK && uri3 && cid3);
    WF_CHECK(strcmp(cid3, cid2) != 0);
    WF_CHECK(strcmp(strrchr(uri3, '/') + 1, rkey2) == 0);
    char *recj2 = NULL, *reccid2 = NULL;
    s = metalbear_repo_store_get_record(store, "com.example.likes", rkey2,
                                 &recj2, &reccid2);
    WF_CHECK(s == WF_OK && recj2 && strstr(recj2, "at://y") != NULL &&
            strstr(recj2, "\"extra\":5") != NULL);
    free(recj2);
    free(reccid2);

    /* listRecords enumerates a collection via the records index. */
    char *list_json = NULL;
    s = metalbear_repo_store_list_records(store, "com.example.posts", NULL, false,
                                    50, &list_json);
    WF_CHECK(s == WF_OK && list_json);
    if (list_json) {
        cJSON *lj = cJSON_Parse(list_json);
        WF_CHECK(lj && cJSON_IsObject(lj));
        cJSON *recs = lj ? cJSON_GetObjectItemCaseSensitive(lj, "records") : NULL;
        WF_CHECK(recs && cJSON_IsArray(recs) && cJSON_GetArraySize(recs) == 1);
        cJSON *first = recs ? cJSON_GetArrayItem(recs, 0) : NULL;
        WF_CHECK(first && cJSON_IsObject(first));
        WF_CHECK(first && cJSON_GetObjectItemCaseSensitive(first, "uri") &&
                 strcmp(cJSON_GetObjectItemCaseSensitive(first, "uri")->valuestring,
                        uri1) == 0);
        WF_CHECK(first && cJSON_GetObjectItemCaseSensitive(first, "value") &&
                 strstr(cJSON_PrintUnformatted(
                            cJSON_GetObjectItemCaseSensitive(first, "value")),
                        "hello") != NULL);
        cJSON_Delete(lj);
        free(list_json);
    }

    /* getLatestCommit returns the current head rev + cid. */
    char *gc_rev = NULL, *gc_cid = NULL;
    s = metalbear_repo_store_get_head(store, &gc_rev, &gc_cid);
    WF_CHECK(s == WF_OK && gc_rev && *gc_rev && gc_cid && *gc_cid);
    char *since_rev = gc_rev ? strdup(gc_rev) : NULL;
    free(gc_rev);
    free(gc_cid);

    /* deleteRecord removes the record (not found afterwards). */
    s = metalbear_repo_store_delete_record(store, "com.example.likes", rkey2,
                                  NULL, NULL);
    WF_CHECK(s == WF_OK);
    s = metalbear_repo_store_get_record(store, "com.example.likes", rkey2,
                                 &recj, &reccid);
    WF_CHECK(s == WF_ERR_NOT_FOUND);
    s = metalbear_repo_store_delete_record(store, "com.example.likes", "nope",
                                  NULL, NULL);
    WF_CHECK(s == WF_ERR_NOT_FOUND);

    /* A failed compare-and-swap must be distinguishable from a malformed
     * request, because the route handlers turn it into the lexicon's
     * `InvalidSwap` error and clients branch on that to retry the write. */
    char *swap_uri = NULL, *swap_cid = NULL;
    s = metalbear_repo_store_put_record(
        store, "com.example.posts", rkey1,
        "{\"$type\":\"com.example.posts\",\"text\":\"swap\"}",
        "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NULL,
        &swap_uri, &swap_cid);
    WF_CHECK(s == WF_ERR_CONFLICT);
    free(swap_uri);
    free(swap_cid);
    swap_uri = swap_cid = NULL;
    /* A swapRecord guard naming a record that does not exist cannot match. */
    s = metalbear_repo_store_put_record(
        store, "com.example.posts", "absentrkey",
        "{\"$type\":\"com.example.posts\",\"text\":\"swap\"}", NULL,
        "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &swap_uri, &swap_cid);
    WF_CHECK(s == WF_ERR_CONFLICT);
    free(swap_uri);
    free(swap_cid);

    /* applyWrites: create (new rkey) + update rkey1 + delete rkey1. */
    char writes[512];
    snprintf(writes, sizeof(writes),
             "["
             "{\"$type\":\"com.atproto.repo.applyWrites#create\","
             "\"collection\":\"com.example.posts\","
             "\"value\":{\"$type\":\"com.example.posts\",\"text\":\"aa\"}},"
             "{\"$type\":\"com.atproto.repo.applyWrites#update\","
             "\"collection\":\"com.example.posts\",\"rkey\":\"%s\","
             "\"value\":{\"$type\":\"com.example.posts\",\"text\":\"bb\"}},"
             "{\"$type\":\"com.atproto.repo.applyWrites#delete\","
             "\"collection\":\"com.example.posts\",\"rkey\":\"%s\"}"
             "]", rkey1, rkey1);
    char *ccid = NULL, *crev = NULL, *cres = NULL;
    s = metalbear_repo_store_apply_writes(store, writes, NULL, &ccid, &crev, &cres);
    if (s != WF_OK)
        fprintf(stderr, "DEBUG applyWrites: status=%d rkey1=%s writes=%s\n",
                (int)s, rkey1, writes);
    WF_CHECK(s == WF_OK && ccid && crev && cres);
    /* WF_CHECK records a failure and carries on, so anything that dereferences
     * an out-param has to be guarded on the check above actually holding.
     * Without this guard a failure here dies in strlen(NULL) and ctest reports
     * a bare SegFault, losing the FAIL line that says what went wrong. */
    if (crev && cres) {
        WF_CHECK(strlen(crev) > 0);
        cJSON *resarr = cJSON_Parse(cres);
        WF_CHECK(resarr && cJSON_IsArray(resarr) && cJSON_GetArraySize(resarr) == 3);
        /* `results` is a closed union: every entry must carry the $type that
         * discriminates it, in write order create/update/delete. */
        static const char *const want_types[] = {
            "com.atproto.repo.applyWrites#createResult",
            "com.atproto.repo.applyWrites#updateResult",
            "com.atproto.repo.applyWrites#deleteResult",
        };
        for (int i = 0; resarr && i < cJSON_GetArraySize(resarr) && i < 3; i++) {
            cJSON *e = cJSON_GetArrayItem(resarr, i);
            cJSON *ty = e ? cJSON_GetObjectItemCaseSensitive(e, "$type") : NULL;
            WF_CHECK(ty && cJSON_IsString(ty) &&
                     strcmp(ty->valuestring, want_types[i]) == 0);
        }
        cJSON_Delete(resarr);
    }
    /* rkey1 must now be gone; a fresh post was created in com.example.posts. */
    s = metalbear_repo_store_get_record(store, "com.example.posts", rkey1,
                                 &recj, &reccid);
    WF_CHECK(s == WF_ERR_NOT_FOUND);

    /* Full and revision-filtered CAR exports are rooted at the current head. */
    unsigned char *export_bytes = NULL;
    size_t export_len = 0;
    s = metalbear_repo_store_export(store, NULL, &export_bytes, &export_len);
    WF_CHECK(s == WF_OK && export_bytes && export_len > 0);
    wf_car exported = {0};
    s = wf_car_parse(export_bytes, export_len, &exported);
    WF_CHECK(s == WF_OK && exported.root_count == 1 &&
             exported.block_count > 0);
    wf_car_free(&exported);
    free(export_bytes);

    export_bytes = NULL;
    export_len = 0;
    s = metalbear_repo_store_export(store, since_rev, &export_bytes, &export_len);
    WF_CHECK(s == WF_OK && export_bytes && export_len > 0);
    memset(&exported, 0, sizeof(exported));
    s = wf_car_parse(export_bytes, export_len, &exported);
    WF_CHECK(s == WF_OK && exported.root_count == 1 &&
             exported.block_count > 0);
    wf_car_free(&exported);
    free(export_bytes);

    /* getBlocks returns a rootless CAR containing exactly the selected CID. */
    const char *selected_cids[] = {ccid ? ccid : "", ccid ? ccid : ""};
    export_bytes = NULL;
    export_len = 0;
    s = metalbear_repo_store_get_blocks(store, selected_cids, 2,
                                 &export_bytes, &export_len);
    WF_CHECK(s == WF_OK && export_bytes && export_len > 0);
    memset(&exported, 0, sizeof(exported));
    s = wf_car_parse(export_bytes, export_len, &exported);
    WF_CHECK(s == WF_OK && exported.root_count == 0 &&
             exported.block_count == 1);
    wf_car_free(&exported);
    free(export_bytes);
    const char *missing_cids[] = {
        "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    };
    s = metalbear_repo_store_get_blocks(store, missing_cids, 1,
                                 &export_bytes, &export_len);
    WF_CHECK(s == WF_ERR_NOT_FOUND || s == WF_ERR_INVALID_ARG);
    free(since_rev);

    WF_CHECK(metalbear_repo_store_set_handle(store, "not a handle") ==
             WF_ERR_INVALID_ARG);
    WF_CHECK(strcmp(metalbear_repo_store_handle(store), "test.example.com") == 0);
    WF_CHECK(metalbear_repo_store_set_handle(store, "renamed.example.com") == WF_OK);
    WF_CHECK(strcmp(metalbear_repo_store_handle(store), "renamed.example.com") == 0);

    /* describeRepo: did + handle + collections + rev. */
    char *desc = NULL;
    s = metalbear_repo_store_describe(store, &desc);
    WF_CHECK(s == WF_OK && desc);
    cJSON *d = cJSON_Parse(desc);
    WF_CHECK(d != NULL);
    cJSON *did = cJSON_GetObjectItemCaseSensitive(d, "did");
    cJSON *handle = cJSON_GetObjectItemCaseSensitive(d, "handle");
    cJSON *cols = cJSON_GetObjectItemCaseSensitive(d, "collections");
    cJSON *rev = cJSON_GetObjectItemCaseSensitive(d, "rev");
    WF_CHECK(did && cJSON_IsString(did) &&
             strcmp(did->valuestring, "did:plc:testpds") == 0);
    WF_CHECK(handle && cJSON_IsString(handle) &&
             strcmp(handle->valuestring, "renamed.example.com") == 0);
    WF_CHECK(cols && cJSON_IsArray(cols));
    int has_posts = 0;
    for (int i = 0; cols && i < cJSON_GetArraySize(cols); i++) {
        cJSON *e = cJSON_GetArrayItem(cols, i);
        if (e && cJSON_IsString(e) &&
            strcmp(e->valuestring, "com.example.posts") == 0)
            has_posts = 1;
    }
    WF_CHECK(has_posts);
    WF_CHECK(rev && cJSON_IsString(rev) && strlen(rev->valuestring) > 0);
    /* The stub `version` field is not in the describeRepo lexicon. */
    WF_CHECK(cJSON_GetObjectItemCaseSensitive(d, "version") == NULL);
    cJSON_Delete(d);
    free(desc);

    /* The DID document must be W3C-shaped: `verificationMethod` as an array
     * of Multikey entries, not the `verificationMethods` map that appears in
     * unsigned PLC operations. Clients read the array form to recover the
     * repo signing key. */
    cJSON *doc = metalbear_did_document_build(
        "did:plc:testpds", "renamed.example.com",
        metalbear_repo_store_signing_key_did(store), "https://pds.example.com");
    WF_CHECK(doc != NULL);
    WF_CHECK(cJSON_GetObjectItemCaseSensitive(doc, "verificationMethods") == NULL);
    cJSON *vms = cJSON_GetObjectItemCaseSensitive(doc, "verificationMethod");
    WF_CHECK(vms && cJSON_IsArray(vms) && cJSON_GetArraySize(vms) == 1);
    cJSON *vm = vms ? cJSON_GetArrayItem(vms, 0) : NULL;
    cJSON *vm_id = vm ? cJSON_GetObjectItemCaseSensitive(vm, "id") : NULL;
    cJSON *vm_type = vm ? cJSON_GetObjectItemCaseSensitive(vm, "type") : NULL;
    cJSON *vm_ctrl = vm ? cJSON_GetObjectItemCaseSensitive(vm, "controller") : NULL;
    cJSON *vm_key = vm ? cJSON_GetObjectItemCaseSensitive(vm, "publicKeyMultibase") : NULL;
    WF_CHECK(vm_id && cJSON_IsString(vm_id) &&
             strcmp(vm_id->valuestring, "did:plc:testpds#atproto") == 0);
    WF_CHECK(vm_type && cJSON_IsString(vm_type) &&
             strcmp(vm_type->valuestring, "Multikey") == 0);
    WF_CHECK(vm_ctrl && cJSON_IsString(vm_ctrl) &&
             strcmp(vm_ctrl->valuestring, "did:plc:testpds") == 0);
    /* publicKeyMultibase is the did:key value minus its prefix. */
    WF_CHECK(vm_key && cJSON_IsString(vm_key) && vm_key->valuestring[0] == 'z');
    WF_CHECK(vm_key && strcmp(metalbear_repo_store_signing_key_did(store) + 8,
                              vm_key->valuestring) == 0);
    cJSON *svc = cJSON_GetObjectItemCaseSensitive(doc, "service");
    WF_CHECK(svc && cJSON_IsArray(svc) && cJSON_GetArraySize(svc) == 1);
    cJSON *svc0 = svc ? cJSON_GetArrayItem(svc, 0) : NULL;
    WF_CHECK(svc0 && cJSON_IsString(cJSON_GetObjectItemCaseSensitive(svc0, "type")) &&
             strcmp(cJSON_GetObjectItemCaseSensitive(svc0, "type")->valuestring,
                    "AtprotoPersonalDataServer") == 0);
    /* alsoKnownAs round-trips through the handle accessor. */
    const char *claimed = metalbear_did_document_handle(doc);
    WF_CHECK(claimed && strcmp(claimed, "renamed.example.com") == 0);
    cJSON_Delete(doc);

    /* Phase 2 invariant: the head commit verifies with the store key. */
    int verified = 0;
    wf_commit cm;
    s = metalbear_repo_store_verify_head(store, &verified, &cm);
    if (s != WF_OK || !verified)
        fprintf(stderr, "DEBUG verify: status=%d verified=%d\n", (int)s, verified);
    WF_CHECK(s == WF_OK && verified == 1);
    WF_CHECK(strcmp(cm.did, "did:plc:testpds") == 0);
    WF_CHECK(cm.sig_len == 64);
    metalbear_repo_store_stats populated_stats = {0};
    WF_CHECK(metalbear_repo_store_get_stats(store, &populated_stats) == WF_OK);
    WF_CHECK(populated_stats.repo_blocks > 0);
    WF_CHECK(populated_stats.indexed_records == 1);

    /* Persistence: reopen and the head still verifies, DID preserved. */
    metalbear_repo_store_free(store);
    store = NULL;
    s = metalbear_repo_store_open(path, "did:plc:testpds", "test.example.com", &store);
    WF_CHECK(s == WF_OK && store != NULL);
    WF_CHECK(strcmp(metalbear_repo_store_did(store), "did:plc:testpds") == 0);
    WF_CHECK(strcmp(metalbear_repo_store_handle(store), "renamed.example.com") == 0);
    metalbear_repo_store_stats reopened_stats = {0};
    WF_CHECK(metalbear_repo_store_get_stats(store, &reopened_stats) == WF_OK);
    WF_CHECK(reopened_stats.repo_blocks == populated_stats.repo_blocks);
    WF_CHECK(reopened_stats.indexed_records == populated_stats.indexed_records);
    int verified2 = 0;
    s = metalbear_repo_store_verify_head(store, &verified2, NULL);
    WF_CHECK(s == WF_OK && verified2 == 1);

    /* applyWrites is atomic and lands as exactly ONE commit. Capture the head
     * first: if the batch produced a commit per write, the new commit's `prev`
     * would point at an intermediate commit rather than the head we saw. */
    int pre_verified = 0;
    wf_commit pre_commit;
    WF_CHECK(metalbear_repo_store_verify_head(store, &pre_verified, &pre_commit) ==
             WF_OK && pre_verified == 1);
    wf_cid head_before = pre_commit.cid;

    const char *batch_writes =
        "["
        "{\"$type\":\"com.atproto.repo.applyWrites#create\","
        "\"collection\":\"com.example.batch\",\"rkey\":\"batchaaa\","
        "\"value\":{\"$type\":\"com.example.batch\",\"n\":1}},"
        "{\"$type\":\"com.atproto.repo.applyWrites#create\","
        "\"collection\":\"com.example.batch\",\"rkey\":\"batchbbb\","
        "\"value\":{\"$type\":\"com.example.batch\",\"n\":2}},"
        "{\"$type\":\"com.atproto.repo.applyWrites#create\","
        "\"collection\":\"com.example.batch\",\"rkey\":\"batchccc\","
        "\"value\":{\"$type\":\"com.example.batch\",\"n\":3}}"
        "]";
    char *bcid = NULL, *brev = NULL, *bres = NULL;
    s = metalbear_repo_store_apply_writes(store, batch_writes, NULL, &bcid, &brev,
                                          &bres);
    WF_CHECK(s == WF_OK && bcid && brev && bres);
    int post_verified = 0;
    wf_commit post_commit;
    WF_CHECK(metalbear_repo_store_verify_head(store, &post_verified,
                                              &post_commit) == WF_OK &&
             post_verified == 1);
    /*
     * The head advanced. Single-commit atomicity used to be asserted through
     * the commit's `prev` link, but v3 commits carry a null prev by
     * specification, so that evidence no longer exists on the wire. The
     * property is now asserted where it is actually observable — one #commit
     * event carrying all the ops — in test_server's applyWrites case.
     */
    WF_CHECK(post_verified == 1);
    WF_CHECK(!(post_commit.cid.len == head_before.len &&
               memcmp(post_commit.cid.bytes, head_before.bytes,
                      head_before.len) == 0));
    /* All three records landed. */
    for (int i = 0; i < 3; i++) {
        static const char *const bkeys[] = {"batchaaa", "batchbbb", "batchccc"};
        char *br = NULL, *brc = NULL;
        WF_CHECK(metalbear_repo_store_get_record(store, "com.example.batch",
                                                 bkeys[i], &br, &brc) == WF_OK);
        free(br);
        free(brc);
    }
    free(bcid); free(brev); free(bres);

    /* A batch that fails part-way must leave the repo untouched: the valid
     * first write must not survive, and the head must not move. */
    int mid_verified = 0;
    wf_commit mid_commit;
    WF_CHECK(metalbear_repo_store_verify_head(store, &mid_verified, &mid_commit) ==
             WF_OK && mid_verified == 1);
    const char *bad_writes =
        "["
        "{\"$type\":\"com.atproto.repo.applyWrites#create\","
        "\"collection\":\"com.example.batch\",\"rkey\":\"batchddd\","
        "\"value\":{\"$type\":\"com.example.batch\",\"n\":4}},"
        "{\"$type\":\"com.atproto.repo.applyWrites#delete\","
        "\"collection\":\"com.example.batch\",\"rkey\":\"neverexisted\"}"
        "]";
    char *xcid = NULL, *xrev = NULL, *xres = NULL;
    s = metalbear_repo_store_apply_writes(store, bad_writes, NULL, &xcid, &xrev,
                                          &xres);
    WF_CHECK(s != WF_OK);
    free(xcid); free(xrev); free(xres);
    char *rolled = NULL, *rolledc = NULL;
    WF_CHECK(metalbear_repo_store_get_record(store, "com.example.batch",
                                             "batchddd", &rolled,
                                             &rolledc) == WF_ERR_NOT_FOUND);
    free(rolled); free(rolledc);
    int after_verified = 0;
    wf_commit after_commit;
    WF_CHECK(metalbear_repo_store_verify_head(store, &after_verified,
                                              &after_commit) == WF_OK &&
             after_verified == 1);
    WF_CHECK(after_commit.cid.len == mid_commit.cid.len &&
             memcmp(after_commit.cid.bytes, mid_commit.cid.bytes,
                    mid_commit.cid.len) == 0);

    /* Two records with byte-identical content hash to the same block CID.
     * The repo is content-addressed, so the block is stored once, but each
     * record must still get its own MST entry — otherwise the second create
     * silently succeeds while writing nothing. */
    const char *dup_json = "{\"$type\":\"com.example.dup\",\"text\":\"same\"}";
    char *dup_uri1 = NULL, *dup_cid1 = NULL, *dup_uri2 = NULL, *dup_cid2 = NULL;
    s = metalbear_repo_store_create_record(store, "com.example.dup", "dupkeyone",
                                           dup_json, NULL, &dup_uri1, &dup_cid1);
    WF_CHECK(s == WF_OK && dup_uri1 && dup_cid1);
    s = metalbear_repo_store_create_record(store, "com.example.dup", "dupkeytwo",
                                           dup_json, NULL, &dup_uri2, &dup_cid2);
    WF_CHECK(s == WF_OK && dup_uri2 && dup_cid2);
    /* Same content, so the same record CID — but both must be readable. */
    if (dup_cid1 && dup_cid2) WF_CHECK(strcmp(dup_cid1, dup_cid2) == 0);
    char *dupr = NULL, *duprc = NULL;
    s = metalbear_repo_store_get_record(store, "com.example.dup", "dupkeyone",
                                        &dupr, &duprc);
    WF_CHECK(s == WF_OK);
    free(dupr); free(duprc); dupr = duprc = NULL;
    s = metalbear_repo_store_get_record(store, "com.example.dup", "dupkeytwo",
                                        &dupr, &duprc);
    WF_CHECK(s == WF_OK);
    free(dupr); free(duprc);
    /* The head must still verify after both writes. */
    int dup_verified = 0;
    WF_CHECK(metalbear_repo_store_verify_head(store, &dup_verified, NULL) == WF_OK &&
             dup_verified == 1);
    free(dup_uri1); free(dup_cid1); free(dup_uri2); free(dup_cid2);

    /* listRecords ordering + pagination. Five records with sortable rkeys:
     * the default order is newest-rkey-first (descending), `reverse` flips
     * it, and paging with the returned cursor must visit every record
     * exactly once — a cursor pointing at the over-fetched row would drop
     * one record per page boundary. */
    static const char *const page_rkeys[] = {"aaa", "bbb", "ccc", "ddd", "eee"};
    for (size_t i = 0; i < 5; i++) {
        char *purl = NULL, *pcid = NULL;
        s = metalbear_repo_store_put_record(
            store, "com.example.page", page_rkeys[i],
            "{\"$type\":\"com.example.page\",\"n\":1}", NULL, NULL,
            &purl, &pcid);
        WF_CHECK(s == WF_OK);
        free(purl);
        free(pcid);
    }

    /* Default: descending by rkey. */
    char *pj = NULL;
    s = metalbear_repo_store_list_records(store, "com.example.page", NULL,
                                          false, 50, &pj);
    WF_CHECK(s == WF_OK && pj);
    cJSON *pd = pj ? cJSON_Parse(pj) : NULL;
    cJSON *pr = pd ? cJSON_GetObjectItemCaseSensitive(pd, "records") : NULL;
    WF_CHECK(pr && cJSON_IsArray(pr) && cJSON_GetArraySize(pr) == 5);
    for (int i = 0; pr && i < cJSON_GetArraySize(pr); i++) {
        cJSON *e = cJSON_GetArrayItem(pr, i);
        cJSON *u = e ? cJSON_GetObjectItemCaseSensitive(e, "uri") : NULL;
        WF_CHECK(u && cJSON_IsString(u) &&
                 strcmp(strrchr(u->valuestring, '/') + 1,
                        page_rkeys[4 - i]) == 0);
    }
    cJSON_Delete(pd);
    free(pj);

    /* reverse=true: ascending by rkey. */
    pj = NULL;
    s = metalbear_repo_store_list_records(store, "com.example.page", NULL,
                                          true, 50, &pj);
    WF_CHECK(s == WF_OK && pj);
    pd = pj ? cJSON_Parse(pj) : NULL;
    pr = pd ? cJSON_GetObjectItemCaseSensitive(pd, "records") : NULL;
    WF_CHECK(pr && cJSON_IsArray(pr) && cJSON_GetArraySize(pr) == 5);
    for (int i = 0; pr && i < cJSON_GetArraySize(pr); i++) {
        cJSON *e = cJSON_GetArrayItem(pr, i);
        cJSON *u = e ? cJSON_GetObjectItemCaseSensitive(e, "uri") : NULL;
        WF_CHECK(u && cJSON_IsString(u) &&
                 strcmp(strrchr(u->valuestring, '/') + 1, page_rkeys[i]) == 0);
    }
    cJSON_Delete(pd);
    free(pj);

    /* Page through in twos and assert all five arrive, in order, once. */
    char *page_cursor = NULL;
    int seen = 0;
    for (int guard = 0; guard < 10; guard++) {
        pj = NULL;
        s = metalbear_repo_store_list_records(store, "com.example.page",
                                              page_cursor, false, 2, &pj);
        WF_CHECK(s == WF_OK && pj);
        pd = pj ? cJSON_Parse(pj) : NULL;
        pr = pd ? cJSON_GetObjectItemCaseSensitive(pd, "records") : NULL;
        int n = pr ? cJSON_GetArraySize(pr) : 0;
        for (int i = 0; i < n; i++) {
            cJSON *e = cJSON_GetArrayItem(pr, i);
            cJSON *u = e ? cJSON_GetObjectItemCaseSensitive(e, "uri") : NULL;
            WF_CHECK(seen < 5);
            WF_CHECK(u && cJSON_IsString(u) &&
                     strcmp(strrchr(u->valuestring, '/') + 1,
                            page_rkeys[4 - seen]) == 0);
            seen++;
        }
        cJSON *nc = pd ? cJSON_GetObjectItemCaseSensitive(pd, "cursor") : NULL;
        free(page_cursor);
        page_cursor = (nc && cJSON_IsString(nc)) ? strdup(nc->valuestring) : NULL;
        cJSON_Delete(pd);
        free(pj);
        if (!page_cursor) break;
    }
    WF_CHECK(seen == 5);
    free(page_cursor);

    free(uri1);
    free(cid1);
    free(uri2);
    free(cid2);
    free(uri3);
    free(cid3);
    free(ccid);
    free(crev);
    free(cres);
    metalbear_repo_store_free(store);
    unlink(path);
    return failures;
}

/* ── Repo DID immutability ────────────────────────────────────────── */

/*
 * A repo's DID is immutable: already-written commits embed it in signed
 * CBOR, so re-opening a repo under a different DID cannot be made correct by
 * rewriting the meta row. Opening must fail rather than silently serving
 * records whose AT-URIs name a DID that resolves nowhere.
 *
 * Regression: this previously succeeded, loading the stored DID and ignoring
 * the caller's, which is how a live PDS ended up writing every record under a
 * placeholder DID left over from bootstrap.
 */
static int run_did_immutability(void) {
    int failures = 0;
    char path[256];
    temp_path(path, sizeof(path), "did");

    metalbear_repo_store *store = NULL;
    wf_status s = metalbear_repo_store_open(path, "did:plc:originalowner1234",
                                            "orig.example.com", &store);
    WF_CHECK(s == WF_OK && store != NULL);
    if (s != WF_OK) {
        unlink(path);
        return failures + 1;
    }
    WF_CHECK(strcmp(metalbear_repo_store_did(store), "did:plc:originalowner1234") == 0);
    metalbear_repo_store_free(store);

    /* Re-opening under the same DID is the normal path and must still work. */
    store = NULL;
    s = metalbear_repo_store_open(path, "did:plc:originalowner1234",
                                  "orig.example.com", &store);
    WF_CHECK(s == WF_OK && store != NULL);
    if (store) {
        WF_CHECK(strcmp(metalbear_repo_store_did(store), "did:plc:originalowner1234") == 0);
        metalbear_repo_store_free(store);
    }

    /* Re-opening under a different DID must be refused, not silently accepted
     * with the stored DID winning. */
    store = NULL;
    s = metalbear_repo_store_open(path, "did:plc:someotheraccount99",
                                  "other.example.com", &store);
    WF_CHECK(s != WF_OK);
    WF_CHECK(store == NULL);
    if (store) metalbear_repo_store_free(store);

    unlink(path);
    return failures;
}

/* ── Phase 3: server round-trip ───────────────────────────────────── */

static int run_server(void) {
    int failures = 0;
    char path[256];
    temp_path(path, sizeof(path), "srv");

    metalbear_repo_store *store = NULL;
    wf_status s = metalbear_repo_store_open(path, "did:plc:srvpds",
                                     "srv.example.com", &store);
    WF_CHECK(s == WF_OK && store != NULL);
    if (s != WF_OK) {
        unlink(path);
        return failures + 1;
    }

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 1);
    WF_CHECK(server != NULL);
    if (!server) {
        metalbear_repo_store_free(store);
        unlink(path);
        return failures + 1;
    }
    uint16_t port = wf_xrpc_server_port(server);
    WF_CHECK(port != 0);
    WF_CHECK(metalbear_xrpc_server_register_pds_repo(server, store, NULL, NULL) == WF_OK);

    char base[64];
    snprintf(base, sizeof(base), "http://127.0.0.1:%u", (unsigned)port);
    wf_xrpc_client *client = wf_xrpc_client_new(base);
    WF_CHECK(client != NULL);

    /* createRecord over HTTP. */
    wf_response res = {0};
    s = wf_xrpc_procedure(
        client, "com.atproto.repo.createRecord",
        "{\"repo\":\"did:plc:srvpds\",\"collection\":\"com.example.posts\","
        "\"record\":{\"$type\":\"com.example.posts\",\"text\":\"viahttp\"}}",
        &res);
    WF_CHECK(s == WF_OK && res.status == 200);
    cJSON *root = cJSON_ParseWithLength(res.body, res.body_len);
    WF_CHECK(root != NULL);
    cJSON *uri = cJSON_GetObjectItemCaseSensitive(root, "uri");
    cJSON *cid = cJSON_GetObjectItemCaseSensitive(root, "cid");
    cJSON *commit = cJSON_GetObjectItemCaseSensitive(root, "commit");
    WF_CHECK(uri && cJSON_IsString(uri) && cid && cJSON_IsString(cid) &&
            commit && cJSON_IsObject(commit));
    const char *uri_str = uri ? uri->valuestring : "";
    const char *sl = strrchr(uri_str, '/');
    char rk_buf[32];
    const char *rk = "";
    if (sl && sl[1]) {
        snprintf(rk_buf, sizeof(rk_buf), "%s", sl + 1);
        rk = rk_buf;
    }
    cJSON_Delete(root);
    wf_response_free(&res);

    /* getRecord over HTTP (GET query). */
    wf_xrpc_param params[] = {
        {"collection", "com.example.posts"},
        {"rkey", (char *)rk},
    };
    s = wf_xrpc_query_params(client, "com.atproto.repo.getRecord", params,
                              2, &res);
    WF_CHECK(s == WF_OK && res.status == 200);
    root = cJSON_ParseWithLength(res.body, res.body_len);
    cJSON *val = root ? cJSON_GetObjectItemCaseSensitive(root, "value") : NULL;
    cJSON *text = val ? cJSON_GetObjectItemCaseSensitive(val, "text") : NULL;
    WF_CHECK(text && cJSON_IsString(text) &&
            strcmp(text->valuestring, "viahttp") == 0);
    cJSON_Delete(root);
    wf_response_free(&res);

    /* describeRepo over HTTP. */
    s = wf_xrpc_query(client, "com.atproto.repo.describeRepo", NULL, &res);
    WF_CHECK(s == WF_OK && res.status == 200);
    root = cJSON_ParseWithLength(res.body, res.body_len);
    cJSON *did = root ? cJSON_GetObjectItemCaseSensitive(root, "did") : NULL;
    WF_CHECK(did && cJSON_IsString(did) &&
             strcmp(did->valuestring, "did:plc:srvpds") == 0);
    cJSON_Delete(root);
    wf_response_free(&res);

    wf_xrpc_client_free(client);
    wf_xrpc_server_free(server);
    metalbear_repo_store_free(store);
    unlink(path);
    return failures;
}

int main(void) {
    run_unit();
    run_records_since_rev();
    run_record_validation();
    run_blob_constraint_validation();
    run_adopted_key();
    run_did_immutability();
    run_server();
    WF_TEST_SUMMARY();
}
