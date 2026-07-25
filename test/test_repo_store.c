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
    WF_CHECK(s == WF_OK && ccid && crev && cres);
    /* WF_CHECK records a failure and carries on, so anything that dereferences
     * an out-param has to be guarded on the check above actually holding.
     * Without this guard a failure here dies in strlen(NULL) and ctest reports
     * a bare SegFault, losing the FAIL line that says what went wrong. */
    if (crev && cres) {
        WF_CHECK(strlen(crev) > 0);
        cJSON *resarr = cJSON_Parse(cres);
        WF_CHECK(resarr && cJSON_IsArray(resarr) && cJSON_GetArraySize(resarr) == 3);
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
    run_did_immutability();
    run_server();
    WF_TEST_SUMMARY();
}
