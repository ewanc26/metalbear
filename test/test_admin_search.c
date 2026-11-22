/*
 * test_admin_search.c -- offline tests for com.atproto.admin.searchAccounts.
 *
 * Uses the real account registry on a temporary SQLite file, calls the route
 * handler directly, and checks the admin auth callback separately. No server
 * socket is needed.
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

#include "../src/admin/admin_routes.h"
#include "../src/server_internal.h"

#include "metalbear/account/account_registry.h"

#include <cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static char temp_dir[] = "/tmp/metalbear-admin-search-XXXXXX";
static metalbear_server server;
static metalbear_account_registry *registry;

static void add_account(const char *n, const char *email) {
    char did[128];
    char handle[128];
    char dir[512];
    snprintf(did, sizeof(did), "did:plc:%s", n);
    snprintf(handle, sizeof(handle), "%s.example", n);
    snprintf(dir, sizeof(dir), "%s/%s", temp_dir, n);
    WF_CHECK(metalbear_account_registry_add_with_email(
                 registry, did, handle, "hash", dir, email, 1) == WF_OK);
}

/* An account created before the registry's email column existed, or whose
 * email was set later, has the address only in its account store. The search
 * must still find it: that store is where build_account_view reads email. */
static void add_store_email_account(const char *n, const char *email) {
    char did[128];
    char handle[128];
    char dir[512];
    char path[640];
    snprintf(did, sizeof(did), "did:plc:%s", n);
    snprintf(handle, sizeof(handle), "%s.example", n);
    snprintf(dir, sizeof(dir), "%s/%s", temp_dir, n);
    WF_CHECK(mkdir(dir, 0700) == 0);
    WF_CHECK(metalbear_account_registry_add_with_email(
                 registry, did, handle, "hash", dir, "", 1) == WF_OK);
    snprintf(path, sizeof(path), "%s/account.sqlite3", dir);
    metalbear_account_store *store = NULL;
    WF_CHECK(metalbear_account_store_open(path, "hash", &store) == WF_OK);
    WF_CHECK(store != NULL);
    if (store) {
        WF_CHECK(metalbear_account_store_email(store, email) == WF_OK);
        metalbear_account_store_free(store);
    }
}

/* Build a request and return the parsed JSON body. The caller deletes it. */
static cJSON *search(const char *term, const char *email, const char *cursor,
                     int limit, int *out_status) {
    wf_xrpc_request req;
    memset(&req, 0, sizeof(req));
    req.nsid = "com.atproto.admin.searchAccounts";
    req.method = "GET";
    req.params = cJSON_CreateObject();
    WF_CHECK(req.params != NULL);
    if (term) cJSON_AddStringToObject(req.params, "term", term);
    if (email) cJSON_AddStringToObject(req.params, "email", email);
    if (cursor) cJSON_AddStringToObject(req.params, "cursor", cursor);
    if (limit >= 0) cJSON_AddNumberToObject(req.params, "limit", limit);

    wf_xrpc_response resp = WF_XRPC_RESPONSE_INIT;
    WF_CHECK(admin_search_accounts(&server, &req, &resp) == WF_OK);
    cJSON *root =
        resp.body ? cJSON_ParseWithLength(resp.body, resp.body_len) : NULL;
    if (out_status) *out_status = resp.http_status;
    if (root && resp.http_status == 200)
        WF_CHECK(
            cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(root, "accounts")));
    cJSON_Delete(req.params);
    free(resp.body);
    free(resp.content_type);
    return root;
}

static size_t account_count(const cJSON *root) {
    return (size_t)cJSON_GetArraySize(
        cJSON_GetObjectItemCaseSensitive(root, "accounts"));
}

static const char *account_did(const cJSON *root, size_t i) {
    cJSON *accounts = cJSON_GetObjectItemCaseSensitive(root, "accounts");
    cJSON *item = cJSON_GetArrayItem(accounts, (int)i);
    cJSON *did = cJSON_GetObjectItemCaseSensitive(item, "did");
    return cJSON_IsString(did) ? did->valuestring : NULL;
}

static const char *next_cursor(const cJSON *root) {
    cJSON *cursor = cJSON_GetObjectItemCaseSensitive(root, "cursor");
    return cJSON_IsString(cursor) ? cursor->valuestring : NULL;
}

int main(void) {
    WF_CHECK(mkdtemp(temp_dir) != NULL);
    char registry_path[512];
    snprintf(registry_path, sizeof(registry_path), "%s/registry.sqlite3",
             temp_dir);
    WF_CHECK(metalbear_account_registry_open(registry_path, &registry) ==
             WF_OK);
    WF_CHECK(registry != NULL);

    memset(&server, 0, sizeof(server));
    server.registry = registry;
    server.data_directory = temp_dir;
    server.admin_password = "secret";

    add_account("user001", "alice@example.test");
    add_account("user002", "bob@example.org");
    add_account("user003", "carol@example.test");

    /* term matches a handle, a DID and an email, case-insensitively. */
    {
        cJSON *root = search("USER001.EXAMPLE", NULL, NULL, -1, NULL);
        WF_CHECK(root != NULL);
        WF_CHECK(account_count(root) == 1);
        WF_CHECK(strcmp(account_did(root, 0), "did:plc:user001") == 0);
        WF_CHECK(cJSON_GetObjectItemCaseSensitive(
                     cJSON_GetArrayItem(
                         cJSON_GetObjectItemCaseSensitive(root, "accounts"), 0),
                     "indexedAt") != NULL);
        cJSON_Delete(root);
    }
    {
        cJSON *root = search("USER002", NULL, NULL, -1, NULL);
        WF_CHECK(root != NULL);
        WF_CHECK(account_count(root) == 1);
        WF_CHECK(strcmp(account_did(root, 0), "did:plc:user002") == 0);
        cJSON_Delete(root);
    }
    {
        cJSON *root = search("BOB@EXAMPLE.ORG", NULL, NULL, -1, NULL);
        WF_CHECK(root != NULL);
        WF_CHECK(account_count(root) == 1);
        WF_CHECK(strcmp(account_did(root, 0), "did:plc:user002") == 0);
        cJSON_Delete(root);
    }

    /* The lexicon's `email` parameter filters on email only. */
    {
        cJSON *root = search(NULL, "@example.test", NULL, -1, NULL);
        WF_CHECK(root != NULL);
        WF_CHECK(account_count(root) == 2);
        cJSON_Delete(root);
    }

    /* An address that exists only in the account store (older registry rows,
     * or email set after signup) is searchable too. */
    add_store_email_account("legacy001", "legacy@example.test");
    {
        cJSON *root = search(NULL, "legacy@example.test", NULL, -1, NULL);
        WF_CHECK(root != NULL);
        WF_CHECK(account_count(root) == 1);
        WF_CHECK(strcmp(account_did(root, 0), "did:plc:legacy001") == 0);
        cJSON_Delete(root);
    }
    {
        cJSON *root = search("LEGACY@EXAMPLE.TEST", NULL, NULL, -1, NULL);
        WF_CHECK(root != NULL);
        WF_CHECK(account_count(root) == 1);
        WF_CHECK(strcmp(account_did(root, 0), "did:plc:legacy001") == 0);
        cJSON_Delete(root);
    }

    /* No filter lists accounts; limit=1 uses a DID keyset cursor. */
    {
        cJSON *first = search(NULL, NULL, NULL, 1, NULL);
        WF_CHECK(first != NULL);
        WF_CHECK(account_count(first) == 1);
        const char *cursor = next_cursor(first);
        WF_CHECK(cursor != NULL);

        cJSON *second = search(NULL, NULL, cursor, 1, NULL);
        WF_CHECK(second != NULL);
        WF_CHECK(account_count(second) == 1);
        WF_CHECK(strcmp(account_did(first, 0), account_did(second, 0)) != 0);
        const char *cursor2 = next_cursor(second);
        WF_CHECK(cursor2 != NULL);

        cJSON *third = search(NULL, NULL, cursor2, 1, NULL);
        WF_CHECK(third != NULL);
        WF_CHECK(account_count(third) == 1);
        const char *cursor3 = next_cursor(third);
        WF_CHECK(cursor3 != NULL);

        cJSON *fourth = search(NULL, NULL, cursor3, 1, NULL);
        WF_CHECK(fourth != NULL);
        WF_CHECK(account_count(fourth) == 1);
        WF_CHECK(next_cursor(fourth) == NULL);

        cJSON_Delete(first);
        cJSON_Delete(second);
        cJSON_Delete(third);
        cJSON_Delete(fourth);
    }

    /* A cursor that is not an account DID is a client error. */
    {
        int status = 0;
        cJSON *root = search(NULL, NULL, "did:plc:not-here", -1, &status);
        WF_CHECK(root != NULL);
        WF_CHECK(status == 400);
        WF_CHECK(cJSON_GetObjectItemCaseSensitive(root, "error") != NULL);
        WF_CHECK(cJSON_GetObjectItemCaseSensitive(root, "accounts") == NULL);
        cJSON_Delete(root);
    }

    /* Admin guard: the new NSID is Basic-auth gated like getAccountInfos. */
    {
        wf_xrpc_request req;
        memset(&req, 0, sizeof(req));
        req.nsid = "com.atproto.admin.searchAccounts";
        req.method = "GET";
        WF_CHECK(metalbear_authenticate(&req, &server) == WF_ERR_PERMISSION);
        req.auth_header = "Basic YWRtaW46c2VjcmV0"; /* admin:secret */
        WF_CHECK(metalbear_authenticate(&req, &server) == WF_OK);
        req.auth_header = "Basic YWRtaW46d3Jvbmc="; /* admin:wrong */
        WF_CHECK(metalbear_authenticate(&req, &server) == WF_ERR_PERMISSION);
    }

    /* Limit clamping: 105 accounts with limit=1000 answers 100 + cursor, and
     * the next page answers the remaining five with no cursor. */
    for (int i = 4; i <= 104; i++) {
        char n[32];
        char email[128];
        snprintf(n, sizeof(n), "user%03d", i);
        snprintf(email, sizeof(email), "%s@example.test", n);
        add_account(n, email);
    }
    {
        cJSON *first = search(NULL, NULL, NULL, 1000, NULL);
        WF_CHECK(first != NULL);
        WF_CHECK(account_count(first) == 100);
        const char *cursor = next_cursor(first);
        WF_CHECK(cursor != NULL);
        cJSON *second = search(NULL, NULL, cursor, 1000, NULL);
        WF_CHECK(second != NULL);
        WF_CHECK(account_count(second) == 5);
        WF_CHECK(next_cursor(second) == NULL);
        WF_CHECK(strcmp(account_did(first, 99), cursor) == 0);
        cJSON_Delete(first);
        cJSON_Delete(second);
    }

    metalbear_account_registry_free(registry);
    char path[512];
    const char *names[] = {"registry.sqlite3", "registry.sqlite3-wal",
                           "registry.sqlite3-shm", "account.sqlite3",
                           "legacy001/account.sqlite3"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", temp_dir, names[i]);
        unlink(path);
    }
    snprintf(path, sizeof(path), "%s/legacy001", temp_dir);
    rmdir(path);
    rmdir(temp_dir);
    if (failures == 0) printf("ALL PASS: admin_search\n");
    return failures;
}
