/*
 * test_oauth_scope.c — Tests for OAuth scope parsing and matching
 */

#include "metalbear/oauth_scope.h"
#include "wolfram/xrpc.h"
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  Testing %s... ", name); \
    fflush(stdout); \
} while (0)

#define PASS() do { \
    tests_passed++; \
    printf("PASS\n"); \
} while (0)

#define FAIL(msg, ...) do { \
    printf("FAIL: " msg "\n", ##__VA_ARGS__); \
} while (0)

#define ASSERT(cond, msg, ...) do { \
    if (!(cond)) { \
        FAIL(msg, ##__VA_ARGS__); \
        return; \
    } \
} while (0)

/* Test static scope parsing */
static void test_static_scopes(void) {
    TEST("static scope 'atproto'");
    
    mb_scope_permission *perm = mb_scope_permission_parse("atproto");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->type == MB_SCOPE_TYPE_STATIC, "should be static type");
    ASSERT(strcmp(perm->u.static_scope.value, "atproto") == 0, "value should be 'atproto'");
    
    mb_scope_permission_free(perm);
    PASS();
    
    TEST("static scope 'transition:email'");
    perm = mb_scope_permission_parse("transition:email");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->type == MB_SCOPE_TYPE_STATIC, "should be static type");
    
    mb_scope_permission_free(perm);
    PASS();
    
    TEST("invalid static scope");
    perm = mb_scope_permission_parse("invalid:scope");
    ASSERT(perm == NULL, "should not parse");
    PASS();
}

/* Test repo scope parsing */
static void test_repo_scopes(void) {
    TEST("repo scope with collection only");
    
    mb_scope_permission *perm = mb_scope_permission_parse("repo:app.bsky.feed.post");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->type == MB_SCOPE_TYPE_REPO, "should be repo type");
    ASSERT(strcmp(perm->u.repo.collection, "app.bsky.feed.post") == 0, "collection should match");
    ASSERT(perm->u.repo.actions == MB_REPO_ACTION_ALL, "should have all actions");
    
    mb_scope_permission_free(perm);
    PASS();
    
    TEST("repo scope with create action");
    perm = mb_scope_permission_parse("repo:app.bsky.feed.post?action=create");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->type == MB_SCOPE_TYPE_REPO, "should be repo type");
    ASSERT(perm->u.repo.actions == MB_REPO_ACTION_CREATE, "should have create action only");
    
    mb_scope_permission_free(perm);
    PASS();
    
    TEST("repo scope with multiple actions");
    perm = mb_scope_permission_parse("repo:app.bsky.feed.post?action=create&action=update");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->u.repo.actions == (MB_REPO_ACTION_CREATE | MB_REPO_ACTION_UPDATE), 
           "should have create and update actions");
    
    mb_scope_permission_free(perm);
    PASS();
    
    TEST("repo wildcard scope");
    perm = mb_scope_permission_parse("repo:*");
    ASSERT(perm != NULL, "should parse");
    ASSERT(strcmp(perm->u.repo.collection, "*") == 0, "collection should be wildcard");
    
    mb_scope_permission_free(perm);
    PASS();
    
    TEST("repo wildcard with action");
    perm = mb_scope_permission_parse("repo:*?action=create");
    ASSERT(perm != NULL, "should parse");
    ASSERT(strcmp(perm->u.repo.collection, "*") == 0, "collection should be wildcard");
    ASSERT(perm->u.repo.actions == MB_REPO_ACTION_CREATE, "should have create action");
    
    mb_scope_permission_free(perm);
    PASS();
}

/* Test scope set operations */
static void test_scope_set(void) {
    TEST("parse scope set");
    
    mb_scope_set set;
    int status = mb_scope_set_parse("atproto transition:email", &set);
    ASSERT(status == WF_OK, "should parse");
    ASSERT(set.count == 2, "should have 2 permissions");
    
    mb_scope_set_free(&set);
    PASS();
    
    TEST("parse empty scope set");
    status = mb_scope_set_parse("", &set);
    ASSERT(status == WF_OK, "should parse");
    ASSERT(set.count == 0, "should have 0 permissions");
    
    mb_scope_set_free(&set);
    PASS();
    
    TEST("parse scope set with invalid scopes");
    status = mb_scope_set_parse("atproto invalid:scope repo:app.bsky.feed.post", &set);
    ASSERT(status == WF_OK, "should parse");
    ASSERT(set.count == 2, "should have 2 valid permissions");
    
    mb_scope_set_free(&set);
    PASS();
}

/* Test scope matching */
static void test_scope_matching(void) {
    TEST("full access with atproto");
    
    mb_scope_set set;
    mb_scope_set_parse("atproto", &set);
    
    ASSERT(mb_scope_set_is_full_access(&set), "atproto should grant full access");
    ASSERT(mb_scope_set_allows_repo(&set, "app.bsky.feed.post", MB_REPO_ACTION_CREATE), 
           "should allow repo create");
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.feed.post"), "should allow read");
    
    mb_scope_set_free(&set);
    PASS();
    
    TEST("limited repo scope");
    mb_scope_set_parse("repo:app.bsky.feed.post?action=create", &set);
    
    ASSERT(!mb_scope_set_is_full_access(&set), "should not grant full access");
    ASSERT(mb_scope_set_allows_repo(&set, "app.bsky.feed.post", MB_REPO_ACTION_CREATE), 
           "should allow create on matching collection");
    ASSERT(!mb_scope_set_allows_repo(&set, "app.bsky.feed.post", MB_REPO_ACTION_UPDATE), 
           "should not allow update");
    ASSERT(!mb_scope_set_allows_repo(&set, "app.bsky.graph.follow", MB_REPO_ACTION_CREATE), 
           "should not allow create on different collection");
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.feed.post"), 
           "should allow read on matching collection");
    
    mb_scope_set_free(&set);
    PASS();
    
    TEST("wildcard repo scope");
    mb_scope_set_parse("repo:*?action=create&action=update", &set);
    
    ASSERT(!mb_scope_set_is_full_access(&set), "should not grant full access");
    ASSERT(mb_scope_set_allows_repo(&set, "any.collection", MB_REPO_ACTION_CREATE), 
           "should allow create on any collection");
    ASSERT(mb_scope_set_allows_repo(&set, "any.collection", MB_REPO_ACTION_UPDATE), 
           "should allow update on any collection");
    ASSERT(!mb_scope_set_allows_repo(&set, "any.collection", MB_REPO_ACTION_DELETE), 
           "should not allow delete");
    
    mb_scope_set_free(&set);
    PASS();
}

/* Test scope normalization */
static void test_scope_normalization(void) {
    TEST("normalize scope string");
    
    char *normalized = mb_scope_normalize("  atproto   transition:email  ");
    ASSERT(normalized != NULL, "should normalize");
    ASSERT(strcmp(normalized, "atproto transition:email") == 0 || 
           strcmp(normalized, "transition:email atproto") == 0, 
           "should be normalized: got '%s'", normalized);
    
    free(normalized);
    PASS();
    
    TEST("normalize with invalid scopes");
    normalized = mb_scope_normalize("atproto invalid scope:app.bsky.feed.post");
    ASSERT(normalized != NULL, "should normalize");
    
    free(normalized);
    PASS();
}

int main(void) {
    printf("OAuth Scope Tests\n");
    printf("=================\n\n");
    
    test_static_scopes();
    test_repo_scopes();
    test_scope_set();
    test_scope_matching();
    test_scope_normalization();
    
    printf("\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    return tests_run == tests_passed ? 0 : 1;
}
