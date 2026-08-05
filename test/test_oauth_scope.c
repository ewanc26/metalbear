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

    TEST("near-miss static scope 'atprotz' must not match 'atproto'");
    perm = mb_scope_permission_parse("atprotz");
    ASSERT(perm == NULL, "should not parse — 7 chars but not 'atproto'");
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

    TEST("normalize identity scope");
    normalized = mb_scope_normalize("atproto identity:update");
    ASSERT(normalized != NULL, "should normalize");
    ASSERT(strstr(normalized, "identity:update") != NULL,
           "identity scope should be preserved: got '%s'", normalized);
    free(normalized);
    PASS();

    TEST("normalize account scope");
    normalized = mb_scope_normalize("atproto account:delete");
    ASSERT(normalized != NULL, "should normalize");
    ASSERT(strstr(normalized, "account:delete") != NULL,
           "account scope should be preserved: got '%s'", normalized);
    free(normalized);
    PASS();

    TEST("normalize rpc scope");
    normalized = mb_scope_normalize("atproto rpc:com.atproto.repo.*");
    ASSERT(normalized != NULL, "should normalize");
    ASSERT(strstr(normalized, "rpc:com.atproto.repo.*") != NULL,
           "rpc scope should be preserved: got '%s'", normalized);
    free(normalized);
    PASS();
}

/* Per-collection read enforcement (issue: narrow OAuth grants must be
 * limited to exactly the reads their scope implies -- not "any repo scope
 * matches" and not "the scope set is merely non-empty"). server.c's
 * authenticate_request gates real requests on exactly this function, so its
 * per-collection precision is what makes that gate meaningful rather than a
 * no-op. */
static void test_read_scope_denial(void) {
    TEST("empty scope set denies read of anything");
    mb_scope_set set;
    mb_scope_set_parse("", &set);
    ASSERT(!mb_scope_set_is_full_access(&set),
           "empty set must not be full access");
    ASSERT(!mb_scope_set_allows_read(&set, "app.bsky.feed.post"),
           "an empty scope set must not imply any read -- a non-empty check "
           "alone is not sufficient enforcement");
    mb_scope_set_free(&set);
    PASS();

    TEST("action-restricted scope allows read of its own collection only");
    mb_scope_set_parse("repo:app.bsky.feed.post?action=create", &set);
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.feed.post"),
           "a scope naming the collection allows reading it, regardless of "
           "which write action it grants");
    ASSERT(!mb_scope_set_allows_read(&set, "app.bsky.graph.follow"),
           "the same scope must NOT allow reading an unrelated collection -- "
           "\"any repo scope matches\" would wrongly allow this");
    ASSERT(!mb_scope_set_allows_read(&set, "app.bsky.actor.profile"),
           "nor any other unrelated collection");
    mb_scope_set_free(&set);
    PASS();

    TEST("multiple narrow scopes each cover only their own collection");
    mb_scope_set_parse(
        "repo:app.bsky.feed.post?action=create "
        "repo:app.bsky.graph.follow?action=create", &set);
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.feed.post"),
           "first named collection is readable");
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.graph.follow"),
           "second named collection is readable");
    ASSERT(!mb_scope_set_allows_read(&set, "app.bsky.feed.like"),
           "a third, unnamed collection is not");
    mb_scope_set_free(&set);
    PASS();

    TEST("wildcard repo scope allows read of any collection");
    mb_scope_set_parse("repo:*?action=create", &set);
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.feed.post"),
           "wildcard collection covers reads too");
    ASSERT(mb_scope_set_allows_read(&set, "any.other.collection"),
           "including collections never explicitly named");
    mb_scope_set_free(&set);
    PASS();

    TEST("a non-repo scope alone denies every collection read");
    mb_scope_set_parse("transition:generic", &set);
    ASSERT(!mb_scope_set_is_full_access(&set),
           "transition:generic is not full access");
    ASSERT(!mb_scope_set_allows_read(&set, "app.bsky.feed.post"),
           "a scope set with no repo permission at all must deny every "
           "collection read, not fall back to allowing it");
    mb_scope_set_free(&set);
    PASS();
}

/* Test dynamic scope types beyond repo and blob */
static void test_dynamic_scopes(void) {
    TEST("identity scope parse");
    mb_scope_permission *perm = mb_scope_permission_parse("identity:update");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_IDENTITY,
           "should parse identity:update");
    ASSERT(strcmp(perm->u.identity.action, "update") == 0,
           "action should be 'update'");
    mb_scope_permission_free(perm);
    PASS();

    TEST("identity wildcard scope parse");
    perm = mb_scope_permission_parse("identity:*");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_IDENTITY,
           "should parse identity:*");
    ASSERT(strcmp(perm->u.identity.action, "*") == 0,
           "action should be '*'");
    mb_scope_permission_free(perm);
    PASS();

    TEST("account scope parse");
    perm = mb_scope_permission_parse("account:delete");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_ACCOUNT,
           "should parse account:delete");
    ASSERT(strcmp(perm->u.account.action, "delete") == 0,
           "action should be 'delete'");
    mb_scope_permission_free(perm);
    PASS();

    TEST("rpc scope parse");
    perm = mb_scope_permission_parse("rpc:com.atproto.repo.*");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_RPC,
           "should parse rpc:com.atproto.repo.*");
    ASSERT(strcmp(perm->u.rpc.nsid, "com.atproto.repo.*") == 0,
           "nsid should match");
    mb_scope_permission_free(perm);
    PASS();

    TEST("include scope parse");
    perm = mb_scope_permission_parse("include:transition:email");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_INCLUDE,
           "should parse include:transition:email");
    mb_scope_permission_free(perm);
    PASS();

    TEST("invalid identity scope rejected");
    perm = mb_scope_permission_parse("identity:invalid");
    ASSERT(perm == NULL, "identity:invalid should not parse");
    PASS();

    TEST("invalid account scope rejected");
    perm = mb_scope_permission_parse("account:invalid");
    ASSERT(perm == NULL, "account:invalid should not parse");
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
    test_dynamic_scopes();
    test_read_scope_denial();
    
    printf("\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    return tests_run == tests_passed ? 0 : 1;
}
