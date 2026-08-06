/*
 * test_oauth_scope.c — Tests for OAuth scope parsing and matching
 */

#include "metalbear/oauth/oauth_scope.h"
#include "wolfram/xrpc.h"
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  Testing %s... ", name);                                      \
        fflush(stdout);                                                        \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg, ...)                                                         \
    do {                                                                       \
        printf("FAIL: " msg "\n", ##__VA_ARGS__);                              \
    } while (0)

#define ASSERT(cond, msg, ...)                                                 \
    do {                                                                       \
        if (!(cond)) {                                                         \
            FAIL(msg, ##__VA_ARGS__);                                          \
            return;                                                            \
        }                                                                      \
    } while (0)

/* Test static scope parsing */
static void test_static_scopes(void) {
    TEST("static scope 'atproto'");

    mb_scope_permission *perm = mb_scope_permission_parse("atproto");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->type == MB_SCOPE_TYPE_STATIC, "should be static type");
    ASSERT(strcmp(perm->u.static_scope.value, "atproto") == 0,
           "value should be 'atproto'");

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

    mb_scope_permission *perm =
        mb_scope_permission_parse("repo:app.bsky.feed.post");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->type == MB_SCOPE_TYPE_REPO, "should be repo type");
    ASSERT(strcmp(perm->u.repo.collection, "app.bsky.feed.post") == 0,
           "collection should match");
    ASSERT(perm->u.repo.actions == MB_REPO_ACTION_ALL,
           "should have all actions");

    mb_scope_permission_free(perm);
    PASS();

    TEST("repo scope with create action");
    perm = mb_scope_permission_parse("repo:app.bsky.feed.post?action=create");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->type == MB_SCOPE_TYPE_REPO, "should be repo type");
    ASSERT(perm->u.repo.actions == MB_REPO_ACTION_CREATE,
           "should have create action only");

    mb_scope_permission_free(perm);
    PASS();

    TEST("repo scope with multiple actions");
    perm = mb_scope_permission_parse(
        "repo:app.bsky.feed.post?action=create&action=update");
    ASSERT(perm != NULL, "should parse");
    ASSERT(perm->u.repo.actions ==
               (MB_REPO_ACTION_CREATE | MB_REPO_ACTION_UPDATE),
           "should have create and update actions");

    mb_scope_permission_free(perm);
    PASS();

    TEST("repo wildcard scope");
    perm = mb_scope_permission_parse("repo:*");
    ASSERT(perm != NULL, "should parse");
    ASSERT(strcmp(perm->u.repo.collection, "*") == 0,
           "collection should be wildcard");

    mb_scope_permission_free(perm);
    PASS();

    TEST("repo wildcard with action");
    perm = mb_scope_permission_parse("repo:*?action=create");
    ASSERT(perm != NULL, "should parse");
    ASSERT(strcmp(perm->u.repo.collection, "*") == 0,
           "collection should be wildcard");
    ASSERT(perm->u.repo.actions == MB_REPO_ACTION_CREATE,
           "should have create action");

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
    status = mb_scope_set_parse("atproto invalid:scope repo:app.bsky.feed.post",
                                &set);
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

    ASSERT(mb_scope_set_is_full_access(&set),
           "atproto should grant full access");
    ASSERT(mb_scope_set_allows_repo(&set, "app.bsky.feed.post",
                                    MB_REPO_ACTION_CREATE),
           "should allow repo create");
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.feed.post"),
           "should allow read");

    mb_scope_set_free(&set);
    PASS();

    TEST("limited repo scope");
    mb_scope_set_parse("repo:app.bsky.feed.post?action=create", &set);

    ASSERT(!mb_scope_set_is_full_access(&set), "should not grant full access");
    ASSERT(mb_scope_set_allows_repo(&set, "app.bsky.feed.post",
                                    MB_REPO_ACTION_CREATE),
           "should allow create on matching collection");
    ASSERT(!mb_scope_set_allows_repo(&set, "app.bsky.feed.post",
                                     MB_REPO_ACTION_UPDATE),
           "should not allow update");
    ASSERT(!mb_scope_set_allows_repo(&set, "app.bsky.graph.follow",
                                     MB_REPO_ACTION_CREATE),
           "should not allow create on different collection");
    ASSERT(mb_scope_set_allows_read(&set, "app.bsky.feed.post"),
           "should allow read on matching collection");

    mb_scope_set_free(&set);
    PASS();

    TEST("wildcard repo scope");
    mb_scope_set_parse("repo:*?action=create&action=update", &set);

    ASSERT(!mb_scope_set_is_full_access(&set), "should not grant full access");
    ASSERT(
        mb_scope_set_allows_repo(&set, "any.collection", MB_REPO_ACTION_CREATE),
        "should allow create on any collection");
    ASSERT(
        mb_scope_set_allows_repo(&set, "any.collection", MB_REPO_ACTION_UPDATE),
        "should allow update on any collection");
    ASSERT(!mb_scope_set_allows_repo(&set, "any.collection",
                                     MB_REPO_ACTION_DELETE),
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
    normalized = mb_scope_normalize("atproto identity:handle");
    ASSERT(normalized != NULL, "should normalize");
    ASSERT(strstr(normalized, "identity:handle") != NULL,
           "identity scope should be preserved: got '%s'", normalized);
    free(normalized);
    PASS();

    TEST("normalize account scope");
    normalized = mb_scope_normalize("atproto account:email?action=manage");
    ASSERT(normalized != NULL, "should normalize");
    ASSERT(strstr(normalized, "account:email?action=manage") != NULL,
           "account scope should be preserved: got '%s'", normalized);
    free(normalized);
    PASS();

    TEST("normalize rpc scope");
    normalized = mb_scope_normalize(
        "atproto rpc:com.atproto.repo.getRecord?aud=did:web:x");
    ASSERT(normalized != NULL, "should normalize");
    ASSERT(strstr(normalized, "rpc:com.atproto.repo.getRecord?aud=did:web:x") !=
               NULL,
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
    mb_scope_set_parse("repo:app.bsky.feed.post?action=create "
                       "repo:app.bsky.graph.follow?action=create",
                       &set);
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

/* Test dynamic scope types beyond repo and blob. These grammars mirror
 * bluesky-social/atproto's packages/oauth/oauth-scopes/src/scopes/ exactly
 * (identity-permission.ts, etc.) -- see the reproduction cases in issue
 * #24, which is what this
 * whole block regression-tests. */
static void test_dynamic_scopes(void) {
    TEST("identity scope parse (real client grant: identity:handle)");
    mb_scope_permission *perm = mb_scope_permission_parse("identity:handle");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_IDENTITY,
           "should parse identity:handle");
    ASSERT(strcmp(perm->u.identity.attr, "handle") == 0,
           "attr should be 'handle'");
    mb_scope_permission_free(perm);
    PASS();

    TEST("identity wildcard scope parse");
    perm = mb_scope_permission_parse("identity:*");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_IDENTITY,
           "should parse identity:*");
    ASSERT(strcmp(perm->u.identity.attr, "*") == 0, "attr should be '*'");
    mb_scope_permission_free(perm);
    PASS();

    TEST("account scope parse (real client grant: "
         "account:email?action=manage)");
    perm = mb_scope_permission_parse("account:email?action=manage");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_ACCOUNT,
           "should parse account:email?action=manage");
    ASSERT(strcmp(perm->u.account.attr, "email") == 0,
           "attr should be 'email'");
    ASSERT(perm->u.account.actions == MB_ACCOUNT_ACTION_MANAGE,
           "actions should be MANAGE only");
    mb_scope_permission_free(perm);
    PASS();

    TEST("account scope with default action (read)");
    perm = mb_scope_permission_parse("account:repo");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_ACCOUNT,
           "should parse account:repo");
    ASSERT(strcmp(perm->u.account.attr, "repo") == 0, "attr should be 'repo'");
    ASSERT(perm->u.account.actions == MB_ACCOUNT_ACTION_READ,
           "default action should be READ");
    mb_scope_permission_free(perm);
    PASS();

    TEST("rpc scope parse (real client grant: "
         "rpc:<lxm>?aud=<aud>)");
    perm = mb_scope_permission_parse(
        "rpc:com.atproto.moderation.createReport?aud=did:web:mod.example.com");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_RPC,
           "should parse rpc:...?aud=...");
    ASSERT(perm->u.rpc.lxm_count == 1 &&
               strcmp(perm->u.rpc.lxm[0],
                      "com.atproto.moderation.createReport") == 0,
           "lxm should match");
    ASSERT(strcmp(perm->u.rpc.aud, "did:web:mod.example.com") == 0,
           "aud should match");
    mb_scope_permission_free(perm);
    PASS();

    TEST("rpc scope with wildcard lxm");
    perm = mb_scope_permission_parse("rpc:*?aud=did:web:mod.example.com");
    ASSERT(perm != NULL && perm->u.rpc.lxm_wildcard,
           "should parse rpc:*?aud=... as a wildcard lxm grant");
    mb_scope_permission_free(perm);
    PASS();

    TEST("rpc:*?aud=* is rejected as an unbounded blanket grant");
    perm = mb_scope_permission_parse("rpc:*?aud=*");
    ASSERT(perm == NULL, "rpc:*?aud=* must not parse");
    PASS();

    TEST("rpc scope without aud is rejected (aud is required)");
    perm = mb_scope_permission_parse("rpc:com.example.query");
    ASSERT(perm == NULL, "rpc: without ?aud= must not parse");
    PASS();

    TEST("blob scope parse (real client grant: blob:image/*)");
    perm = mb_scope_permission_parse("blob:image/*");
    ASSERT(perm != NULL && perm->type == MB_SCOPE_TYPE_BLOB,
           "should parse blob:image/*");
    ASSERT(perm->u.blob.accept_count == 1 &&
               strcmp(perm->u.blob.accept[0], "image/*") == 0,
           "accept should match");
    mb_scope_permission_free(perm);
    PASS();

    TEST("blob scope with exact MIME type");
    perm = mb_scope_permission_parse("blob:image/png");
    ASSERT(perm != NULL && perm->u.blob.accept_count == 1 &&
               strcmp(perm->u.blob.accept[0], "image/png") == 0,
           "should parse blob:image/png");
    mb_scope_permission_free(perm);
    PASS();

    TEST("blob scope rejects an NSID (wrong domain for blob:)");
    perm = mb_scope_permission_parse("blob:com.example.foo");
    ASSERT(perm == NULL,
           "blob: must reject collection NSIDs -- it's a MIME pattern, not a "
           "collection");
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

    TEST("invalid account attr rejected");
    perm = mb_scope_permission_parse("account:invalid");
    ASSERT(perm == NULL, "account:invalid should not parse");
    PASS();

    TEST("invalid account action rejected");
    perm = mb_scope_permission_parse("account:email?action=delete");
    ASSERT(perm == NULL, "account:email?action=delete should not parse -- "
                         "'delete' is not a valid account action");
    PASS();

    TEST("old grammar identity:update no longer parses");
    perm = mb_scope_permission_parse("identity:update");
    ASSERT(perm == NULL,
           "the pre-fix invented grammar must not silently keep working");
    PASS();

    TEST("old grammar account:delete no longer parses");
    perm = mb_scope_permission_parse("account:delete");
    ASSERT(perm == NULL,
           "the pre-fix invented grammar must not silently keep working");
    PASS();
}

/* Enforcement functions: mb_scope_set_allows_identity/_account/_blob/_rpc.
 * These are what server.c's authenticate_request actually calls. */
static void test_dynamic_scope_enforcement(void) {
    TEST("identity:* satisfies any attr check");
    mb_scope_set set;
    mb_scope_set_parse("identity:*", &set);
    ASSERT(mb_scope_set_allows_identity(&set, "handle"),
           "identity:* should satisfy a handle check");
    ASSERT(mb_scope_set_allows_identity(&set, "*"),
           "identity:* should satisfy a wildcard check");
    mb_scope_set_free(&set);
    PASS();

    TEST("identity:handle does not satisfy a wildcard check");
    mb_scope_set_parse("identity:handle", &set);
    ASSERT(mb_scope_set_allows_identity(&set, "handle"),
           "identity:handle should satisfy a handle check");
    ASSERT(!mb_scope_set_allows_identity(&set, "*"),
           "identity:handle must not satisfy the broader '*' check "
           "requestPlcOperationSignature/signPlcOperation make");
    mb_scope_set_free(&set);
    PASS();

    TEST("account:email?action=manage satisfies both read and manage");
    mb_scope_set_parse("account:email?action=manage", &set);
    ASSERT(mb_scope_set_allows_account(&set, "email", MB_ACCOUNT_ACTION_READ),
           "manage implies read");
    ASSERT(mb_scope_set_allows_account(&set, "email", MB_ACCOUNT_ACTION_MANAGE),
           "manage satisfies manage");
    ASSERT(!mb_scope_set_allows_account(&set, "repo", MB_ACCOUNT_ACTION_READ),
           "must not satisfy a different attr");
    mb_scope_set_free(&set);
    PASS();

    TEST("account:repo (default read) does not satisfy manage");
    mb_scope_set_parse("account:repo", &set);
    ASSERT(mb_scope_set_allows_account(&set, "repo", MB_ACCOUNT_ACTION_READ),
           "default read satisfies read");
    ASSERT(!mb_scope_set_allows_account(&set, "repo", MB_ACCOUNT_ACTION_MANAGE),
           "read alone must not satisfy manage -- importRepo needs manage");
    mb_scope_set_free(&set);
    PASS();

    TEST("blob:image/* matches any image subtype, not other types");
    mb_scope_set_parse("blob:image/*", &set);
    ASSERT(mb_scope_set_allows_blob(&set, "image/png"),
           "image/* should match image/png");
    ASSERT(mb_scope_set_allows_blob(&set, "image/jpeg"),
           "image/* should match image/jpeg");
    ASSERT(!mb_scope_set_allows_blob(&set, "text/plain"),
           "image/* must not match text/plain");
    mb_scope_set_free(&set);
    PASS();

    TEST("blob:image/png matches only that exact type");
    mb_scope_set_parse("blob:image/png", &set);
    ASSERT(mb_scope_set_allows_blob(&set, "image/png"), "exact match");
    ASSERT(!mb_scope_set_allows_blob(&set, "image/jpeg"),
           "must not match a sibling subtype");
    mb_scope_set_free(&set);
    PASS();

    TEST("rpc: matches lxm+aud together, not separately");
    mb_scope_set_parse(
        "rpc:com.atproto.moderation.createReport?aud=did:web:mod.example.com",
        &set);
    ASSERT(mb_scope_set_allows_rpc(&set, "com.atproto.moderation.createReport",
                                   "did:web:mod.example.com"),
           "exact lxm+aud match");
    ASSERT(!mb_scope_set_allows_rpc(&set, "com.atproto.moderation.createReport",
                                    "did:web:other.example.com"),
           "must not match a different aud");
    ASSERT(!mb_scope_set_allows_rpc(&set, "com.atproto.server.getServiceAuth",
                                    "did:web:mod.example.com"),
           "must not match a different lxm");
    mb_scope_set_free(&set);
    PASS();

    TEST("rpc:*?aud=<aud> matches any lxm against that one audience");
    mb_scope_set_parse("rpc:*?aud=did:web:mod.example.com", &set);
    ASSERT(mb_scope_set_allows_rpc(&set, "com.atproto.server.getServiceAuth",
                                   "did:web:mod.example.com"),
           "wildcard lxm covers any method");
    ASSERT(!mb_scope_set_allows_rpc(&set, "com.atproto.server.getServiceAuth",
                                    "did:web:other.example.com"),
           "aud is still exact");
    mb_scope_set_free(&set);
    PASS();

    TEST("empty scope set denies every dynamic-scope check");
    mb_scope_set_parse("", &set);
    ASSERT(!mb_scope_set_allows_identity(&set, "handle"), "identity denied");
    ASSERT(!mb_scope_set_allows_account(&set, "email", MB_ACCOUNT_ACTION_READ),
           "account denied");
    ASSERT(!mb_scope_set_allows_blob(&set, "image/png"), "blob denied");
    ASSERT(!mb_scope_set_allows_rpc(&set, "com.example.query", "did:web:x"),
           "rpc denied");
    mb_scope_set_free(&set);
    PASS();

    TEST("full access (atproto) satisfies every dynamic-scope check");
    mb_scope_set_parse("atproto", &set);
    ASSERT(mb_scope_set_allows_identity(&set, "handle"), "identity allowed");
    ASSERT(mb_scope_set_allows_account(&set, "email", MB_ACCOUNT_ACTION_MANAGE),
           "account allowed");
    ASSERT(mb_scope_set_allows_blob(&set, "image/png"), "blob allowed");
    ASSERT(mb_scope_set_allows_rpc(&set, "com.example.query", "did:web:x"),
           "rpc allowed");
    mb_scope_set_free(&set);
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
    test_dynamic_scope_enforcement();
    test_read_scope_denial();

    printf("\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return tests_run == tests_passed ? 0 : 1;
}
