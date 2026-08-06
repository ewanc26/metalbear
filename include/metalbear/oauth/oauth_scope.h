/*
 * oauth_scope.h — OAuth scope parsing and matching for AT Protocol
 *
 * Supports both static and dynamic scopes:
 *   - Static: "atproto", "transition:email", "transition:generic",
 * "transition:chat.bsky"
 *   - Dynamic: "repo:<collection>?action=<action>", "blob:<mime>",
 *     "identity:<attr>", "account:<attr>?action=<action>",
 * "rpc:<lxm>?aud=<aud>"
 *
 * Grammar mirrors bluesky-social/atproto's
 * packages/oauth/oauth-scopes/src/scopes/ (identity-permission.ts, etc.)
 * exactly (positional param before '?', named params after):
 *
 *   repo:com.example.foo                    — all actions on one collection
 *   repo:com.example.foo?action=create      — only create on one collection
 *   repo:*?action=create&action=update      — create/update on all collections
 *   blob:image/png                          — one exact MIME type
 *   blob:image/<wildcard>                    — MIME wildcard by top-level type
 *   blob:<wildcard>/<wildcard>               — any MIME type
 *   identity:handle                         — only the handle attribute
 *   identity:*                              — any identity attribute
 *   account:email?action=manage             — manage the email attribute
 *   account:repo                            — read (default action) the repo
 *                                              attribute
 *   rpc:com.example.query?aud=did:web:x     — one lxm against one audience
 *   rpc:*?aud=did:web:x                     — any lxm against one audience
 *
 * repo actions: create, update, delete (default: all three)
 * account attrs: email, repo, status; actions: read, manage (default: read;
 *   manage implies read)
 * identity attrs: handle, * (default: none — always explicit)
 * rpc: "*" for lxm or aud alone is allowed, but "rpc:*?aud=*" (both wildcard)
 *   is rejected as an unbounded blanket grant, matching the reference.
 */

#ifndef METALBEAR_OAUTH_SCOPE_H
#define METALBEAR_OAUTH_SCOPE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Static scope values */
#define MB_SCOPE_ATPROTO "atproto"
#define MB_SCOPE_TRANSITION_EMAIL "transition:email"
#define MB_SCOPE_TRANSITION_GENERIC "transition:generic"
#define MB_SCOPE_TRANSITION_CHAT "transition:chat.bsky"

/* Scope permission types */
typedef enum mb_scope_type {
    MB_SCOPE_TYPE_STATIC,
    MB_SCOPE_TYPE_REPO,
    MB_SCOPE_TYPE_BLOB,
    MB_SCOPE_TYPE_IDENTITY,
    MB_SCOPE_TYPE_ACCOUNT,
    MB_SCOPE_TYPE_RPC,
    MB_SCOPE_TYPE_INCLUDE,
} mb_scope_type;

/* Repo action flags */
typedef enum mb_repo_action {
    MB_REPO_ACTION_NONE = 0,
    MB_REPO_ACTION_CREATE = 1 << 0,
    MB_REPO_ACTION_UPDATE = 1 << 1,
    MB_REPO_ACTION_DELETE = 1 << 2,
    MB_REPO_ACTION_ALL =
        MB_REPO_ACTION_CREATE | MB_REPO_ACTION_UPDATE | MB_REPO_ACTION_DELETE,
} mb_repo_action;

/* account: action flags. MANAGE implies READ (mb_scope_set_allows_account
 * treats a grant carrying MANAGE as satisfying a READ check too), matching
 * the reference's `action.includes('manage') || action.includes(action)`. */
typedef enum mb_account_action {
    MB_ACCOUNT_ACTION_NONE = 0,
    MB_ACCOUNT_ACTION_READ = 1 << 0,
    MB_ACCOUNT_ACTION_MANAGE = 1 << 1,
} mb_account_action;

/* Parsed scope permission */
typedef struct mb_scope_permission {
    mb_scope_type type;
    union {
        struct {
            char *value; /* "atproto", "transition:email", etc. */
        } static_scope;
        struct {
            char *collection; /* NSID or "*" */
            mb_repo_action actions;
        } repo;
        struct {
            char **accept; /* MIME patterns: "image/png", "image/wildcard",
                             "wildcard/wildcard" */
            size_t accept_count;
        } blob;
        struct {
            char *attr; /* "handle" or "*" */
        } identity;
        struct {
            char *attr;                /* "email", "repo", or "status" */
            mb_account_action actions; /* bitmask, default READ */
        } account;
        struct {
            char **lxm; /* one or more NSIDs, or ["*"] */
            size_t lxm_count;
            bool lxm_wildcard; /* true if lxm includes "*" */
            char *aud;         /* DID (optionally "did...#service"), or "*" */
        } rpc;
    } u;
} mb_scope_permission;

/* Owned array of parsed scope permissions */
typedef struct mb_scope_set {
    mb_scope_permission *permissions;
    size_t count;
    size_t capacity;
} mb_scope_set;

/**
 * Parse a space-separated scope string into a scope set.
 * Invalid scopes are silently ignored (per OAuth spec).
 * Returns WF_OK on success, WF_ERR_ALLOC on allocation failure.
 */
int mb_scope_set_parse(const char *scope_str, mb_scope_set *out);

/**
 * Free a scope set and all owned strings.
 */
void mb_scope_set_free(mb_scope_set *set);

/**
 * Check if a scope set grants full "atproto" access.
 * This is true if the set contains "atproto" or a wildcard repo scope
 * with all actions.
 */
bool mb_scope_set_is_full_access(const mb_scope_set *set);

/**
 * Check if a repo operation is allowed by the scope set.
 * @param collection The NSID of the collection being accessed
 * @param action The action being performed (create, update, or delete)
 * @return true if the operation is allowed
 */
bool mb_scope_set_allows_repo(const mb_scope_set *set, const char *collection,
                              mb_repo_action action);

/**
 * Check if a scope set allows reading a collection.
 * Read access is granted if any repo permission matches the collection
 * (since repo permissions grant both read and write).
 */
bool mb_scope_set_allows_read(const mb_scope_set *set, const char *collection);

/**
 * Check if a scope set allows the given identity attribute
 * (`assertIdentity({attr})` in the reference: requestPlcOperationSignature /
 * signPlcOperation / submitPlcOperation check "*"; updateHandle checks
 * "handle"). A grant of "identity:*" satisfies any attr.
 */
bool mb_scope_set_allows_identity(const mb_scope_set *set, const char *attr);

/**
 * Check if a scope set allows the given account attribute + action
 * (`assertAccount({attr, action})` in the reference). A grant whose actions
 * include MANAGE satisfies either a READ or a MANAGE check for that attr.
 */
bool mb_scope_set_allows_account(const mb_scope_set *set, const char *attr,
                                 mb_account_action action);

/**
 * Check if a scope set allows uploading a blob of the given MIME type
 * (`assertBlob({mime})` in the reference, checked against uploadBlob's
 * Content-Type). `mime` must be a concrete type ("image/png"), not a
 * pattern; matching against a wildcard grant (any-type or type-wildcard) is
 * handled internally.
 */
bool mb_scope_set_allows_blob(const mb_scope_set *set, const char *mime);

/**
 * Check if a scope set allows a proxied/service-authed call to the given
 * lxm against the given audience (`assertRpc({lxm, aud})` in the
 * reference — createReport, getServiceAuth, proxied app.bsky.* reads).
 * `aud` is the target service's DID, optionally with a `#serviceId`
 * fragment; `lxm` is the NSID of the method being called.
 */
bool mb_scope_set_allows_rpc(const mb_scope_set *set, const char *lxm,
                             const char *aud);

/**
 * Normalize a scope string (deduplicate, sort, validate).
 * Caller must free the returned string.
 * Returns NULL on allocation failure.
 */
char *mb_scope_normalize(const char *scope_str);

/**
 * Check if a string is a valid static scope value.
 */
bool mb_is_static_scope(const char *value);

/**
 * Parse a single scope permission from a string.
 * Returns NULL if the scope is invalid.
 * Caller must free with mb_scope_permission_free().
 */
mb_scope_permission *mb_scope_permission_parse(const char *str);

/**
 * Free a single scope permission.
 */
void mb_scope_permission_free(mb_scope_permission *perm);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_OAUTH_SCOPE_H */
