/*
 * oauth_scope.h — OAuth scope parsing and matching for AT Protocol
 *
 * Supports both static and dynamic scopes:
 *   - Static: "atproto", "transition:email", "transition:generic",
 * "transition:chat.bsky"
 *   - Dynamic: "repo:<collection>?action=<action>", "blob:*", etc.
 *
 * Scope format (repo):
 *   repo:com.example.foo                    — all actions on specific
 * collection repo:com.example.foo?action=create      — only create on specific
 * collection repo:*?action=create&action=update      — create/update on all
 * collections
 *
 * Actions: create, update, delete
 * Default actions: all three if not specified
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
            char *collection; /* NSID or "*" for blob permissions */
        } blob;
        struct {
            char *action; /* "update" or "*" */
        } identity;
        struct {
            char *action; /* "delete" or "*" */
        } account;
        struct {
            char *nsid; /* NSID pattern */
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
