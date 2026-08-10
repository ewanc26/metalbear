/*
 * oauth_scope.c — OAuth scope parsing and matching for AT Protocol
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "metalbear/oauth/oauth_scope.h"
#include "metalbear/log.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Static scope values ---- */

static const char *const STATIC_SCOPES[] = {
    MB_SCOPE_ATPROTO,
    MB_SCOPE_TRANSITION_EMAIL,
    MB_SCOPE_TRANSITION_GENERIC,
    MB_SCOPE_TRANSITION_CHAT,
};

static const size_t STATIC_SCOPE_COUNT =
    sizeof(STATIC_SCOPES) / sizeof(STATIC_SCOPES[0]);

/* ---- Helpers ---- */

static char *strdup_safe(const char *s) {
    return s ? strdup(s) : NULL;
}

static bool starts_with(const char *str, const char *prefix) {
    return str && prefix && strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool is_nsid_char(char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '-';
}

static bool is_valid_nsid(const char *str) {
    if (!str || !*str) return false;

    /* Must contain at least one dot */
    const char *dot = strchr(str, '.');
    if (!dot) return false;

    /* All characters must be valid NSID characters */
    for (const char *p = str; *p; p++) {
        if (!is_nsid_char(*p)) return false;
    }

    return true;
}

/* "*" or a valid NSID -- an rpc: lxm entry. */
static bool is_valid_lxm(const char *str) {
    return str && (strcmp(str, "*") == 0 || is_valid_nsid(str));
}

/* "*" or an atproto DID reference: a bare DID, or "did...#fragment" with a
 * non-empty fragment and no second '#'. Matches AtprotoDidRefAbsolute /
 * isAtprotoDid from the reference closely enough for scope matching
 * purposes (mirrors server.c's own valid_service_audience). */
static bool is_valid_aud(const char *str) {
    if (!str) return false;
    if (strcmp(str, "*") == 0) return true;
    const char *fragment = strchr(str, '#');
    if (!fragment) return wf_syntax_did_is_valid(str);
    if (fragment == str || !fragment[1] || strchr(fragment + 1, '#'))
        return false;
    size_t len = (size_t)(fragment - str);
    char *did = malloc(len + 1);
    if (!did) return false;
    memcpy(did, str, len);
    did[len] = '\0';
    bool valid = wf_syntax_did_is_valid(did);
    free(did);
    return valid;
}

static bool is_identity_attr(const char *str) {
    return str && (strcmp(str, "handle") == 0 || strcmp(str, "*") == 0);
}

static bool is_account_attr(const char *str) {
    return str && (strcmp(str, "email") == 0 || strcmp(str, "repo") == 0 ||
                   strcmp(str, "status") == 0);
}

/* Accepts "type/subtype", "type/wildcard", or "wildcard/wildcard" -- no
 * embedded '*' except as the whole subtype, no spaces, exactly one '/'.
 * Mirrors oauth-scopes/lib/mime.ts's isAccept(). */
static bool is_valid_accept(const char *str) {
    if (!str || !*str) return false;
    if (strcmp(str, "*/*") == 0) return true;
    const char *slash = strchr(str, '/');
    if (!slash || slash == str || !slash[1]) return false;
    if (strchr(slash + 1, '/')) return false; /* more than one slash */
    if (strchr(str, ' ')) return false;
    const char *star = strchr(str, '*');
    if (!star) return true;
    /* A '*' is only allowed as the entire subtype (type/wildcard). */
    return slash[1] == '*' && slash[2] == '\0';
}

/* ---- Generic query-string parsing (shared by identity/account/blob/rpc) --
 *
 * Each dynamic scope type has exactly one "positional" param (the text
 * between ':' and '?', e.g. the attr in "identity:handle") plus zero or more
 * named params after '?' (e.g. "action" in "account:email?action=manage").
 * A param may be given positionally OR by name, never both -- mirrors the
 * reference parser's own rule ("Positional parameter cannot be used with
 * named parameters", lib/parser.ts). */

typedef struct qparam {
    char *key;
    char *value;
} qparam;

static void query_free(qparam *params, size_t count) {
    if (!params) return;
    for (size_t i = 0; i < count; i++) {
        free(params[i].key);
        free(params[i].value);
    }
    free(params);
}

/* Parses `query` (text after '?', not including it -- may be empty). Returns
 * false only on allocation failure. */
static bool query_parse(const char *query, qparam **out, size_t *out_count) {
    *out = NULL;
    *out_count = 0;
    if (!query || !*query) return true;

    size_t cap = 4, count = 0;
    qparam *params = malloc(cap * sizeof(*params));
    if (!params) return false;

    const char *p = query;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        size_t seg_len = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', seg_len);
        char *key = NULL, *value = NULL;
        if (eq) {
            key = strndup(p, (size_t)(eq - p));
            value = strndup(eq + 1, seg_len - (size_t)(eq - p) - 1);
        } else {
            key = strndup(p, seg_len);
            value = strdup("");
        }
        if (!key || !value) {
            free(key);
            free(value);
            query_free(params, count);
            return false;
        }
        if (count == cap) {
            cap *= 2;
            qparam *tmp = realloc(params, cap * sizeof(*params));
            if (!tmp) {
                free(key);
                free(value);
                query_free(params, count);
                return false;
            }
            params = tmp;
        }
        params[count].key = key;
        params[count].value = value;
        count++;
        p = amp ? amp + 1 : NULL;
    }

    *out = params;
    *out_count = count;
    return true;
}

/* Rejects a query string carrying any key outside `allowed` -- an unknown
 * parameter makes the whole scope unparseable (mirrors the reference: "for
 * (const key of syntax.keys()) if (!schemaKeys.has(key)) return null"). */
static bool query_keys_allowed(const qparam *qp, size_t qp_count,
                               const char *const *allowed,
                               size_t allowed_count) {
    for (size_t i = 0; i < qp_count; i++) {
        bool ok = false;
        for (size_t j = 0; j < allowed_count; j++) {
            if (strcmp(qp[i].key, allowed[j]) == 0) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }
    return true;
}

/* Collects every named occurrence of `key`, or the one positional value when
 * `positional_len` is non-zero (never both -- the same positional-vs-named
 * exclusivity rule as the reference parser), into a caller-owned array.
 * *out_count is 0 when legitimately absent. Returns false on conflict or
 * allocation failure. */
static bool extract_multi(const char *positional, size_t positional_len,
                          const qparam *qp, size_t qp_count, const char *key,
                          char ***out_values, size_t *out_count) {
    *out_values = NULL;
    *out_count = 0;
    size_t named_count = 0;
    for (size_t i = 0; i < qp_count; i++) {
        if (strcmp(qp[i].key, key) == 0) named_count++;
    }
    if (positional_len > 0 && named_count > 0) return false;
    if (positional_len > 0) {
        char *v = strndup(positional, positional_len);
        if (!v) return false;
        char **arr = malloc(sizeof(char *));
        if (!arr) {
            free(v);
            return false;
        }
        arr[0] = v;
        *out_values = arr;
        *out_count = 1;
        return true;
    }
    if (named_count > 0) {
        char **arr = malloc(named_count * sizeof(char *));
        if (!arr) return false;
        size_t n = 0;
        for (size_t i = 0; i < qp_count; i++) {
            if (strcmp(qp[i].key, key) == 0) {
                arr[n] = strdup(qp[i].value);
                if (!arr[n]) {
                    for (size_t j = 0; j < n; j++) free(arr[j]);
                    free(arr);
                    return false;
                }
                n++;
            }
        }
        *out_values = arr;
        *out_count = n;
        return true;
    }
    return true; /* absent */
}

static void free_string_array(char **values, size_t count) {
    if (!values) return;
    for (size_t i = 0; i < count; i++) free(values[i]);
    free(values);
}

/* ---- Scope permission parsing ---- */

mb_scope_permission *mb_scope_permission_parse(const char *str) {
    if (!str || !*str) return NULL;

    /* Check for static scope */
    for (size_t i = 0; i < STATIC_SCOPE_COUNT; i++) {
        if (strcmp(str, STATIC_SCOPES[i]) == 0) {
            mb_scope_permission *perm = calloc(1, sizeof(*perm));
            if (!perm) return NULL;
            perm->type = MB_SCOPE_TYPE_STATIC;
            perm->u.static_scope.value = strdup(str);
            if (!perm->u.static_scope.value) {
                free(perm);
                return NULL;
            }
            return perm;
        }
    }

    /* Parse dynamic scope: <type>:<params> */
    const char *colon = strchr(str, ':');
    if (!colon) return NULL;

    size_t type_len = colon - str;
    if (type_len == 0) return NULL;

    /* Determine scope type */
    mb_scope_type type;
    if (strncmp(str, "repo", type_len) == 0) {
        type = MB_SCOPE_TYPE_REPO;
    } else if (strncmp(str, "blob", type_len) == 0) {
        type = MB_SCOPE_TYPE_BLOB;
    } else if (strncmp(str, "identity", type_len) == 0) {
        type = MB_SCOPE_TYPE_IDENTITY;
    } else if (strncmp(str, "account", type_len) == 0) {
        type = MB_SCOPE_TYPE_ACCOUNT;
    } else if (strncmp(str, "rpc", type_len) == 0) {
        type = MB_SCOPE_TYPE_RPC;
    } else if (strncmp(str, "include", type_len) == 0) {
        type = MB_SCOPE_TYPE_INCLUDE;
    } else {
        return NULL; /* Unknown scope type */
    }

    /* Parse parameters after colon */
    const char *params = colon + 1;
    const char *query = strchr(params, '?');
    size_t positional_len = query ? (size_t)(query - params) : strlen(params);

    mb_scope_permission *perm = calloc(1, sizeof(*perm));
    if (!perm) return NULL;
    perm->type = type;

    switch (type) {
        case MB_SCOPE_TYPE_REPO: {
            /* Extract collection */
            size_t coll_len = query ? (size_t)(query - params) : strlen(params);
            char *collection = strndup(params, coll_len);
            if (!collection) {
                free(perm);
                return NULL;
            }

            /* Validate collection: must be "*" or valid NSID */
            if (strcmp(collection, "*") != 0 && !is_valid_nsid(collection)) {
                free(collection);
                free(perm);
                return NULL;
            }

            perm->u.repo.collection = collection;

            /* Parse actions from query string */
            mb_repo_action actions = MB_REPO_ACTION_ALL;
            if (query) {
                actions = MB_REPO_ACTION_NONE;
                const char *p = query + 1; /* Skip '?' */

                /* Parse action=<value> pairs */
                while (p && *p) {
                    if (starts_with(p, "action=")) {
                        p += 7; /* Skip "action=" */
                        const char *amp = strchr(p, '&');
                        size_t action_len = amp ? (size_t)(amp - p) : strlen(p);

                        if (strncmp(p, "create", action_len) == 0) {
                            actions |= MB_REPO_ACTION_CREATE;
                        } else if (strncmp(p, "update", action_len) == 0) {
                            actions |= MB_REPO_ACTION_UPDATE;
                        } else if (strncmp(p, "delete", action_len) == 0) {
                            actions |= MB_REPO_ACTION_DELETE;
                        }

                        p = amp ? amp + 1 : NULL;
                    } else {
                        /* Skip unknown parameter */
                        const char *amp = strchr(p, '&');
                        p = amp ? amp + 1 : NULL;
                    }
                }
            }

            perm->u.repo.actions = actions;
            break;
        }

        case MB_SCOPE_TYPE_BLOB: {
            /* blob:<mime> (single) or blob:?accept=<mime>&accept=<mime> ...
             * (multiple, matching the reference's "accept" param, which is
             * repeatable). */
            qparam *qp = NULL;
            size_t qp_count = 0;
            if (!query_parse(query ? query + 1 : NULL, &qp, &qp_count)) {
                free(perm);
                return NULL;
            }
            static const char *const allowed[] = {"accept"};
            if (!query_keys_allowed(qp, qp_count, allowed, 1)) {
                query_free(qp, qp_count);
                free(perm);
                return NULL;
            }

            char **accept = NULL;
            size_t accept_count = 0;
            bool ok = extract_multi(params, positional_len, qp, qp_count,
                                    "accept", &accept, &accept_count);
            query_free(qp, qp_count);
            if (!ok || accept_count == 0) {
                free_string_array(accept, accept_count);
                free(perm);
                return NULL;
            }
            for (size_t i = 0; i < accept_count; i++) {
                if (!is_valid_accept(accept[i])) {
                    free_string_array(accept, accept_count);
                    free(perm);
                    return NULL;
                }
            }

            perm->u.blob.accept = accept;
            perm->u.blob.accept_count = accept_count;
            break;
        }

        case MB_SCOPE_TYPE_IDENTITY: {
            /* identity:handle or identity:* -- attr is positional-only:
             * every reference call site sends it that way. */
            qparam *qp = NULL;
            size_t qp_count = 0;
            if (!query_parse(query ? query + 1 : NULL, &qp, &qp_count)) {
                free(perm);
                return NULL;
            }
            if (qp_count > 0) {
                /* No named params are recognized for identity:. */
                query_free(qp, qp_count);
                free(perm);
                return NULL;
            }
            query_free(qp, qp_count);

            if (positional_len == 0) {
                free(perm);
                return NULL;
            }
            char *attr = strndup(params, positional_len);
            if (!attr || !is_identity_attr(attr)) {
                free(attr);
                free(perm);
                return NULL;
            }
            perm->u.identity.attr = attr;
            break;
        }

        case MB_SCOPE_TYPE_ACCOUNT: {
            /* account:<attr>?action=<action>[&action=<action>] -- attr is
             * positional-only (every reference call site sends it that
             * way); action defaults to "read" and "manage" implies "read". */
            qparam *qp = NULL;
            size_t qp_count = 0;
            if (!query_parse(query ? query + 1 : NULL, &qp, &qp_count)) {
                free(perm);
                return NULL;
            }
            static const char *const allowed[] = {"action"};
            if (!query_keys_allowed(qp, qp_count, allowed, 1)) {
                query_free(qp, qp_count);
                free(perm);
                return NULL;
            }

            if (positional_len == 0) {
                query_free(qp, qp_count);
                free(perm);
                return NULL;
            }
            char *attr = strndup(params, positional_len);
            if (!attr || !is_account_attr(attr)) {
                free(attr);
                query_free(qp, qp_count);
                free(perm);
                return NULL;
            }

            size_t action_count = 0;
            for (size_t i = 0; i < qp_count; i++) {
                if (strcmp(qp[i].key, "action") == 0) action_count++;
            }
            mb_account_action bits = MB_ACCOUNT_ACTION_NONE;
            if (action_count == 0) {
                bits = MB_ACCOUNT_ACTION_READ; /* default */
            } else {
                bool valid = true;
                for (size_t i = 0; i < qp_count && valid; i++) {
                    if (strcmp(qp[i].key, "action") != 0) continue;
                    if (strcmp(qp[i].value, "read") == 0) {
                        bits |= MB_ACCOUNT_ACTION_READ;
                    } else if (strcmp(qp[i].value, "manage") == 0) {
                        bits |= MB_ACCOUNT_ACTION_MANAGE;
                    } else {
                        valid = false;
                    }
                }
                if (!valid) {
                    free(attr);
                    query_free(qp, qp_count);
                    free(perm);
                    return NULL;
                }
            }
            query_free(qp, qp_count);

            perm->u.account.attr = attr;
            perm->u.account.actions = bits;
            break;
        }

        case MB_SCOPE_TYPE_RPC: {
            /* rpc:<lxm>?aud=<aud> -- lxm may be positional (single) or
             * named/repeated ("?lxm=a&lxm=b&aud=x"); aud is always named and
             * required. "rpc:*?aud=*" is explicitly forbidden (unbounded
             * blanket grant). */
            qparam *qp = NULL;
            size_t qp_count = 0;
            if (!query_parse(query ? query + 1 : NULL, &qp, &qp_count)) {
                free(perm);
                return NULL;
            }
            static const char *const allowed[] = {"lxm", "aud"};
            if (!query_keys_allowed(qp, qp_count, allowed, 2)) {
                query_free(qp, qp_count);
                free(perm);
                return NULL;
            }

            char **lxm = NULL;
            size_t lxm_count = 0;
            bool ok = extract_multi(params, positional_len, qp, qp_count, "lxm",
                                    &lxm, &lxm_count);
            if (!ok || lxm_count == 0) {
                free_string_array(lxm, lxm_count);
                query_free(qp, qp_count);
                free(perm);
                return NULL;
            }
            bool lxm_wildcard = false;
            for (size_t i = 0; i < lxm_count; i++) {
                if (!is_valid_lxm(lxm[i])) {
                    free_string_array(lxm, lxm_count);
                    query_free(qp, qp_count);
                    free(perm);
                    return NULL;
                }
                if (strcmp(lxm[i], "*") == 0) lxm_wildcard = true;
            }

            char *aud = NULL;
            for (size_t i = 0; i < qp_count; i++) {
                if (strcmp(qp[i].key, "aud") == 0) {
                    if (aud) { /* aud must appear at most once */
                        free(aud);
                        aud = NULL;
                        break;
                    }
                    aud = strdup(qp[i].value);
                }
            }
            query_free(qp, qp_count);
            if (!aud || !is_valid_aud(aud)) {
                free(aud);
                free_string_array(lxm, lxm_count);
                free(perm);
                return NULL;
            }
            if (lxm_wildcard && strcmp(aud, "*") == 0) {
                /* rpc:*?aud=* would be an unbounded grant. */
                free(aud);
                free_string_array(lxm, lxm_count);
                free(perm);
                return NULL;
            }

            perm->u.rpc.lxm = lxm;
            perm->u.rpc.lxm_count = lxm_count;
            perm->u.rpc.lxm_wildcard = lxm_wildcard;
            perm->u.rpc.aud = aud;
            break;
        }

        case MB_SCOPE_TYPE_INCLUDE: {
            /* include:<scope> - reference to another scope */
            perm->u.static_scope.value = strdup_safe(params);
            if (!perm->u.static_scope.value) {
                free(perm);
                return NULL;
            }
            break;
        }

        default:
            free(perm);
            return NULL;
    }

    return perm;
}

void mb_scope_permission_free(mb_scope_permission *perm) {
    if (!perm) return;

    switch (perm->type) {
        case MB_SCOPE_TYPE_STATIC:
        case MB_SCOPE_TYPE_INCLUDE:
            free(perm->u.static_scope.value);
            break;
        case MB_SCOPE_TYPE_REPO:
            free(perm->u.repo.collection);
            break;
        case MB_SCOPE_TYPE_BLOB:
            free_string_array(perm->u.blob.accept, perm->u.blob.accept_count);
            break;
        case MB_SCOPE_TYPE_IDENTITY:
            free(perm->u.identity.attr);
            break;
        case MB_SCOPE_TYPE_ACCOUNT:
            free(perm->u.account.attr);
            break;
        case MB_SCOPE_TYPE_RPC:
            free_string_array(perm->u.rpc.lxm, perm->u.rpc.lxm_count);
            free(perm->u.rpc.aud);
            break;
    }
}

/* ---- Scope set operations ---- */

int mb_scope_set_parse(const char *scope_str, mb_scope_set *out) {
    if (!out) return WF_ERR_INVALID_ARG;

    memset(out, 0, sizeof(*out));

    if (!scope_str || !*scope_str) return WF_OK;

    /* Count scopes (space-separated) */
    size_t count = 1;
    for (const char *p = scope_str; *p; p++) {
        if (*p == ' ') count++;
    }

    /* Allocate array */
    out->permissions = calloc(count, sizeof(*out->permissions));
    if (!out->permissions) return WF_ERR_ALLOC;
    out->capacity = count;

    /* Parse each scope */
    char *str = strdup(scope_str);
    if (!str) {
        free(out->permissions);
        memset(out, 0, sizeof(*out));
        return WF_ERR_ALLOC;
    }

    char *saveptr;
    char *token = strtok_r(str, " ", &saveptr);
    while (token) {
        /* Skip empty tokens */
        while (*token == ' ') token++;
        if (!*token) {
            token = strtok_r(NULL, " ", &saveptr);
            continue;
        }

        mb_scope_permission *perm = mb_scope_permission_parse(token);
        if (perm) {
            /* Transfer ownership */
            out->permissions[out->count++] = *perm;
            free(perm);
        } else {
            LOG_DEBUG("mb_scope_set_parse: ignoring invalid scope '%s'", token);
        }

        token = strtok_r(NULL, " ", &saveptr);
    }

    free(str);
    return WF_OK;
}

void mb_scope_set_free(mb_scope_set *set) {
    if (!set) return;

    for (size_t i = 0; i < set->count; i++) {
        mb_scope_permission_free(&set->permissions[i]);
    }
    free(set->permissions);
    memset(set, 0, sizeof(*set));
}

bool mb_scope_set_is_full_access(const mb_scope_set *set) {
    if (!set) return false;

    for (size_t i = 0; i < set->count; i++) {
        const mb_scope_permission *perm = &set->permissions[i];

        /* "atproto" grants full access */
        if (perm->type == MB_SCOPE_TYPE_STATIC &&
            strcmp(perm->u.static_scope.value, MB_SCOPE_ATPROTO) == 0) {
            return true;
        }

        /* Wildcard repo with all actions grants full access */
        if (perm->type == MB_SCOPE_TYPE_REPO &&
            strcmp(perm->u.repo.collection, "*") == 0 &&
            perm->u.repo.actions == MB_REPO_ACTION_ALL) {
            return true;
        }
    }

    return false;
}

bool mb_scope_set_allows_repo(const mb_scope_set *set, const char *collection,
                              mb_repo_action action) {
    if (!set || !collection) return false;

    /* Full access grants everything */
    if (mb_scope_set_is_full_access(set)) return true;

    for (size_t i = 0; i < set->count; i++) {
        const mb_scope_permission *perm = &set->permissions[i];

        if (perm->type == MB_SCOPE_TYPE_REPO) {
            /* Check collection match */
            bool coll_match = strcmp(perm->u.repo.collection, "*") == 0 ||
                              strcmp(perm->u.repo.collection, collection) == 0;

            /* Check action match */
            bool action_match = (perm->u.repo.actions & action) != 0;

            if (coll_match && action_match) return true;
        }
    }

    return false;
}

bool mb_scope_set_allows_read(const mb_scope_set *set, const char *collection) {
    if (!set || !collection) return false;

    /* Full access grants everything */
    if (mb_scope_set_is_full_access(set)) return true;

    for (size_t i = 0; i < set->count; i++) {
        const mb_scope_permission *perm = &set->permissions[i];

        if (perm->type == MB_SCOPE_TYPE_REPO) {
            /* Any repo permission grants read access to that collection */
            if (strcmp(perm->u.repo.collection, "*") == 0 ||
                strcmp(perm->u.repo.collection, collection) == 0) {
                return true;
            }
        }
    }

    return false;
}

bool mb_scope_set_allows_identity(const mb_scope_set *set, const char *attr) {
    if (!set || !attr) return false;
    if (mb_scope_set_is_full_access(set)) return true;

    for (size_t i = 0; i < set->count; i++) {
        const mb_scope_permission *perm = &set->permissions[i];
        if (perm->type != MB_SCOPE_TYPE_IDENTITY) continue;
        if (strcmp(perm->u.identity.attr, "*") == 0 ||
            strcmp(perm->u.identity.attr, attr) == 0) {
            return true;
        }
    }
    return false;
}

bool mb_scope_set_allows_account(const mb_scope_set *set, const char *attr,
                                 mb_account_action action) {
    if (!set || !attr) return false;
    if (mb_scope_set_is_full_access(set)) return true;

    for (size_t i = 0; i < set->count; i++) {
        const mb_scope_permission *perm = &set->permissions[i];
        if (perm->type != MB_SCOPE_TYPE_ACCOUNT) continue;
        if (strcmp(perm->u.account.attr, attr) != 0) continue;
        if ((perm->u.account.actions & MB_ACCOUNT_ACTION_MANAGE) ||
            (perm->u.account.actions & action)) {
            return true;
        }
    }
    return false;
}

bool mb_scope_set_allows_blob(const mb_scope_set *set, const char *mime) {
    if (!set || !mime || !strchr(mime, '/')) return false;
    if (mb_scope_set_is_full_access(set)) return true;

    for (size_t i = 0; i < set->count; i++) {
        const mb_scope_permission *perm = &set->permissions[i];
        if (perm->type != MB_SCOPE_TYPE_BLOB) continue;
        for (size_t j = 0; j < perm->u.blob.accept_count; j++) {
            const char *accept = perm->u.blob.accept[j];
            if (strcmp(accept, "*/*") == 0) return true;
            size_t alen = strlen(accept);
            if (alen > 1 && accept[alen - 1] == '*' &&
                strncmp(accept, mime, alen - 1) == 0) {
                return true; /* type-wildcard, e.g. image/wildcard */
            }
            if (strcmp(accept, mime) == 0) return true;
        }
    }
    return false;
}

bool mb_scope_set_allows_rpc(const mb_scope_set *set, const char *lxm,
                             const char *aud) {
    if (!set || !lxm || !aud) return false;
    if (mb_scope_set_is_full_access(set)) return true;

    for (size_t i = 0; i < set->count; i++) {
        const mb_scope_permission *perm = &set->permissions[i];
        if (perm->type != MB_SCOPE_TYPE_RPC) continue;
        bool aud_match = strcmp(perm->u.rpc.aud, "*") == 0 ||
                         strcmp(perm->u.rpc.aud, aud) == 0;
        if (!aud_match) continue;
        if (perm->u.rpc.lxm_wildcard) return true;
        for (size_t j = 0; j < perm->u.rpc.lxm_count; j++) {
            if (strcmp(perm->u.rpc.lxm[j], lxm) == 0) return true;
        }
    }
    return false;
}

/* ---- Utility functions ---- */

bool mb_is_static_scope(const char *value) {
    if (!value) return false;

    for (size_t i = 0; i < STATIC_SCOPE_COUNT; i++) {
        if (strcmp(value, STATIC_SCOPES[i]) == 0) {
            return true;
        }
    }

    return false;
}

char *mb_scope_normalize(const char *scope_str) {
    mb_scope_set set;
    if (mb_scope_set_parse(scope_str, &set) != WF_OK) {
        return NULL;
    }

    /* Build normalized string */
    char *result = NULL;
    size_t len = 0;

    for (size_t i = 0; i < set.count; i++) {
        const mb_scope_permission *perm = &set.permissions[i];
        char *buf = NULL;
        int buf_len_signed;

        switch (perm->type) {
            case MB_SCOPE_TYPE_STATIC:
                buf_len_signed =
                    asprintf(&buf, "%s", perm->u.static_scope.value);
                break;
            case MB_SCOPE_TYPE_REPO: {
                const char *actions_str = "";
                char action_buf[64] = "";
                if (perm->u.repo.actions != MB_REPO_ACTION_ALL) {
                    int first = 1;
                    if (perm->u.repo.actions & MB_REPO_ACTION_CREATE) {
                        strcat(action_buf,
                               first ? "?action=create" : "&action=create");
                        first = 0;
                    }
                    if (perm->u.repo.actions & MB_REPO_ACTION_UPDATE) {
                        strcat(action_buf,
                               first ? "?action=update" : "&action=update");
                        first = 0;
                    }
                    if (perm->u.repo.actions & MB_REPO_ACTION_DELETE) {
                        strcat(action_buf,
                               first ? "?action=delete" : "&action=delete");
                        first = 0;
                    }
                    actions_str = action_buf;
                }
                buf_len_signed = asprintf(&buf, "repo:%s%s",
                                          perm->u.repo.collection, actions_str);
                break;
            }
            case MB_SCOPE_TYPE_BLOB:
                buf_len_signed =
                    asprintf(&buf, "blob:%s", perm->u.blob.accept[0]);
                break;
            case MB_SCOPE_TYPE_IDENTITY:
                buf_len_signed =
                    asprintf(&buf, "identity:%s", perm->u.identity.attr);
                break;
            case MB_SCOPE_TYPE_ACCOUNT: {
                const char *action_str =
                    (perm->u.account.actions & MB_ACCOUNT_ACTION_MANAGE)
                        ? "?action=manage"
                        : "";
                buf_len_signed = asprintf(&buf, "account:%s%s",
                                          perm->u.account.attr, action_str);
                break;
            }
            case MB_SCOPE_TYPE_RPC:
                buf_len_signed = asprintf(&buf, "rpc:%s?aud=%s",
                                          perm->u.rpc.lxm[0], perm->u.rpc.aud);
                break;
            case MB_SCOPE_TYPE_INCLUDE:
                buf_len_signed =
                    asprintf(&buf, "include:%s", perm->u.static_scope.value);
                break;
            default:
                continue;
        }

        if (buf_len_signed < 0) {
            free(buf);
            continue;
        }
        size_t buf_len = (size_t)buf_len_signed;

        /* Append to result */
        size_t new_len = len + (len > 0 ? 1 : 0) + buf_len;
        char *new_result = realloc(result, new_len + 1);
        if (!new_result) {
            free(buf);
            free(result);
            mb_scope_set_free(&set);
            return NULL;
        }
        result = new_result;

        if (len > 0) {
            result[len++] = ' ';
        }
        memcpy(result + len, buf, buf_len);
        len = new_len;
        result[len] = '\0';
        free(buf);
    }

    mb_scope_set_free(&set);
    return result ? result : strdup("");
}
