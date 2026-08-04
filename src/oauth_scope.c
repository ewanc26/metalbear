/*
 * oauth_scope.c — OAuth scope parsing and matching for AT Protocol
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/oauth_scope.h"
#include "metalbear/log.h"
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
        return NULL;  /* Unknown scope type */
    }
    
    /* Parse parameters after colon */
    const char *params = colon + 1;
    const char *query = strchr(params, '?');
    
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
                const char *p = query + 1;  /* Skip '?' */
                
                /* Parse action=<value> pairs */
                while (p && *p) {
                    if (starts_with(p, "action=")) {
                        p += 7;  /* Skip "action=" */
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
            /* blob:<collection> or blob:* */
            size_t coll_len = query ? (size_t)(query - params) : strlen(params);
            char *collection = strndup(params, coll_len);
            if (!collection) {
                free(perm);
                return NULL;
            }
            
            if (strcmp(collection, "*") != 0 && !is_valid_nsid(collection)) {
                free(collection);
                free(perm);
                return NULL;
            }
            
            perm->u.blob.collection = collection;
            break;
        }
        
        case MB_SCOPE_TYPE_IDENTITY: {
            /* identity:update or identity:* */
            size_t action_len = query ? (size_t)(query - params) : strlen(params);
            char *action = strndup(params, action_len);
            if (!action) {
                free(perm);
                return NULL;
            }
            
            if (strcmp(action, "update") != 0 && strcmp(action, "*") != 0) {
                free(action);
                free(perm);
                return NULL;
            }
            
            perm->u.identity.action = action;
            break;
        }
        
        case MB_SCOPE_TYPE_ACCOUNT: {
            /* account:delete or account:* */
            size_t action_len = query ? (size_t)(query - params) : strlen(params);
            char *action = strndup(params, action_len);
            if (!action) {
                free(perm);
                return NULL;
            }
            
            if (strcmp(action, "delete") != 0 && strcmp(action, "*") != 0) {
                free(action);
                free(perm);
                return NULL;
            }
            
            perm->u.account.action = action;
            break;
        }
        
        case MB_SCOPE_TYPE_RPC: {
            /* rpc:<nsid-pattern> */
            size_t nsid_len = query ? (size_t)(query - params) : strlen(params);
            char *nsid = strndup(params, nsid_len);
            if (!nsid) {
                free(perm);
                return NULL;
            }
            
            /* Validate NSID pattern (can contain *) */
            bool valid = true;
            for (char *p = nsid; *p && valid; p++) {
                if (!is_nsid_char(*p) && *p != '*') {
                    valid = false;
                }
            }
            
            if (!valid) {
                free(nsid);
                free(perm);
                return NULL;
            }
            
            perm->u.rpc.nsid = nsid;
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
            free(perm->u.blob.collection);
            break;
        case MB_SCOPE_TYPE_IDENTITY:
            free(perm->u.identity.action);
            break;
        case MB_SCOPE_TYPE_ACCOUNT:
            free(perm->u.account.action);
            break;
        case MB_SCOPE_TYPE_RPC:
            free(perm->u.rpc.nsid);
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

bool mb_scope_set_allows_repo(const mb_scope_set *set,
                               const char *collection,
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
        char buf[256];
        size_t buf_len;
        
        switch (perm->type) {
            case MB_SCOPE_TYPE_STATIC:
                buf_len = snprintf(buf, sizeof(buf), "%s",
                                   perm->u.static_scope.value);
                break;
            case MB_SCOPE_TYPE_REPO: {
                const char *actions_str = "";
                if (perm->u.repo.actions != MB_REPO_ACTION_ALL) {
                    /* Build action string */
                    char action_buf[64] = "";
                    int first = 1;
                    if (perm->u.repo.actions & MB_REPO_ACTION_CREATE) {
                        strcat(action_buf, first ? "?action=create" : "&action=create");
                        first = 0;
                    }
                    if (perm->u.repo.actions & MB_REPO_ACTION_UPDATE) {
                        strcat(action_buf, first ? "?action=update" : "&action=update");
                        first = 0;
                    }
                    if (perm->u.repo.actions & MB_REPO_ACTION_DELETE) {
                        strcat(action_buf, first ? "?action=delete" : "&action=delete");
                        first = 0;
                    }
                    actions_str = action_buf;
                }
                buf_len = snprintf(buf, sizeof(buf), "repo:%s%s",
                                   perm->u.repo.collection, actions_str);
                break;
            }
            case MB_SCOPE_TYPE_BLOB:
                buf_len = snprintf(buf, sizeof(buf), "blob:%s",
                                   perm->u.blob.collection);
                break;
            case MB_SCOPE_TYPE_IDENTITY:
                buf_len = snprintf(buf, sizeof(buf), "identity:%s",
                                   perm->u.identity.action);
                break;
            case MB_SCOPE_TYPE_ACCOUNT:
                buf_len = snprintf(buf, sizeof(buf), "account:%s",
                                   perm->u.account.action);
                break;
            case MB_SCOPE_TYPE_RPC:
                buf_len = snprintf(buf, sizeof(buf), "rpc:%s",
                                   perm->u.rpc.nsid);
                break;
            case MB_SCOPE_TYPE_INCLUDE:
                buf_len = snprintf(buf, sizeof(buf), "include:%s",
                                   perm->u.static_scope.value);
                break;
            default:
                continue;
        }
        
        if (buf_len >= sizeof(buf)) continue;
        
        /* Append to result */
        size_t new_len = len + (len > 0 ? 1 : 0) + buf_len;
        char *new_result = realloc(result, new_len + 1);
        if (!new_result) {
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
    }
    
    mb_scope_set_free(&set);
    return result ? result : strdup("");
}
