/*
 * blob_store.c — in-memory / file-backed blob store keyed by CID string.
 *
 * A small, self-contained store letting MetalBear persist and serve blobs as a
 * PDS would. See blob_store.h for ownership and mode semantics.
 */

#include "metalbear/repo/blob_store.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>

typedef struct metalbear_blob_node {
    char *cid;           /* owned CID string (key) */
    char *mime;          /* owned MIME type */
    unsigned char *data; /* owned blob bytes */
    size_t len;
    char **refs; /* owned array of owned record URI strings */
    size_t ref_count;
    struct metalbear_blob_node *next;
} metalbear_blob_node;

struct metalbear_blob_store {
    bool file_backed;
    char *dir;                 /* owned base directory (file-backed only) */
    metalbear_blob_node *head; /* in-memory index; source of truth */
};

/* Join dir + name into a heap buffer (caller frees). Tolerates a trailing
 * slash on dir. Returns NULL on allocation failure. */
static char *blob_path(const char *dir, const char *name) {
    size_t dlen = strlen(dir);
    size_t nlen = strlen(name);
    int sep = (dlen > 0 && dir[dlen - 1] == '/') ? 0 : 1;
    char *out = (char *)malloc(dlen + nlen + 1 + sep);
    if (!out) return NULL;
    memcpy(out, dir, dlen);
    if (sep) out[dlen] = '/';
    memcpy(out + dlen + sep, name, nlen);
    out[dlen + sep + nlen] = '\0';
    return out;
}

/* Append a node to the store's in-memory index (takes ownership of args). */
static wf_status blob_node_push(metalbear_blob_store *store, char *cid,
                                char *mime, unsigned char *data, size_t len) {
    metalbear_blob_node *node = (metalbear_blob_node *)calloc(1, sizeof(*node));
    if (!node) {
        free(cid);
        free(mime);
        free(data);
        return WF_ERR_ALLOC;
    }
    node->cid = cid;
    node->mime = mime;
    node->data = data;
    node->len = len;
    node->next = store->head;
    store->head = node;
    return WF_OK;
}

static void blob_node_free(metalbear_blob_node *node) {
    if (!node) return;
    free(node->cid);
    free(node->mime);
    free(node->data);
    for (size_t i = 0; i < node->ref_count; i++) free(node->refs[i]);
    free(node->refs);
    free(node);
}

/* Find a node by CID, or NULL. */
static metalbear_blob_node *blob_node_find(metalbear_blob_store *store,
                                           const char *cid) {
    for (metalbear_blob_node *n = store->head; n; n = n->next)
        if (strcmp(n->cid, cid) == 0) return n;
    return NULL;
}

static size_t refs_index_of(metalbear_blob_node *n, const char *uri) {
    for (size_t i = 0; i < n->ref_count; i++)
        if (strcmp(n->refs[i], uri) == 0) return i;
    return n->ref_count; /* not found */
}

/* Append `uri` to a node's association list (caller has already checked it
 * is not a duplicate). Returns WF_ERR_ALLOC on OOM. */
static wf_status refs_append(metalbear_blob_node *n, const char *uri) {
    char **grown =
        (char **)realloc(n->refs, (n->ref_count + 1) * sizeof(*grown));
    if (!grown) return WF_ERR_ALLOC;
    n->refs = grown;
    char *copy = strdup(uri);
    if (!copy) return WF_ERR_ALLOC;
    n->refs[n->ref_count++] = copy;
    return WF_OK;
}

/* Remove the association at `idx` (swap-with-last; order is unspecified and
 * unobserved by any caller). */
static void refs_remove_at(metalbear_blob_node *n, size_t idx) {
    free(n->refs[idx]);
    n->refs[idx] = n->refs[n->ref_count - 1];
    n->ref_count--;
}

/* Path to a blob's association sidecar (file-backed stores only). Caller
 * frees. Returns NULL on allocation failure. */
static char *blob_refs_path(const char *dir, const char *cid) {
    char *p = blob_path(dir, cid);
    if (!p) return NULL;
    size_t plen = strlen(p);
    char *grown = (char *)realloc(p, plen + 6); /* ".refs\0" */
    if (!grown) {
        free(p);
        return NULL;
    }
    memcpy(grown + plen, ".refs", 6);
    return grown;
}

/* Rewrite (or remove, if empty) a node's association sidecar to match its
 * in-memory state. Best-effort: an IO failure here does not unwind the
 * in-memory change, matching the store's existing "in-memory index is the
 * source of truth" contract. */
static void persist_refs(metalbear_blob_store *store, metalbear_blob_node *n) {
    if (!store->file_backed) return;
    char *path = blob_refs_path(store->dir, n->cid);
    if (!path) return;
    if (n->ref_count == 0) {
        remove(path);
        free(path);
        return;
    }
    FILE *f = fopen(path, "wb");
    if (f) {
        for (size_t i = 0; i < n->ref_count; i++)
            fprintf(f, "%s\n", n->refs[i]);
        fclose(f);
    }
    free(path);
}

/* Load a node's association sidecar, if present, into its in-memory refs. */
static void load_refs(metalbear_blob_store *store, metalbear_blob_node *n) {
    char *path = blob_refs_path(store->dir, n->cid);
    if (!path) return;
    FILE *f = fopen(path, "rb");
    free(path);
    if (!f) return;
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        if (l == 0) continue;
        if (refs_index_of(n, line) != n->ref_count) continue; /* dedupe */
        (void)refs_append(n, line); /* best-effort load */
    }
    fclose(f);
}

/* Read an entire file into a heap buffer (caller frees). Returns WF_OK and sets
 * the output buffer and length; WF_ERR_NOT_FOUND if unopenable; WF_ERR_ALLOC on
 * OOM. */
static wf_status blob_read_file(const char *path, unsigned char **out,
                                size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return WF_ERR_NOT_FOUND;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return WF_ERR_INTERNAL;
    }
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return WF_ERR_INTERNAL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return WF_ERR_INTERNAL;
    }
    unsigned char *buf =
        (unsigned char *)malloc((size_t)size ? (size_t)size : 1);
    if (!buf) {
        fclose(f);
        return WF_ERR_ALLOC;
    }
    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) {
        free(buf);
        return WF_ERR_INTERNAL;
    }
    *out = buf;
    *out_len = (size_t)size;
    return WF_OK;
}

static bool blob_ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s), lx = strlen(suffix);
    return ls >= lx && strcmp(s + ls - lx, suffix) == 0;
}

static bool blob_cid_is_valid(const char *cid) {
    if (!cid || !*cid) return false;
    for (const unsigned char *p = (const unsigned char *)cid; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9'))) {
            return false;
        }
    }
    return true;
}

metalbear_blob_store *metalbear_blob_store_new(const char *path) {
    metalbear_blob_store *store =
        (metalbear_blob_store *)calloc(1, sizeof(*store));
    if (!store) return NULL;

    if (path && path[0] != '\0') {
        store->file_backed = true;
        store->dir = strdup(path);
        if (!store->dir) {
            free(store);
            return NULL;
        }

        /* Load any pre-existing blobs from disk into the in-memory index. */
        DIR *d = opendir(store->dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                const char *name = ent->d_name;
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
                if (blob_ends_with(name, ".mime")) continue;
                if (blob_ends_with(name, ".refs")) continue;
                if (!blob_cid_is_valid(name)) continue;

                char *datap = blob_path(store->dir, name);
                char *mimep = blob_path(store->dir, name);
                if (!datap || !mimep) {
                    free(datap);
                    free(mimep);
                    continue;
                }
                /* Append ".mime" to the mime sidecar path. */
                size_t plen = strlen(mimep);
                char *mp = (char *)realloc(mimep, plen + 6);
                if (!mp) {
                    free(datap);
                    free(mimep);
                    continue;
                }
                mimep = mp;
                memcpy(mimep + plen, ".mime", 6);

                unsigned char *data = NULL;
                size_t dlen = 0;
                char *mime = NULL;
                size_t mlen = 0;
                unsigned char *mraw = NULL;
                size_t mraw_len = 0;

                if (blob_read_file(datap, &data, &dlen) != WF_OK) {
                    free(datap);
                    free(mimep);
                    continue;
                }
                if (blob_read_file(mimep, &mraw, &mraw_len) != WF_OK) {
                    free(datap);
                    free(mimep);
                    free(data);
                    continue;
                }
                mime = (char *)malloc(mraw_len + 1);
                if (!mime) {
                    free(datap);
                    free(mimep);
                    free(data);
                    free(mraw);
                    continue;
                }
                memcpy(mime, mraw, mraw_len);
                mime[mraw_len] = '\0';
                mlen = mraw_len;
                (void)mlen;

                char *cid = strdup(name);
                if (!cid) {
                    free(datap);
                    free(mimep);
                    free(data);
                    free(mraw);
                    free(mime);
                    continue;
                }
                /* Best-effort index load; ignore failures. */
                if (blob_node_push(store, cid, mime, data, dlen) == WF_OK)
                    load_refs(store, store->head); /* push inserts at head */

                free(datap);
                free(mimep);
                free(mraw);
            }
            closedir(d);
        }
    }

    return store;
}

void metalbear_blob_store_free(metalbear_blob_store *store) {
    if (!store) return;
    metalbear_blob_node *n = store->head;
    while (n) {
        metalbear_blob_node *next = n->next;
        blob_node_free(n);
        n = next;
    }
    free(store->dir);
    free(store);
}

wf_status metalbear_blob_store_put(metalbear_blob_store *store, const char *cid,
                                   const char *mime_type,
                                   const unsigned char *data, size_t len) {
    if (!store || !blob_cid_is_valid(cid) || !mime_type || !data) {
        return WF_ERR_INVALID_ARG;
    }

    unsigned char *data_copy = (unsigned char *)malloc(len ? len : 1);
    if (!data_copy) return WF_ERR_ALLOC;
    memcpy(data_copy, data, len);
    char *cid_copy = strdup(cid);
    char *mime_copy = strdup(mime_type);
    if (!cid_copy || !mime_copy) {
        free(data_copy);
        free(cid_copy);
        free(mime_copy);
        return WF_ERR_ALLOC;
    }

    /* Replace an existing entry with the same CID. */
    for (metalbear_blob_node *n = store->head; n; n = n->next) {
        if (strcmp(n->cid, cid) == 0) {
            free(n->mime);
            free(n->data);
            n->mime = mime_copy;
            n->data = data_copy;
            n->len = len;
            free(cid_copy);
            goto persist;
        }
    }

    if (blob_node_push(store, cid_copy, mime_copy, data_copy, len) != WF_OK) {
        return WF_ERR_ALLOC;
    }

persist:
    if (store->file_backed) {
        char *datap = blob_path(store->dir, cid);
        char *mimep = blob_path(store->dir, cid);
        wf_status st = WF_OK;
        if (!datap || !mimep) {
            free(datap);
            free(mimep);
            return WF_ERR_INTERNAL;
        }
        size_t plen = strlen(mimep);
        char *mp = (char *)realloc(mimep, plen + 6);
        if (!mp) {
            free(datap);
            free(mimep);
            return WF_ERR_INTERNAL;
        }
        mimep = mp;
        memcpy(mimep + plen, ".mime", 6);

        FILE *f = fopen(datap, "wb");
        if (!f) {
            st = WF_ERR_INTERNAL;
        } else {
            if (fwrite(data, 1, len, f) != len) st = WF_ERR_INTERNAL;
            fclose(f);
        }
        if (st == WF_OK) {
            FILE *mf = fopen(mimep, "wb");
            if (!mf) {
                st = WF_ERR_INTERNAL;
            } else {
                if (fwrite(mime_type, 1, strlen(mime_type), mf) !=
                    strlen(mime_type))
                    st = WF_ERR_INTERNAL;
                fclose(mf);
            }
        }
        free(datap);
        free(mimep);
        if (st != WF_OK) return st;
    }

    return WF_OK;
}

wf_status metalbear_blob_store_get(metalbear_blob_store *store, const char *cid,
                                   unsigned char **out_data, size_t *out_len,
                                   char **out_mime) {
    if (!store || !blob_cid_is_valid(cid) || !out_data || !out_len ||
        !out_mime) {
        return WF_ERR_INVALID_ARG;
    }
    *out_data = NULL;
    *out_len = 0;
    *out_mime = NULL;

    for (metalbear_blob_node *n = store->head; n; n = n->next) {
        if (strcmp(n->cid, cid) == 0) {
            unsigned char *data = (unsigned char *)malloc(n->len ? n->len : 1);
            char *mime = strdup(n->mime);
            if (!data || !mime) {
                free(data);
                free(mime);
                return WF_ERR_ALLOC;
            }
            memcpy(data, n->data, n->len);
            *out_data = data;
            *out_len = n->len;
            *out_mime = mime;
            return WF_OK;
        }
    }

    return WF_ERR_NOT_FOUND;
}

wf_status metalbear_blob_store_exists(metalbear_blob_store *store,
                                      const char *cid) {
    if (!store || !blob_cid_is_valid(cid)) return WF_ERR_INVALID_ARG;
    for (metalbear_blob_node *n = store->head; n; n = n->next) {
        if (strcmp(n->cid, cid) == 0) return WF_OK;
    }
    return WF_ERR_NOT_FOUND;
}

wf_status metalbear_blob_store_delete(metalbear_blob_store *store,
                                      const char *cid) {
    if (!store || !blob_cid_is_valid(cid)) return WF_ERR_INVALID_ARG;

    metalbear_blob_node **link = &store->head;
    while (*link && strcmp((*link)->cid, cid) != 0) link = &(*link)->next;
    if (!*link) return WF_ERR_NOT_FOUND;

    if (store->file_backed) {
        char *datap = blob_path(store->dir, cid);
        char *mimep = blob_path(store->dir, cid);
        if (!datap || !mimep) {
            free(datap);
            free(mimep);
            return WF_ERR_ALLOC;
        }
        size_t plen = strlen(mimep);
        char *mp = (char *)realloc(mimep, plen + 6);
        if (!mp) {
            free(datap);
            free(mimep);
            return WF_ERR_ALLOC;
        }
        mimep = mp;
        memcpy(mimep + plen, ".mime", 6);

        if (remove(datap) != 0) {
            free(datap);
            free(mimep);
            return WF_ERR_INTERNAL;
        }
        if (remove(mimep) != 0) {
            metalbear_blob_node *node = *link;
            FILE *f = fopen(datap, "wb");
            if (f) {
                if (fwrite(node->data, 1, node->len, f) != node->len) {
                    (void)remove(datap);
                }
                fclose(f);
            }
            free(datap);
            free(mimep);
            return WF_ERR_INTERNAL;
        }
        free(datap);
        free(mimep);

        /* Best-effort: an orphaned .refs sidecar is harmless (skipped by the
         * loader's blob_cid_is_valid check either way), but remove it so a
         * stale one can never be misread if a future CID happens to collide. */
        char *refsp = blob_refs_path(store->dir, cid);
        if (refsp) {
            remove(refsp);
            free(refsp);
        }
    }

    metalbear_blob_node *node = *link;
    *link = node->next;
    blob_node_free(node);
    return WF_OK;
}

wf_status metalbear_blob_store_list(metalbear_blob_store *store,
                                    char ***out_cids, size_t *out_count) {
    if (!store || !out_cids || !out_count) return WF_ERR_INVALID_ARG;
    *out_cids = NULL;
    *out_count = 0;

    size_t count = 0;
    for (metalbear_blob_node *n = store->head; n; n = n->next) count++;
    if (count == 0) return WF_OK;

    char **cids = (char **)calloc(count, sizeof(*cids));
    if (!cids) return WF_ERR_ALLOC;
    size_t i = 0;
    wf_status status = WF_OK;
    for (metalbear_blob_node *n = store->head; n && status == WF_OK;
         n = n->next) {
        cids[i] = strdup(n->cid);
        if (!cids[i])
            status = WF_ERR_ALLOC;
        else
            i++;
    }
    if (status != WF_OK) {
        for (size_t j = 0; j < i; j++) free(cids[j]);
        free(cids);
        return status;
    }
    *out_cids = cids;
    *out_count = count;
    return WF_OK;
}

void metalbear_blob_store_list_free(char **cids, size_t count) {
    if (!cids) return;
    for (size_t i = 0; i < count; i++) free(cids[i]);
    free(cids);
}

void metalbear_blob_walk_refs(const cJSON *node,
                              void (*cb)(const char *cid, void *ctx),
                              void *ctx) {
    if (!node || !cb) return;
    if (cJSON_IsObject(node)) {
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(node, "$type");
        if (cJSON_IsString(type) && type->valuestring &&
            strcmp(type->valuestring, "blob") == 0) {
            const cJSON *ref = cJSON_GetObjectItemCaseSensitive(node, "ref");
            const cJSON *link =
                cJSON_IsObject(ref)
                    ? cJSON_GetObjectItemCaseSensitive(ref, "$link")
                    : NULL;
            if (cJSON_IsString(link) && link->valuestring)
                cb(link->valuestring, ctx);
            return; /* blob objects carry no nested records */
        }
        if (!cJSON_IsString(type)) {
            const cJSON *cid = cJSON_GetObjectItemCaseSensitive(node, "cid");
            const cJSON *mime =
                cJSON_GetObjectItemCaseSensitive(node, "mimeType");
            if (cJSON_IsString(cid) && cid->valuestring &&
                cJSON_IsString(mime)) {
                cb(cid->valuestring, ctx);
                return;
            }
        }
        const cJSON *child = NULL;
        cJSON_ArrayForEach(child, node)
            metalbear_blob_walk_refs(child, cb, ctx);
    } else if (cJSON_IsArray(node)) {
        const cJSON *child = NULL;
        cJSON_ArrayForEach(child, node)
            metalbear_blob_walk_refs(child, cb, ctx);
    }
}

wf_status metalbear_blob_store_associate(metalbear_blob_store *store,
                                         const char *cid,
                                         const char *record_uri) {
    if (!store || !blob_cid_is_valid(cid) || !record_uri || !record_uri[0])
        return WF_ERR_INVALID_ARG;
    metalbear_blob_node *n = blob_node_find(store, cid);
    if (!n) return WF_ERR_NOT_FOUND;
    if (refs_index_of(n, record_uri) != n->ref_count)
        return WF_OK; /* already associated */
    wf_status st = refs_append(n, record_uri);
    if (st != WF_OK) return st;
    persist_refs(store, n);
    return WF_OK;
}

wf_status metalbear_blob_store_dissociate(metalbear_blob_store *store,
                                          const char *cid,
                                          const char *record_uri) {
    if (!store || !blob_cid_is_valid(cid) || !record_uri || !record_uri[0])
        return WF_ERR_INVALID_ARG;
    metalbear_blob_node *n = blob_node_find(store, cid);
    if (!n) return WF_ERR_NOT_FOUND;
    size_t idx = refs_index_of(n, record_uri);
    if (idx == n->ref_count) return WF_OK; /* not associated: no-op success */
    refs_remove_at(n, idx);
    if (n->ref_count == 0) {
        /* Dereferenced: garbage, matching the reference PDS's
         * deleteDereferencedBlobs. Delete outright rather than waiting on a
         * timer — see metalbear_blob_store_dissociate's header comment. */
        return metalbear_blob_store_delete(store, cid);
    }
    persist_refs(store, n);
    return WF_OK;
}

wf_status metalbear_blob_store_is_referenced(metalbear_blob_store *store,
                                             const char *cid) {
    if (!store || !blob_cid_is_valid(cid)) return WF_ERR_INVALID_ARG;
    metalbear_blob_node *n = blob_node_find(store, cid);
    if (!n) return WF_ERR_NOT_FOUND;
    return n->ref_count > 0 ? WF_OK : WF_ERR_NOT_FOUND;
}
