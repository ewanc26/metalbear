/*
 * blob_store.c — in-memory / file-backed blob store keyed by CID string.
 *
 * A small, self-contained store letting MetalBear persist and serve blobs as a
 * PDS would. See blob_store.h for ownership and mode semantics.
 */

#include "metalbear/repo/blob_store.h"

#include "wolfram/tid.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

typedef struct metalbear_blob_node {
    char *cid;           /* owned CID string (key) */
    char *mime;          /* owned MIME type */
    unsigned char *data; /* owned bytes in memory mode; NULL when file-backed */
    size_t len;
    char **refs; /* owned array of owned record URI strings */
    size_t ref_count;
    /* TID (from wf_tid_now, same process clock as repo commit revs) at which
     * this blob was first seen; empty when unknown. Sorts by creation order
     * via strcmp, which is how listBlobs' `since` filter compares. */
    char rev[15];
    struct metalbear_blob_node *next;
} metalbear_blob_node;

struct metalbear_blob_store {
    bool file_backed;
    char *dir;                 /* owned base directory (file-backed only) */
    metalbear_blob_node *head; /* in-memory index; source of truth */
    pthread_mutex_t mutex;     /* guards head and all node mutations */
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

/* Join dir + cid + suffix into a heap buffer (caller frees). */
static char *blob_sidecar_path(const char *dir, const char *cid,
                               const char *suffix) {
    char *path = blob_path(dir, cid);
    if (!path) return NULL;
    size_t plen = strlen(path);
    size_t slen = strlen(suffix);
    char *grown = (char *)realloc(path, plen + slen + 1);
    if (!grown) {
        free(path);
        return NULL;
    }
    memcpy(grown + plen, suffix, slen + 1);
    return grown;
}

/* Mint the next process TID into `rev`, or clear it on failure. */
static void blob_tid_now(char rev[15]) {
    rev[0] = '\0';
    if (wf_tid_now(rev) != WF_OK) rev[0] = '\0';
}

/* Append a node to the store's in-memory index (takes ownership of args).
 * `rev` (may be NULL) is copied into the node's fixed first-seen field. */
static wf_status blob_node_push(metalbear_blob_store *store, char *cid,
                                char *mime, unsigned char *data, size_t len,
                                const char *rev) {
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
    if (rev) snprintf(node->rev, sizeof(node->rev), "%s", rev);
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
    return blob_sidecar_path(dir, cid, ".refs");
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

/* Path to a blob's first-seen rev sidecar (file-backed stores only). Caller
 * frees. Returns NULL on allocation failure. */
static char *blob_rev_path(const char *dir, const char *cid) {
    return blob_sidecar_path(dir, cid, ".rev");
}

/* Rewrite a node's first-seen rev sidecar to match its in-memory state, or
 * leave nothing behind when the node has none. Best-effort, like persist_refs.
 */
static void persist_rev(metalbear_blob_store *store, metalbear_blob_node *n) {
    if (!store->file_backed || n->rev[0] == '\0') return;
    char *path = blob_rev_path(store->dir, n->cid);
    if (!path) return;
    FILE *f = fopen(path, "wb");
    if (f) {
        fprintf(f, "%s\n", n->rev);
        fclose(f);
    }
    free(path);
}

/* Load a node's first-seen rev sidecar, if present. Leaves `rev` empty when
 * the sidecar is absent (a store that predates the tracking). */
static void load_rev(metalbear_blob_store *store, metalbear_blob_node *n) {
    char *path = blob_rev_path(store->dir, n->cid);
    if (!path) return;
    FILE *f = fopen(path, "rb");
    free(path);
    if (!f) return;
    char line[16];
    if (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        if (l > 0) snprintf(n->rev, sizeof(n->rev), "%s", line);
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

static wf_status blob_write_file(const char *path, const void *data,
                                 size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return WF_ERR_INTERNAL;
    bool ok = fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0) ok = false;
    return ok ? WF_OK : WF_ERR_INTERNAL;
}

/* Persist payload and MIME bytes before publishing their metadata in the
 * in-memory index. Temporary files keep readers from observing partial
 * writes; callers hold store->mutex while this runs. */
static wf_status blob_write_backing_files(metalbear_blob_store *store,
                                          const char *cid,
                                          const char *mime_type,
                                          const unsigned char *data,
                                          size_t len) {
    char *datap = blob_path(store->dir, cid);
    char *mimep = blob_sidecar_path(store->dir, cid, ".mime");
    char *data_tmp = blob_sidecar_path(store->dir, cid, ".tmp");
    char *mime_tmp = blob_sidecar_path(store->dir, cid, ".mime.tmp");
    if (!datap || !mimep || !data_tmp || !mime_tmp) {
        free(datap);
        free(mimep);
        free(data_tmp);
        free(mime_tmp);
        return WF_ERR_ALLOC;
    }

    (void)remove(data_tmp);
    (void)remove(mime_tmp);
    wf_status st = blob_write_file(data_tmp, data, len);
    if (st == WF_OK)
        st = blob_write_file(mime_tmp, mime_type, strlen(mime_type));
    if (st == WF_OK && rename(data_tmp, datap) != 0) st = WF_ERR_INTERNAL;
    if (st == WF_OK && rename(mime_tmp, mimep) != 0) st = WF_ERR_INTERNAL;
    if (st != WF_OK) {
        (void)remove(data_tmp);
        (void)remove(mime_tmp);
    }

    free(datap);
    free(mimep);
    free(data_tmp);
    free(mime_tmp);
    return st;
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

    if (pthread_mutex_init(&store->mutex, NULL) != 0) {
        free(store);
        return NULL;
    }

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
                if (blob_ends_with(name, ".rev")) continue;
                if (!blob_cid_is_valid(name)) continue;

                char *datap = blob_path(store->dir, name);
                char *mimep = blob_sidecar_path(store->dir, name, ".mime");
                if (!datap || !mimep) {
                    free(datap);
                    free(mimep);
                    continue;
                }
                size_t dlen = 0;
                char *mime = NULL;
                unsigned char *mraw = NULL;
                size_t mraw_len = 0;
                struct stat data_stat;

                if (stat(datap, &data_stat) != 0 ||
                    !S_ISREG(data_stat.st_mode) || data_stat.st_size < 0 ||
                    (uintmax_t)data_stat.st_size > SIZE_MAX) {
                    free(datap);
                    free(mimep);
                    continue;
                }
                dlen = (size_t)data_stat.st_size;
                if (blob_read_file(mimep, &mraw, &mraw_len) != WF_OK) {
                    free(datap);
                    free(mimep);
                    continue;
                }
                mime = (char *)malloc(mraw_len + 1);
                if (!mime) {
                    free(datap);
                    free(mimep);
                    free(mraw);
                    continue;
                }
                memcpy(mime, mraw, mraw_len);
                mime[mraw_len] = '\0';

                char *cid = strdup(name);
                if (!cid) {
                    free(datap);
                    free(mimep);
                    free(mraw);
                    free(mime);
                    continue;
                }
                /* Best-effort index load; ignore failures. */
                if (blob_node_push(store, cid, mime, NULL, dlen, NULL) ==
                    WF_OK) {
                    load_refs(store, store->head); /* push inserts at head */
                    load_rev(store, store->head);
                }

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
    pthread_mutex_lock(&store->mutex);
    metalbear_blob_node *n = store->head;
    while (n) {
        metalbear_blob_node *next = n->next;
        blob_node_free(n);
        n = next;
    }
    free(store->dir);
    pthread_mutex_unlock(&store->mutex);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

wf_status metalbear_blob_store_put(metalbear_blob_store *store, const char *cid,
                                   const char *mime_type,
                                   const unsigned char *data, size_t len) {
    if (!store || !blob_cid_is_valid(cid) || !mime_type || !data) {
        return WF_ERR_INVALID_ARG;
    }

    unsigned char *data_copy = NULL;
    if (!store->file_backed) {
        data_copy = (unsigned char *)malloc(len ? len : 1);
        if (!data_copy) return WF_ERR_ALLOC;
        memcpy(data_copy, data, len);
    }
    char *cid_copy = strdup(cid);
    char *mime_copy = strdup(mime_type);
    if (!cid_copy || !mime_copy) {
        free(data_copy);
        free(cid_copy);
        free(mime_copy);
        return WF_ERR_ALLOC;
    }

    pthread_mutex_lock(&store->mutex);
    if (store->file_backed) {
        wf_status st =
            blob_write_backing_files(store, cid, mime_type, data, len);
        if (st != WF_OK) {
            free(data_copy);
            free(cid_copy);
            free(mime_copy);
            pthread_mutex_unlock(&store->mutex);
            return st;
        }
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
            /* A re-upload of a blob whose first-seen rev was never recorded
             * (e.g. loaded from a store created before rev tracking) records
             * this upload as its first-seen moment. */
            if (n->rev[0] == '\0') {
                blob_tid_now(n->rev);
                persist_rev(store, n);
            }
            pthread_mutex_unlock(&store->mutex);
            return WF_OK;
        }
    }

    char rev[15];
    blob_tid_now(rev);
    if (blob_node_push(store, cid_copy, mime_copy, data_copy, len, rev) !=
        WF_OK) {
        if (store->file_backed) {
            char *datap = blob_path(store->dir, cid);
            char *mimep = blob_sidecar_path(store->dir, cid, ".mime");
            if (datap) (void)remove(datap);
            if (mimep) (void)remove(mimep);
            free(datap);
            free(mimep);
        }
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_ALLOC;
    }
    persist_rev(store, store->head); /* push inserts at head */
    pthread_mutex_unlock(&store->mutex);
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

    pthread_mutex_lock(&store->mutex);
    for (metalbear_blob_node *n = store->head; n; n = n->next) {
        if (strcmp(n->cid, cid) == 0) {
            char *mime = strdup(n->mime);
            if (!mime) {
                pthread_mutex_unlock(&store->mutex);
                return WF_ERR_ALLOC;
            }

            unsigned char *data = NULL;
            size_t len = 0;
            wf_status st = WF_OK;
            if (store->file_backed) {
                char *datap = blob_path(store->dir, cid);
                if (!datap)
                    st = WF_ERR_ALLOC;
                else
                    st = blob_read_file(datap, &data, &len);
                free(datap);
            } else {
                data = (unsigned char *)malloc(n->len ? n->len : 1);
                if (!data)
                    st = WF_ERR_ALLOC;
                else {
                    memcpy(data, n->data, n->len);
                    len = n->len;
                }
            }
            if (st != WF_OK) {
                free(mime);
                pthread_mutex_unlock(&store->mutex);
                return st;
            }
            n->len = len;
            *out_data = data;
            *out_len = len;
            *out_mime = mime;
            pthread_mutex_unlock(&store->mutex);
            return WF_OK;
        }
    }
    pthread_mutex_unlock(&store->mutex);

    return WF_ERR_NOT_FOUND;
}

wf_status metalbear_blob_store_exists(metalbear_blob_store *store,
                                      const char *cid) {
    if (!store || !blob_cid_is_valid(cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    for (metalbear_blob_node *n = store->head; n; n = n->next) {
        if (strcmp(n->cid, cid) == 0) {
            pthread_mutex_unlock(&store->mutex);
            return WF_OK;
        }
    }
    pthread_mutex_unlock(&store->mutex);
    return WF_ERR_NOT_FOUND;
}

/* Deletes the node for `cid`. Assumes the caller already holds
 * store->mutex and leaves it held on return -- factored out so
 * metalbear_blob_store_dissociate can delete a just-zeroed blob within the
 * same critical section it dropped the last reference in, rather than
 * unlocking and calling back in, which would open a window for a
 * concurrent associate to re-reference the blob just before this deletes
 * it out from under that fresh reference. */
static wf_status blob_store_delete_locked(metalbear_blob_store *store,
                                          const char *cid) {
    metalbear_blob_node **link = &store->head;
    while (*link && strcmp((*link)->cid, cid) != 0) link = &(*link)->next;
    if (!*link) {
        return WF_ERR_NOT_FOUND;
    }

    metalbear_blob_node *node = *link;
    if (store->file_backed) {
        char *datap = blob_path(store->dir, cid);
        char *mimep = blob_sidecar_path(store->dir, cid, ".mime");
        char *data_trash = blob_sidecar_path(store->dir, cid, ".delete");
        char *mime_trash =
            blob_sidecar_path(store->dir, cid, ".mime.delete");
        if (!datap || !mimep || !data_trash || !mime_trash) {
            free(datap);
            free(mimep);
            free(data_trash);
            free(mime_trash);
            return WF_ERR_ALLOC;
        }

        (void)remove(data_trash);
        (void)remove(mime_trash);
        if (rename(datap, data_trash) != 0) {
            free(datap);
            free(mimep);
            free(data_trash);
            free(mime_trash);
            return WF_ERR_INTERNAL;
        }
        if (rename(mimep, mime_trash) != 0) {
            (void)rename(data_trash, datap);
            free(datap);
            free(mimep);
            free(data_trash);
            free(mime_trash);
            return WF_ERR_INTERNAL;
        }

        *link = node->next;
        blob_node_free(node);
        (void)remove(data_trash);
        (void)remove(mime_trash);
        free(datap);
        free(mimep);
        free(data_trash);
        free(mime_trash);

        char *refsp = blob_refs_path(store->dir, cid);
        if (refsp) {
            (void)remove(refsp);
            free(refsp);
        }
        char *revp = blob_rev_path(store->dir, cid);
        if (revp) {
            (void)remove(revp);
            free(revp);
        }
        return WF_OK;
    }

    *link = node->next;
    blob_node_free(node);
    return WF_OK;
}

wf_status metalbear_blob_store_delete(metalbear_blob_store *store,
                                      const char *cid) {
    if (!store || !blob_cid_is_valid(cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    wf_status st = blob_store_delete_locked(store, cid);
    pthread_mutex_unlock(&store->mutex);
    return st;
}

wf_status metalbear_blob_store_list(metalbear_blob_store *store,
                                    char ***out_cids, size_t *out_count) {
    if (!store || !out_cids || !out_count) return WF_ERR_INVALID_ARG;
    *out_cids = NULL;
    *out_count = 0;

    pthread_mutex_lock(&store->mutex);

    size_t count = 0;
    for (metalbear_blob_node *n = store->head; n; n = n->next) count++;
    if (count == 0) {
        pthread_mutex_unlock(&store->mutex);
        return WF_OK;
    }

    char **cids = (char **)calloc(count, sizeof(*cids));
    if (!cids) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_ALLOC;
    }
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
    pthread_mutex_unlock(&store->mutex);
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

wf_status metalbear_blob_store_list_since(metalbear_blob_store *store,
                                          const char *since, char ***out_cids,
                                          size_t *out_count) {
    if (!store || !since || !out_cids || !out_count) return WF_ERR_INVALID_ARG;
    *out_cids = NULL;
    *out_count = 0;

    pthread_mutex_lock(&store->mutex);

    size_t count = 0;
    for (metalbear_blob_node *n = store->head; n; n = n->next)
        if (n->rev[0] != '\0' && strcmp(n->rev, since) > 0) count++;
    if (count == 0) {
        pthread_mutex_unlock(&store->mutex);
        return WF_OK;
    }

    char **cids = (char **)calloc(count, sizeof(*cids));
    if (!cids) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_ALLOC;
    }
    size_t i = 0;
    wf_status status = WF_OK;
    for (metalbear_blob_node *n = store->head; n && status == WF_OK;
         n = n->next) {
        if (n->rev[0] == '\0' || strcmp(n->rev, since) <= 0) continue;
        cids[i] = strdup(n->cid);
        if (!cids[i])
            status = WF_ERR_ALLOC;
        else
            i++;
    }
    pthread_mutex_unlock(&store->mutex);
    if (status != WF_OK) {
        for (size_t j = 0; j < i; j++) free(cids[j]);
        free(cids);
        return status;
    }
    *out_cids = cids;
    *out_count = count;
    return WF_OK;
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
    pthread_mutex_lock(&store->mutex);
    metalbear_blob_node *n = blob_node_find(store, cid);
    if (!n) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_NOT_FOUND;
    }
    if (n->rev[0] == '\0') {
        /* First association of a blob that predates rev tracking: record
         * this association as its first-seen moment. */
        blob_tid_now(n->rev);
        persist_rev(store, n);
    }
    wf_status st = WF_OK;
    if (refs_index_of(n, record_uri) != n->ref_count)
        st = WF_OK; /* already associated — no-op */
    else
        st = refs_append(n, record_uri);
    if (st == WF_OK) persist_refs(store, n);
    pthread_mutex_unlock(&store->mutex);
    return st;
}

wf_status metalbear_blob_store_dissociate(metalbear_blob_store *store,
                                          const char *cid,
                                          const char *record_uri) {
    if (!store || !blob_cid_is_valid(cid) || !record_uri || !record_uri[0])
        return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    metalbear_blob_node *n = blob_node_find(store, cid);
    if (!n) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_NOT_FOUND;
    }
    size_t idx = refs_index_of(n, record_uri);
    if (idx == n->ref_count) {
        pthread_mutex_unlock(&store->mutex);
        return WF_OK; /* not associated: no-op success */
    }
    refs_remove_at(n, idx);
    if (n->ref_count == 0) {
        /* Dereferenced: garbage, matching the reference PDS's
         * deleteDereferencedBlobs. Delete outright rather than waiting on a
         * timer — see metalbear_blob_store_dissociate's header comment.
         * Delete within this same locked section (blob_store_delete_locked,
         * not the public metalbear_blob_store_delete) so a concurrent
         * associate can't slip a fresh reference onto this node between
         * dropping to zero and the delete happening. */
        wf_status del_st = blob_store_delete_locked(store, cid);
        pthread_mutex_unlock(&store->mutex);
        return del_st;
    }
    persist_refs(store, n);
    pthread_mutex_unlock(&store->mutex);
    return WF_OK;
}

wf_status metalbear_blob_store_is_referenced(metalbear_blob_store *store,
                                             const char *cid) {
    if (!store || !blob_cid_is_valid(cid)) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&store->mutex);
    metalbear_blob_node *n = blob_node_find(store, cid);
    if (!n) {
        pthread_mutex_unlock(&store->mutex);
        return WF_ERR_NOT_FOUND;
    }
    wf_status st = n->ref_count > 0 ? WF_OK : WF_ERR_NOT_FOUND;
    pthread_mutex_unlock(&store->mutex);
    return st;
}
