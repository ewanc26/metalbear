#ifndef METALBEAR_REPO_STORE_INTERNAL_H
#define METALBEAR_REPO_STORE_INTERNAL_H

/* The full metalbear_repo_store layout and the handful of cross-cutting
 * engine helpers the PDS route handlers need (uri construction, commit
 * persistence, reindex, sync event emission), shared between repo_store.c
 * (the storage engine, which defines these) and repo_routes.c (the
 * com.atproto.repo.* XRPC handlers, which call into them -- h_import_repo in
 * particular manipulates commits and the block store as directly as the
 * engine itself does). Not part of the public API --
 * include/metalbear/repo/repo_store.h keeps the opaque metalbear_repo_store
 * typedef for external consumers; this header is the real definition,
 * visible only within this module. */

#include "metalbear/repo/repo_store.h"

#include "wolfram/crypto.h"
#include "wolfram/repo/car.h"
#include "wolfram/repo/cid.h"

#include <cJSON.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct metalbear_repo_store {
    char *path;
    char *did;
    char *handle;
    wf_signing_key key;
    char *signing_key_didkey; /* did:key multibase, for wf_repo_verify */
    sqlite3 *db;
    wf_car car;              /* accumulated blocks; roots -> &head */
    wf_cid head;             /* current head commit CID (len 0 = empty) */
    size_t persisted_blocks; /* count of blocks already flushed to db */
    metalbear_repo_store_event_cb event_cb;
    void *event_ctx;
    pthread_mutex_t mutex; /* guards db, car, head, persisted_blocks */
};

/* Build `at://<did>/<collection>/<rkey>`. Caller frees. */
char *make_uri(const char *did, const char *collection, const char *rkey);

/* Add the shared commit-metadata fields (rev, prev, etc.) that every
 * describe/list response embeds alongside a record's value. */
void add_commit_meta(metalbear_repo_store *s, cJSON *parent);

/* Rebuild the record and blob indexes from the current head by walking the
 * MST. Used after directly replacing the block store's contents (import). */
wf_status reindex_all(metalbear_repo_store *s);

/* Persist `new_head`'s blocks and update the store's durable head pointer. */
wf_status commit_persist(metalbear_repo_store *s, const wf_cid *new_head);

/* Notify the store's event callback (if any) that the head advanced,
 * without describing the individual operations -- used where the new state
 * was not built incrementally (import) so there is no per-op diff to
 * report. */
void emit_sync_event(metalbear_repo_store *s);

/* Export the repo's CAR (commit + blocks, optionally since `since`).
 * The _locked variant must be called with `s->mutex` held. */
wf_status metalbear_repo_store_export(metalbear_repo_store *s,
                                      const char *since,
                                      unsigned char **out_data,
                                      size_t *out_len);
wf_status metalbear_repo_store_export_locked(metalbear_repo_store *s,
                                             const char *since,
                                             unsigned char **out_data,
                                             size_t *out_len);

/* Emit one #commit event describing `ops_count` mutations landed by a
 * single signed commit. */
void emit_commit_event_ops(metalbear_repo_store *s, const wf_cid *old_head,
                           const metalbear_repo_store_op *ops,
                           size_t ops_count);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_REPO_STORE_INTERNAL_H */
