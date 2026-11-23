#ifndef METALBEAR_BLOB_LIFECYCLE_H
#define METALBEAR_BLOB_LIFECYCLE_H

/*
 * blob_lifecycle.h -- schema-7 host-wide blob lifecycle state (issue #253).
 *
 * Uploads are temporary until a record references them. This store keeps the
 * per-(account, CID) state and the revision-aware record references that let
 * the sweeper tell a still-reachable blob from an abandoned upload. Blob
 * payloads stay in the existing per-account blob directories; this database
 * only records their state, size, first-seen time, and which record revisions
 * reference them. References are append-only here: an old repository revision
 * still makes its blobs reachable until repo GC removes that revision, at
 * which point the sweep prunes the stale rows.
 */

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_blob_lifecycle metalbear_blob_lifecycle;

typedef struct metalbear_blob_sweep_summary {
    size_t temporary;            /* all temporary copies */
    uint64_t temporary_bytes;    /* payload bytes held by temporaries */
    size_t expiring;             /* temporaries older than the window */
    size_t unreferenced_durable; /* durables with no live revision refs */
    size_t deleted;              /* payload copies actually removed */
    size_t refs_pruned;          /* stale revision rows removed */
} metalbear_blob_sweep_summary;

/* Callback used by the sweep and the gauge to ask whether a repo revision
 * still exists. WF_ERR_NOT_FOUND means "collected"; any other error means
 * "unknown", so the caller keeps the reference rather than deleting data. */
typedef wf_status (*metalbear_blob_revision_exists_cb)(const char *did,
                                                       const char *rev,
                                                       void *ctx);
typedef wf_status (*metalbear_blob_delete_cb)(const char *did, const char *cid,
                                              void *ctx);

/* Open (creating and migrating if needed) <data_dir>/blob_lifecycle.sqlite3. */
metalbear_blob_lifecycle *
metalbear_blob_lifecycle_open(const char *data_directory);
void metalbear_blob_lifecycle_free(metalbear_blob_lifecycle *life);

/*
 * Record an upload for `did`/`cid`. A new row starts temporary; re-uploading
 * an already-promoted copy keeps it durable, because a live record may still
 * reference those bytes. Returns WF_ERR_INVALID_ARG on bad inputs.
 */
wf_status metalbear_blob_lifecycle_mark_uploaded(metalbear_blob_lifecycle *life,
                                                 const char *did,
                                                 const char *cid, size_t size,
                                                 int64_t now);

/*
 * Promote a temporary copy to durable. Sets *changed to 1 when this call
 * performed the transition, so the caller can account the bytes once.
 */
wf_status metalbear_blob_lifecycle_promote(metalbear_blob_lifecycle *life,
                                           const char *did, const char *cid,
                                           int *changed);

/* Add a record reference at `rev`, promoting the copy if needed. */
wf_status metalbear_blob_lifecycle_add_ref(metalbear_blob_lifecycle *life,
                                           const char *did, const char *cid,
                                           const char *uri, const char *rev);

/* Remove every revision reference a record URI held for this copy. Called on
 * dereference so the last-reference loss is visible to the sweep immediately,
 * even when repo GC keeps old revisions around. */
wf_status metalbear_blob_lifecycle_remove_refs(metalbear_blob_lifecycle *life,
                                               const char *did, const char *cid,
                                               const char *uri);

/* Remove a copy's state and references after its payload has been deleted. */
wf_status metalbear_blob_lifecycle_forget(metalbear_blob_lifecycle *life,
                                          const char *did, const char *cid);

/*
 * Seed a durable row for a payload that predates lifecycle tracking. Existing
 * state is never overwritten, so a live temporary upload cannot be promoted
 * by a restart scan.
 */
wf_status metalbear_blob_lifecycle_seed_blob(metalbear_blob_lifecycle *life,
                                             const char *did, const char *cid,
                                             size_t size, int64_t now);

/*
 * Return 1 when the copy is durable, 0 when temporary, negative on error.
 * A missing row is reported as temporary (hidden) so an operator database
 * rebuilt from scratch never accidentally exposes an untracked upload.
 */
int metalbear_blob_lifecycle_is_durable(metalbear_blob_lifecycle *life,
                                        const char *did, const char *cid);

/* Counters for /metrics and the dry-run report, without changing anything.
 * `revision_exists` may be NULL, in which case every stored reference counts
 * as live; pass the server's callback to count stale refs accurately. */
wf_status metalbear_blob_lifecycle_stats(
    metalbear_blob_lifecycle *life, int64_t now, int64_t temp_seconds,
    metalbear_blob_revision_exists_cb revision_exists, void *ctx,
    metalbear_blob_sweep_summary *out);

/*
 * One sweep pass. `revision_exists` lets the sweeper drop refs whose commit
 * revision is no longer in the account's repo; `delete_blob` removes a payload
 * copy. Both may be NULL, in which case stale refs are reported but kept and
 * no copy is removed.
 */
wf_status metalbear_blob_lifecycle_sweep(
    metalbear_blob_lifecycle *life, int64_t now, int64_t temp_seconds,
    bool dry_run, metalbear_blob_revision_exists_cb revision_exists,
    metalbear_blob_delete_cb delete_blob, void *ctx,
    metalbear_blob_sweep_summary *out);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_BLOB_LIFECYCLE_H */
