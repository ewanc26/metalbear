/*
 * repo_store.h — a durable, writable repo storage engine for a
 * self-hosted AT Protocol PDS.
 *
 * This module is the first coherent slice of a self-hosted Personal
 * Data Server (PDS). It persists records in a content-addressed store
 * (SQLite) and applies writes by reusing the SDK's existing, tested
 * repo primitives (wf_repo_create_record / wf_repo_update_record /
 * wf_repo_delete_record / wf_repo_get_record, which in turn build MST
 * mutations and produce signed v3 commits via wf_commit_create).
 *
 * Every mutation yields a signed commit that is verifiable by the
 * SDK's existing commit-verification path (wf_repo_verify /
 * wf_sync_verify_commit) given the repo's signing key — that is the
 * core invariant of a real PDS.
 *
 * All write endpoints of com.atproto.repo are supported:
 *   createRecord, putRecord, deleteRecord, getRecord,
 *   applyWrites, describeRepo.
 *
 * Ownership: every heap-allocated string output (out_uri, out_cid,
 * out_record_json, out_commit_cid, out_commit_rev, out_results_json,
 * out_json) is caller-owned and freed with free().
 *
 * This module is built only when wolfram is configured with
 * -DWOLFRAM_BUILD_SERVER=ON (it links SQLite for durable storage).
 *
 * Thread-safety: a single metalbear_repo_store is NOT safe for concurrent
 * writers. The current PDS slice serialises all writes through the
 * route handlers (a single worker thread per request, one in flight);
 * cross-request concurrency is a documented limitation.
 */

#ifndef METALBEAR_REPO_STORE_H
#define METALBEAR_REPO_STORE_H

#include <cJSON.h>
#include <stdbool.h>

#include "wolfram/validate.h"
#include "wolfram/xrpc.h"
#include "wolfram/crypto.h"
#include "wolfram/repo/commit.h"
#include "wolfram/xrpc_server.h"

/* Forward declaration; the resolver may resolve a blob store per request. */
typedef struct metalbear_blob_store metalbear_blob_store;

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque, durable repo store handle. */
typedef struct metalbear_repo_store metalbear_repo_store;

typedef struct metalbear_repo_store_stats {
    size_t repo_blocks;
    size_t indexed_records;
} metalbear_repo_store_stats;

typedef enum metalbear_repo_store_event_kind {
    METALBEAR_REPO_STORE_EVENT_COMMIT,
    METALBEAR_REPO_STORE_EVENT_SYNC,
} metalbear_repo_store_event_kind;

/** One mutation within a commit event, mirroring subscribeRepos #repoOp. */
typedef struct metalbear_repo_store_op {
    const char *action;            /* create / update / delete */
    const char *collection;
    const char *rkey;
    wf_cid cid;                    /* new record CID; unset for delete */
    int has_cid;
    wf_cid prev;                   /* previous record CID, when known */
    int has_prev;
} metalbear_repo_store_op;

/**
 * A repository event emitted after durable persistence. All pointers and CAR
 * bytes are borrowed and remain valid only for the callback invocation.
 *
 * One event describes one stored commit, which may carry several ops: a
 * batched applyWrites is a single commit and must reach the firehose as a
 * single #commit event listing every op it applied.
 */
typedef struct metalbear_repo_store_event {
    metalbear_repo_store_event_kind kind;
    const char *did;
    wf_cid commit_cid;
    const char *rev;
    const char *since;             /* NULL for a genesis commit */
    wf_cid prev_data;
    int has_prev_data;
    const metalbear_repo_store_op *ops;  /* commit only */
    size_t ops_count;
    const unsigned char *blocks;   /* incremental CAR, full CAR for sync */
    size_t blocks_len;
} metalbear_repo_store_event;

typedef void (*metalbear_repo_store_event_cb)(const metalbear_repo_store_event *event,
                                       void *context);

/**
 * Open (or create) a durable repo store at `path`.
 *
 * On first creation the store generates a fresh secp256k1 signing key,
 * persists it together with `did` / `handle`, and starts with an empty
 * repo (no head commit). On subsequent opens the persisted did/handle/
 * key are loaded and `did` / `handle` are ignored.
 *
 * Ownership: the returned store is caller-owned; free it with
 * metalbear_repo_store_free.
 */
wf_status metalbear_repo_store_open(const char *path, const char *did,
                             const char *handle, metalbear_repo_store **out);

/**
 * As metalbear_repo_store_open, but on first creation adopts `signing_key`
 * instead of generating one (NULL keeps the generating behaviour). Required
 * when the account's DID document is published before the repo exists: the
 * repo must sign with exactly the key that document advertises, or every
 * commit it produces is unverifiable to relays and AppViews.
 *
 * Ignored when the store already exists — a repo's signing key is fixed at
 * creation.
 */
wf_status metalbear_repo_store_open_with_key(const char *path, const char *did,
                             const char *handle,
                             const wf_signing_key *signing_key,
                             metalbear_repo_store **out);

/** Close a store and release all resources. Safe to call with NULL. */
void metalbear_repo_store_free(metalbear_repo_store *store);

/** Repo DID (e.g. "did:plc:..."). Borrowed; valid until store free. */
const char *metalbear_repo_store_did(const metalbear_repo_store *store);

/** Repo handle (e.g. "example.com"). Borrowed; valid until store free. */
const char *metalbear_repo_store_handle(const metalbear_repo_store *store);

/** Signing key did:key (e.g. "did:key:z..."). Borrowed; valid until store free. */
const char *metalbear_repo_store_signing_key_did(const metalbear_repo_store *store);

wf_status metalbear_repo_store_set_handle(metalbear_repo_store *store, const char *handle);

wf_status metalbear_repo_store_get_stats(metalbear_repo_store *store,
                                  metalbear_repo_store_stats *out_stats);

/** Install or clear the post-persistence repository event observer. */
void metalbear_repo_store_set_event_callback(metalbear_repo_store *store,
                                      metalbear_repo_store_event_cb callback,
                                      void *context);

/**
 * Append a new record (createRecord).
 *
 * When `rkey_or_null` is NULL a fresh TID record key is minted. The
 * record JSON (which must contain a $type field) is encoded to
 * DAG-CBOR, added to the MST, and a signed commit is produced.
 *
 * On WF_OK, *out_uri ("at://<did>/<collection>/<rkey>") and *out_cid
 * (record CID, base32) are caller-owned strings (free() them).
 *
 * When `swap_commit_or_null` is non-NULL it must equal the current repo
 * head commit CID (a compare-and-swap guard); a mismatch fails the
 * write (mirrors atproto's InvalidSwap). NULL means "no guard".
 *
 * The supplied `rkey_or_null` (if any) is validated against atproto's
 * record-key rules, and a present `$type` must equal `collection`.
 */
wf_status metalbear_repo_store_create_record(metalbear_repo_store *store,
                                      const char *collection,
                                      const char *rkey_or_null,
                                      const char *record_json,
                                      const char *swap_commit_or_null,
                                      char **out_uri, char **out_cid);

/**
 * Put a record (putRecord) — upsert by rkey.
 *
 * If a record with `rkey` already exists it is updated in place;
 * otherwise a new record is created. Outputs mirror createRecord.
 *
 * `swap_commit_or_null` / `swap_record_or_null` are compare-and-swap
 * guards (mirroring atproto's InvalidSwap): `swap_commit` must equal the
 * current repo head and `swap_record` must equal the existing record CID.
 * A NULL guard means "no guard". The `rkey` is validated against atproto's
 * record-key rules and a present `$type` must equal `collection`.
 */
wf_status metalbear_repo_store_put_record(metalbear_repo_store *store,
                                   const char *collection,
                                   const char *rkey,
                                   const char *record_json,
                                   const char *swap_commit_or_null,
                                   const char *swap_record_or_null,
                                   char **out_uri, char **out_cid);

/**
 * Delete a record (deleteRecord). Returns WF_ERR_NOT_FOUND when the
 * repo is empty or the record does not exist.
 *
 * `swap_commit_or_null` / `swap_record_or_null` are compare-and-swap
 * guards (mirroring atproto's InvalidSwap): `swap_commit` must equal the
 * current repo head and `swap_record` must equal the existing record CID.
 * A NULL guard means "no guard". The `rkey` is validated against
 * atproto's record-key rules.
 */
wf_status metalbear_repo_store_delete_record(metalbear_repo_store *store,
                                      const char *collection,
                                      const char *rkey,
                                      const char *swap_commit_or_null,
                                      const char *swap_record_or_null);

/**
 * Fetch a record (getRecord).
 *
 * On WF_OK, *out_record_json (the canonical record JSON, including its
 * $type) and *out_cid (record CID, base32) are caller-owned strings.
 * Returns WF_ERR_NOT_FOUND when the repo is empty or the record
 * does not exist.
 */
wf_status metalbear_repo_store_get_record(metalbear_repo_store *store,
                                   const char *collection,
                                   const char *rkey,
                                   char **out_record_json,
                                   char **out_cid);

/**
 * Apply a batch of writes (applyWrites).
 *
 * `writes_json` is the JSON array of write operations (the `writes`
 * field of com.atproto.repo.applyWrites). Each element is an object
 * discriminated by its `$type`:
 *   "com.atproto.repo.applyWrites#create"  -> {collection, rkey?, value}
 *   "com.atproto.repo.applyWrites#update"  -> {collection, rkey, value}
 *   "com.atproto.repo.applyWrites#delete"  -> {collection, rkey}
 *
 * Operations are applied in order. Each op advances the repo head; the
 * final head commit is reported as the overall commit. On WF_OK,
 * *out_commit_cid / *out_commit_rev describe that commit and
 * *out_results_json is a JSON array of per-op results
 * ({uri, cid, validationStatus:"unknown"} for create/update; empty
 * object for delete).
 *
 * `swap_commit_or_null` is a compare-and-swap guard on the repo head
 * (mirroring atproto's InvalidSwap); a mismatch fails the whole batch.
 * NULL means "no guard".
 *
 * All three outputs are caller-owned strings (free() them).
 *
 * Limitations: each write emits its own signed commit rather than a
 * single batched commit (the returned commit is the final head), and
 * the batch is capped at 200 writes (mirroring atproto's limit).
 */
wf_status metalbear_repo_store_apply_writes(metalbear_repo_store *store,
                                      const char *writes_json,
                                      const char *swap_commit_or_null,
                                      char **out_commit_cid,
                                      char **out_commit_rev,
                                      char **out_results_json);

/**
 * Records written after `rev`, oldest first, as
 * `{"records":[{uri,cid,collection,indexedAt,value}, ...]}`.
 *
 * This is the read-after-write query: an AppView reports how far it has
 * indexed via the `atproto-repo-rev` response header, and anything newer than
 * that is a write the user has made but cannot see yet. Returns an empty array
 * when the quoted rev does not appear to describe this repo at all, so a
 * mismatched rev degrades to a stale view rather than a wrong one.
 *
 * *out_json is a caller-owned JSON string.
 */
wf_status metalbear_repo_store_records_since_rev(metalbear_repo_store *store,
                                                 const char *rev, int limit,
                                                 char **out_json);

/**
 * Produce the base describeRepo payload (did, handle, collections, rev).
 * The route handler adds the lexicon's required didDoc and handleIsCorrect,
 * which need the identity layer. *out_json is a caller-owned JSON string.
 */
wf_status metalbear_repo_store_describe(metalbear_repo_store *store, char **out_json);

/**
 * Verify the current head commit against the store's signing key using
 * the SDK's existing commit-verification path (wf_repo_verify).
 *
 * On WF_OK, *out_verified is set to 1 when the signature over the
 * commit is authentic, 0 otherwise. `out_commit` may be NULL.
 */
wf_status metalbear_repo_store_verify_head(metalbear_repo_store *store,
                                     int *out_verified,
                                     wf_commit *out_commit);

/**
 * List records in a collection (com.atproto.repo.listRecords).
 *
 * Enumerates the `records` index. By default records are returned in
 * ascending rkey order, skipping keys lexicographically after `cursor`
 * (NULL for the start). When `reverse` is set, records are returned in
 * descending rkey order (the first page is the tail of the collection);
 * in that mode `cursor` selects keys lexicographically *before* it. At
 * most `limit` records are returned (capped at the lexicon max of 100;
 * default 50). When more records remain, *out_json carries a `cursor`
 * field set to the last returned rkey for the next page.
 *
 * On WF_OK, *out_json is a caller-owned JSON string of the shape
 * {"records":[{"uri","cid","value"}], "cursor"?}. Free it with free().
 */
wf_status metalbear_repo_store_list_records(metalbear_repo_store *store,
                                     const char *collection,
                                     const char *cursor,
                                     bool reverse,
                                     int limit,
                                     char **out_json);

/**
 * Stream every record in the repository (all collections) to a callback,
 * ordered by (collection, rkey). Used by com.atproto.repo.listMissingBlobs
 * to scan record values for blob references without materialising the whole
 * repo in memory.
 *
 * `value_json` is the record's JSON encoding (borrowed; valid only for the
 * duration of the call). Return WF_OK from `visit` to continue iteration;
 * any other status aborts the walk and is propagated to the caller, letting
 * the consumer stop early (e.g. once a page is full).
 */
wf_status metalbear_repo_store_foreach_record(
    metalbear_repo_store *store,
    wf_status (*visit)(const char *collection, const char *rkey,
                       const char *value_json, void *ctx),
    void *ctx);

/**
 * Return the current head commit's rev + CID
 * (com.atproto.sync.getLatestCommit). Returns WF_ERR_NOT_FOUND when the
 * repository is empty (no head commit yet). On WF_OK, *out_rev and
 * *out_cid are caller-owned strings (free() them).
 */
wf_status metalbear_repo_store_get_head(metalbear_repo_store *store, char **out_rev,
                                 char **out_cid);

/**
 * Export the repository as a CAR rooted at the current commit.
 *
 * When `since_or_null` is NULL or empty, all persisted repo blocks are
 * included. Otherwise only blocks created at revisions lexicographically
 * newer than the supplied TID revision are included, matching
 * com.atproto.sync.getRepo's incremental export semantics. On WF_OK,
 * `*out_data` is caller-owned and freed with free().
 */
wf_status metalbear_repo_store_export(metalbear_repo_store *store,
                               const char *since_or_null,
                               unsigned char **out_data, size_t *out_len);

/**
 * Export just the current commit block as a single-block CAR rooted at it.
 *
 * This is what a firehose #sync event carries: the lexicon says "CAR file
 * containing the commit, as a block" and caps it at 10000 bytes. Using the
 * full-repo export here produces an oversized event that a validating relay
 * rejects, so do not substitute metalbear_repo_store_export.
 * On WF_OK, `*out_data` is caller-owned and freed with free().
 */
wf_status metalbear_repo_store_export_commit(metalbear_repo_store *store,
                                             unsigned char **out_data,
                                             size_t *out_len);

/**
 * Export selected repository blocks as a rootless CAR.
 *
 * Every requested CID must exist; otherwise WF_ERR_NOT_FOUND is returned and
 * no partial CAR is produced. Duplicate input CIDs are emitted once. The
 * caller owns `*out_data` and frees it with free().
 */
wf_status metalbear_repo_store_get_blocks(metalbear_repo_store *store,
                                     const char *const *cids,
                                     size_t cid_count,
                                     unsigned char **out_data,
                                     size_t *out_len);

/**
 * Fetch a single record as a CAR file rooted at the current commit.
 *
 * The returned CAR contains the commit block as root and the requested
 * record block.  The caller owns `*out_data` and frees it with free().
 * Returns WF_ERR_NOT_FOUND when the record does not exist.
 */
wf_status metalbear_repo_store_get_record_car(metalbear_repo_store *store,
                                       const char *collection,
                                       const char *rkey,
                                       unsigned char **out_data,
                                       size_t *out_len);

/** Mint a service-auth JWT with the repository's persisted signing key. */
wf_status metalbear_repo_store_create_service_auth(metalbear_repo_store *store,
                                             const char *audience,
                                             int64_t expiration,
                                             const char *lxm,
                                             char **out_token);

/* ------------------------------------------------------------------ */
/* XRPC server integration                                             */
/* ------------------------------------------------------------------ */

/**
 * Register the core com.atproto.repo read/write route handlers on an
 * XRPC server, backed by `store`. The server owns no reference to
 * `store`; the caller must keep `store` alive for the server's
 * lifetime and free it after wf_xrpc_server_free.
 */
wf_status metalbear_xrpc_server_register_pds_repo(wf_xrpc_server *server,
                                             metalbear_repo_store *store,
                                             const char *service_did,
                                             const char *public_url);

/*
 * Per-request resolver for multi-tenant PDS deployments. Given the
 * incoming request, return the repo store (and/or blob store) that
 * should service it, resolved from req->params (did/repo/collection/
 * rkey) and/or req->authed_subject. The returned pointers are BORROWED
 * for the duration of the request and must NOT be freed by the server.
 * If the account cannot be resolved return WF_ERR_NOT_FOUND (or any
 * error) and leave *out_repo / *out_blobs NULL; the handler maps this
 * to a 400 RepoNotFound / AccountNotFound. out_repo / out_blobs may be
 * independently NULL.
 */
typedef wf_status (*metalbear_xrpc_repo_resolver)(void *ctx,
                                           const wf_xrpc_request *req,
                                           metalbear_repo_store **out_repo,
                                           metalbear_blob_store **out_blobs);

/**
 * Register the com.atproto.repo read/write route handlers on an XRPC
 * server with a per-request resolver instead of a fixed store, enabling
 * a multi-tenant PDS to serve different accounts from different stores.
 *
 * The resolver is invoked for every request; it must return (via
 * out_repo) the metalbear_repo_store that should service the request, resolved
 * from req->params / req->authed_subject. The returned store is
 * borrowed for the request duration; the caller keeps ownership of both
 * `ctx` and the stores the resolver returns and must free them after
 * wf_xrpc_server_free. The server owns the internal routing bundle it
 * allocates and frees it on wf_xrpc_server_free.
 */
wf_status metalbear_xrpc_server_register_pds_repo_resolver(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx,
    const char *service_did, const char *public_url);

/*
 * Resolve the authoritative W3C DID document for `did`, returning it as
 * heap-allocated JSON text the caller frees, or NULL when it cannot be
 * resolved. Used by describeRepo to verify a handle bi-directionally.
 */
typedef char *(*metalbear_xrpc_did_doc_provider)(void *ctx, const char *did);

/*
 * Consulted before a repository read is served, so moderation state that the
 * repository itself does not carry can refuse the request. `record_uri` names
 * the single record being read, or is NULL when the request is about the
 * repository as a whole. Return false with `resp` already filled in to refuse;
 * the handler then returns without touching the store.
 *
 * The guard, not the store, is where a takedown lives: a taken-down record
 * stays in the repository — removing it would rewrite history and break the
 * commit chain — and is withheld at the point it would be served.
 */
typedef bool (*metalbear_xrpc_repo_access_guard)(void *ctx,
                                                 const wf_xrpc_request *req,
                                                 const char *record_uri,
                                                 wf_xrpc_response *resp);

/**
 * As metalbear_xrpc_server_register_pds_repo_resolver, additionally wiring an
 * identity-layer DID document provider and a lexicon registry. Without a
 * provider, describeRepo falls back to a locally derived document and reports
 * handleIsCorrect=false, since the PDS cannot confirm the handle resolves back
 * to the DID on its own. Without a registry, every write reports
 * validationStatus "unknown", since nothing can be checked. Without a guard,
 * every record the store holds is served.
 *
 * The registry is borrowed and must outlive the server.
 *
 * `accepting_imports` and `max_import_size` gate com.atproto.repo.importRepo
 * (refpds PDS_ACCEPTING_REPO_IMPORTS / PDS_MAX_REPO_IMPORT_SIZE):
 * accepting_imports false refuses every import with an honest
 * "Service is not accepting repo imports"; max_import_size > 0 caps the CAR
 * body's byte length (0 = unlimited).
 */
wf_status metalbear_xrpc_server_register_pds_repo_resolver_ex(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx,
    const char *service_did, const char *public_url,
    metalbear_xrpc_did_doc_provider did_doc_provider, void *did_doc_ctx,
    const wf_lexicon_registry *lexicons,
    metalbear_xrpc_repo_access_guard guard, void *guard_ctx,
    bool accepting_imports, int64_t max_import_size);

/** Outcome of checking a record against the lexicon corpus. */
typedef enum metalbear_validation_status {
    /* No schema is loaded for the collection, so nothing was checked. */
    METALBEAR_VALIDATION_UNKNOWN = 0,
    /* A schema was found and the record satisfies it. */
    METALBEAR_VALIDATION_VALID,
} metalbear_validation_status;

/**
 * Check `record_json` against the schema for `collection`, mirroring the
 * reference PDS's prepareWrite:
 *
 *   - no registry, or no schema for the collection: WF_OK with
 *     *out_status = UNKNOWN, unless `require_schema` (the caller passed
 *     validate:true), which is WF_ERR_NOT_FOUND — the caller asked for a
 *     guarantee that cannot be given.
 *   - schema found and satisfied: WF_OK with *out_status = VALID.
 *   - schema found and violated: WF_ERR_VALIDATION. The record must be
 *     rejected, not stored with a warning.
 *
 * *out_message, when non-NULL and set, is a caller-owned description of the
 * first violation suitable for an InvalidRecord error message.
 */
wf_status metalbear_validate_record(const wf_lexicon_registry *lexicons,
                                    const char *collection,
                                    const char *record_json,
                                    bool require_schema,
                                    metalbear_validation_status *out_status,
                                    char **out_message);

/**
 * Build the W3C DID document for an atproto account: `verificationMethod` as
 * an array of Multikey entries (`<did>#atproto`) and the #atproto_pds service
 * entry. Caller owns the returned cJSON node.
 */
cJSON *metalbear_did_document_build(const char *did, const char *handle,
                                    const char *signing_key_didkey,
                                    const char *pds_endpoint);

/** First at:// handle claimed by a DID document's alsoKnownAs, or NULL.
 *  Borrowed from `document`. */
const char *metalbear_did_document_handle(const cJSON *document);

/** did:key of the repo signing key from the document's #atproto
 *  verification method. Heap-allocated; caller frees. NULL when absent. */
char *metalbear_did_document_signing_key(const cJSON *document);

/** serviceEndpoint of the document's #atproto_pds service entry, or NULL.
 *  Borrowed from `document`. */
const char *metalbear_did_document_pds_endpoint(const cJSON *document);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_REPO_STORE_H */
