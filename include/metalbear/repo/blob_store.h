/*
 * blob_store.h — a simple, self-contained blob store keyed by CID string.
 *
 * MetalBear can act as a small PDS: it stores uploaded blobs and serves them
 * back via com.atproto.repo.uploadBlob / com.atproto.sync.getBlob. The store
 * is intentionally decoupled from the SQLite session/repo-mirror store so it
 * can be used (and tested) independently.
 *
 * Two modes are supported:
 *   - In-memory: pass NULL/"" for the path to metalbear_blob_store_new. Blobs
 *     live only for the lifetime of the handle.
 *   - File-backed: pass a directory path. Each blob is written as a file named
 *     by its CID (safe base32 charset), with the MIME type in a sidecar
 *     "<cid>.mime" file. Re-opening the same path indexes compact metadata;
 *     payload bytes remain on disk and are read only when requested.
 *
 * Optional at-rest encryption of the stored blob payloads: when the store is
 * built with METALBEAR_BUILD_BLOB_CRYPTO and set up with
 * metalbear_blob_store_set_crypto_passphrase, each file-backed blob's payload
 * bytes are encrypted with libsodium crypto_secretbox_easy (XSalsa20-Poly1305)
 * before they hit disk and decrypted on read. A per-store Argon2id salt lives
 * in a "<dir>/.blobstore.salt" meta file (created on first use) and the key is
 * derived from the caller-supplied passphrase. The metadata sidecars
 * ("<cid>.mime", "<cid>.refs", "<cid>.rev") remain plaintext; only the blob
 * payload bytes are encrypted. All cryptography is delegated to libsodium; no
 * hand-rolled crypto is present.
 *
 * The store also tracks which record URIs reference each blob
 * (metalbear_blob_store_associate / _dissociate / _is_referenced) — the repo
 * write path (repo_store.c) uses this to keep a blob alive only as long as
 * some record still names it, deleting it the moment the last one stops,
 * mirroring the reference PDS's record_blob bookkeeping. A file-backed
 * store persists associations in a "<cid>.refs" sidecar.
 *
 * Each blob also records the TID at which it was first seen — uploaded, or
 * first associated with a record when the store predates the tracking — so
 * com.atproto.sync.listBlobs' `since` filter can list only the blobs whose
 * first-seen rev sorts after a given repo revision
 * (metalbear_blob_store_list_since). A file-backed store persists the rev in a
 * "<cid>.rev" sidecar.
 *
 * Ownership: outputs from metalbear_blob_store_get (out_data, out_mime) are
 * heap-allocated and freed with free() by the caller. The CID is the caller's
 * string (e.g. the canonical raw multicodec CID from metalbear_cid_of_bytes).
 */

#ifndef METALBEAR_BLOB_STORE_H
#define METALBEAR_BLOB_STORE_H

#include "wolfram/util.h"
#include "metalbear/repo/repo_store.h"
#include <cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_blob_store metalbear_blob_store;

/**
 * Create a blob store.
 *
 * @param path  Directory for file-backed storage, or NULL/"" for in-memory.
 * @return Handle, or NULL on allocation/IO failure.
 */
metalbear_blob_store *metalbear_blob_store_new(const char *path);

/** Free the store. File-backed blobs are left on disk (caller removes `path`).
 */
void metalbear_blob_store_free(metalbear_blob_store *store);

/**
 * Enable at-rest encryption of the file-backed blob payloads.
 *
 * Derives a libsodium secret-box key from `passphrase` via Argon2id
 * (crypto_pwhash) and, from then on, encrypts every blob payload written to
 * disk and decrypts every one read back (crypto_secretbox_easy /
 * crypto_secretbox_open_easy, XSalsa20-Poly1305). A per-store salt is
 * persisted in "<dir>/.blobstore.salt" on first use so the same passphrase
 * derives the same key across restarts.
 *
 * Must be called after metalbear_blob_store_new and before any reads of a
 * store that was written encrypted; a store written with encryption must be
 * re-opened with the same passphrase to recover its blobs. Passing a null or
 * empty store path (in-memory mode) is an error — encryption only applies to
 * the file-backed store.
 *
 * Returns WF_ERR_NOT_IMPLEMENTED when this build was not configured with
 * METALBEAR_BUILD_BLOB_CRYPTO (the store stays plaintext). WF_ERR_INVALID_ARG
 * on in-memory stores or a null/empty passphrase.
 *
 * The passphrase itself is never persisted; only the salt is. The key is
 * zeroed on metalbear_blob_store_free.
 */
wf_status
metalbear_blob_store_set_crypto_passphrase(metalbear_blob_store *store,
                                           const char *passphrase);

/**
 * Store a blob under `cid`. `mime_type` is copied. `data`/`len` hold the raw
 * blob bytes. Returns WF_OK, WF_ERR_INVALID_ARG on bad inputs, or
 * WF_ERR_INTERNAL on file IO failure.
 */
wf_status metalbear_blob_store_put(metalbear_blob_store *store, const char *cid,
                                   const char *mime_type,
                                   const unsigned char *data, size_t len);

/**
 * Store a blob by streaming `source_path` into the backing store. File-backed
 * stores copy with bounded memory and publish atomically; in-memory stores
 * necessarily retain the payload. `expected_len` must match the source file.
 */
wf_status metalbear_blob_store_put_file(metalbear_blob_store *store,
                                        const char *cid, const char *mime_type,
                                        const char *source_path,
                                        size_t expected_len);

/**
 * Retrieve a blob. On WF_OK, out_data/out_len/out_mime are set to owned
 * buffers (each freed with free()). Returns WF_ERR_NOT_FOUND if absent.
 */
wf_status metalbear_blob_store_get(metalbear_blob_store *store, const char *cid,
                                   unsigned char **out_data, size_t *out_len,
                                   char **out_mime);

/** Return WF_OK if the blob exists, WF_ERR_NOT_FOUND otherwise. */
wf_status metalbear_blob_store_exists(metalbear_blob_store *store,
                                      const char *cid);

wf_status metalbear_blob_store_delete(metalbear_blob_store *store,
                                      const char *cid);

/**
 * Enumerate every stored blob CID. On WF_OK, *out_cids receives a
 * caller-owned NULL-terminated array of CID strings (each freed with
 * free()); use metalbear_blob_store_list_free to release it. Returns
 * WF_ERR_ALLOC on OOM. The order of CIDs is unspecified.
 */
wf_status metalbear_blob_store_list(metalbear_blob_store *store,
                                    char ***out_cids, size_t *out_count);

/** Free a CID array returned by metalbear_blob_store_list. Safe to call with
 * NULL. */
void metalbear_blob_store_list_free(char **cids, size_t count);

/*
 * Enumerate the stored blob CIDs whose first-seen rev sorts strictly after
 * `since`, a repo revision TID (the value a client passes to
 * com.atproto.sync.listBlobs as `since`). Blobs with no recorded rev (loaded
 * from a store created before rev tracking) are never returned here; the
 * plain metalbear_blob_store_list still returns them. Same ownership and
 * allocation contract as metalbear_blob_store_list, and the order of CIDs is
 * unspecified.
 */
wf_status metalbear_blob_store_list_since(metalbear_blob_store *store,
                                          const char *since, char ***out_cids,
                                          size_t *out_count);

/*
 * Recursively find blob references within a record's JSON value and invoke
 * `cb(cid, ctx)` once per occurrence (callers dedupe as needed). A modern
 * blob ref is {"$type":"blob","ref":{"$link":"<cid>"},...}; a legacy blob is
 * {"cid":"<cid>","mimeType":...} with no $type member. Shared by every
 * write-path caller that needs a record's referenced blob CIDs: write-time
 * association/dereference, listMissingBlobs, and checkAccountStatus's
 * expectedBlobs.
 */
void metalbear_blob_walk_refs(const cJSON *node,
                              void (*cb)(const char *cid, void *ctx),
                              void *ctx);

/*
 * Associate `record_uri` with the blob `cid` (idempotent: associating the
 * same pair twice is a no-op). Returns WF_ERR_NOT_FOUND if no blob is stored
 * under `cid` — a record must not reference an unuploaded blob — WF_ERR_ALLOC
 * on OOM, or WF_ERR_INVALID_ARG on bad inputs. Persisted for file-backed
 * stores (survives a restart).
 */
wf_status metalbear_blob_store_associate(metalbear_blob_store *store,
                                         const char *cid,
                                         const char *record_uri);

/*
 * Remove `record_uri`'s association with `cid`. If that was the blob's last
 * remaining association, the blob is deleted from the store outright — this
 * mirrors the reference PDS's deleteDereferencedBlobs: a blob kept alive only
 * by a record write that no longer references it is garbage, removed
 * immediately rather than on a timer. Returns WF_OK whether or not
 * `record_uri` actually held an association, or WF_ERR_NOT_FOUND if `cid` is
 * unknown to the store.
 *
 * A caller processing a write that both drops and re-adds a reference to the
 * same CID (e.g. putRecord replacing a record but keeping one of its blobs)
 * must associate the new value's blobs BEFORE dissociating the old value's,
 * so a still-wanted blob's reference count never touches zero.
 */
wf_status metalbear_blob_store_dissociate(metalbear_blob_store *store,
                                          const char *cid,
                                          const char *record_uri);

/*
 * WF_OK if `cid` currently has at least one record association,
 * WF_ERR_NOT_FOUND if the CID is unknown to the store or has none.
 */
wf_status metalbear_blob_store_is_referenced(metalbear_blob_store *store,
                                             const char *cid);

/*
 * Server integration (requires WOLFRAM_BUILD_SERVER). Registers
 * com.atproto.repo.uploadBlob (procedure) and com.atproto.sync.getBlob (query)
 * on `server`, backed by `store`. The upload handler computes the blob's
 * raw multicodec CID, stores it, and returns the TypedBlobRef; the get handler
 * serves the raw bytes with the stored Content-Type. `store` must outlive the
 * server registration.
 */
wf_status
metalbear_xrpc_server_register_blob_store(wf_xrpc_server *server,
                                          metalbear_blob_store *store);

/*
 * Register the blob routes with a per-request resolver for multi-tenant PDS
 * deployments. The resolver is invoked for every request; it must return (via
 * out_blobs) the metalbear_blob_store that should service the request. The
 * returned store is borrowed for the request duration.
 */
wf_status metalbear_xrpc_server_register_blob_store_resolver(
    wf_xrpc_server *server, metalbear_xrpc_repo_resolver resolver, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_BLOB_STORE_H */
