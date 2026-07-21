#ifndef METALBEAR_ACCOUNT_REGISTRY_H
#define METALBEAR_ACCOUNT_REGISTRY_H

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_account_registry metalbear_account_registry;

typedef struct metalbear_account_entry {
    char *did;
    char *handle;
    char *password_hash;
    char *data_directory;
    int active;
} metalbear_account_entry;

typedef struct metalbear_invite_code_entry {
    char *code;
    char *for_account;
    int uses_remaining;
    int disabled;
    char *created_by;
    char *created_at;
} metalbear_invite_code_entry;

/* Open the account registry, creating it when absent. */
wf_status metalbear_account_registry_open(const char *path,
                                          metalbear_account_registry **out);
void metalbear_account_registry_free(metalbear_account_registry *registry);

/* Register a new account. Returns WF_ERR_CONFLICT if handle is taken. */
wf_status metalbear_account_registry_add(
    metalbear_account_registry *registry,
    const char *did, const char *handle,
    const char *password_hash, const char *data_directory);

/* Look up an account by handle. Caller must free the returned entry. */
wf_status metalbear_account_registry_find_by_handle(
    metalbear_account_registry *registry,
    const char *handle, metalbear_account_entry **out);

/* Look up an account by DID. Caller must free the returned entry. */
wf_status metalbear_account_registry_find_by_did(
    metalbear_account_registry *registry,
    const char *did, metalbear_account_entry **out);

/* List all accounts. Caller must free the array and each entry. */
wf_status metalbear_account_registry_list(
    metalbear_account_registry *registry,
    metalbear_account_entry **out_entries, size_t *out_count);

void metalbear_account_entry_free(metalbear_account_entry *entry);
void metalbear_account_entries_free(metalbear_account_entry *entries,
                                    size_t count);

/* Remove an account from the registry. */
wf_status metalbear_account_registry_remove(
    metalbear_account_registry *registry,
    const char *did);

/* Update the handle for an existing account (keyed by DID). Returns
 * WF_ERR_CONFLICT if the new handle is already taken by another account. */
wf_status metalbear_account_registry_update_handle(
    metalbear_account_registry *registry,
    const char *did, const char *new_handle);

/*
 * Compute the per-account data directory name for `did` under `root`.
 *
 * Each account stores its repositories and state in a dedicated subdirectory
 * of the PDS data root, named by a filesystem-safe encoding of the DID (':' is
 * replaced with '_'). On WF_OK, *out receives a caller-owned absolute path
 * (ending without a slash) that already joins root and the encoded name;
 * free() it when done. The mapping is deterministic so re-opening an account
 * always resolves to the same directory.
 */
wf_status metalbear_account_dir_for_did(const char *root, const char *did,
                                        char **out);

/* --- Invite codes ------------------------------------------------------- */

wf_status metalbear_account_registry_create_invite_codes(
    metalbear_account_registry *registry,
    const char *for_account,
    const char **codes, size_t code_count,
    int use_count);

/* Validate and consume an invite code.  Returns WF_OK on success,
 * WF_ERR_NOT_FOUND if the code does not exist or is exhausted, and
 * WF_ERR_CONFLICT if the code is disabled. */
wf_status metalbear_account_registry_consume_invite_code(
    metalbear_account_registry *registry,
    const char *code, const char *used_by);

/* Return invite codes created for (or attributed to) the given DID. */
wf_status metalbear_account_registry_get_invite_codes(
    metalbear_account_registry *registry,
    const char *did,
    metalbear_invite_code_entry **out, size_t *out_count);

void metalbear_invite_code_entries_free(metalbear_invite_code_entry *entries,
                                       size_t count);

/* --- Subject takedown status -------------------------------------------- */

/* Set or clear a takedown on a subject.  Exactly one of did, uri, or
 * blob_cid must be non-NULL.  Pass ref=NULL to clear the takedown. */
wf_status metalbear_account_registry_set_takedown(
    metalbear_account_registry *registry,
    const char *did, const char *uri, const char *blob_cid,
    const char *ref);

/* Get takedown status for a subject.  Exactly one of did, uri, or
 * blob_cid must be non-NULL.  On WF_OK *out_ref is either NULL (no
 * takedown) or a heap-allocated ref string; caller frees it. */
wf_status metalbear_account_registry_get_takedown(
    metalbear_account_registry *registry,
    const char *did, const char *uri, const char *blob_cid,
    char **out_ref);

#ifdef __cplusplus
}
#endif

#endif
