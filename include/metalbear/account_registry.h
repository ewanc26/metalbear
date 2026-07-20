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

#ifdef __cplusplus
}
#endif

#endif
