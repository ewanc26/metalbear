#ifndef METALBEAR_ACCOUNT_H
#define METALBEAR_ACCOUNT_H

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_account_store metalbear_account_store;

typedef enum metalbear_credential_kind {
    METALBEAR_CREDENTIAL_INVALID = 0,
    METALBEAR_CREDENTIAL_ACCOUNT,
    METALBEAR_CREDENTIAL_APP_PASSWORD,
    METALBEAR_CREDENTIAL_APP_PASSWORD_PRIVILEGED,
} metalbear_credential_kind;

typedef struct metalbear_app_password {
    char *name;
    char *created_at;
    bool privileged;
} metalbear_app_password;

wf_status metalbear_account_store_open(const char *path,
                                       const char *bootstrap_password,
                                       metalbear_account_store **out);
void metalbear_account_store_free(metalbear_account_store *store);
int metalbear_account_is_active(metalbear_account_store *store);
/* *out_deactivated_at is NULL (not an error) when the account is active or
 * has never been deactivated; otherwise an ISO-8601 timestamp the caller
 * frees with free(). */
wf_status metalbear_account_get_deactivated_at(metalbear_account_store *store,
                                               char **out_deactivated_at);
wf_status metalbear_account_deactivate(metalbear_account_store *store,
                                       const char *delete_after);
wf_status metalbear_account_activate(metalbear_account_store *store);
int metalbear_account_verify_password(metalbear_account_store *store,
                                      const char *password);
metalbear_credential_kind
metalbear_account_verify_credential(metalbear_account_store *store,
                                    const char *password,
                                    char **out_app_password_name);
wf_status metalbear_account_create_app_password(metalbear_account_store *store,
                                                const char *name,
                                                bool privileged,
                                                char **out_password,
                                                char **out_created_at);
wf_status
metalbear_account_list_app_passwords(metalbear_account_store *store,
                                     metalbear_app_password **out_passwords,
                                     size_t *out_count);
void metalbear_app_passwords_free(metalbear_app_password *passwords,
                                  size_t count);
wf_status metalbear_account_revoke_app_password(metalbear_account_store *store,
                                                const char *name);
wf_status metalbear_account_delete(metalbear_account_store *store);
wf_status metalbear_account_store_email(metalbear_account_store *store,
                                        const char *email);
wf_status metalbear_account_get_email(metalbear_account_store *store,
                                      char **out_email, int *out_confirmed);
wf_status metalbear_account_create_email_token(metalbear_account_store *store,
                                               const char *kind,
                                               char *out_token,
                                               size_t token_len);
wf_status metalbear_account_verify_email_token(metalbear_account_store *store,
                                               const char *kind,
                                               const char *token);
/* Delete every outstanding email token of the given kind (e.g.
 * "reset_password"), without needing to know the token value itself.
 * Matches the reference's emailToken.deleteEmailToken(dbTxn, did, kind). */
wf_status
metalbear_account_delete_email_tokens_by_kind(metalbear_account_store *store,
                                              const char *kind);
/* Delete every outstanding email token regardless of kind. Matches the
 * reference's emailToken.deleteAllEmailTokens(dbTxn, did), called whenever
 * an admin overrides the account's email: any token minted against the old
 * email (confirm/update/reset) must not remain usable afterward. */
wf_status
metalbear_account_delete_all_email_tokens(metalbear_account_store *store);
wf_status metalbear_account_reset_password(metalbear_account_store *store,
                                           const char *new_password);
wf_status metalbear_account_store_prefs_get(metalbear_account_store *store,
                                            char **out_json);
wf_status metalbear_account_store_prefs_put(metalbear_account_store *store,
                                            const char *json);
/* Published signing key (did:key:z...) advertised by this account's DID
 * document. NULL (with WF_OK) when no admin override has been set, in which
 * case the repo's creation-time key is used. The caller frees *out_didkey. */
wf_status
metalbear_account_store_get_signing_key(metalbear_account_store *store,
                                        char **out_didkey);
/* Persist the published signing key after a successful PLC operation. A NULL
 * key clears the override, returning the account to its creation-time key. */
wf_status
metalbear_account_store_set_signing_key(metalbear_account_store *store,
                                        const char *didkey);
/* Return whether the account may receive new invite codes (default 1). */
bool metalbear_account_invites_enabled(metalbear_account_store *store);
/* Set whether the account may receive new invite codes. */
wf_status metalbear_account_set_invites_enabled(metalbear_account_store *store,
                                                bool enabled);
/*
 * Per-account storage quotas and current usage, both in bytes. A quota of 0
 * means unlimited (the default). `blob` selects blob bytes; false selects
 * durable repo block bytes. reserve_bytes atomically checks that adding
 * `amount` stays within the quota (and does not overflow) before recording
 * it, returning WF_ERR_RATE_LIMIT when it would not. release_bytes clamps at
 * zero. set_usage is for reconciliation after GC and for initialising a store
 * that predates the usage columns. All of these serialise on the account
 * store's own mutex, so callers need no extra lock.
 */
wf_status metalbear_account_get_quotas(metalbear_account_store *store,
                                       uint64_t *out_repo_bytes,
                                       uint64_t *out_blob_bytes);
wf_status metalbear_account_set_quotas(metalbear_account_store *store,
                                       uint64_t repo_bytes,
                                       uint64_t blob_bytes);
wf_status metalbear_account_get_usage(metalbear_account_store *store,
                                      uint64_t *out_repo_bytes,
                                      uint64_t *out_blob_bytes);
wf_status metalbear_account_set_usage(metalbear_account_store *store, bool blob,
                                      uint64_t used);
wf_status metalbear_account_reserve_bytes(metalbear_account_store *store,
                                          bool blob, uint64_t amount);
wf_status metalbear_account_release_bytes(metalbear_account_store *store,
                                          bool blob, uint64_t amount);
/* Hash a password with scrypt for storage. Caller must free the result. */
char *metalbear_account_hash_password(const char *password);

#ifdef __cplusplus
}
#endif

#endif
