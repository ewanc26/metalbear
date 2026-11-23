#ifndef METALBEAR_AUTH_H
#define METALBEAR_AUTH_H

#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_auth_store metalbear_auth_store;

typedef enum metalbear_access_scope {
    METALBEAR_ACCESS_FULL = 0,
    METALBEAR_ACCESS_APP_PASSWORD,
    METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED,
    /* Issued by createSession's `allowTakendown` instead of refusing a
     * taken-down account outright. Narrower than every other tier: gates
     * only the handful of routes a taken-down holder needs to appeal or
     * migrate away (see takendown_route_allowed in server.c), matching the
     * reference's AuthScope.Takendown. */
    METALBEAR_ACCESS_TAKENDOWN,
} metalbear_access_scope;

typedef struct metalbear_session_tokens {
    char *access_jwt;
    char *refresh_jwt;
} metalbear_session_tokens;

void metalbear_session_tokens_free(metalbear_session_tokens *tokens);

/* Opens the restart-persistent HS256 session store, creating it when absent. */
wf_status metalbear_auth_store_open(const char *path, const char *service_did,
                                    const char *account_did,
                                    metalbear_auth_store **out);
void metalbear_auth_store_free(metalbear_auth_store *store);

/* Mint an access/refresh pair and persist the refresh token identifier. */
wf_status metalbear_auth_create_session(metalbear_auth_store *store,
                                        metalbear_session_tokens *out);
wf_status metalbear_auth_create_scoped_session(metalbear_auth_store *store,
                                               metalbear_access_scope scope,
                                               const char *app_password_name,
                                               metalbear_session_tokens *out);

/* Verify a signed, unexpired access token and its exact audience/subject. */
wf_status metalbear_auth_verify_access(metalbear_auth_store *store,
                                       const char *token);
wf_status metalbear_auth_verify_access_scope(metalbear_auth_store *store,
                                             const char *token,
                                             metalbear_access_scope *out_scope);

/* Rotate a refresh token, preserving upstream's two-hour reuse grace period. */
wf_status metalbear_auth_rotate_refresh(metalbear_auth_store *store,
                                        const char *refresh_token,
                                        metalbear_session_tokens *out);

/* Revoke the presented refresh token. Expired but authentic tokens are valid.
 */
wf_status metalbear_auth_revoke_refresh(metalbear_auth_store *store,
                                        const char *refresh_token);

/* Revoke every refresh chain minted from a named app password. */
wf_status
metalbear_auth_revoke_app_password_sessions(metalbear_auth_store *store,
                                            const char *app_password_name);
wf_status metalbear_auth_delete_all(metalbear_auth_store *store);

/* Two-factor login state for this account (docs/totp.md). One enrolled secret
 * at most. The secret is stored sealed under the server key, so this layer
 * only sees ciphertext. */
typedef struct metalbear_auth_totp {
    unsigned char *secret; /* sealed; caller frees */
    size_t secret_len;
    bool active;
    int64_t last_step;
    bool found;
} metalbear_auth_totp;

void metalbear_auth_totp_free(metalbear_auth_totp *record);
/* Stores a pending secret, not yet active. Replaces any pending one. */
wf_status metalbear_auth_totp_put_pending(metalbear_auth_store *store,
                                          const unsigned char *sealed,
                                          size_t sealed_len);
wf_status metalbear_auth_totp_get(metalbear_auth_store *store,
                                  metalbear_auth_totp *out);
/* Activates the pending secret and stores the backup-code hashes, in one
 * transaction. The step is the one the confirming code matched, so that code
 * cannot be replayed. Fails when nothing is pending. */
wf_status metalbear_auth_totp_activate(metalbear_auth_store *store,
                                       const unsigned char (*hashes)[32],
                                       size_t hash_count, int64_t step);
/* Records a step as used, only if it is later than the last one used. Returns
 * true when this call recorded it, so a code that already matched is refused.
 */
wf_status metalbear_auth_totp_use_step(metalbear_auth_store *store,
                                       int64_t step, bool *recorded);
/* Deletes a backup code's hash if present. */
wf_status metalbear_auth_totp_consume_backup(metalbear_auth_store *store,
                                             const unsigned char hash[32],
                                             bool *consumed);
/* Removes the secret and every backup code. */
wf_status metalbear_auth_totp_disable(metalbear_auth_store *store);

/* Trusted devices that skip the second factor on a later full-password login
 * (issue #131). The browser never gets the stored value back: only a keyed
 * hash, a public id for revocation and an expiry are persisted in the same
 * per-account auth database as the session keys. */
typedef struct metalbear_auth_trusted_device {
    char *id; /* public handle, safe to show in a list and revoke */
    int64_t created_at;
    int64_t expires_at;
} metalbear_auth_trusted_device;

void metalbear_auth_trusted_device_list_free(
    metalbear_auth_trusted_device *items, size_t count);
/* Stores a new device. The caller supplies the id and the keyed hash; raw
 * tokens never reach this layer. Expired rows are pruned on every write. */
wf_status metalbear_auth_trusted_device_add(metalbear_auth_store *store,
                                            const char *id,
                                            const unsigned char hash[32],
                                            int64_t created_at,
                                            int64_t expires_at);
/* True only when a non-expired row matches the presented hash. Never throws
 * when the table is absent or the database cannot be read: *valid stays
 * false, so a failed lookup requires the second factor again. */
wf_status metalbear_auth_trusted_device_valid(metalbear_auth_store *store,
                                              const unsigned char hash[32],
                                              bool *valid);
wf_status
metalbear_auth_trusted_device_list(metalbear_auth_store *store,
                                   metalbear_auth_trusted_device **out,
                                   size_t *out_count);
/* Sets *removed to false when the id is not present. */
wf_status metalbear_auth_trusted_device_remove(metalbear_auth_store *store,
                                               const char *id, bool *removed);
wf_status metalbear_auth_trusted_device_remove_all(metalbear_auth_store *store);

#ifdef __cplusplus
}
#endif

#endif
