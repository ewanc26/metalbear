#ifndef METALBEAR_AUTH_H
#define METALBEAR_AUTH_H

#include "wolfram/xrpc.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_auth_store metalbear_auth_store;

typedef enum metalbear_access_scope {
    METALBEAR_ACCESS_FULL = 0,
    METALBEAR_ACCESS_APP_PASSWORD,
    METALBEAR_ACCESS_APP_PASSWORD_PRIVILEGED,
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
wf_status metalbear_auth_create_scoped_session(
    metalbear_auth_store *store, metalbear_access_scope scope,
    const char *app_password_name, metalbear_session_tokens *out);

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

/* Revoke the presented refresh token. Expired but authentic tokens are valid. */
wf_status metalbear_auth_revoke_refresh(metalbear_auth_store *store,
                                        const char *refresh_token);

/* Revoke every refresh chain minted from a named app password. */
wf_status metalbear_auth_revoke_app_password_sessions(
    metalbear_auth_store *store, const char *app_password_name);
wf_status metalbear_auth_delete_all(metalbear_auth_store *store);

#ifdef __cplusplus
}
#endif

#endif
