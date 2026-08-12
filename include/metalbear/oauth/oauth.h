#ifndef METALBEAR_OAUTH_H
#define METALBEAR_OAUTH_H

#include "wolfram/oauth.h"
#include "wolfram/xrpc.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_oauth_store metalbear_oauth_store;

typedef struct metalbear_oauth_request {
    const char *client_id;
    const char *redirect_uri;
    const char *scope;
    const char *state;
    const char *code_challenge;
    const char *dpop_jkt;
} metalbear_oauth_request;

typedef struct metalbear_oauth_grant {
    char *access_token;
    char *refresh_token;
    int64_t expires_in;
} metalbear_oauth_grant;

void metalbear_oauth_grant_free(metalbear_oauth_grant *grant);

/*
 * Open the host's OAuth store. Takes no account: the store holds one signing
 * key for the server, and the account a token speaks for travels with the
 * grant. Binding a single subject here could only ever admit one account.
 */
wf_status metalbear_oauth_store_open(const char *path, const char *issuer,
                                     metalbear_oauth_store **out);
void metalbear_oauth_store_free(metalbear_oauth_store *store);

/* Owned public JWK/JWKS documents for discovery endpoints. */
wf_status metalbear_oauth_public_jwk(metalbear_oauth_store *store,
                                     char **out_jwk);
wf_status metalbear_oauth_jwks(metalbear_oauth_store *store, char **out_jwks);

/* Persist a five-minute pushed authorization request. */
wf_status metalbear_oauth_create_par(metalbear_oauth_store *store,
                                     const metalbear_oauth_request *request,
                                     char **out_request_uri,
                                     int64_t *out_expires_in);

/*
 * Look up a pending PAR without consuming it -- for the consent screen to
 * show what is actually being requested (scope) before the user decides.
 * Fails the same way metalbear_oauth_authorize does on a client_id mismatch
 * (WF_ERR_PERMISSION) or an unknown/expired request_uri (WF_ERR_NOT_FOUND),
 * but never deletes the PAR row: the user can reload the consent page (or
 * the frontend can retry) without invalidating the request they are still
 * deciding on.
 */
wf_status metalbear_oauth_par_peek(metalbear_oauth_store *store,
                                   const char *request_uri,
                                   const char *client_id, char **out_scope,
                                   char **out_redirect_uri);

/* Consume a PAR and issue a five-minute, one-time authorization code. */
/* `subject` is the account DID the issued code (and every token minted from
 * it) speaks for. */
wf_status metalbear_oauth_authorize(metalbear_oauth_store *store,
                                    const char *request_uri,
                                    const char *client_id, const char *subject,
                                    char **out_code, char **out_redirect_uri,
                                    char **out_state);

/* Exchange a code using S256 PKCE and the same DPoP key used at PAR. */
wf_status metalbear_oauth_exchange_code(metalbear_oauth_store *store,
                                        const char *code, const char *client_id,
                                        const char *redirect_uri,
                                        const char *code_verifier,
                                        const char *dpop_jkt,
                                        metalbear_oauth_grant *out);

/* Rotate a refresh token and retain its client, scope, and DPoP binding. */
wf_status metalbear_oauth_refresh(metalbear_oauth_store *store,
                                  const char *refresh_token,
                                  const char *client_id, const char *dpop_jkt,
                                  metalbear_oauth_grant *out);
wf_status metalbear_oauth_revoke(metalbear_oauth_store *store,
                                 const char *token);

/* Verify a self-issued access token plus its request-bound DPoP proof. */
wf_status metalbear_oauth_verify_request(metalbear_oauth_store *store,
                                         const char *authorization,
                                         const char *dpop_proof,
                                         const char *method, const char *uri,
                                         wf_oauth_verified_token **out);

/*
 * A device session: proof, held by a browser as a cookie, that this browser
 * has already presented an account password once. `/oauth/authorize` is a
 * plain page navigation with no Authorization header, so this is what a
 * bearer token is everywhere else — the thing that lets the endpoint tell an
 * authenticated browser apart from anyone who merely knows a handle.
 *
 * Deliberately outside the account/app-password credential system: a device
 * session is bearer-by-cookie rather than bearer-by-header, lives 30 days,
 * and is revoked by name rather than rotated. Folding it into
 * metalbear_auth_store would give the browser session the refresh-rotation
 * semantics an API client needs and a browser cookie does not.
 */
#define METALBEAR_DEVICE_SESSION_LIFETIME_SECONDS (30 * 24 * 60 * 60)

/* Create a device session for `subject` (an account DID). *out_token is a
 * caller-owned opaque bearer value; store it only as a cookie, never log or
 * echo it. */
wf_status metalbear_oauth_device_session_create(metalbear_oauth_store *store,
                                                const char *subject,
                                                char **out_token);

/*
 * Resolve a device session token to the account DID it was issued for.
 * Writes into `out` (caller-supplied buffer) and returns WF_OK, or
 * WF_ERR_NOT_FOUND if the token is unknown, expired, or NULL.
 */
wf_status metalbear_oauth_device_session_verify(metalbear_oauth_store *store,
                                                const char *token, char *out,
                                                size_t out_len);

/* Revoke a device session. Revoking an unknown or already-expired token is
 * WF_OK: the desired state — signed out — already holds. */
wf_status metalbear_oauth_device_session_revoke(metalbear_oauth_store *store,
                                                const char *token);

/*
 * One device session, as surfaced to an account-management UI: a stable,
 * non-secret identifier (base64url of the session's token_hash) and its
 * expiry. Exposing the hash is safe -- it does not let anyone forge the
 * token that hashes to it, since that would require breaking SHA-256
 * preimage resistance -- but the bearer token itself is never returned
 * once issued.
 */
typedef struct metalbear_oauth_device_session_info {
    char *session_id;
    int64_t expires_at;
} metalbear_oauth_device_session_info;

/* List every still-valid device session for `subject`, most recently
 * expiring first (every session is minted with the same fixed lifetime, so
 * expiry order is also creation order). Caller frees with
 * metalbear_oauth_device_session_info_list_free. */
wf_status metalbear_oauth_device_session_list(
    metalbear_oauth_store *store, const char *subject,
    metalbear_oauth_device_session_info **out_items, size_t *out_count);

void metalbear_oauth_device_session_info_list_free(
    metalbear_oauth_device_session_info *items, size_t count);

/* Revoke one device session by the session_id
 * metalbear_oauth_device_session_list returned, scoped to `subject` so one
 * account can never revoke another's session by guessing or reusing an id.
 * WF_ERR_NOT_FOUND if it does not belong to `subject` (including "does not
 * exist at all"). */
wf_status metalbear_oauth_device_session_revoke_by_id(
    metalbear_oauth_store *store, const char *subject, const char *session_id);

/* One OAuth client currently holding a live grant (refresh token) for an
 * account -- what an account-management "connected apps" page lists. */
typedef struct metalbear_oauth_grant_info {
    char *client_id;
    char *scope;
    int64_t expires_at;
} metalbear_oauth_grant_info;

/* List every OAuth client with a still-valid refresh token for `subject`,
 * one entry per distinct client_id (a client that re-authorized more than
 * once is still one connection, not several). Caller frees with
 * metalbear_oauth_grant_info_list_free. */
wf_status metalbear_oauth_grants_list(metalbear_oauth_store *store,
                                      const char *subject,
                                      metalbear_oauth_grant_info **out_items,
                                      size_t *out_count);

void metalbear_oauth_grant_info_list_free(metalbear_oauth_grant_info *items,
                                          size_t count);

/* Revoke every refresh token `client_id` holds for `subject` -- ending that
 * app's access outright rather than waiting for its current token to
 * expire. WF_OK even if the client had no live grant: the desired state
 * (disconnected) already holds. */
wf_status metalbear_oauth_grants_revoke(metalbear_oauth_store *store,
                                        const char *subject,
                                        const char *client_id);

/* ── Passkeys (WebAuthn) ────────────────────────────────────────────────
 *
 * A passkey is a P-256 public key credential registered by a browser's
 * WebAuthn implementation, usable as an alternative to a password for
 * signing in (via the /oauth/passkey/authenticate routes, which end the
 * same way POST /oauth/signin does: a device session). See
 * src/oauth/webauthn.c for the
 * CBOR/ceremony verification these functions build on.
 */

#define METALBEAR_WEBAUTHN_CHALLENGE_LIFETIME_SECONDS 120

typedef enum metalbear_webauthn_ceremony {
    METALBEAR_WEBAUTHN_CEREMONY_REGISTRATION,
    METALBEAR_WEBAUTHN_CEREMONY_AUTHENTICATION,
} metalbear_webauthn_ceremony;

/* Issue a fresh challenge for `subject`, bound to one ceremony kind so an
 * authentication challenge can't later be replayed to complete a
 * registration (or vice versa). *out_challenge is a caller-owned
 * base64url-encoded random value (free with free()). */
wf_status metalbear_oauth_passkey_challenge_create(
    metalbear_oauth_store *store, metalbear_webauthn_ceremony ceremony,
    const char *subject, char **out_challenge);

/* Consume a challenge (single-use, like an authorization code): verifies
 * it exists, matches `ceremony`, and has not expired, then deletes it and
 * writes the subject it was issued for into `out` (caller-supplied
 * buffer). WF_ERR_NOT_FOUND if the challenge is unknown, expired, or was
 * issued for a different ceremony. */
wf_status metalbear_oauth_passkey_challenge_consume(
    metalbear_oauth_store *store, const char *challenge,
    metalbear_webauthn_ceremony ceremony, char *out, size_t out_len);

/* Register a new passkey for `subject`. WF_ERR_DUPLICATE if this exact
 * credential (by ID) is already registered -- to this account or another,
 * since a physical authenticator's credential ID is globally unique. */
wf_status metalbear_oauth_passkey_add(metalbear_oauth_store *store,
                                      const char *subject,
                                      const unsigned char *credential_id,
                                      size_t credential_id_len,
                                      const unsigned char public_key_x[32],
                                      const unsigned char public_key_y[32],
                                      const char *name);

/* Look up a passkey by credential ID (how a browser identifies which
 * credential it just used, at authentication time, before the account
 * that owns it is otherwise known). WF_ERR_NOT_FOUND if unregistered. */
wf_status metalbear_oauth_passkey_lookup(
    metalbear_oauth_store *store, const unsigned char *credential_id,
    size_t credential_id_len, char *out_subject, size_t out_subject_len,
    unsigned char public_key_x[32], unsigned char public_key_y[32],
    uint32_t *out_sign_count);

/* Update a passkey's stored signature counter and last-used timestamp
 * after a successful authentication. A monotonically non-increasing
 * counter (checked by the caller before calling this) is the standard
 * WebAuthn signal that a credential may have been cloned. */
wf_status metalbear_oauth_passkey_touch(metalbear_oauth_store *store,
                                        const unsigned char *credential_id,
                                        size_t credential_id_len,
                                        uint32_t new_sign_count);

/* One passkey, as surfaced to an account-management UI. id is the
 * credential ID, base64url-encoded. */
typedef struct metalbear_oauth_passkey_info {
    char *id;
    char *name; /* NULL if never named */
    int64_t created_at;
    int64_t last_used_at; /* 0 if never used */
} metalbear_oauth_passkey_info;

/* List every passkey registered for `subject`, most recently created
 * first. Caller frees with metalbear_oauth_passkey_info_list_free. */
wf_status metalbear_oauth_passkey_list(metalbear_oauth_store *store,
                                       const char *subject,
                                       metalbear_oauth_passkey_info **out_items,
                                       size_t *out_count);

void metalbear_oauth_passkey_info_list_free(metalbear_oauth_passkey_info *items,
                                            size_t count);

/* Remove one passkey by the id metalbear_oauth_passkey_list returned,
 * scoped to `subject` so one account can never remove another's passkey.
 * WF_ERR_NOT_FOUND if it does not belong to `subject`. */
wf_status metalbear_oauth_passkey_remove(metalbear_oauth_store *store,
                                         const char *subject, const char *id);

/* Whether `subject` has at least one registered passkey -- lets a login
 * page decide whether to offer "sign in with a passkey" at all before the
 * user has typed anything past their identifier. */
wf_status metalbear_oauth_passkey_exists(metalbear_oauth_store *store,
                                         const char *subject, int *out_exists);

#ifdef __cplusplus
}
#endif

#endif
