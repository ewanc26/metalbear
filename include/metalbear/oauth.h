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

wf_status metalbear_oauth_store_open(const char *path, const char *issuer,
                                     const char *subject,
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

/* Consume a PAR and issue a five-minute, one-time authorization code. */
wf_status metalbear_oauth_authorize(metalbear_oauth_store *store,
                                    const char *request_uri,
                                    const char *client_id,
                                    char **out_code,
                                    char **out_redirect_uri,
                                    char **out_state);

/* Exchange a code using S256 PKCE and the same DPoP key used at PAR. */
wf_status metalbear_oauth_exchange_code(metalbear_oauth_store *store,
                                        const char *code,
                                        const char *client_id,
                                        const char *redirect_uri,
                                        const char *code_verifier,
                                        const char *dpop_jkt,
                                        metalbear_oauth_grant *out);

/* Rotate a refresh token and retain its client, scope, and DPoP binding. */
wf_status metalbear_oauth_refresh(metalbear_oauth_store *store,
                                  const char *refresh_token,
                                  const char *client_id,
                                  const char *dpop_jkt,
                                  metalbear_oauth_grant *out);
wf_status metalbear_oauth_revoke(metalbear_oauth_store *store,
                                 const char *token);

/* Verify a self-issued access token plus its request-bound DPoP proof. */
wf_status metalbear_oauth_verify_request(
    metalbear_oauth_store *store, const char *authorization,
    const char *dpop_proof, const char *method, const char *uri,
    wf_oauth_verified_token **out);

#ifdef __cplusplus
}
#endif

#endif
