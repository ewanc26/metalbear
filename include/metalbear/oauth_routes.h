#ifndef METALBEAR_OAUTH_ROUTES_H
#define METALBEAR_OAUTH_ROUTES_H

#include "metalbear/oauth.h"
#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register all OAuth HTTP routes on the XRPC server.
 * Routes bypass the XRPC auth callback and handle their own authentication.
 * Paths registered:
 *   GET  /.well-known/oauth-authorization-server
 *   GET  /.well-known/oauth-protected-resource
 *   GET  /oauth/jwks
 *   POST /oauth/par
 *   POST /oauth/token
 *   POST /oauth/revoke
 *   GET  /oauth/authorize */
/*
 * Resolve an account hint (a handle or DID supplied as `login_hint`) to the
 * account's DID. Writes it into `out` and returns 1, or returns 0 when no such
 * account is hosted here.
 */
typedef int (*metalbear_oauth_subject_resolver)(void *ctx, const char *hint,
                                                char *out, size_t out_len);

/*
 * `resolve_subject` names which account an authorization is for. It is
 * required: with no privileged account there is no default identity to issue
 * a token for, and guessing one would hand a client somebody else's session.
 */
wf_status metalbear_oauth_routes_register(wf_xrpc_server *server,
                                          metalbear_oauth_store *store,
                                          const char *public_url,
                                          const char *service_did,
                                          metalbear_oauth_subject_resolver
                                              resolve_subject,
                                          void *resolver_ctx);

#ifdef __cplusplus
}
#endif

#endif
