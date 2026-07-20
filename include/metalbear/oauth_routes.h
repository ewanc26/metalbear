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
wf_status metalbear_oauth_routes_register(wf_xrpc_server *server,
                                          metalbear_oauth_store *store,
                                          const char *public_url,
                                          const char *service_did,
                                          const char *account_did);

#ifdef __cplusplus
}
#endif

#endif
