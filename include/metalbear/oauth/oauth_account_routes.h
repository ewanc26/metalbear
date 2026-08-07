#ifndef METALBEAR_OAUTH_ACCOUNT_ROUTES_H
#define METALBEAR_OAUTH_ACCOUNT_ROUTES_H

/*
 * Account-management handlers for OAuth state: connected apps (grants) and
 * active device sessions. Unlike oauth_routes.c's routes, these are
 * ordinary JWT-authenticated XRPC procedures/queries (registered by
 * server.c through the standard authenticate() callback, ctx = server,
 * exactly like list_app_passwords in session_routes.c) rather than raw
 * HTTP routes with their own cookie-based auth -- this is "manage my own
 * account", reached from the authenticated account area, not part of the
 * OAuth authorization flow itself.
 *
 * Not part of the AT Protocol lexicon (there is no standard for this), so
 * these are registered under a project-scoped nsid rather than
 * com.atproto.* -- following the same non-lexicon precedent as this
 * server's own "_health" query.
 */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status oauth_list_devices(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);
wf_status oauth_revoke_device(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response);
wf_status oauth_list_grants(void *ctx, const wf_xrpc_request *request,
                            wf_xrpc_response *response);
wf_status oauth_revoke_grant(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_OAUTH_ACCOUNT_ROUTES_H */
