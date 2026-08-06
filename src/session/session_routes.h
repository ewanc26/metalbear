#ifndef METALBEAR_SESSION_ROUTES_H
#define METALBEAR_SESSION_ROUTES_H

/* com.atproto.server.* session and app-password XRPC handlers
 * (createSession, getSession, refreshSession, deleteSession,
 * create/list/revokeAppPassword, deactivate/activateAccount), registered by
 * server.c's metalbear_server_start against these definitions in
 * session_routes.c. Not part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status create_session(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response);
wf_status get_session(void *ctx, const wf_xrpc_request *request,
                      wf_xrpc_response *response);
wf_status refresh_session(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response);
wf_status delete_session(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response);
wf_status create_app_password(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response);
wf_status list_app_passwords(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);
wf_status revoke_app_password(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response);
wf_status deactivate_account(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);
wf_status activate_account(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_SESSION_ROUTES_H */
