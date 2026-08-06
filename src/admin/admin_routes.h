#ifndef METALBEAR_ADMIN_ROUTES_H
#define METALBEAR_ADMIN_ROUTES_H

/* com.atproto.admin.* XRPC handlers, registered by server.c's
 * metalbear_server_start against these definitions in admin_routes.c. Not
 * part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status admin_get_account_info(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response);
wf_status admin_get_subject_status(void *ctx, const wf_xrpc_request *request,
                                   wf_xrpc_response *response);
wf_status admin_update_subject_status(void *ctx, const wf_xrpc_request *request,
                                      wf_xrpc_response *response);
wf_status admin_send_email(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response);
wf_status admin_get_account_infos(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response);
wf_status admin_update_account_handle(void *ctx, const wf_xrpc_request *request,
                                      wf_xrpc_response *response);
wf_status admin_update_account_email(void *ctx, const wf_xrpc_request *request,
                                     wf_xrpc_response *response);
wf_status admin_update_account_password(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response);
wf_status admin_enable_account_invites(void *ctx,
                                       const wf_xrpc_request *request,
                                       wf_xrpc_response *response);
wf_status admin_disable_account_invites(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response);
wf_status admin_get_invite_codes(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response);
wf_status admin_disable_invite_codes(void *ctx, const wf_xrpc_request *request,
                                     wf_xrpc_response *response);
wf_status admin_delete_account(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_ADMIN_ROUTES_H */
