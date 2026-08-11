#ifndef METALBEAR_ACCOUNT_ROUTES_H
#define METALBEAR_ACCOUNT_ROUTES_H

/* Account-lifecycle XRPC handlers -- com.atproto.server.createAccount,
 * email confirmation/update, password reset, invite codes,
 * checkAccountStatus, and reserveSigningKey -- registered by server.c's
 * metalbear_server_start against these definitions in account_routes.c. Not
 * part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status create_account(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response);
wf_status request_email_confirmation(void *ctx, const wf_xrpc_request *request,
                                     wf_xrpc_response *response);
wf_status confirm_email(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response);
wf_status request_email_update(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response);
wf_status update_email(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response);
wf_status request_password_reset(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response);
wf_status reset_password(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response);
wf_status get_account_invite_codes(void *ctx, const wf_xrpc_request *request,
                                   wf_xrpc_response *response);
wf_status check_account_status(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response);
wf_status reserve_signing_key(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response);
wf_status create_invite_code(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);
wf_status create_invite_codes(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response);
wf_status check_signup_queue(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);
wf_status request_account_delete(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response);
wf_status delete_account(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_ACCOUNT_ROUTES_H */
