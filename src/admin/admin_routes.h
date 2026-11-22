#ifndef METALBEAR_ADMIN_ROUTES_H
#define METALBEAR_ADMIN_ROUTES_H

/* com.atproto.admin.* XRPC handlers, registered by server.c's
 * metalbear_server_start against these definitions in admin_routes.c. Not
 * part of the public API.
 *
 * Each `_audited` entry is the wrapper actually registered with the server:
 * it calls the plain handler, then appends one row to the operator audit log
 * (issue #160) with the call's outcome. Refused calls are logged separately
 * by the shared auth callback. */

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
wf_status admin_search_accounts(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response);
wf_status admin_update_account_handle(void *ctx, const wf_xrpc_request *request,
                                      wf_xrpc_response *response);
wf_status admin_update_account_signing_key(void *ctx,
                                           const wf_xrpc_request *request,
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
wf_status admin_export_account_bundle(void *ctx, const wf_xrpc_request *request,
                                      wf_xrpc_response *response);

#define METALBEAR_ADMIN_AUDITED(name)                                          \
    wf_status name##_audited(void *ctx, const wf_xrpc_request *request,        \
                             wf_xrpc_response *response)

METALBEAR_ADMIN_AUDITED(admin_get_account_info);
METALBEAR_ADMIN_AUDITED(admin_get_subject_status);
METALBEAR_ADMIN_AUDITED(admin_update_subject_status);
METALBEAR_ADMIN_AUDITED(admin_send_email);
METALBEAR_ADMIN_AUDITED(admin_get_account_infos);
METALBEAR_ADMIN_AUDITED(admin_search_accounts);
METALBEAR_ADMIN_AUDITED(admin_update_account_handle);
METALBEAR_ADMIN_AUDITED(admin_update_account_signing_key);
METALBEAR_ADMIN_AUDITED(admin_update_account_email);
METALBEAR_ADMIN_AUDITED(admin_update_account_password);
METALBEAR_ADMIN_AUDITED(admin_enable_account_invites);
METALBEAR_ADMIN_AUDITED(admin_disable_account_invites);
METALBEAR_ADMIN_AUDITED(admin_get_invite_codes);
METALBEAR_ADMIN_AUDITED(admin_disable_invite_codes);
METALBEAR_ADMIN_AUDITED(admin_delete_account);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_ADMIN_ROUTES_H */
