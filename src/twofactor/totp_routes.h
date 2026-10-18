#ifndef METALBEAR_TWOFACTOR_TOTP_ROUTES_H
#define METALBEAR_TWOFACTOR_TOTP_ROUTES_H

/* Two-factor login over XRPC (docs/totp.md): enrolment, confirmation and
 * disable, and the check that createSession makes when an account has the
 * factor on. Not part of the AT Protocol lexicon; registered under the
 * project-scoped uk.ewancroft.totp.* names, like the other such routes. */

#include <stdbool.h>

#include "../server_internal.h"

wf_status totp_enrol(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response);
wf_status totp_confirm(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response);
wf_status totp_disable(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response);

/* True when the account has an active second factor. */
bool metalbear_totp_login_required(metalbear_server *server,
                                   metalbear_account_context *acct);

/* Checks a login's second factor. A six-digit token is a TOTP code, and any
 * other token is a backup code. Returns WF_OK with *accepted set, or an error
 * when the store could not be read. A code is accepted once. */
wf_status metalbear_totp_check_login_token(metalbear_server *server,
                                           metalbear_account_context *acct,
                                           const char *token, bool *accepted);

#endif
