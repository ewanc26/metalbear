#include "oauth_credentials.h"
#include "../server_internal.h"

#include <string.h>
#include <stdio.h>

/*
 * Resolve an OAuth `login_hint` (handle or DID) to the account's DID.
 *
 * Handed to the OAuth routes so an authorization names a real account hosted
 * here. Returning 0 for an unknown hint is what keeps the endpoint from
 * issuing a token for an identity this server does not host.
 */
int resolve_oauth_subject(void *ctx, const char *hint, char *out,
                          size_t out_len) {
    metalbear_server *server = ctx;
    if (!server || !hint || !hint[0] || !out || out_len == 0) return 0;
    metalbear_account_context *acct = context_for_identifier(server, hint);
    if (!acct || !acct->did || !acct->did[0]) return 0;
    if (strlen(acct->did) >= out_len) return 0;
    snprintf(out, out_len, "%s", acct->did);
    return 1;
}

/*
 * Verify credentials for a device session — /oauth/authorize's proof that
 * the browser controls the account login_hint names, not merely that it
 * knows the handle.
 *
 * Account password only. metalbear_account_verify_credential also accepts
 * app passwords, which valid_login (createSession's own check) is right to
 * allow: an app password is meant to open a session scoped to one
 * third-party client. A device session is not that — it authorizes THIS
 * endpoint to grant arbitrary OTHER OAuth clients access, and opens the web
 * UI's account management including creating further app passwords. An app
 * password that could open one would be a scoped credential escalating
 * itself to full account control, so METALBEAR_CREDENTIAL_ACCOUNT is
 * checked explicitly rather than accepting whatever
 * metalbear_account_verify_credential accepted.
 */
int verify_oauth_credential(void *ctx, const char *identifier,
                            const char *password, char *out, size_t out_len) {
    metalbear_server *server = ctx;
    if (!server || !identifier || !identifier[0] || !password || !out ||
        out_len == 0)
        return 0;
    metalbear_account_context *acct =
        context_for_identifier(server, identifier);
    if (!acct || !acct->did || !acct->did[0]) return 0;
    metalbear_credential_kind credential =
        metalbear_account_verify_credential(acct->account, password, NULL);
    if (credential != METALBEAR_CREDENTIAL_ACCOUNT) return 0;
    if (strlen(acct->did) >= out_len) return 0;
    snprintf(out, out_len, "%s", acct->did);
    return 1;
}
