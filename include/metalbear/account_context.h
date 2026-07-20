#ifndef METALBEAR_ACCOUNT_CONTEXT_H
#define METALBEAR_ACCOUNT_CONTEXT_H

#include "metalbear/account.h"
#include "metalbear/auth.h"
#include "metalbear/key_rotation.h"
#include "metalbear/oauth.h"
#include "metalbear/sequencer.h"
#include "wolfram/blob_store.h"
#include "metalbear/repo_store.h"
#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * account_context.h — a per-account bundle of the durable stores a PDS needs
 * for one user (repository, blobs, auth, account state, sequencer, OAuth, and
 * signing-key rotation). MetalBear is multi-account: each account lives in its
 * own subdirectory under the PDS data root, and a request resolves the account
 * it acts on (from auth, a did/repo param, or a handle) into one of these.
 *
 * Ownership: an opened context's stores are freed by
 * metalbear_account_context_close. The bootstrap/primary account's context is
 * owned by the server and lives for the process lifetime.
 */

typedef struct metalbear_account_context {
    char *did;
    char *handle;
    char *data_directory; /* absolute path to the account's store directory */
    metalbear_repo_store *repo;
    wf_blob_store *blobs;
    metalbear_auth_store *auth;
    metalbear_account_store *account;
    metalbear_sequencer *sequencer;
    metalbear_oauth_store *oauth;
    metalbear_key_rotation *key_rotation;
    bool active;
} metalbear_account_context;

/*
 * Open (creating if absent) every store for the account described by `did`,
 * `handle`, and `data_directory`. `service_did`/`public_url` come from the PDS
 * configuration and are needed to initialise the auth/OAuth stores.
 * `password` is the plaintext bootstrap password; on first creation it seeds
 * the account credential verifier (subsequent opens may pass NULL after the
 * verifier exists — but pass the password when known to be safe). On WF_OK the
 * context is fully populated with the caller owning it via
 * metalbear_account_context_close.
 */
wf_status metalbear_account_context_open(const char *service_did,
                                         const char *public_url,
                                         const char *did, const char *handle,
                                         const char *data_directory,
                                         const char *password,
                                         metalbear_account_context **out);

/* Free every store in the context and the context itself. Safe with NULL. */
void metalbear_account_context_close(metalbear_account_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_ACCOUNT_CONTEXT_H */
