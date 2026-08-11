#include "account_routes.h"
#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/repo/blob_store.h"
#include "wolfram/crypto.h"
#include "wolfram/plc.h"
#include "wolfram/syntax.h"

#include <cJSON.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mint a did:plc for `handle` and return it (caller frees), writing the
 * account signing key the operation publishes into *out_signing_key. The
 * repo created for this DID must adopt that key: a repo signing with anything
 * else contradicts its own DID document, and relays reject it. */
static char *mint_plc_did(metalbear_server *server, const char *handle,
                          wf_signing_key *out_signing_key) {
    cJSON *root = NULL;
    cJSON *verification = NULL;
    char *unsigned_json = NULL;
    char *signed_json = NULL;
    char *account_didkey = NULL;
    char *rotation_didkey = NULL;
    wf_signing_key acct_key;
    wf_signing_key rotation_key;
    char *plc_did = NULL;

    memset(&acct_key, 0, sizeof(acct_key));
    memset(&rotation_key, 0, sizeof(rotation_key));

    /* 1. Generate fresh secp256k1 signing key for the new account. */
    if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &acct_key) != WF_OK) {
        LOG_ERROR("failed to generate account signing key");
        goto fail;
    }
    if (wf_signing_key_public_didkey(&acct_key, &account_didkey) != WF_OK) {
        LOG_ERROR("failed to get account did:key");
        goto fail;
    }

    /* 2. Load the server's PLC rotation key to sign the genesis operation.
     * It belongs to the host, so minting a DID no longer depends on some
     * other account existing first. */
    if (metalbear_key_rotation_current_key(server->plc_rotation,
                                           &rotation_key) != WF_OK) {
        LOG_ERROR("failed to get rotation key");
        goto fail;
    }
    if (wf_signing_key_public_didkey(&rotation_key, &rotation_didkey) !=
        WF_OK) {
        LOG_ERROR("failed to get rotation did:key");
        goto fail;
    }

    /* 3. Build the unsigned plc_operation. */
    const char *rotation_keys[] = {rotation_didkey};
    char aka_buf[256];
    char services_buf[512];
    snprintf(aka_buf, sizeof(aka_buf), "at://%s", handle);
    snprintf(services_buf, sizeof(services_buf),
             "{\"atproto_pds\":{\"type\":\"AtprotoPersonalDataServer\","
             "\"endpoint\":\"%s\"}}",
             server->public_url ? server->public_url : "");

    wf_plc_operation_update update = {
        .rotation_keys = rotation_keys,
        .rotation_keys_count = 1,
        .verification_methods_json = NULL,
        .services_json = services_buf,
        .also_known_as = (const char *const[]){aka_buf},
        .also_known_as_count = 1,
        .prev = NULL,
    };

    if (wf_plc_operation_build(&update, &unsigned_json) != WF_OK) {
        LOG_ERROR("failed to build PLC operation");
        goto fail;
    }

    /* Inject the account did:key into verificationMethods. */
    root = cJSON_Parse(unsigned_json);
    if (!root) {
        LOG_ERROR("failed to parse unsigned operation JSON");
        goto fail;
    }
    verification =
        cJSON_GetObjectItemCaseSensitive(root, "verificationMethods");
    if (!cJSON_IsObject(verification)) {
        LOG_ERROR("unsigned operation missing verificationMethods");
        goto fail;
    }
    {
        cJSON *old =
            cJSON_DetachItemFromObjectCaseSensitive(verification, "atproto");
        if (old) cJSON_Delete(old);
    }
    if (!cJSON_AddStringToObject(verification, "atproto", account_didkey)) {
        LOG_ERROR("failed to add atproto verification method");
        goto fail;
    }
    char *unsigned_with_key = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    root = NULL;
    if (!unsigned_with_key) {
        LOG_ERROR("failed to serialize unsigned operation with key");
        goto fail;
    }

    /* 5. Sign the genesis operation with the rotation key. */
    if (wf_plc_operation_sign(unsigned_with_key, &rotation_key, &signed_json) !=
        WF_OK) {
        LOG_ERROR("failed to sign PLC operation");
        goto fail;
    }

    /* 6. Compute the deterministic DID from the signed operation (including
     *    the sig field, matching the @did-plc/lib reference implementation). */
    if (wf_plc_operation_compute_did(signed_json, &plc_did) != WF_OK) {
        LOG_ERROR("failed to compute PLC DID");
        goto fail;
    }

    /* 7. Submit to the PLC directory; the response body is unused.
     * The operation documents themselves are never logged: they carry the
     * account's rotation and signing did:keys and the signature over them, and
     * this runs at INFO on a server whose logs are routinely shipped
     * elsewhere. The DID and directory URL are enough to trace a submission. */
    LOG_INFO("submitting PLC operation to %s for DID %s", server->plc_url,
             plc_did);
    if (wf_plc_submit_operation_raw(server->plc_url, plc_did, signed_json) !=
        WF_OK) {
        LOG_ERROR("failed to submit PLC operation to directory");
        free(plc_did);
        plc_did = NULL;
        goto fail;
    }

    free(unsigned_json);
    free(unsigned_with_key);
    free(signed_json);
    free(account_didkey);
    free(rotation_didkey);
    if (out_signing_key) *out_signing_key = acct_key;
    return plc_did;

fail:
    free(unsigned_json);
    free(signed_json);
    free(account_didkey);
    free(rotation_didkey);
    return NULL;
}

wf_status create_account(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *handle =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "handle")
            : NULL;
    cJSON *password =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "password")
            : NULL;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    cJSON *email =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "email")
            : NULL;
    cJSON *plcOp = request->params
                       ? cJSON_GetObjectItemCaseSensitive(request->params,
                                                          "plcOp")
                       : NULL;
    /* Reject the signed-PLC-operation import path: it is an entryway-PDS
     * feature and this host never accepts it, matching the reference's
     * validateInputsForLocalPds (createAccount.ts:213-215). */
    if (plcOp && !cJSON_IsNull(plcOp)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Unsupported input: \"plcOp\"");
        return WF_OK;
    }
    if (!cJSON_IsString(email) || !email->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Email is required");
        return WF_OK;
    }
    if (!cJSON_IsString(handle) || !handle->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "handle is required");
        return WF_OK;
    }
    if (!cJSON_IsString(password) || !password->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidPassword",
                                   "password is required");
        return WF_OK;
    }
    /* Match the reference's NEW_PASSWORD_MAX_LENGTH ceiling
     * (createAccount.ts:217-221, scrypt.ts:6). */
    if (strlen(password->valuestring) > 256) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "Password too long. Maximum length is 256 characters.");
        return WF_OK;
    }
    LOG_DEBUG("create_account: attempt handle=%s email=%s did=%s",
              handle->valuestring, email->valuestring,
              cJSON_IsString(did) && did->valuestring[0] ? did->valuestring
                                                         : "(auto)");
    /* Invite-gated signups (refpds PDS_INVITE_REQUIRED): when enabled,
     * reject account creation unless a non-empty invite code is supplied
     * and the code has remaining uses. */
    if (server->invite_required) {
        cJSON *invite = request->params ? cJSON_GetObjectItemCaseSensitive(
                                              request->params, "inviteCode")
                                        : NULL;
        if (!cJSON_IsString(invite) || !invite->valuestring[0]) {
            wf_xrpc_response_set_error(response, 400, "InvalidInviteCode",
                                       "an invite code is required to sign up");
            return WF_OK;
        }
        /* Validate and consume the invite code. */
        if (metalbear_account_registry_consume_invite_code(
                server->registry, invite->valuestring, handle->valuestring) !=
            WF_OK) {
            wf_xrpc_response_set_error(
                response, 400, "InvalidInviteCode",
                "the invite code is invalid or exhausted");
            return WF_OK;
        }
    }
    /* Full handle syntax, not just the domain suffix: the reference runs the
     * handle through baseNormalizeAndValidate before anything else
     * (createAccount.ts:238-242). The Wolfram validator enforces RFC-style
     * labels (letters/digits/hyphens, 1-63 per label, no leading/trailing
     * hyphen), at least two labels, a letter-led final component, and the
     * 253-character ceiling. */
    if (wf_syntax_handle_validate(handle->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "invalid handle syntax");
        return WF_OK;
    }
    /* Check if the handle is already registered */
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_handle(
            server->registry, handle->valuestring, &existing) == WF_OK) {
        metalbear_account_entry_free(existing);
        wf_xrpc_response_set_error(response, 400, "HandleNotAvailable",
                                   "Handle is already taken");
        return WF_OK;
    }

    /* Reject a second signup on an email already registered to an account
     * (getAccountByEmail, createAccount.ts:256-258). */
    if (metalbear_account_registry_find_by_email(
            server->registry, email->valuestring, &existing) == WF_OK) {
        metalbear_account_entry_free(existing);
        char msg[512];
        snprintf(msg, sizeof(msg), "Email already taken: %s",
                 email->valuestring);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest", msg);
        return WF_OK;
    }

    /* Ensure handle uses the configured user domain (matches refpds behavior).
     */
    size_t handle_len = strlen(handle->valuestring);
    size_t ud_len = server->user_domain ? strlen(server->user_domain) : 0;
    if (ud_len == 0 || handle_len <= ud_len ||
        strcmp(handle->valuestring + handle_len - ud_len,
               server->user_domain) != 0) {
        wf_xrpc_response_set_error(response, 400, "UnsupportedDomain",
                                   "handle is not provided on this domain");
        return WF_OK;
    }
    /* Enforce 3-18 character label before the domain. */
    size_t label_len = handle_len - ud_len;
    if (label_len < 3 || label_len > 18) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "handle too short or too long");
        return WF_OK;
    }

    /* Resolve the new account's DID. A caller may supply one (e.g. a
     * did:web or a did:plc minted out of band), or the PDS may mint a
     * server-side did:plc via PLC when configured; otherwise we mint a fresh
     * did:key so every account is independently addressable and isolated. */
    char *account_did = NULL;
    /* Set only when this server minted the DID, in which case the repo must be
     * created with the key that DID document publishes. */
    wf_signing_key minted_key;
    bool have_minted_key = false;
    memset(&minted_key, 0, sizeof(minted_key));
    bool imported_did = cJSON_IsString(did) && did->valuestring[0];
    bool example_did = imported_did &&
                       strncmp(did->valuestring, "did:example:", 12) == 0;
    if (imported_did && !example_did) {
        /* Importing a DID requires proving control of it: the reference
         * rejects an imported DID unless the requester authenticates as
         * exactly that identity (createAccount.ts:267-275). createAccount is
         * a public route, so authenticate() never fills in authed_subject;
         * verify the bearer token against the named DID's own auth store
         * here, the same way authenticate() does for an authenticated route.
         * An unknown DID has no auth store and no access token can speak for
         * it, so this fails closed as AuthRequired. */
        const char *provided = bearer_token(request->auth_header);
        bool owns_did = false;
        if (provided) {
            char *sub = jwt_subject(provided);
            if (sub && sub[0] && strcmp(sub, did->valuestring) == 0) {
                metalbear_account_context *sub_acct =
                    context_for_did(server, sub);
                metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
                if (sub_acct &&
                    metalbear_auth_verify_access_scope(sub_acct->auth,
                                                       provided, &scope) ==
                    WF_OK)
                    owns_did = true;
            }
            free(sub);
        }
        if (!owns_did) {
            char msg[512];
            snprintf(msg, sizeof(msg),
                     "Missing auth to create account with did: %s",
                     did->valuestring);
            wf_xrpc_response_set_error(response, 401, "AuthRequired", msg);
            return WF_OK;
        }
        /* An access token can only speak for an account this host already
         * holds, so an authenticated import necessarily names an existing DID.
         * Reject it here rather than letting the flow below deactivate the
         * owner's live account and then fail the registry insert on the DID
         * primary key. */
        metalbear_account_entry *by_did = NULL;
        if (metalbear_account_registry_find_by_did(server->registry,
                                                   did->valuestring,
                                                   &by_did) == WF_OK) {
            metalbear_account_entry_free(by_did);
            char msg[512];
            snprintf(msg, sizeof(msg), "DID already taken: %s",
                     did->valuestring);
            wf_xrpc_response_set_error(response, 400, "InvalidRequest", msg);
            return WF_OK;
        }
    }
    if (example_did) {
        account_did = strdup(did->valuestring);
        if (!account_did) {
            wf_xrpc_response_set_error(response, 500, "InternalError",
                                       "Could not allocate account DID");
            return WF_OK;
        }
        LOG_INFO("create_account: using provided DID=%s for handle=%s",
                 account_did, handle->valuestring);
    } else if (server->plc_url && server->plc_url[0]) {
        LOG_DEBUG("create_account: minting PLC DID for handle=%s",
                  handle->valuestring);
        account_did = mint_plc_did(server, handle->valuestring, &minted_key);
        have_minted_key = account_did != NULL;
        if (!account_did) {
            wf_xrpc_response_set_error(response, 500, "InternalError",
                                       "Could not mint PLC DID");
            return WF_OK;
        }
        LOG_INFO("create_account: minted PLC DID=%s for handle=%s", account_did,
                 handle->valuestring);
    } else if (!imported_did) {
        wf_signing_key key;
        if (wf_signing_key_generate(WF_KEY_TYPE_SECP256K1, &key) != WF_OK ||
            wf_signing_key_public_didkey(&key, &account_did) != WF_OK) {
            wf_xrpc_response_set_error(response, 500, "InternalError",
                                       "Could not generate account DID");
            return WF_OK;
        }
        minted_key = key;
        have_minted_key = true;
        LOG_INFO("create_account: generated did:key=%s for handle=%s",
                 account_did, handle->valuestring);
    }

    /* Provision a dedicated, filesystem-isolated data directory for the
     * account under the PDS data root. */
    char *data_dir = NULL;
    if (metalbear_account_dir_for_did(server->data_directory, account_did,
                                      &data_dir) != WF_OK ||
        !data_dir) {
        free(account_did);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not build data directory");
        return WF_OK;
    }

    /* Open the account's full store bundle. This creates the repository with
     * its own signing key and persists the password verifier in the account
     * store — a real, isolated account rather than registry metadata alone. */
    metalbear_account_context *acct = NULL;
    /*
     * Open against the PDS-wide log, not a private one.
     *
     * Passing no sequencer here made the context open its own log under the
     * account directory and seed the account's #identity and #account events
     * into it. Nothing ever reads that file: every later request resolves the
     * account through the cache, which uses the server's log. A relay's first
     * sight of a new DID was therefore a bare #commit with no identity or
     * account event before it.
     */
    wf_status status = metalbear_account_context_open_shared(
        server->service_did, server->public_url, account_did,
        handle->valuestring, data_dir, password->valuestring,
        have_minted_key ? &minted_key : NULL, server->sequencer, &acct);
    if (status != WF_OK) {
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not provision account stores");
        return WF_OK;
    }

    /* A DID-imported account starts deactivated: control of the DID was
     * proven, but the account's state is not assumed before identity and
     * activation work is done (createAccount.ts:267-275, 86-88). */
    if (imported_did && !example_did &&
        metalbear_account_deactivate(acct->account, NULL) != WF_OK) {
        metalbear_account_context_close(acct);
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not deactivate imported account");
        return WF_OK;
    }

    if (metalbear_account_store_email(acct->account, email->valuestring) !=
        WF_OK) {
        metalbear_account_context_close(acct);
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not store account email");
        return WF_OK;
    }

    /* Record the account in the shared registry with its absolute data
     * directory so future requests can resolve and reopen it. */
    status = metalbear_account_registry_add_with_email(
        server->registry, account_did, handle->valuestring, "", data_dir,
        email->valuestring, example_did ? 1 : (imported_did ? 0 : 1));
    if (status == WF_ERR_CONFLICT) {
        metalbear_account_context_close(acct);
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 400, "HandleNotAvailable",
                                   "Handle is already taken");
        return WF_OK;
    }
    if (status != WF_OK) {
        metalbear_account_context_close(acct);
        free(account_did);
        free(data_dir);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not register account");
        return WF_OK;
    }

    /*
     * Announce the new account on the host firehose -- unless it was
     * imported deactivated: upstream sequences no account-creation event for
     * a deactivated account (createAccount.ts:86-88).
     *
     * The registry row is now durable, so the account exists as far as this
     * PDS is concerned; a relay learns of it only from these events. Emitting
     * #identity and #account before any #commit is what lets a consumer bind
     * the DID to its handle and know it is active — without them the first
     * thing the network sees is a commit for a DID it has never heard of.
     */
    if (!imported_did &&
        metalbear_sequencer_account_activation(server->sequencer, account_did,
                                               handle->valuestring,
                                               acct->repo) != WF_OK) {
        /* Not fatal to account creation: the account is already durable, and
         * reconciliation heals a missing tail event. Log loudly — a silently
         * unannounced account looks exactly like a working one locally. */
        LOG_ERROR("create_account: could not sequence creation events for "
                  "did=%s handle=%s; account exists but is unannounced",
                  account_did, handle->valuestring);
    }
    /* Make the handle resolvable. Without a `_atproto` TXT record an AppView
     * shows the account as handle.invalid, which is what every account minted
     * under a wildcard-covered subdomain looked like before this. */
    publish_handle_dns(server, handle->valuestring, account_did);

    /* Issue a session scoped to the new account's own auth store. */
    metalbear_session_tokens tokens = {0};
    wf_status session_status = metalbear_auth_create_scoped_session(
        acct->auth, METALBEAR_ACCESS_FULL, NULL, &tokens);
    /* Build didDoc while the account context is still open. */
    cJSON *did_doc = NULL;
    if (server->public_url) did_doc = build_did_doc(server, acct);
    /* Capture email confirmation state before closing the context. */
    int confirmed = 0;
    metalbear_account_get_email(acct->account, NULL, &confirmed);
    metalbear_account_context_close(acct);
    free(data_dir);
    if (session_status != WF_OK) {
        LOG_ERROR(
            "create_account: failed to create session for handle=%s did=%s",
            handle->valuestring, account_did);
        free(account_did);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create session");
        return WF_OK;
    }

    metalbear_metrics_inc(METALBEAR_METRIC_ACCOUNTS_CREATED);
    LOG_INFO("create_account: created handle=%s did=%s email=%s",
             handle->valuestring, account_did, email->valuestring);

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_session_tokens_free(&tokens);
        free(account_did);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "accessJwt", tokens.access_jwt);
    cJSON_AddStringToObject(root, "refreshJwt", tokens.refresh_jwt);
    cJSON_AddStringToObject(root, "handle", handle->valuestring);
    cJSON_AddStringToObject(root, "did", account_did);
    if (confirmed)
        cJSON_AddBoolToObject(root, "emailAuthFactor", true);
    else
        cJSON_AddBoolToObject(root, "emailAuthFactor", false);
    if (did_doc) cJSON_AddItemToObject(root, "didDoc", did_doc);
    metalbear_session_tokens_free(&tokens);
    free(account_did);
    return set_json(response, root);
}

wf_status request_email_confirmation(void *ctx, const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (!check_endpoint_rate_limit(server->rl_request_email_confirmation_day,
                                   server->rl_request_email_confirmation_hour,
                                   acct->did, 1, response)) {
        return WF_OK;
    }
    char *email = NULL;
    int confirmed = 0;
    if (metalbear_account_get_email(acct->account, &email, &confirmed) !=
            WF_OK ||
        !email) {
        wf_xrpc_response_set_error(response, 400, "AccountNotFound",
                                   "No email address on file");
        free(email);
        return WF_OK;
    }
    if (confirmed) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Email is already confirmed");
        free(email);
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "confirm", token,
                                             sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create confirmation token");
        return WF_OK;
    }
    if (server->email && metalbear_email_send_verification(server->email, email,
                                                           token) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not send confirmation email");
        return WF_OK;
    }
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

wf_status confirm_email(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *email =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "email")
            : NULL;
    cJSON *token =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "token")
            : NULL;
    if (!cJSON_IsString(email) || !email->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidEmail",
                                   "email is required");
        return WF_OK;
    }
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "token is required");
        return WF_OK;
    }
    wf_status status = metalbear_account_verify_email_token(
        acct->account, "confirm", token->valuestring);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired confirmation token");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

wf_status request_email_update(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (!check_endpoint_rate_limit(server->rl_request_email_update_day,
                                   server->rl_request_email_update_hour,
                                   acct->did, 1, response)) {
        return WF_OK;
    }
    char *email = NULL;
    int confirmed = 0;
    if (metalbear_account_get_email(acct->account, &email, &confirmed) !=
            WF_OK ||
        !email) {
        free(email);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "No email address on file");
        return WF_OK;
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "update", token,
                                             sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create update token");
        return WF_OK;
    }
    if (server->email && metalbear_email_send_verification(server->email, email,
                                                           token) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not send update email");
        return WF_OK;
    }
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "tokenRequired", true);
    return set_json(response, root);
}

wf_status update_email(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *email_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "email")
            : NULL;
    cJSON *token =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "token")
            : NULL;
    if (!cJSON_IsString(email_param) || !email_param->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "email is required");
        return WF_OK;
    }
    /* Check if current email is confirmed — token required only then */
    char *current_email = NULL;
    int confirmed = 0;
    metalbear_account_get_email(acct->account, &current_email, &confirmed);
    if (confirmed) {
        if (!cJSON_IsString(token) || !token->valuestring[0]) {
            free(current_email);
            wf_xrpc_response_set_error(response, 400, "TokenRequired",
                                       "Token is required when email is "
                                       "already confirmed");
            return WF_OK;
        }
        wf_status status = metalbear_account_verify_email_token(
            acct->account, "update", token->valuestring);
        if (status != WF_OK) {
            free(current_email);
            wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                       "Invalid or expired update token");
            return WF_OK;
        }
    }
    free(current_email);
    /* Store the new email address and mark it unconfirmed */
    if (metalbear_account_store_email(acct->account,
                                      email_param->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not store email address");
        return WF_OK;
    }
    return WF_OK;
}

/*
 * Find the account a password-reset request refers to.
 *
 * These flows are unauthenticated — the caller presents an email address, or a
 * token minted against one account — so the account has to be looked up rather
 * than assumed. Both previously operated on the server's configured account
 * regardless of what was presented, which meant a user resetting their own
 * password reset somebody else's, and no other account could reset at all.
 *
 * Linear over the registry, which is fine: both routes are rate-limited by
 * their email round-trip and are not on any hot path.
 */
static metalbear_account_context *context_for_email(metalbear_server *server,
                                                    const char *email) {
    if (!email || !email[0]) return NULL;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK)
        return NULL;
    metalbear_account_context *found = NULL;
    for (size_t i = 0; i < count && !found; i++) {
        metalbear_account_context *acct =
            context_for_did(server, entries[i].did);
        if (!acct) continue;
        char *stored = NULL;
        metalbear_account_get_email(acct->account, &stored, NULL);
        if (stored && stored[0] && strcmp(stored, email) == 0) found = acct;
        free(stored);
    }
    metalbear_account_entries_free(entries, count);
    return found;
}

/* Find the account an email token was minted for. `purpose` is "reset" or
 * "delete". Tokens are per-account, so the only way to identify the account
 * from a bare token is to ask each one whether it issued it. */
static metalbear_account_context *
context_for_email_token(metalbear_server *server, const char *purpose,
                        const char *token) {
    if (!purpose || !token || !token[0]) return NULL;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK)
        return NULL;
    metalbear_account_context *found = NULL;
    for (size_t i = 0; i < count && !found; i++) {
        metalbear_account_context *acct =
            context_for_did(server, entries[i].did);
        if (acct && metalbear_account_verify_email_token(acct->account, purpose,
                                                         token) == WF_OK)
            found = acct;
    }
    metalbear_account_entries_free(entries, count);
    return found;
}

wf_status request_password_reset(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    if (!check_endpoint_rate_limit(server->rl_request_password_reset_day,
                                   server->rl_request_password_reset_hour,
                                   request->client_ip, 1, response)) {
        return WF_OK;
    }
    cJSON *email_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "email")
            : NULL;
    if (!cJSON_IsString(email_param) || !email_param->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "email is required");
        return WF_OK;
    }
    /* Look the account up by the address presented, rather than assuming one.
     */
    metalbear_account_context *acct =
        context_for_email(server, email_param->valuestring);
    char *email = NULL;
    if (acct) metalbear_account_get_email(acct->account, &email, NULL);
    if (!acct || !email || !email[0] ||
        strcmp(email, email_param->valuestring) != 0) {
        free(email);
        /* Always return success to avoid email enumeration */
        cJSON *root = cJSON_CreateObject();
        if (!root) return WF_ERR_ALLOC;
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(response, root);
    }
    char token[33];
    if (metalbear_account_create_email_token(acct->account, "reset", token,
                                             sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create reset token");
        return WF_OK;
    }
    /*
     * Unlike request_email_confirmation/request_email_update (both
     * authenticated -- the caller already knows their own account exists),
     * this endpoint is unauthenticated and deliberately always reports
     * success for an account that exists, to avoid email enumeration (see
     * the same-shaped branch above for a non-existent one). Surfacing an
     * email-send failure as an error here would reintroduce exactly that:
     * during an SMTP outage, real accounts would 500 while made-up
     * addresses kept getting 200, telling an attacker exactly which
     * addresses are real. Log it instead, so an operator can notice a
     * broken mail pipe from logs/metrics without the response leaking
     * anything to the caller.
     */
    if (server->email && metalbear_email_send_password_reset(
                             server->email, email, token) != WF_OK) {
        LOG_ERROR("request_password_reset: failed to send reset email to "
                  "did=%s",
                  acct->did);
    }
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "success", true);
    return set_json(response, root);
}

wf_status reset_password(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *token =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "token")
            : NULL;
    cJSON *password =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "password")
            : NULL;
    if (!cJSON_IsString(token) || !token->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "token is required");
        return WF_OK;
    }
    if (!cJSON_IsString(password) || !password->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "password is required");
        return WF_OK;
    }
    metalbear_account_context *acct =
        context_for_email_token(server, "reset", token->valuestring);
    if (!acct) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired reset token");
        return WF_OK;
    }
    wf_status status =
        metalbear_account_reset_password(acct->account, password->valuestring);
    if (status != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not reset password");
        return WF_OK;
    }
    return WF_OK;
}

wf_status get_account_invite_codes(void *ctx, const wf_xrpc_request *request,
                                   wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    /* The auth callback resolves the DID into authed_subject; use it
     * to look up the account's invite codes. */
    const char *did = request->authed_subject;
    cJSON *root = cJSON_CreateObject();
    cJSON *codes = cJSON_CreateArray();
    if (!root || !codes) {
        cJSON_Delete(root);
        cJSON_Delete(codes);
        return WF_ERR_ALLOC;
    }
    bool include_used = query_param_bool(request->params, "includeUsed", true);

    if (did && server->registry) {
        metalbear_invite_code_entry *entries = NULL;
        size_t count = 0;
        if (metalbear_account_registry_get_invite_codes(
                server->registry, did, &entries, &count) == WF_OK) {
            for (size_t i = 0; i < count; i++) {
                metalbear_invite_code_use_entry *use_entries = NULL;
                size_t use_count = 0;
                metalbear_account_registry_get_invite_code_uses(
                    server->registry, entries[i].code, &use_entries,
                    &use_count);

                int available = entries[i].uses_remaining + (int)use_count;
                if (!include_used && (int)use_count >= available) {
                    metalbear_invite_code_use_entries_free(use_entries,
                                                           use_count);
                    continue;
                }

                cJSON *obj = cJSON_CreateObject();
                if (!obj) {
                    metalbear_invite_code_use_entries_free(use_entries,
                                                           use_count);
                    continue;
                }
                cJSON_AddStringToObject(obj, "code", entries[i].code);
                cJSON_AddNumberToObject(obj, "available", available);
                cJSON_AddBoolToObject(obj, "disabled",
                                      entries[i].disabled != 0);
                cJSON_AddStringToObject(
                    obj, "forAccount",
                    entries[i].for_account ? entries[i].for_account : did);
                cJSON_AddStringToObject(
                    obj, "createdBy",
                    entries[i].created_by ? entries[i].created_by : "admin");
                cJSON_AddStringToObject(
                    obj, "createdAt",
                    entries[i].created_at ? entries[i].created_at
                                          : "1970-01-01T00:00:00.000Z");

                cJSON *uses = cJSON_CreateArray();
                if (uses) {
                    for (size_t k = 0; k < use_count; k++) {
                        cJSON *use = cJSON_CreateObject();
                        if (!use) continue;
                        cJSON_AddStringToObject(use, "usedBy",
                                                use_entries[k].used_by);
                        cJSON_AddStringToObject(use, "usedAt",
                                                use_entries[k].used_at);
                        cJSON_AddItemToArray(uses, use);
                    }
                }
                metalbear_invite_code_use_entries_free(use_entries, use_count);
                cJSON_AddItemToObject(obj, "uses",
                                      uses ? uses : cJSON_CreateArray());
                cJSON_AddItemToArray(codes, obj);
            }
            metalbear_invite_code_entries_free(entries, count);
        }
    }
    cJSON_AddItemToObject(root, "codes", codes);
    return set_json(response, root);
}

/* Distinct blob CIDs referenced by the repo's records — checkAccountStatus's
 * `expectedBlobs`, which a migrating client compares against `importedBlobs`
 * to know whether blob transfer is complete. */
typedef struct blob_ref_tally {
    char **cids;
    size_t count;
} blob_ref_tally;

static void blob_ref_tally_add(const char *cid, void *opaque) {
    blob_ref_tally *tally = opaque;
    for (size_t i = 0; i < tally->count; i++)
        if (strcmp(tally->cids[i], cid) == 0) return;
    char **grown = realloc(tally->cids, (tally->count + 1) * sizeof(*grown));
    if (!grown) return;
    tally->cids = grown;
    tally->cids[tally->count] = strdup(cid);
    if (tally->cids[tally->count]) tally->count++;
}

static wf_status blob_ref_tally_visit(const char *collection, const char *rkey,
                                      const char *value_json, void *ctx) {
    (void)collection;
    (void)rkey;
    cJSON *value = cJSON_Parse(value_json);
    if (!value) return WF_OK;
    metalbear_blob_walk_refs(value, blob_ref_tally_add, ctx);
    cJSON_Delete(value);
    return WF_OK;
}

static size_t count_referenced_blobs(metalbear_repo_store *repo) {
    blob_ref_tally tally = {0};
    if (metalbear_repo_store_foreach_record(repo, blob_ref_tally_visit,
                                            &tally) != WF_OK) {
        for (size_t i = 0; i < tally.count; i++) free(tally.cids[i]);
        free(tally.cids);
        return 0;
    }
    size_t count = tally.count;
    for (size_t i = 0; i < tally.count; i++) free(tally.cids[i]);
    free(tally.cids);
    return count;
}

/* ---- checkAccountStatus (query) ---- */
wf_status check_account_status(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    bool active = metalbear_account_is_active(acct->account);
    char *rev = NULL;
    char *cid = NULL;
    metalbear_repo_store_get_head(acct->repo, &rev, &cid);
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(rev);
        free(cid);
        return WF_ERR_ALLOC;
    }
    bool valid_did = did_doc_matches_service(server, acct);
    cJSON_AddBoolToObject(root, "activated", active);
    cJSON_AddBoolToObject(root, "validDid", valid_did);
    cJSON_AddStringToObject(root, "repoCommit", cid ? cid : "");
    cJSON_AddStringToObject(root, "repoRev", rev ? rev : "");
    metalbear_repo_store_stats stats = {0};
    char **blob_cids = NULL;
    size_t blob_count = 0;
    if (metalbear_repo_store_get_stats(acct->repo, &stats) != WF_OK ||
        metalbear_blob_store_list(acct->blobs, &blob_cids, &blob_count) !=
            WF_OK) {
        metalbear_blob_store_list_free(blob_cids, blob_count);
        cJSON_Delete(root);
        free(rev);
        free(cid);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not inspect account storage");
        return WF_OK;
    }
    metalbear_blob_store_list_free(blob_cids, blob_count);
    cJSON_AddNumberToObject(root, "repoBlocks", (double)stats.repo_blocks);
    cJSON_AddNumberToObject(root, "indexedRecords",
                            (double)stats.indexed_records);
    cJSON_AddNumberToObject(root, "privateStateValues", 0);
    cJSON_AddNumberToObject(root, "expectedBlobs",
                            (double)count_referenced_blobs(acct->repo));
    cJSON_AddNumberToObject(root, "importedBlobs", (double)blob_count);
    free(rev);
    free(cid);
    return set_json(response, root);
}

/* ---- reserveSigningKey (procedure) ---- */
wf_status reserve_signing_key(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    char *didkey = NULL;
    /* Unauthenticated, matching the reference: this is called during account
     * migration for a DID that has no account here yet, so there is no
     * session to authenticate and no account store to reserve against. The
     * reservation lives in the server's key store. */
    if (metalbear_key_rotation_reserve(server->plc_rotation, &didkey) !=
        WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not reserve signing key");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(didkey);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "signingKey", didkey);
    free(didkey);
    return set_json(response, root);
}

static void gen_invite_code(char *buf, size_t size) {
    static const char alphabet[] =
        "23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    unsigned char raw[24];
    if (RAND_bytes(raw, (int)sizeof(raw)) != 1) {
        memset(raw, 0, sizeof(raw));
        for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (unsigned char)i;
    }
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(raw) && pos + 1 < size; i++) {
        if (i > 0 && i % 4 == 0 && pos + 1 < size) buf[pos++] = '-';
        buf[pos++] = alphabet[raw[i] % (sizeof(alphabet) - 1)];
    }
    buf[pos] = '\0';
}

/* ---- createInviteCode (procedure) ---- */
wf_status create_invite_code(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *useCount =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "useCount")
            : NULL;
    if (!cJSON_IsNumber(useCount) || useCount->valuedouble < 1) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "useCount is required and must be > 0");
        return WF_OK;
    }
    cJSON *forAccount =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "forAccount")
            : NULL;
    const char *account =
        (cJSON_IsString(forAccount) && forAccount->valuestring[0])
            ? forAccount->valuestring
            : "admin";
    char code[64];
    gen_invite_code(code, sizeof(code));
    const char *codes[] = {code};
    if (metalbear_account_registry_create_invite_codes(
            server->registry, account, codes, 1, (int)useCount->valuedouble) !=
        WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not persist invite code");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "code", code);
    return set_json(response, root);
}

/* ---- createInviteCodes (procedure) ---- */
wf_status create_invite_codes(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *codeCount =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "codeCount")
            : NULL;
    cJSON *useCount =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "useCount")
            : NULL;
    if (!cJSON_IsNumber(codeCount) || codeCount->valuedouble < 1 ||
        !cJSON_IsNumber(useCount) || useCount->valuedouble < 1) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "codeCount and useCount are required and > 0");
        return WF_OK;
    }
    int count = (int)codeCount->valuedouble;
    if (count > 100) count = 100;
    int per_code_uses = (int)useCount->valuedouble;
    cJSON *forAccounts =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "forAccounts")
            : NULL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON *codes_arr = cJSON_CreateArray();
    if (!codes_arr) {
        cJSON_Delete(root);
        return WF_ERR_ALLOC;
    }

    /* Collect accounts to create codes for. */
    const char *accounts[32];
    size_t account_count = 0;
    if (cJSON_IsArray(forAccounts) && cJSON_GetArraySize(forAccounts) > 0) {
        size_t n = cJSON_GetArraySize(forAccounts);
        if (n > 32) n = 32;
        for (size_t a = 0; a < n; a++) {
            cJSON *acct = cJSON_GetArrayItem(forAccounts, a);
            accounts[a] = (cJSON_IsString(acct) && acct->valuestring)
                              ? acct->valuestring
                              : "admin";
        }
        account_count = n;
    } else {
        accounts[0] = "admin";
        account_count = 1;
    }

    for (size_t a = 0; a < account_count; a++) {
        cJSON *account_obj = cJSON_CreateObject();
        if (!account_obj) {
            cJSON_Delete(root);
            cJSON_Delete(codes_arr);
            return WF_ERR_ALLOC;
        }
        cJSON_AddStringToObject(account_obj, "account", accounts[a]);
        cJSON *code_list = cJSON_CreateArray();
        if (!code_list) {
            cJSON_Delete(root);
            cJSON_Delete(codes_arr);
            cJSON_Delete(account_obj);
            return WF_ERR_ALLOC;
        }

        /* Generate and persist codes. */
        const char *generated[100];
        for (int i = 0; i < count; i++) {
            char code[64];
            gen_invite_code(code, sizeof(code));
            generated[i] = NULL; /* stack; persist below */
            cJSON_AddItemToArray(code_list, cJSON_CreateString(code));
            /* Persist each code individually (gen_invite_code writes to stack).
             */
            char *code_copy = strdup(code);
            if (code_copy) {
                const char *single_code[] = {code_copy};
                metalbear_account_registry_create_invite_codes(
                    server->registry, accounts[a], single_code, 1,
                    per_code_uses);
                free(code_copy);
            }
        }
        (void)generated;
        cJSON_AddItemToObject(account_obj, "codes", code_list);
        cJSON_AddItemToArray(codes_arr, account_obj);
    }
    cJSON_AddItemToObject(root, "codes", codes_arr);
    return set_json(response, root);
}
