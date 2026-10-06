/*
 * preferences_routes.c — app.bsky.actor.getPreferences / putPreferences, and
 * the mod-service JWT verifier their auth (and server.c's) uses.
 *
 * Preferences live on the PDS, not the AppView, so these are core routes:
 * they used to sit in appview_routes.c, which the minimal profile does not
 * build, and that broke the Pi 1B/Zero configuration at compile time.
 */
#include "preferences_routes.h"
#include "../server_internal.h"

#include "metalbear/account/account.h"
#include "metalbear/account/account_context.h"
#include "metalbear/log.h"
#include "metalbear/oauth/auth.h"

#include "wolfram/identity.h"
#include "wolfram/server.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- app.bsky.actor.getPreferences / putPreferences ----
 * The reference PDS proxies these to the AppView too, but MetalBear stores
 * them locally rather than round-tripping through an upstream — see the
 * exclusion of these two NSIDs from the generic proxy fallback in server.c. */

/* Verify an inbound mod-service JWT. See the declaration in appview_routes.h
 * for the contract; this mirrors packages/pds/src/auth-verifier.ts's
 * modService/verifyServiceJwt (iss allowlist, aud + lxm binding) on top of
 * wolfram's wf_server_verify_service_auth (structure, exp, signature). */
wf_status metalbear_verify_mod_service_auth(const char *mod_service_did,
                                            const char *local_service_did,
                                            const char *token, char **out_iss) {
    char *did = NULL;
    char *didkey = NULL;
    wf_service_auth_claims claims = {0};
    wf_status status = WF_ERR_PERMISSION;

    if (!out_iss) return WF_ERR_INVALID_ARG;
    *out_iss = NULL;
    if (!mod_service_did || !mod_service_did[0] || !local_service_did ||
        !local_service_did[0] || !token)
        return WF_ERR_PERMISSION;

    /* Issuer check first, before any resolution: an access token's `iss` is
     * the OAuth provider, and a user JWT's `iss`/`sub` is never the trusted
     * mod service — reject cheaply so ordinary auth does not pay for a DID
     * resolution it will not use. */
    char *iss = jwt_claim(token, "iss");
    if (!iss) return WF_ERR_PERMISSION;
    bool trusted = strcmp(iss, mod_service_did) == 0;
    if (!trusted) {
        size_t ml = strlen(mod_service_did);
        trusted = strncmp(iss, mod_service_did, ml) == 0 &&
                  strcmp(iss + ml, "#atproto_labeler") == 0;
    }
    if (!trusted) goto done;

    /* Signing key: the bare DID, unless the token's issuer carried the
     * `#atproto_labeler` service fragment, in which case the document's
     * `#atproto_label` key verifies (matches the reference's
     * `serviceId === 'atproto_labeler' ? 'atproto_label' : 'atproto'`). A
     * did:key issuer IS its own signing key and resolves offline; every other
     * method resolves the published verification method from the DID
     * document (network), exactly like the repo-import path and the
     * reference's did-resolver. */
    const char *frag = strchr(iss, '#');
    const char *key_id = frag && strcmp(frag, "#atproto_labeler") == 0
                             ? "#atproto_label"
                             : "#atproto";
    size_t dl = frag ? (size_t)(frag - iss) : strlen(iss);
    did = malloc(dl + 1);
    if (!did) {
        status = WF_ERR_ALLOC;
        goto done;
    }
    memcpy(did, iss, dl);
    did[dl] = '\0';

    if (strncmp(did, "did:key:", 8) == 0) {
        didkey = did;
        did = NULL;
    } else {
        wf_xrpc_client *client = wf_xrpc_client_new("https://localhost");
        if (!client) {
            status = WF_ERR_ALLOC;
            goto done;
        }
        wf_status kst =
            wf_did_resolve_verification_key(client, did, key_id, &didkey);
        wf_xrpc_client_free(client);
        if (kst != WF_OK || !didkey) goto done;
    }

    /* Structural/signature/expiry verification, then the aud + lxm bindings
     * the reference checks separately from the signature. */
    if (wf_server_verify_service_auth(token, didkey, 0, &claims) != WF_OK)
        goto done;
    if (!claims.aud || strcmp(claims.aud, local_service_did) != 0) goto done;
    if (!claims.lxm || strcmp(claims.lxm, "app.bsky.actor.getPreferences") != 0)
        goto done;

    /* Everything checked: surfaces the token's issuer exactly as sent,
     * fragment included, matching the reference's mod_service credentials. */
    *out_iss = iss;
    iss = NULL;
    status = WF_OK;

done:
    wf_service_auth_claims_free(&claims);
    free(didkey);
    free(did);
    free(iss);
    return status;
}

/* Handler-side hasAccessFull (the reference's isAccessFull / isModerator):
 * a mod-service request is a moderator and always gets everything; a user
 * access token needs full scope. Returns WF_OK and sets *scope (0 = full)
 * for the user path. */
static bool request_has_access_full(const wf_xrpc_request *request,
                                    metalbear_account_context *acct) {
    if (request->authed_principal_kind == WF_XRPC_PRINCIPAL_SERVICE)
        return true;
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    const char *provided = bearer_token(request->auth_header);
    if (metalbear_auth_verify_access_scope(acct->auth, provided, &scope) !=
        WF_OK)
        return false;
    return scope == METALBEAR_ACCESS_FULL;
}

/* app.bsky.actor.defs.personalDetailsPref — the sole full-access-only pref
 * (upstream preference/util.ts isFullAccessOnlyPref). Hidden from a reader
 * without hasAccessFull and rejected on write by one. */
#define PERSONAL_DETAILS_PREF_TYPE "app.bsky.actor.defs.personalDetailsPref"
/* app.bsky.actor.defs.declaredAgePref — computed from personalDetailsPref's
 * birthDate (upstream isReadOnlyPref); never persisted by the client, so a
 * writer drops it rather than storing a derived value. */
#define DECLARED_AGE_PREF_TYPE "app.bsky.actor.defs.declaredAgePref"

static bool pref_is_type(const cJSON *pref, const char *type) {
    cJSON *t = cJSON_GetObjectItemCaseSensitive(pref, "$type");
    return cJSON_IsString(t) && t->valuestring &&
           strcmp(t->valuestring, type) == 0;
}

wf_status get_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = NULL;
    char *target = NULL;
    if (request->authed_principal_kind == WF_XRPC_PRINCIPAL_SERVICE) {
        /* Mod-service request (verified in authenticate): act on the account
         * named by the undocumented `did` query param, not the token's own
         * subject — the reference's getAccountDidFromParams path. */
        cJSON *did =
            request->params
                ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                : NULL;
        if (cJSON_IsString(did) && did->valuestring[0])
            target = did->valuestring;
        if (!target || strncmp(target, "did:", 4) != 0) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "Invalid or missing did parameter");
            return WF_OK;
        }
        acct = context_for_did(server, target);
        if (!acct) {
            wf_xrpc_response_set_error(response, 400, "NotFound",
                                       "Repo not found");
            return WF_OK;
        }
    } else {
        acct = resolve_request_context(server, request);
        if (!acct) {
            wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                       "Invalid access token");
            return WF_OK;
        }
    }
    char *prefs_json = NULL;
    if (metalbear_account_store_prefs_get(acct->account, &prefs_json) !=
            WF_OK ||
        !prefs_json) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "preferences", cJSON_CreateArray());
        return set_json(response, root);
    }
    cJSON *root = cJSON_Parse(prefs_json);
    free(prefs_json);
    if (!root) {
        cJSON *empty = cJSON_CreateObject();
        cJSON_AddItemToObject(empty, "preferences", cJSON_CreateArray());
        return set_json(response, empty);
    }
    if (!request_has_access_full(request, acct)) {
        /* hasAccessFull=false: drop the full-access-only pref from the
         * response (upstream prefAllowed), matching what a standard-scope
         * session is permitted to see. */
        cJSON *prefs = cJSON_GetObjectItemCaseSensitive(root, "preferences");
        if (cJSON_IsArray(prefs)) {
            cJSON *item = prefs->child;
            while (item) {
                cJSON *next = item->next;
                if (pref_is_type(item, PERSONAL_DETAILS_PREF_TYPE)) {
                    cJSON_DetachItemViaPointer(prefs, item);
                    cJSON_Delete(item);
                }
                item = next;
            }
        }
    }
    return set_json(response, root);
}

wf_status put_actor_preferences(void *ctx, const wf_xrpc_request *request,
                                wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (!request->body || request->body_len == 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "empty body");
        return WF_OK;
    }
    cJSON *parsed =
        cJSON_ParseWithLength((const char *)request->body, request->body_len);
    if (!parsed) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "invalid JSON");
        return WF_OK;
    }
    cJSON *prefs = cJSON_GetObjectItemCaseSensitive(parsed, "preferences");
    if (!cJSON_IsArray(prefs)) {
        cJSON_Delete(parsed);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "preferences must be an array");
        return WF_OK;
    }
    if (!request_has_access_full(request, acct)) {
        /* hasAccessFull=false: refuse to persist the full-access-only pref
         * (upstream transactor's forbiddenPrefs check) and drop the derived
         * read-only pref below, which upstream never stores. */
        cJSON *item = prefs->child;
        while (item) {
            if (pref_is_type(item, PERSONAL_DETAILS_PREF_TYPE)) {
                cJSON_Delete(parsed);
                wf_xrpc_response_set_error(
                    response, 400, "InvalidRequest",
                    "Do not have authorization to set "
                    "preferences: " PERSONAL_DETAILS_PREF_TYPE);
                return WF_OK;
            }
            item = item->next;
        }
    }
    /* The derived declaredAgePref is computed server-side from
     * personalDetailsPref.birthDate and never stored (upstream isReadOnlyPref
     * — the read filter above and this write drop run for full and standard
     * access alike). Removes it, then serializes the filtered preferences, so
     * what is persisted matches the reference. */
    {
        cJSON *item = prefs->child;
        while (item) {
            cJSON *next = item->next;
            if (pref_is_type(item, DECLARED_AGE_PREF_TYPE)) {
                cJSON_DetachItemViaPointer(prefs, item);
                cJSON_Delete(item);
            }
            item = next;
        }
    }
    char *body_copy = cJSON_PrintUnformatted(parsed);
    cJSON_Delete(parsed);
    if (!body_copy) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "allocation failed");
        return WF_OK;
    }
    if (metalbear_account_store_prefs_put(acct->account, body_copy) != WF_OK) {
        free(body_copy);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "failed to store preferences");
        return WF_OK;
    }
    free(body_copy);
    return WF_OK;
}
