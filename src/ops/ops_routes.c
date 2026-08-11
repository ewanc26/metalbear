#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "ops_routes.h"
#include "../server_internal.h"

#include <cJSON.h>

/* ---- com.atproto.server.describeServer (query) ---- */
wf_status describe_server(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    (void)request;
    metalbear_server *server = ctx;
    cJSON *root = cJSON_CreateObject();
    cJSON *domains = cJSON_CreateArray();
    cJSON *contact = cJSON_CreateObject();
    if (!root || !domains || !contact) {
        cJSON_Delete(root);
        cJSON_Delete(domains);
        cJSON_Delete(contact);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", server->service_did);
    cJSON_AddItemToArray(domains, cJSON_CreateString(server->user_domain));
    cJSON_AddItemToObject(root, "availableUserDomains", domains);
    cJSON_AddBoolToObject(root, "inviteCodeRequired", server->invite_required);
    cJSON_AddBoolToObject(root, "phoneVerificationRequired", false);
    if (server->blob_upload_limit > 0)
        cJSON_AddNumberToObject(root, "blobUploadLimit",
                                (double)server->blob_upload_limit);
    if (server->account_email && server->account_email[0])
        cJSON_AddStringToObject(contact, "email", server->account_email);
    cJSON_AddItemToObject(root, "contact", contact);
    /* `links` is part of the lexicon, so policy URLs belong here rather than
     * in anything MetalBear-specific. */
    if ((server->privacy_policy_url && server->privacy_policy_url[0]) ||
        (server->terms_of_service_url && server->terms_of_service_url[0])) {
        cJSON *links = cJSON_CreateObject();
        if (links) {
            if (server->privacy_policy_url && server->privacy_policy_url[0])
                cJSON_AddStringToObject(links, "privacyPolicy",
                                        server->privacy_policy_url);
            if (server->terms_of_service_url && server->terms_of_service_url[0])
                cJSON_AddStringToObject(links, "termsOfService",
                                        server->terms_of_service_url);
            cJSON_AddItemToObject(root, "links", links);
        }
    }
    return set_json(response, root);
}

/* ---- GET /operator.json (MetalBear-specific) ----
 *
 * Who runs this instance and what software it is. Deliberately not an XRPC
 * method: none of this is in any lexicon, and putting it under /xrpc/ would
 * imply a protocol surface that does not exist. The landing page reads it so
 * that the operator details have one source of truth — the server config —
 * rather than being duplicated into a static page that then goes stale.
 */
wf_status operator_info(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    (void)request;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;

    cJSON *op = cJSON_CreateObject();
    if (op) {
        if (server->operator_name)
            cJSON_AddStringToObject(op, "name", server->operator_name);
        if (server->operator_email)
            cJSON_AddStringToObject(op, "email", server->operator_email);
        else if (server->account_email)
            cJSON_AddStringToObject(op, "email", server->account_email);
        if (server->operator_url)
            cJSON_AddStringToObject(op, "url", server->operator_url);
        if (server->support_url)
            cJSON_AddStringToObject(op, "supportUrl", server->support_url);
        cJSON_AddItemToObject(root, "operator", op);
    }

    cJSON *sw = cJSON_CreateObject();
    if (sw) {
        cJSON_AddStringToObject(sw, "name", "MetalBear");
        cJSON_AddStringToObject(sw, "version", METALBEAR_VERSION);
        /* The SDK version, so the frontend landing page can name the pair it
         * is running without a second admin-gated call. */
        cJSON_AddStringToObject(sw, "wolframVersion", WOLFRAM_VERSION_STRING);
        /* Build provenance: not a secret (unlike admin-gated
         * /_debug/health's identity/config fields) -- an operator's users
         * and the landing page both benefit from knowing exactly which
         * commit is live. */
        cJSON_AddStringToObject(sw, "commit", METALBEAR_BUILD_COMMIT);
        cJSON_AddStringToObject(sw, "builtAt", METALBEAR_BUILD_TIME);
        /* Where this build sits on the software release life cycle
         * (https://en.wikipedia.org/wiki/Software_release_life_cycle) --
         * "pre-alpha"/"alpha"/"beta"/"rc"/"stable" by convention, set via
         * -DMETALBEAR_RELEASE_STAGE at build time. Public for the same
         * reason commit/builtAt are: a client deciding how much to trust an
         * instance benefits from knowing this without guessing from the 0.x
         * version number alone. */
        cJSON_AddStringToObject(sw, "releaseStage", METALBEAR_RELEASE_STAGE);
        cJSON_AddStringToObject(sw, "repository",
                                "https://github.com/ewanc26/metalbear");
        cJSON_AddStringToObject(sw, "license", "AGPL-3.0-only");
        cJSON_AddItemToObject(root, "software", sw);
    }

    if (server->instance_description)
        cJSON_AddStringToObject(root, "description",
                                server->instance_description);
    /* A testing instance says so, so nobody mistakes its accounts for people.
     */
    cJSON_AddBoolToObject(root, "development", server->development);
    return set_json(response, root);
}

/* ---- _health (query) ---- */
wf_status health(void *ctx, const wf_xrpc_request *request,
                 wf_xrpc_response *response) {
    (void)ctx;
    (void)request;
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(root, "version", METALBEAR_VERSION);
    return set_json(response, root);
}
