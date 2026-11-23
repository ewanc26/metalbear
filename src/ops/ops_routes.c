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
#include "metalbear/video_upload.h"

#include <cJSON.h>
#include <stdio.h>

/* Signup metadata is MetalBear-specific, so it lives in /operator.json
 * rather than inventing a field in describeServer's lexicon. describeServer's
 * inviteCodeRequired still has to agree with it, though, or clients get two
 * contradictory answers. Probe the configured user domain so a per-domain
 * admission list is reflected in both. */
static metalbear_admission_mode
advertised_admission_mode(const metalbear_server *server) {
    if (!server) return METALBEAR_ADMISSION_CLOSED;
    if (!server->user_domain) return server->admission_default_mode;
    char probe[320];
    int written =
        snprintf(probe, sizeof(probe), "signup%s", server->user_domain);
    if (written < 0 || (size_t)written >= sizeof(probe))
        return server->admission_default_mode;
    return metalbear_admission_for_handle(
        probe, server->admission_default_mode, server->admission_open_domains,
        server->admission_invite_domains, server->admission_closed_domains);
}

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
    cJSON_AddBoolToObject(root, "inviteCodeRequired",
                          advertised_admission_mode(server) ==
                              METALBEAR_ADMISSION_INVITE);
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

    /* Implementation facts consumed by the bundled landing page. Keeping
     * these beside the running build metadata prevents capability copy from
     * drifting away from the server that is actually deployed. */
    cJSON *capabilities = cJSON_CreateObject();
    if (capabilities) {
#ifdef METALBEAR_MODULE_VIDEO
        cJSON_AddBoolToObject(capabilities, "multipartVideoUpload", true);
        cJSON_AddNumberToObject(capabilities, "maxVideoBytes",
                                (double)METALBEAR_VIDEO_MAX_BYTES);
        cJSON_AddNumberToObject(capabilities, "videoPartBytes",
                                (double)METALBEAR_VIDEO_PART_BYTES);
#endif
        /* Only advertise verification mail when the server can actually send
         * it: a built without SMTP, or one with no host configured, must not
         * send a signup to check an inbox that will never receive anything. */
#ifdef METALBEAR_MODULE_EMAIL
        cJSON_AddBoolToObject(capabilities, "emailVerificationAvailable",
                              server->email != NULL);
#else
        cJSON_AddBoolToObject(capabilities, "emailVerificationAvailable",
                              false);
#endif
        cJSON_AddItemToObject(root, "capabilities", capabilities);
    }

    /* Self-serve signup policy (issue #258). There is no lexicon field for
     * "open"/"invite"/"closed", so the bundled frontend reads this alongside
     * describeServer's availableUserDomains and inviteCodeRequired. The
     * server remains authoritative: createAccount still enforces admission. */
    metalbear_admission_mode mode = advertised_admission_mode(server);
    cJSON *registration = cJSON_CreateObject();
    if (registration) {
        cJSON_AddStringToObject(registration, "mode",
                                metalbear_admission_mode_name(mode));
        cJSON_AddBoolToObject(registration, "inviteCodeRequired",
                              mode == METALBEAR_ADMISSION_INVITE);
        cJSON_AddBoolToObject(registration, "closed",
                              mode == METALBEAR_ADMISSION_CLOSED);
        cJSON_AddItemToObject(root, "registration", registration);
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
