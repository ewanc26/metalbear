/*
 * lexicon_routes.c -- com.atproto.lexicon.resolveLexicon.
 *
 * The reference PDS answers this from its own lexicon store; MetalBear
 * answers from the Wolfram corpus it already loads at startup
 * (server->lexicons), so a client pointed at a self-hosted instance resolves
 * an NSID without going to the upstream repo. The document is served
 * verbatim as application/json; an unknown NSID is a 400 InvalidRequest,
 * matching the reference's "Lexicon not found".
 */

#include "lexicon_routes.h"

#include "server_internal.h"

#include "wolfram/validate.h"

#include <cJSON.h>

#include <string.h>

wf_status resolve_lexicon(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const char *nsid = NULL;

    if (request->params && cJSON_IsObject(request->params)) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(request->params, "nsid");
        if (cJSON_IsString(item) && item->valuestring) nsid = item->valuestring;
    }
    if (!nsid || !nsid[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "missing required nsid parameter");
        return WF_OK;
    }
    if (!server->lexicons) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "no lexicon corpus loaded");
        return WF_OK;
    }

    const char *doc = NULL;
    size_t doc_len = 0;
    wf_status st =
        wf_lexicon_registry_document(server->lexicons, nsid, &doc, &doc_len);
    if (st == WF_ERR_NOT_FOUND) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "lexicon not found");
        return WF_OK;
    }
    if (st != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "lexicon lookup failed");
        return WF_OK;
    }

    wf_xrpc_response_set_body(response, doc, doc_len);
    wf_xrpc_response_set_content_type(response, "application/json");
    return WF_OK;
}
