#include "moderation_routes.h"
#include "../server_internal.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

wf_status create_report(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *body = request->params;
    if (!body || !cJSON_IsObject(body)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Missing request body");
        return WF_OK;
    }

    cJSON *reason_type = cJSON_GetObjectItemCaseSensitive(body, "reasonType");
    cJSON *subject = cJSON_GetObjectItemCaseSensitive(body, "subject");
    cJSON *reason = cJSON_GetObjectItemCaseSensitive(body, "reason");
    cJSON *mod_tool = cJSON_GetObjectItemCaseSensitive(body, "modTool");

    if (!cJSON_IsString(reason_type) || !reason_type->valuestring[0]) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "reasonType is required");
        return WF_OK;
    }
    if (!subject || !cJSON_IsObject(subject)) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "subject is required");
        return WF_OK;
    }

    char subject_type[64] = "";
    char subject_uri[512] = "";
    char subject_cid[128] = "";
    bool is_repo_ref = false;

    cJSON *subject_did = cJSON_GetObjectItemCaseSensitive(subject, "did");
    cJSON *subject_uri_js = cJSON_GetObjectItemCaseSensitive(subject, "uri");
    cJSON *subject_cid_js = cJSON_GetObjectItemCaseSensitive(subject, "cid");

    if (cJSON_IsString(subject_did)) {
        is_repo_ref = true;
        snprintf(subject_uri, sizeof(subject_uri), "%s",
                 subject_did->valuestring);
    } else if (cJSON_IsString(subject_uri_js)) {
        snprintf(subject_uri, sizeof(subject_uri), "%s",
                 subject_uri_js->valuestring);
        if (cJSON_IsString(subject_cid_js))
            snprintf(subject_cid, sizeof(subject_cid), "%s",
                     subject_cid_js->valuestring);
    } else {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "subject must be repoRef or strongRef");
        return WF_OK;
    }

    const char *reporter_did = request->authed_subject;
    if (!reporter_did || !reporter_did[0]) {
        cJSON_Delete(body);
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }

    char *mod_tool_name = NULL;
    char *mod_tool_meta = NULL;
    if (mod_tool && cJSON_IsObject(mod_tool)) {
        cJSON *name = cJSON_GetObjectItemCaseSensitive(mod_tool, "name");
        cJSON *meta = cJSON_GetObjectItemCaseSensitive(mod_tool, "meta");
        if (cJSON_IsString(name) && name->valuestring[0])
            mod_tool_name = name->valuestring;
        if (cJSON_IsObject(meta)) mod_tool_meta = cJSON_PrintUnformatted(meta);
    }

    char created_at[64];
    time_t now = time(NULL);
    if (strftime(created_at, sizeof(created_at), "%Y-%m-%dT%H:%M:%SZ",
                 gmtime(&now)) == 0) {
        free(mod_tool_meta);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Failed to format timestamp");
        return WF_OK;
    }

    int64_t report_id = 0;
    wf_status st = metalbear_report_store_create(
        server->reports, reporter_did, reason_type->valuestring,
        cJSON_IsString(reason) ? reason->valuestring : NULL, subject_type,
        subject_uri, subject_cid[0] ? subject_cid : NULL, mod_tool_name,
        mod_tool_meta, &report_id);
    free(mod_tool_meta);

    if (st != WF_OK || report_id == 0) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Failed to create report");
        return WF_OK;
    }

    cJSON *out = cJSON_CreateObject();
    if (!out) return WF_ERR_ALLOC;
    cJSON_AddNumberToObject(out, "id", (double)report_id);
    cJSON_AddStringToObject(out, "reasonType", reason_type->valuestring);
    if (reason && cJSON_IsString(reason))
        cJSON_AddStringToObject(out, "reason", reason->valuestring);

    cJSON *out_subject = cJSON_CreateObject();
    if (!out_subject) {
        cJSON_Delete(out);
        return WF_ERR_ALLOC;
    }
    if (is_repo_ref && subject_did && cJSON_IsString(subject_did)) {
        cJSON_AddStringToObject(out_subject, "did", subject_did->valuestring);
    } else {
        if (subject_uri[0])
            cJSON_AddStringToObject(out_subject, "uri", subject_uri);
        if (subject_cid[0])
            cJSON_AddStringToObject(out_subject, "cid", subject_cid);
    }
    cJSON_AddItemToObject(out, "subject", out_subject);
    cJSON_AddStringToObject(out, "reportedBy", reporter_did);
    cJSON_AddStringToObject(out, "createdAt", created_at);

    char *js = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    if (!js) return WF_ERR_ALLOC;
    wf_xrpc_response_set_body(response, js, strlen(js));
    free(js);
    return WF_OK;
}
