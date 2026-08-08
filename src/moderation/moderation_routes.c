#include "moderation_routes.h"
#include "../server_internal.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Known values of com.atproto.moderation.defs#reasonType, transcribed from
 * the atproto lexicon's moderation/defs.json `knownValues` array. The
 * reference PDS applies the same closed set through lexicon validation on
 * the createReport input schema.
 */
static const char *const k_known_reason_types[] = {
    "com.atproto.moderation.defs#reasonSpam",
    "com.atproto.moderation.defs#reasonViolation",
    "com.atproto.moderation.defs#reasonMisleading",
    "com.atproto.moderation.defs#reasonSexual",
    "com.atproto.moderation.defs#reasonRude",
    "com.atproto.moderation.defs#reasonOther",
    "com.atproto.moderation.defs#reasonAppeal",

    "tools.ozone.report.defs#reasonAppeal",
    "tools.ozone.report.defs#reasonOther",

    "tools.ozone.report.defs#reasonViolenceAnimal",
    "tools.ozone.report.defs#reasonViolenceThreats",
    "tools.ozone.report.defs#reasonViolenceGraphicContent",
    "tools.ozone.report.defs#reasonViolenceGlorification",
    "tools.ozone.report.defs#reasonViolenceExtremistContent",
    "tools.ozone.report.defs#reasonViolenceTrafficking",
    "tools.ozone.report.defs#reasonViolenceOther",

    "tools.ozone.report.defs#reasonSexualAbuseContent",
    "tools.ozone.report.defs#reasonSexualNCII",
    "tools.ozone.report.defs#reasonSexualDeepfake",
    "tools.ozone.report.defs#reasonSexualAnimal",
    "tools.ozone.report.defs#reasonSexualUnlabeled",
    "tools.ozone.report.defs#reasonSexualOther",

    "tools.ozone.report.defs#reasonChildSafetyCSAM",
    "tools.ozone.report.defs#reasonChildSafetyGroom",
    "tools.ozone.report.defs#reasonChildSafetyPrivacy",
    "tools.ozone.report.defs#reasonChildSafetyHarassment",
    "tools.ozone.report.defs#reasonChildSafetyOther",

    "tools.ozone.report.defs#reasonHarassmentTroll",
    "tools.ozone.report.defs#reasonHarassmentTargeted",
    "tools.ozone.report.defs#reasonHarassmentHateSpeech",
    "tools.ozone.report.defs#reasonHarassmentDoxxing",
    "tools.ozone.report.defs#reasonHarassmentOther",

    "tools.ozone.report.defs#reasonMisleadingBot",
    "tools.ozone.report.defs#reasonMisleadingImpersonation",
    "tools.ozone.report.defs#reasonMisleadingSpam",
    "tools.ozone.report.defs#reasonMisleadingScam",
    "tools.ozone.report.defs#reasonMisleadingElections",
    "tools.ozone.report.defs#reasonMisleadingOther",

    "tools.ozone.report.defs#reasonRuleSiteSecurity",
    "tools.ozone.report.defs#reasonRuleProhibitedSales",
    "tools.ozone.report.defs#reasonRuleBanEvasion",
    "tools.ozone.report.defs#reasonRuleOther",

    "tools.ozone.report.defs#reasonSelfHarmContent",
    "tools.ozone.report.defs#reasonSelfHarmED",
    "tools.ozone.report.defs#reasonSelfHarmStunts",
    "tools.ozone.report.defs#reasonSelfHarmSubstances",
    "tools.ozone.report.defs#reasonSelfHarmOther",
};

static bool is_known_reason_type(const char *reason_type) {
    for (size_t i = 0; i < sizeof(k_known_reason_types) /
                               sizeof(k_known_reason_types[0]);
         i++)
        if (strcmp(reason_type, k_known_reason_types[i]) == 0) return true;
    return false;
}

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
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "reasonType is required");
        return WF_OK;
    }
    if (!is_known_reason_type(reason_type->valuestring)) {
        char msg[640];
        snprintf(msg, sizeof(msg),
                 "Invalid reasonType '%s': expected a value from "
                 "com.atproto.moderation.defs#reasonType knownValues",
                 reason_type->valuestring);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest", msg);
        return WF_OK;
    }
    if (!subject || !cJSON_IsObject(subject)) {
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
        snprintf(subject_type, sizeof(subject_type), "repoRef");
        snprintf(subject_uri, sizeof(subject_uri), "%s",
                 subject_did->valuestring);
    } else if (cJSON_IsString(subject_uri_js)) {
        snprintf(subject_type, sizeof(subject_type), "strongRef");
        snprintf(subject_uri, sizeof(subject_uri), "%s",
                 subject_uri_js->valuestring);
        if (cJSON_IsString(subject_cid_js))
            snprintf(subject_cid, sizeof(subject_cid), "%s",
                     subject_cid_js->valuestring);
    } else {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "subject must be repoRef or strongRef");
        return WF_OK;
    }

    const char *reporter_did = request->authed_subject;
    if (!reporter_did || !reporter_did[0]) {
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
        cJSON_AddStringToObject(out_subject, "$type",
                                "com.atproto.admin.defs#repoRef");
        cJSON_AddStringToObject(out_subject, "did", subject_did->valuestring);
    } else {
        cJSON_AddStringToObject(out_subject, "$type",
                                "com.atproto.repo.strongRef");
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
