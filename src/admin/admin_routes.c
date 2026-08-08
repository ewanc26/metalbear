#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif

#include "admin_routes.h"

#include "../server_internal.h"

#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/email.h"
#include "metalbear/log.h"
#include "metalbear/oauth/auth.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/repo/repo_store.h"
#include "metalbear/sequencer.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/*
 * `com.atproto.admin.defs#statusAttr` — `applied` is required, so a status
 * that is not applied is reported as `applied: false` rather than by omitting
 * the field. A moderator reading an omitted key cannot tell "not taken down"
 * from "this server does not track takedowns".
 */
static cJSON *status_attr(bool applied, const char *ref) {
    cJSON *attr = cJSON_CreateObject();
    if (!attr) return NULL;
    cJSON_AddBoolToObject(attr, "applied", applied);
    if (applied && ref && ref[0]) cJSON_AddStringToObject(attr, "ref", ref);
    return attr;
}

/* Render the current UTC time as an ISO-8601 datetime (the
 * com.atproto.admin.defs#accountView `indexedAt` field). */
static void iso_now(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm tm;
#if defined(_WIN32)
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Build a full com.atproto.server.defs#inviteCode JSON object from a
 * registry entry, including its real per-redemption `uses` log. Shared by
 * getInviteCodes (every code) and getAccountInfo/getAccountInfos'
 * `invitedBy` (the one code that created a given account). `fallback_did`
 * fills forAccount/createdBy when the registry row itself has neither
 * (self-service codes never recorded created_by). */
static cJSON *build_invite_code_json(metalbear_server *server,
                                     const metalbear_invite_code_entry *entry,
                                     const char *fallback_did) {
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddStringToObject(obj, "code", entry->code);
    cJSON_AddStringToObject(obj, "forAccount",
                            entry->for_account ? entry->for_account
                                               : fallback_did);
    cJSON_AddStringToObject(
        obj, "createdBy", entry->created_by ? entry->created_by : fallback_did);
    cJSON_AddBoolToObject(obj, "disabled", entry->disabled != 0);
    cJSON_AddStringToObject(
        obj, "createdAt",
        entry->created_at ? entry->created_at : "1970-01-01T00:00:00.000Z");
    cJSON *uses = cJSON_CreateArray();
    if (!uses) {
        cJSON_Delete(obj);
        return NULL;
    }
    metalbear_invite_code_use_entry *use_entries = NULL;
    size_t use_count = 0;
    if (metalbear_account_registry_get_invite_code_uses(
            server->registry, entry->code, &use_entries, &use_count) == WF_OK) {
        for (size_t k = 0; k < use_count; k++) {
            cJSON *use = cJSON_CreateObject();
            if (!use) continue;
            cJSON_AddStringToObject(use, "usedBy", use_entries[k].used_by);
            cJSON_AddStringToObject(use, "usedAt", use_entries[k].used_at);
            cJSON_AddItemToArray(uses, use);
        }
        metalbear_invite_code_use_entries_free(use_entries, use_count);
    }
    cJSON_AddNumberToObject(obj, "available",
                            entry->uses_remaining + (int)use_count);
    cJSON_AddItemToObject(obj, "uses", uses);
    return obj;
}

/* ---- com.atproto.admin.getAccountInfo (query, admin-gated) ----
 * Mirrors refpds `pdsadmin account list`: look the DID up in the
 * registry and return its did/handle/email/active. Unknown DID is an
 * honest AccountNotFound (404), never a fabricated success. */
wf_status admin_get_account_info(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, did->valuestring, &entry) != WF_OK ||
        !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        metalbear_account_entry_free(entry);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", entry->did);
    cJSON_AddStringToObject(root, "handle", entry->handle);
    cJSON_AddBoolToObject(root, "active", entry->active != 0);
    cJSON_AddBoolToObject(root, "invitesDisabled", false);
    /* Email lives in the account's own store; open it read-only. */
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    if (acct_path) {
        metalbear_account_store *acct = NULL;
        if (metalbear_account_store_open(acct_path, "", &acct) == WF_OK) {
            if (!metalbear_account_invites_enabled(acct))
                cJSON_ReplaceItemInObject(root, "invitesDisabled",
                                          cJSON_CreateBool(true));
            char *email = NULL;
            int confirmed = 0;
            if (metalbear_account_get_email(acct, &email, &confirmed) ==
                    WF_OK &&
                email && email[0])
                cJSON_AddStringToObject(root, "email", email);
            free(email);
            char *deactivated_at = NULL;
            if (metalbear_account_get_deactivated_at(acct, &deactivated_at) ==
                    WF_OK &&
                deactivated_at)
                cJSON_AddStringToObject(root, "deactivatedAt", deactivated_at);
            free(deactivated_at);
            metalbear_account_store_free(acct);
        }
        free(acct_path);
    }
    /* com.atproto.admin.defs#accountView's indexedAt is the account's own
     * creation time (getAccountInfo.ts: account.createdAt), not "now" --
     * using the request time made every call return a different value for
     * the same account. */
    cJSON_AddStringToObject(root, "indexedAt",
                            entry->created_at ? entry->created_at : "");
    /* invitedBy: the code that created this account, if any (self-signup
     * with invites off, or created before invite tracking, leaves this
     * absent -- matches the reference's optional field). */
    metalbear_invite_code_entry *invited_by_entry = NULL;
    if (metalbear_account_registry_get_invite_code_for_account(
            server->registry, entry->did, entry->handle, &invited_by_entry) ==
        WF_OK) {
        cJSON *invited_by_json =
            build_invite_code_json(server, invited_by_entry, entry->did);
        if (invited_by_json)
            cJSON_AddItemToObject(root, "invitedBy", invited_by_json);
        metalbear_invite_code_entries_free(invited_by_entry, 1);
    }
    /* invites: codes this account itself owns/has minted. */
    metalbear_invite_code_entry *own_codes = NULL;
    size_t own_code_count = 0;
    if (metalbear_account_registry_get_invite_codes(server->registry,
                                                    entry->did, &own_codes,
                                                    &own_code_count) == WF_OK) {
        cJSON *invites = cJSON_CreateArray();
        if (invites) {
            for (size_t i = 0; i < own_code_count; i++) {
                cJSON *code_json =
                    build_invite_code_json(server, &own_codes[i], entry->did);
                if (code_json) cJSON_AddItemToArray(invites, code_json);
            }
            cJSON_AddItemToObject(root, "invites", invites);
        }
        metalbear_invite_code_entries_free(own_codes, own_code_count);
    }
    metalbear_account_entry_free(entry);
    return set_json(response, root);
}

/* ---- com.atproto.admin.getSubjectStatus (query, admin-gated) ---- */
wf_status admin_get_subject_status(void *ctx, const wf_xrpc_request *request,
                                   wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
            : NULL;
    cJSON *uri_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "uri")
            : NULL;
    cJSON *blob_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "blob")
            : NULL;
    const char *did = cJSON_IsString(did_param) ? did_param->valuestring : NULL;
    const char *uri = cJSON_IsString(uri_param) ? uri_param->valuestring : NULL;
    const char *blob =
        cJSON_IsString(blob_param) ? blob_param->valuestring : NULL;
    if (!did && !uri && !blob) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "at least one of did, uri, or blob is required");
        return WF_OK;
    }
    /* A CID names content, not an upload, so a blob subject is only
     * identifiable together with the account that holds it. */
    if (blob && !did) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Must provide a did to request blob state");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON *subject = cJSON_CreateObject();
    if (!subject) {
        cJSON_Delete(root);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToObject(root, "subject", subject);

    /*
     * Blob first, then record, then account. A blob subject carries a DID as
     * well as a CID, so testing `did` first would answer about the account
     * that holds the blob instead of about the blob.
     */
    char *takedown_ref = NULL;
    if (blob) {
        metalbear_account_registry_get_takedown(server->registry, did, NULL,
                                                blob, &takedown_ref);
        if (!takedown_ref) {
            cJSON_Delete(root);
            wf_xrpc_response_set_error(response, 400, "NotFound",
                                       "Subject not found");
            return WF_OK;
        }
        cJSON_AddStringToObject(subject, "$type",
                                "com.atproto.admin.defs#repoBlobRef");
        cJSON_AddStringToObject(subject, "did", did);
        cJSON_AddStringToObject(subject, "cid", blob);
    } else if (uri) {
        /* `com.atproto.repo.strongRef` requires `cid`, so the record is
         * resolved to supply one; a strict client rejects a reference that
         * carries only the URI. */
        char authority[256], collection[256], rkey[256];
        char *record_cid = NULL;
        if (split_at_uri(uri, authority, sizeof authority, collection,
                         sizeof collection, rkey, sizeof rkey)) {
            metalbear_account_context *acct =
                context_for_identifier(server, authority);
            char *record_json = NULL;
            if (acct && metalbear_repo_store_get_record(acct->repo, collection,
                                                        rkey, &record_json,
                                                        &record_cid) != WF_OK)
                record_cid = NULL;
            free(record_json);
        }
        if (record_cid)
            metalbear_account_registry_get_takedown(server->registry, NULL, uri,
                                                    NULL, &takedown_ref);
        if (!record_cid || !takedown_ref) {
            free(record_cid);
            free(takedown_ref);
            cJSON_Delete(root);
            wf_xrpc_response_set_error(response, 400, "NotFound",
                                       "Subject not found");
            return WF_OK;
        }
        cJSON_AddStringToObject(subject, "$type", "com.atproto.repo.strongRef");
        cJSON_AddStringToObject(subject, "uri", uri);
        cJSON_AddStringToObject(subject, "cid", record_cid);
        free(record_cid);
    } else {
        metalbear_account_entry *entry = NULL;
        if (metalbear_account_registry_find_by_did(server->registry, did,
                                                   &entry) != WF_OK ||
            !entry) {
            cJSON_Delete(root);
            wf_xrpc_response_set_error(response, 400, "NotFound",
                                       "Subject not found");
            return WF_OK;
        }
        metalbear_account_registry_get_takedown(server->registry, did, NULL,
                                                NULL, &takedown_ref);
        cJSON_AddStringToObject(subject, "$type",
                                "com.atproto.admin.defs#repoRef");
        cJSON_AddStringToObject(subject, "did", did);
        cJSON_AddItemToObject(root, "deactivated",
                              status_attr(!entry->active, NULL));
        metalbear_account_entry_free(entry);
    }
    cJSON_AddItemToObject(root, "takedown",
                          status_attr(takedown_ref != NULL, takedown_ref));
    free(takedown_ref);
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateSubjectStatus (procedure, admin-gated) ---- */
wf_status admin_update_subject_status(void *ctx, const wf_xrpc_request *request,
                                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *subject =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "subject")
            : NULL;
    if (!subject) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "subject is required");
        return WF_OK;
    }
    cJSON *type = cJSON_GetObjectItemCaseSensitive(subject, "$type");
    const char *type_str = cJSON_IsString(type) ? type->valuestring : NULL;
    cJSON *takedown =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "takedown")
            : NULL;
    cJSON *deactivated =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "deactivated")
            : NULL;

    const char *did = NULL, *uri = NULL, *blob_cid = NULL;
    char did_buf[256] = {0}, uri_buf[1024] = {0}, blob_buf[128] = {0};

    if (type_str && strcmp(type_str, "com.atproto.admin.defs#repoRef") == 0) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(subject, "did");
        if (!cJSON_IsString(d) || !d->valuestring[0]) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "did is required for repoRef");
            return WF_OK;
        }
        snprintf(did_buf, sizeof(did_buf), "%s", d->valuestring);
        did = did_buf;
    } else if (type_str &&
               strcmp(type_str, "com.atproto.repo.strongRef") == 0) {
        cJSON *u = cJSON_GetObjectItemCaseSensitive(subject, "uri");
        if (!cJSON_IsString(u) || !u->valuestring[0]) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "uri is required for strongRef");
            return WF_OK;
        }
        snprintf(uri_buf, sizeof(uri_buf), "%s", u->valuestring);
        uri = uri_buf;
    } else if (type_str &&
               strcmp(type_str, "com.atproto.admin.defs#repoBlobRef") == 0) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(subject, "did");
        cJSON *c = cJSON_GetObjectItemCaseSensitive(subject, "cid");
        if (!cJSON_IsString(d) || !d->valuestring[0] || !cJSON_IsString(c) ||
            !c->valuestring[0]) {
            wf_xrpc_response_set_error(
                response, 400, "InvalidRequest",
                "did and cid are required for repoBlobRef");
            return WF_OK;
        }
        snprintf(did_buf, sizeof(did_buf), "%s", d->valuestring);
        snprintf(blob_buf, sizeof(blob_buf), "%s", c->valuestring);
        did = did_buf;
        blob_cid = blob_buf;
    } else {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "unknown subject type");
        return WF_OK;
    }

    bool account_subject = did && !uri && !blob_cid;
    cJSON *takedown_applied =
        takedown ? cJSON_GetObjectItemCaseSensitive(takedown, "applied") : NULL;
    cJSON *deactivated_applied =
        deactivated ? cJSON_GetObjectItemCaseSensitive(deactivated, "applied")
                    : NULL;

    /* The two would race to decide the account's status and the event that
     * announces it, so the reference refuses the pair outright. */
    if (cJSON_IsTrue(takedown_applied) && deactivated &&
        !cJSON_IsTrue(deactivated_applied)) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "Cannot activate and takedown an account at the same time");
        return WF_OK;
    }

    /* Apply takedown if present. */
    if (takedown) {
        cJSON *ref = cJSON_GetObjectItemCaseSensitive(takedown, "ref");
        const char *ref_str = cJSON_IsString(ref) ? ref->valuestring : "admin";
        bool applying = cJSON_IsTrue(takedown_applied);
        metalbear_account_registry_set_takedown(
            server->registry, did, uri, blob_cid, applying ? ref_str : NULL);
        /*
         * Every session the account holds is revoked, so a takedown takes
         * effect on the tokens already issued rather than only on new logins.
         * Lifting it does not restore them: the holder logs in again.
         */
        if (applying) metalbear_metrics_inc(METALBEAR_METRIC_TAKEDOWNS_APPLIED);
        if (account_subject && applying) {
            metalbear_account_context *acct = context_for_did(server, did);
            if (acct) metalbear_auth_delete_all(acct->auth);
            LOG_INFO("takedown: applied to did=%s ref=%s", did, ref_str);
        } else if (account_subject) {
            LOG_INFO("takedown: lifted from did=%s", did);
        }
    }

    /* Handle account deactivation (repoRef only). */
    if (deactivated && account_subject) {
        metalbear_account_context *acct = context_for_did(server, did);
        if (acct) {
            if (cJSON_IsTrue(deactivated_applied))
                metalbear_account_deactivate(acct->account, NULL);
            else
                metalbear_account_activate(acct->account);
        }
    }

    /*
     * Announce the resulting status once, whatever changed. Sequenced against
     * the server's own log rather than a resolved context's, so the event is
     * not silently skipped for an account that happens not to be cached —
     * and computed after both changes have been applied, so an account that
     * is deactivated *and* taken down is announced as taken down rather than
     * as whichever call ran last.
     */
    if (account_subject) {
        metalbear_account_context *acct = context_for_did(server, did);
        if (acct) {
            bool active = false;
            const char *status = account_status_string(server, acct, &active);
            metalbear_sequencer_account_status(server->sequencer, did,
                                               active ? 1 : 0, status);
        }
    }

    /* Return updated status (echo subject + takedown). */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON *out_subject = cJSON_Duplicate(subject, 1);
    if (!out_subject) {
        cJSON_Delete(root);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToObject(root, "subject", out_subject);
    if (takedown) {
        cJSON *out_td = cJSON_Duplicate(takedown, 1);
        if (out_td) cJSON_AddItemToObject(root, "takedown", out_td);
    }
    return set_json(response, root);
}

/* ---- com.atproto.admin.sendEmail (procedure, admin-gated) ---- */
wf_status admin_send_email(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *recipient =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "recipientDid")
            : NULL;
    cJSON *content =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "content")
            : NULL;
    cJSON *subject_item =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "subject")
            : NULL;
    if (!cJSON_IsString(recipient) || !recipient->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "recipientDid is required");
        return WF_OK;
    }
    if (!cJSON_IsString(content) || !content->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "content is required");
        return WF_OK;
    }
    /* Look up the recipient's email. */
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, recipient->valuestring, &entry) != WF_OK ||
        !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "recipient account not found");
        return WF_OK;
    }
    char *email = NULL;
    int confirmed = 0;
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    if (acct_path) {
        metalbear_account_store *acct = NULL;
        if (metalbear_account_store_open(acct_path, "", &acct) == WF_OK) {
            metalbear_account_get_email(acct, &email, &confirmed);
            metalbear_account_store_free(acct);
        }
        free(acct_path);
    }
    metalbear_account_entry_free(entry);
    if (!email || !email[0]) {
        free(email);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "recipient has no email address");
        return WF_OK;
    }
    /* Send the email if the email module is configured. */
    const char *subj = cJSON_IsString(subject_item)
                           ? subject_item->valuestring
                           : "Message from PDS administrator";
    bool sent = false;
    if (server->email) {
        sent = metalbear_email_send(server->email, email, subj,
                                    content->valuestring) == WF_OK;
    }
    free(email);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "sent", sent);
    return set_json(response, root);
}

/* ---- Helper: build accountView JSON for admin endpoints ---- */
static cJSON *build_account_view(metalbear_server *server,
                                 const metalbear_account_entry *entry) {
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddStringToObject(obj, "did", entry->did);
    cJSON_AddStringToObject(obj, "handle", entry->handle);
    cJSON_AddBoolToObject(obj, "active", entry->active != 0);
    cJSON_AddBoolToObject(obj, "invitesDisabled", false);
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    if (acct_path) {
        metalbear_account_store *acct = NULL;
        if (metalbear_account_store_open(acct_path, "", &acct) == WF_OK) {
            if (!metalbear_account_invites_enabled(acct))
                cJSON_ReplaceItemInObject(obj, "invitesDisabled",
                                          cJSON_CreateBool(true));
            char *email = NULL;
            int confirmed = 0;
            if (metalbear_account_get_email(acct, &email, &confirmed) ==
                    WF_OK &&
                email && email[0]) {
                cJSON_AddStringToObject(obj, "email", email);
                if (confirmed) {
                    char indexed_at[32];
                    iso_now(indexed_at, sizeof(indexed_at));
                    cJSON_AddStringToObject(obj, "emailConfirmedAt",
                                            indexed_at);
                }
            }
            free(email);
            char *deactivated_at = NULL;
            if (metalbear_account_get_deactivated_at(acct, &deactivated_at) ==
                    WF_OK &&
                deactivated_at)
                cJSON_AddStringToObject(obj, "deactivatedAt", deactivated_at);
            free(deactivated_at);
            metalbear_account_store_free(acct);
        }
        free(acct_path);
    }
    /* Same fix as admin_get_account_info: the account's own creation time,
     * not the request time. */
    cJSON_AddStringToObject(obj, "indexedAt",
                            entry->created_at ? entry->created_at : "");
    /* Same invitedBy/invites as admin_get_account_info. */
    metalbear_invite_code_entry *invited_by_entry = NULL;
    if (metalbear_account_registry_get_invite_code_for_account(
            server->registry, entry->did, entry->handle, &invited_by_entry) ==
        WF_OK) {
        cJSON *invited_by_json =
            build_invite_code_json(server, invited_by_entry, entry->did);
        if (invited_by_json)
            cJSON_AddItemToObject(obj, "invitedBy", invited_by_json);
        metalbear_invite_code_entries_free(invited_by_entry, 1);
    }
    metalbear_invite_code_entry *own_codes = NULL;
    size_t own_code_count = 0;
    if (metalbear_account_registry_get_invite_codes(server->registry,
                                                    entry->did, &own_codes,
                                                    &own_code_count) == WF_OK) {
        cJSON *invites = cJSON_CreateArray();
        if (invites) {
            for (size_t i = 0; i < own_code_count; i++) {
                cJSON *code_json =
                    build_invite_code_json(server, &own_codes[i], entry->did);
                if (code_json) cJSON_AddItemToArray(invites, code_json);
            }
            cJSON_AddItemToObject(obj, "invites", invites);
        }
        metalbear_invite_code_entries_free(own_codes, own_code_count);
    }
    return obj;
}

/* ---- com.atproto.admin.getAccountInfos (query, admin-gated) ---- */
wf_status admin_get_account_infos(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *dids =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "dids")
            : NULL;
    if (!cJSON_IsArray(dids) || cJSON_GetArraySize(dids) == 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "dids array is required");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *infos = cJSON_CreateArray();
    if (!root || !infos) {
        cJSON_Delete(root);
        cJSON_Delete(infos);
        return WF_ERR_ALLOC;
    }
    size_t n = cJSON_GetArraySize(dids);
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(dids, i);
        if (!cJSON_IsString(item) || !item->valuestring[0]) continue;
        metalbear_account_entry *entry = NULL;
        if (metalbear_account_registry_find_by_did(
                server->registry, item->valuestring, &entry) != WF_OK ||
            !entry)
            continue;
        cJSON *view = build_account_view(server, entry);
        metalbear_account_entry_free(entry);
        if (view) cJSON_AddItemToArray(infos, view);
    }
    cJSON_AddItemToObject(root, "infos", infos);
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateAccountHandle (procedure, admin-gated) ---- */
wf_status admin_update_account_handle(void *ctx, const wf_xrpc_request *request,
                                      wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    cJSON *handle =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "handle")
            : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    if (!cJSON_IsString(handle) || !handle->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "handle is required");
        return WF_OK;
    }
    /* Same syntax check the self-service update_handle route applies
     * (identity_routes.c) -- an admin override must not be able to set a
     * handle the account holder themselves could never set, matching the
     * reference's shared normalizeAndValidateHandle. */
    if (!wf_syntax_handle_is_valid(handle->valuestring)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "invalid handle");
        return WF_OK;
    }
    /* Check handle is not already taken by another account. */
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_handle(
            server->registry, handle->valuestring, &existing) == WF_OK) {
        bool conflict =
            existing && strcmp(existing->did, did->valuestring) != 0;
        metalbear_account_entry_free(existing);
        if (conflict) {
            wf_xrpc_response_set_error(response, 400, "HandleNotAvailable",
                                       "Handle is already taken");
            return WF_OK;
        }
    }
    /* Update the registry. */
    if (metalbear_account_registry_update_handle(
            server->registry, did->valuestring, handle->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not update handle");
        return WF_OK;
    }
    /* Update the account context if open. */
    metalbear_account_context *acct = context_for_did(server, did->valuestring);
    char *old_handle = NULL;
    if (acct) {
        old_handle = strdup(acct->handle);
        metalbear_repo_store_set_handle(acct->repo, handle->valuestring);
        free(acct->handle);
        acct->handle = strdup(handle->valuestring);
    }

    publish_handle_dns(server, handle->valuestring, did->valuestring);
    /* Only when the old handle was known: the context is the only place it is
     * held, and guessing at a name to delete risks removing someone else's. */
    if (old_handle && strcmp(old_handle, handle->valuestring) != 0)
        retract_handle_dns(server, old_handle);
    free(old_handle);

    /* Same as the self-service path: an unannounced rename leaves every
     * consumer serving the old handle indefinitely. */
    if (metalbear_sequencer_identity(server->sequencer, did->valuestring,
                                     handle->valuestring) != WF_OK)
        LOG_ERROR("admin_update_account_handle: could not sequence #identity "
                  "for did=%s handle=%s; the rename is durable but unannounced",
                  did->valuestring, handle->valuestring);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateAccountEmail (procedure, admin-gated) ---- */
wf_status admin_update_account_email(void *ctx, const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *account =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "account")
            : NULL;
    cJSON *email =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "email")
            : NULL;
    if (!cJSON_IsString(account) || !account->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "account (DID or handle) is required");
        return WF_OK;
    }
    if (!cJSON_IsString(email) || !email->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "email is required");
        return WF_OK;
    }
    /* Resolve to DID. */
    metalbear_account_entry *entry = NULL;
    wf_status lookup = metalbear_account_registry_find_by_did(
        server->registry, account->valuestring, &entry);
    if (lookup != WF_OK || !entry) {
        lookup = metalbear_account_registry_find_by_handle(
            server->registry, account->valuestring, &entry);
    }
    if (lookup != WF_OK || !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "Account not found");
        return WF_OK;
    }
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    metalbear_account_entry_free(entry);
    if (!acct_path) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Internal error");
        return WF_OK;
    }
    metalbear_account_store *acct = NULL;
    wf_status status = metalbear_account_store_open(acct_path, "", &acct);
    free(acct_path);
    if (status != WF_OK || !acct) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not open account store");
        return WF_OK;
    }
    metalbear_account_store_email(acct, email->valuestring);
    /* Every outstanding email token (confirm/update/reset) was minted
     * against the old email; leaving them valid after an admin override
     * would let a stale token confirm or reset against an address the
     * account holder never saw. Matches the reference's
     * emailToken.deleteAllEmailTokens in the same transaction
     * (account-manager.ts's updateAccountEmail). */
    metalbear_account_delete_all_email_tokens(acct);
    metalbear_account_store_free(acct);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.updateAccountPassword (procedure, admin-gated) ---- */
wf_status admin_update_account_password(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    cJSON *password =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "password")
            : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    if (!cJSON_IsString(password) || !password->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "password is required");
        return WF_OK;
    }
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, did->valuestring, &entry) != WF_OK ||
        !entry) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "Account not found");
        return WF_OK;
    }
    char *acct_path = join_path(entry->data_directory, "account.sqlite3");
    metalbear_account_entry_free(entry);
    if (!acct_path) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Internal error");
        return WF_OK;
    }
    metalbear_account_store *acct = NULL;
    wf_status status = metalbear_account_store_open(acct_path, "", &acct);
    free(acct_path);
    if (status != WF_OK || !acct) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not open account store");
        return WF_OK;
    }
    metalbear_account_reset_password(acct, password->valuestring);
    /* The reset token that (if any) led here is now spent; matches the
     * reference deleting the "reset_password"-kind token in the same
     * transaction (account-manager.ts's updateAccountPassword). */
    metalbear_account_delete_email_tokens_by_kind(acct, "reset");
    metalbear_account_store_free(acct);
    /*
     * Revoke every session the account holds, matching the reference
     * (account-manager.ts's updateAccountPassword revokes refresh tokens in
     * the same transaction). An admin resets a password to lock an attacker
     * out; leaving their existing sessions alive would defeat the point.
     */
    metalbear_account_context *sess_acct =
        context_for_did(server, did->valuestring);
    if (sess_acct) metalbear_auth_delete_all(sess_acct->auth);
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.enableAccountInvites (procedure, admin-gated) ---- */
wf_status admin_enable_account_invites(void *ctx,
                                       const wf_xrpc_request *request,
                                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *account =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "account")
            : NULL;
    if (!cJSON_IsString(account) || !account->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "account is required");
        return WF_OK;
    }
    metalbear_account_context *acct =
        context_for_did(server, account->valuestring);
    if (!acct) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    if (metalbear_account_set_invites_enabled(acct->account, true) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "could not persist invite state");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.disableAccountInvites (procedure, admin-gated) ---- */
wf_status admin_disable_account_invites(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *account =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "account")
            : NULL;
    if (!cJSON_IsString(account) || !account->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "account is required");
        return WF_OK;
    }
    metalbear_account_context *acct =
        context_for_did(server, account->valuestring);
    if (!acct) {
        wf_xrpc_response_set_error(response, 404, "AccountNotFound",
                                   "account is not hosted here");
        return WF_OK;
    }
    if (metalbear_account_set_invites_enabled(acct->account, false) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "could not persist invite state");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.admin.getInviteCodes (query, admin-gated) ---- */
wf_status admin_get_invite_codes(void *ctx, const wf_xrpc_request *request,
                                 wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    int limit = query_param_int(request->params, "limit", 100, 1, 500);
    cJSON *sort_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "sort")
            : NULL;
    const char *sort = cJSON_IsString(sort_param) && sort_param->valuestring[0]
                           ? sort_param->valuestring
                           : "recent";
    /* "usage" needs a use-count-ordered index this registry does not have
     * yet; an honest 400 beats silently falling back to "recent" and
     * returning results in an order the caller did not ask for. */
    if (strcmp(sort, "recent") != 0) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "only sort=recent is supported (usage sort is not implemented)");
        return WF_OK;
    }
    cJSON *cursor_param =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor")
            : NULL;
    /* Keyset cursor: "<createdAt><US><code>" (US = 0x1F, a control byte no
     * real created_at or client-supplied code is expected to contain), the
     * last row's own sort key from the previous page -- opaque to the
     * caller, who is only ever expected to echo it back verbatim. */
    char after_created_at[40] = {0};
    char after_code[256] = {0};
    if (cJSON_IsString(cursor_param) && cursor_param->valuestring[0]) {
        const char *sep = strchr(cursor_param->valuestring, '\x1f');
        if (!sep) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "malformed cursor");
            return WF_OK;
        }
        size_t created_len = (size_t)(sep - cursor_param->valuestring);
        if (created_len >= sizeof(after_created_at) ||
            strlen(sep + 1) >= sizeof(after_code)) {
            wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                       "malformed cursor");
            return WF_OK;
        }
        memcpy(after_created_at, cursor_param->valuestring, created_len);
        after_created_at[created_len] = '\0';
        strcpy(after_code, sep + 1);
    }
    /* Fetch one extra row to learn whether a next page exists without a
     * separate COUNT query. */
    metalbear_invite_code_entry *icode_entries = NULL;
    size_t icode_count = 0;
    if (metalbear_account_registry_list_invite_codes(
            server->registry, after_created_at[0] ? after_created_at : NULL,
            after_code[0] ? after_code : NULL, (size_t)limit + 1,
            &icode_entries, &icode_count) != WF_OK) {
        icode_entries = NULL;
        icode_count = 0;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *codes = cJSON_CreateArray();
    if (!root || !codes) {
        cJSON_Delete(root);
        cJSON_Delete(codes);
        metalbear_invite_code_entries_free(icode_entries, icode_count);
        return WF_ERR_ALLOC;
    }
    size_t returned = icode_count > (size_t)limit ? (size_t)limit : icode_count;
    for (size_t i = 0; i < returned; i++) {
        cJSON *obj = build_invite_code_json(server, &icode_entries[i],
                                            icode_entries[i].for_account);
        if (obj) cJSON_AddItemToArray(codes, obj);
    }
    if (icode_count > (size_t)limit) {
        /* There is a next page: point the cursor at the last row actually
         * returned (index `returned - 1`), not the lookahead row itself. */
        char next_cursor[296];
        snprintf(next_cursor, sizeof(next_cursor), "%s\x1f%s",
                 icode_entries[returned - 1].created_at,
                 icode_entries[returned - 1].code);
        cJSON_AddStringToObject(root, "cursor", next_cursor);
    }
    metalbear_invite_code_entries_free(icode_entries, icode_count);
    cJSON_AddItemToObject(root, "codes", codes);
    return set_json(response, root);
}

/* ---- com.atproto.admin.disableInviteCodes (procedure, admin-gated) ---- */
wf_status admin_disable_invite_codes(void *ctx, const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *codes =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "codes")
            : NULL;
    cJSON *accounts =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "accounts")
            : NULL;

    size_t code_count = 0, account_count = 0;
    const char **code_ptrs = NULL, **account_ptrs = NULL;

    if (cJSON_IsArray(codes) && cJSON_GetArraySize(codes) > 0) {
        code_count = cJSON_GetArraySize(codes);
        code_ptrs = calloc(code_count, sizeof(*code_ptrs));
        if (!code_ptrs) return WF_ERR_ALLOC;
        for (size_t i = 0; i < code_count; i++) {
            cJSON *item = cJSON_GetArrayItem(codes, i);
            code_ptrs[i] = cJSON_IsString(item) ? item->valuestring : NULL;
        }
    }
    if (cJSON_IsArray(accounts) && cJSON_GetArraySize(accounts) > 0) {
        account_count = cJSON_GetArraySize(accounts);
        account_ptrs = calloc(account_count, sizeof(*account_ptrs));
        if (!account_ptrs) {
            free(code_ptrs);
            return WF_ERR_ALLOC;
        }
        for (size_t i = 0; i < account_count; i++) {
            cJSON *item = cJSON_GetArrayItem(accounts, i);
            account_ptrs[i] = cJSON_IsString(item) ? item->valuestring : NULL;
        }
        for (size_t i = 0; i < account_count; i++) {
            if (account_ptrs[i] && strcmp(account_ptrs[i], "admin") == 0) {
                free(code_ptrs);
                free(account_ptrs);
                wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                           "cannot disable admin invite codes");
                return WF_OK;
            }
        }
    }

    wf_status status = metalbear_account_registry_disable_invite_codes(
        server->registry, code_ptrs, code_count, account_ptrs, account_count);
    free(code_ptrs);
    free(account_ptrs);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    cJSON_AddBoolToObject(root, "disabled", status == WF_OK);
    return set_json(response, root);
}

/* ---- com.atproto.admin.deleteAccount (procedure, admin-gated) ---- */
static int rmtree_remove_cb(const char *path, const struct stat *sb, int type,
                            struct FTW *ftwbuf) {
    (void)sb;
    (void)type;
    (void)ftwbuf;
    return remove(path);
}
static void rmtree(const char *path) {
    nftw(path, rmtree_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

wf_status admin_delete_account(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    if (!cJSON_IsString(did) || !did->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "did is required");
        return WF_OK;
    }
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_did(
            server->registry, did->valuestring, &entry) != WF_OK ||
        !entry) {
        /* Idempotent, matching the reference exactly (deleteAccount.ts runs
         * deleteAccount/sequenceAccountDeletion/actorStore.destroy
         * unconditionally, with no existence check at all): the desired
         * end state -- this DID hosts no account -- already holds, so a
         * retry of a delete whose response was lost in transit succeeds
         * rather than surprising the caller with a 404 for the very thing
         * it just asked to happen. */
        cJSON *root = cJSON_CreateObject();
        if (!root) return WF_ERR_ALLOC;
        return set_json(response, root);
    }

    char *data_dir = strdup(entry->data_directory);
    char *handle = entry->handle ? strdup(entry->handle) : NULL;
    metalbear_account_entry_free(entry);
    if (!data_dir) {
        free(handle);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "could not copy data directory");
        return WF_OK;
    }

    /*
     * Announce the deletion before the registry row goes away.
     *
     * This used to resolve a context after the removal, which only succeeded
     * when the account happened to still be in the in-memory cache — for any
     * other account the registry lookup then failed and the #account event was
     * skipped entirely, so relays never learned the account was gone. Sequence
     * it against the host log directly, which needs no context at all.
     */
    metalbear_sequencer_account_status(server->sequencer, did->valuestring, 0,
                                       "deleted");
    /*
     * Then drop everything else this DID ever published. The data directory
     * is about to be removed, and leaving the same records on the firehose
     * would keep serving them to any consumer backfilling from an old cursor
     * — a deletion that removes the copy nobody reads and keeps the copy the
     * network does.
     */
    int64_t purged = 0;
    metalbear_sequencer_purge_account(server->sequencer, did->valuestring,
                                      &purged);
    metalbear_metrics_inc(METALBEAR_METRIC_ACCOUNTS_DELETED);
    LOG_INFO("admin_delete_account: purged %lld firehose events for did=%s",
             (long long)purged, did->valuestring);

    metalbear_account_registry_remove(server->registry, did->valuestring);
    /* Moderation state goes with it: a DID re-registered later must not
     * inherit the deleted account's takedowns. */
    metalbear_account_registry_clear_takedowns_for_did(server->registry,
                                                       did->valuestring);

    /* Drop the handle's TXT record: leaving it would keep pointing resolvers
     * at a DID this host no longer serves. */
    retract_handle_dns(server, handle);
    free(handle);

    rmtree(data_dir);
    free(data_dir);

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}
