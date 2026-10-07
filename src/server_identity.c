/* Identity documents and service auth: did:web, handle resolution, the TLS
 * check and getServiceAuth. */

#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "server_internal.h"

#include "admin/admin_routes.h"
#include "identity/identity_routes.h"
#include "oauth/oauth_credentials.h"
#include "session/session_routes.h"
#include "account/account_routes.h"
#include "account/preferences_routes.h"
#include "sync/sync_routes.h"
#ifdef METALBEAR_MODULE_APPVIEW
#include "appview/appview_routes.h"
#endif
#include "moderation/moderation_routes.h"
#ifdef METALBEAR_MODULE_VIDEO
#include "video/video_routes.h"
#endif
#include "ops/status.h"
#include "ops/ops_routes.h"
#include "repo/blob_store_server.h"

#include "metalbear/server.h"
#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/account/account_context.h"
#include "metalbear/account/account_cache.h"
#include "metalbear/oauth/auth.h"
#include "metalbear/repo/backup.h"
#ifdef METALBEAR_MODULE_EMAIL
#include "metalbear/email.h"
#endif
#ifdef METALBEAR_MODULE_DNS
#include "metalbear/dns/handle_dns.h"
#endif
#include "metalbear/repo/key_rotation.h"
#include "metalbear/oauth/oauth.h"
#include "metalbear/oauth/oauth_account_routes.h"
#include "metalbear/oauth/oauth_scope.h"
#include "metalbear/moderation/report.h"
#include "metalbear/oauth/oauth_routes.h"
#include "metalbear/sequencer.h"

#include "metalbear/repo/blob_store.h"
#ifdef METALBEAR_MODULE_UPDATE_WATCHER
#include "metalbear/ops/update_watcher.h"
#endif
#include "wolfram/crypto.h"
#include "wolfram/plc.h"
#include "metalbear/repo/repo_store.h"
#include "wolfram/repo/cid.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ftw.h>
#include <curl/curl.h>

/* Logging lives in log.c so the daemon shares it: see metalbear/log.h. */

/* ---- admin / refpds config (mirrors refpds PDS_* env) ---- */

/* struct metalbear_server is defined in server_internal.h, shared with the
 * route-handler modules this file delegates to (src/admin/, etc.). */

/*
 * Point `_atproto.<handle>` at `did`, if a provider is configured.
 *
 * Never fatal to the operation that triggered it. The account or the rename is
 * already durable by the time this runs, and an unresolvable handle is a
 * recoverable state: the record can be written by hand, and the next handle
 * change tries again. Failing the request instead would leave the caller
 * believing nothing happened when the account exists.
 */
void publish_handle_dns(metalbear_server *server, const char *handle,
                        const char *did) {
#ifdef METALBEAR_MODULE_DNS
    if (!server->handle_dns || !handle || !did) return;
    if (metalbear_handle_dns_publish(server->handle_dns, handle, did) !=
        WF_OK) {
        metalbear_metrics_inc(METALBEAR_METRIC_DNS_FAILURES);
        LOG_ERROR("dns: could not publish _atproto.%s for did=%s: %s; the "
                  "handle will not resolve until the record exists",
                  handle, did,
                  metalbear_handle_dns_last_error(server->handle_dns));
        return;
    }
    LOG_INFO("dns: published _atproto.%s -> %s", handle, did);
#else
    (void)server;
    (void)handle;
    (void)did;
#endif
}

/* Drop `_atproto.<handle>`, if a provider is configured. Same rule: a stale
 * record is a smaller problem than a failed deletion, so this only logs. */
void retract_handle_dns(metalbear_server *server, const char *handle) {
#ifdef METALBEAR_MODULE_DNS
    if (!server->handle_dns || !handle) return;
    if (metalbear_handle_dns_retract(server->handle_dns, handle) != WF_OK) {
        metalbear_metrics_inc(METALBEAR_METRIC_DNS_FAILURES);
        LOG_WARN("dns: could not remove _atproto.%s: %s; the record now points "
                 "at a handle this host no longer serves",
                 handle, metalbear_handle_dns_last_error(server->handle_dns));
        return;
    }
    LOG_INFO("dns: removed _atproto.%s", handle);
#else
    (void)server;
    (void)handle;
#endif
}

cJSON *build_did_doc(metalbear_server *server,
                     metalbear_account_context *acct) {
    const char *signing_didkey =
        acct->repo ? metalbear_repo_store_signing_key_did(acct->repo) : NULL;
    return metalbear_did_document_build(acct->did, acct->handle, signing_didkey,
                                        server->public_url);
}

static bool valid_service_audience(const char *audience) {
    if (!audience || strlen(audience) > 2048) return false;
    const char *fragment = strchr(audience, '#');
    if (!fragment) return wf_syntax_did_is_valid(audience);
    if (fragment == audience || !fragment[1] || strchr(fragment + 1, '#'))
        return false;
    size_t length = (size_t)(fragment - audience);
    char *did = malloc(length + 1);
    if (!did) return false;
    memcpy(did, audience, length);
    did[length] = '\0';
    bool valid = wf_syntax_did_is_valid(did);
    free(did);
    return valid;
}

static bool protected_service_method(const char *lxm) {
    static const char *const methods[] = {
        "com.atproto.admin.sendEmail",
        "com.atproto.identity.requestPlcOperationSignature",
        "com.atproto.identity.signPlcOperation",
        "com.atproto.identity.submitPlcOperation",
        "com.atproto.identity.updateHandle",
        "com.atproto.server.activateAccount",
        "com.atproto.server.confirmEmail",
        "com.atproto.server.createAppPassword",
        "com.atproto.server.deactivateAccount",
        "com.atproto.server.getAccountInviteCodes",
        "com.atproto.server.getSession",
        "com.atproto.server.listAppPasswords",
        "com.atproto.server.requestAccountDelete",
        "com.atproto.server.requestEmailConfirmation",
        "com.atproto.server.requestEmailUpdate",
        "com.atproto.server.revokeAppPassword",
        "com.atproto.server.updateEmail",
    };
    if (!lxm) return false;
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
        if (strcmp(lxm, methods[i]) == 0) return true;
    return false;
}

static bool privileged_service_method(const char *lxm) {
    return lxm && (strncmp(lxm, "chat.bsky.", 10) == 0 ||
                   strcmp(lxm, "com.atproto.server.createAccount") == 0);
}

wf_status metalbear_get_service_auth(void *ctx, const wf_xrpc_request *request,
                                     wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *aud = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "aud")
                     : NULL;
    cJSON *exp_item =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "exp")
            : NULL;
    cJSON *lxm_item =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "lxm")
            : NULL;
    const char *lxm = cJSON_IsString(lxm_item) ? lxm_item->valuestring : NULL;
    if (!cJSON_IsString(aud) || !valid_service_audience(aud->valuestring) ||
        (lxm_item &&
         (!cJSON_IsString(lxm_item) || !wf_syntax_nsid_is_valid(lxm))) ||
        protected_service_method(lxm)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Invalid service auth audience or method");
        return WF_OK;
    }
    metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    if (metalbear_auth_verify_access_scope(
            acct->auth, bearer_token(request->auth_header), &scope) != WF_OK) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    /*
     * A takendown-scoped session is let through the takendown gate for
     * getServiceAuth specifically so its holder can migrate away -- minting
     * a service-auth token to call createAccount on another PDS. It has no
     * business minting one for anything else, matching the reference's
     * explicit `isTakendown(scope) && lxm !== createAccount.lxm` refusal
     * (server/getServiceAuth.ts).
     */
    if (scope == METALBEAR_ACCESS_TAKENDOWN &&
        (!lxm || strcmp(lxm, "com.atproto.server.createAccount") != 0)) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Bad token scope");
        return WF_OK;
    }
    if (scope == METALBEAR_ACCESS_APP_PASSWORD &&
        privileged_service_method(lxm)) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidRequest",
            "Insufficient access for privileged service method");
        return WF_OK;
    }
    int64_t expiration = 0;
    if (exp_item) {
        long long parsed = 0;
        if (cJSON_IsString(exp_item)) {
            char *end = NULL;
            errno = 0;
            parsed = strtoll(exp_item->valuestring, &end, 10);
            if (errno || !end || *end) parsed = 0;
        } else if (cJSON_IsNumber(exp_item)) {
            parsed = (long long)exp_item->valuedouble;
        } else {
            wf_xrpc_response_set_error(response, 400, "BadExpiration",
                                       "Expiration must be a valid timestamp");
            return WF_OK;
        }
        int64_t now = (int64_t)time(NULL);
        if (parsed < now || parsed - now > 3600 ||
            (!lxm && parsed - now > 60)) {
            wf_xrpc_response_set_error(response, 400, "BadExpiration",
                                       "Expiration is outside allowed bounds");
            return WF_OK;
        }
        expiration = (int64_t)parsed;
    }
    char *token = NULL;
    if (metalbear_repo_store_create_service_auth(
            acct->repo, aud->valuestring, expiration, lxm, &token) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create service token");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(token);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "token", token);
    free(token);
    return set_json(response, root);
}

char *metalbear_public_url_from_service_did(const char *did) {
    static const char prefix[] = "did:web:";
    if (!did || strncmp(did, prefix, sizeof(prefix) - 1) != 0) return NULL;
    const char *source = did + sizeof(prefix) - 1;
    size_t capacity = strlen(source) + strlen("https://") + 1;
    char *url = malloc(capacity);
    if (!url) return NULL;
    char *output = url;
    memcpy(output, "https://", strlen("https://"));
    output += strlen("https://");
    while (*source) {
        if (source[0] == '%' && source[1] == '3' &&
            (source[2] == 'A' || source[2] == 'a')) {
            *output++ = ':';
            source += 3;
        } else {
            *output++ = *source == ':' ? '/' : *source;
            source++;
        }
    }
    *output = '\0';
    return url;
}

/* ---- /tls-check (public, mimics refpds on_demand_tls ask endpoint) ---- */
static wf_status tls_check_handler(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    cJSON *domain_item =
        req->params ? cJSON_GetObjectItemCaseSensitive(req->params, "domain")
                    : NULL;
    if (!cJSON_IsString(domain_item) || !domain_item->valuestring[0]) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "bad or missing domain query param");
        return WF_OK;
    }
    const char *domain = domain_item->valuestring;

    char service_hostname[256] = {0};
    /* sizeof("did:web:")-1 == 8; comparing/skipping 9 matches nothing real. */
    if (strncmp(server->service_did, "did:web:", sizeof("did:web:") - 1) == 0) {
        const char *host = server->service_did + sizeof("did:web:") - 1;
        size_t len = strlen(host);
        if (len < sizeof(service_hostname)) {
            memcpy(service_hostname, host, len);
            service_hostname[len] = '\0';
        }
    } else if (server->public_url) {
        const char *p = strstr(server->public_url, "://");
        if (p) {
            p += 3;
            const char *slash = strchr(p, '/');
            size_t len = slash ? (size_t)(slash - p) : strlen(p);
            if (len < sizeof(service_hostname)) {
                memcpy(service_hostname, p, len);
                service_hostname[len] = '\0';
            }
        }
    }

    if (service_hostname[0] && strcmp(domain, service_hostname) == 0) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(resp, root);
    }

    size_t domain_len = strlen(domain);
    size_t ud_len = server->user_domain ? strlen(server->user_domain) : 0;
    if (ud_len == 0 || domain_len <= ud_len ||
        strcmp(domain + domain_len - ud_len, server->user_domain) != 0) {
        wf_xrpc_response_set_error(resp, 400, "InvalidRequest",
                                   "handles are not provided on this domain");
        return WF_OK;
    }

    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_handle(server->registry, domain,
                                                  &entry) == WF_OK &&
        entry) {
        metalbear_account_entry_free(entry);
        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "success", true);
        return set_json(resp, root);
    }
    metalbear_account_entry_free(entry);

    wf_xrpc_response_set_error(resp, 404, "NotFound",
                               "handle not found for this domain");
    return WF_OK;
}

static char *extract_hostname(const char *host_header) {
    if (!host_header || !host_header[0]) return NULL;
    const char *colon = strchr(host_header, ':');
    size_t len = colon ? (size_t)(colon - host_header) : strlen(host_header);
    if (len == 0 || len > 253) return NULL;
    char *hostname = malloc(len + 1);
    if (!hostname) return NULL;
    memcpy(hostname, host_header, len);
    hostname[len] = '\0';
    return hostname;
}

static metalbear_account_entry *
resolve_hostname_to_account(metalbear_server *server, const char *hostname) {
    if (!server || !hostname || !hostname[0]) return NULL;
    metalbear_account_entry *entry = NULL;
    wf_status status = metalbear_account_registry_find_by_handle(
        server->registry, hostname, &entry);
    if (status == WF_OK && entry) return entry;
    metalbear_account_entry_free(entry);
    entry = NULL;
    size_t ud_len = server->user_domain ? strlen(server->user_domain) : 0;
    size_t dn_len = strlen(hostname);
    if (ud_len > 0 && dn_len > ud_len &&
        strcmp(hostname + dn_len - ud_len, server->user_domain) == 0) {
        status = metalbear_account_registry_find_by_handle(server->registry,
                                                           hostname, &entry);
    }
    if (status == WF_OK && entry) return entry;
    metalbear_account_entry_free(entry);
    /*
     * No fallback account. A hostname that matches no registered handle
     * resolves to nothing — falling back to a configured account answered
     * every unknown hostname with that account's identity, which is a wrong
     * answer rather than a missing one.
     */
    return NULL;
}

/* ---- /.well-known/atproto-did (query, dynamic per-hostname) ---- */
static wf_status handle_atproto_did(void *ctx, const wf_xrpc_request *request,
                                    wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    char *hostname = extract_hostname(request->host_header);
    if (!hostname) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "missing or invalid Host header");
        return WF_OK;
    }
    metalbear_account_entry *entry =
        resolve_hostname_to_account(server, hostname);
    free(hostname);
    if (!entry) {
        wf_xrpc_response_set_error(response, 404, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    wf_xrpc_response_set_body(response, entry->did, strlen(entry->did));
    wf_xrpc_response_set_content_type(response, "text/plain; charset=utf-8");
    metalbear_account_entry_free(entry);
    return WF_OK;
}

/* ---- /.well-known/did.json (query, dynamic per-hostname) ---- */
static wf_status handle_well_known_did(void *ctx,
                                       const wf_xrpc_request *request,
                                       wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    char *hostname = extract_hostname(request->host_header);
    if (!hostname) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "missing or invalid Host header");
        return WF_OK;
    }

    /* If the service DID is did:web and this hostname matches it, serve the
     * service's own DID document (the PDS identity, not an account). */
    if (server->service_did &&
        strncmp(server->service_did, "did:web:", 8) == 0) {
        const char *service_host = server->service_did + 8;
        bool service_host_matches;
        if (strstr(service_host, "%3A") || strstr(service_host, "%3a")) {
            /* A percent-encoded port (e.g. a local dev instance's
             * did:web:localhost%3A2583) is part of the identity: decode it
             * and compare against the raw Host header, which carries the
             * port as a literal colon -- `hostname` above has already had
             * it stripped and can't distinguish this case. */
            char decoded_service_host[256];
            size_t di = 0;
            for (const char *p = service_host;
                 *p && di + 1 < sizeof(decoded_service_host);) {
                if (p[0] == '%' && p[1] == '3' &&
                    (p[2] == 'A' || p[2] == 'a')) {
                    decoded_service_host[di++] = ':';
                    p += 3;
                } else {
                    decoded_service_host[di++] = *p++;
                }
            }
            decoded_service_host[di] = '\0';
            service_host_matches =
                request->host_header &&
                strcmp(request->host_header, decoded_service_host) == 0;
        } else {
            service_host_matches = strcmp(hostname, service_host) == 0;
        }
        if (service_host_matches) {
            free(hostname);
            cJSON *doc = cJSON_CreateObject();
            if (!doc) {
                wf_xrpc_response_set_error(response, 500, "InternalError",
                                           "Could not allocate DID document");
                return WF_OK;
            }
            cJSON *context = cJSON_CreateArray();
            cJSON_AddItemToArray(
                context, cJSON_CreateString("https://www.w3.org/ns/did/v1"));
            cJSON_AddItemToObject(doc, "@context", context);
            cJSON_AddStringToObject(doc, "id", server->service_did);
            cJSON *services = cJSON_CreateArray();
            cJSON *service = cJSON_CreateObject();
            cJSON_AddStringToObject(service, "id", "#atproto_pds");
            cJSON_AddStringToObject(service, "type",
                                    "AtprotoPersonalDataServer");
            cJSON_AddStringToObject(service, "serviceEndpoint",
                                    server->public_url ? server->public_url
                                                       : "");
            cJSON_AddItemToArray(services, service);
            cJSON_AddItemToObject(doc, "service", services);
            char *json = cJSON_PrintUnformatted(doc);
            cJSON_Delete(doc);
            if (!json) {
                wf_xrpc_response_set_error(response, 500, "InternalError",
                                           "Could not serialize DID document");
                return WF_OK;
            }
            wf_xrpc_response_set_body(response, json, strlen(json));
            wf_xrpc_response_set_content_type(response,
                                              "application/did+ld+json");
            free(json);
            return WF_OK;
        }
    }

    /* Otherwise, resolve the hostname to an account and serve its DID doc. */
    metalbear_account_entry *entry =
        resolve_hostname_to_account(server, hostname);
    free(hostname);
    if (!entry) {
        wf_xrpc_response_set_error(response, 404, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    metalbear_account_context *acct = context_for_did(server, entry->did);
    metalbear_account_entry_free(entry);
    if (!acct) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not open account context");
        return WF_OK;
    }
    cJSON *did_doc = build_did_doc(server, acct);
    if (!did_doc) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not build DID document");
        return WF_OK;
    }
    char *json = cJSON_PrintUnformatted(did_doc);
    cJSON_Delete(did_doc);
    if (!json) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not serialize DID document");
        return WF_OK;
    }
    wf_xrpc_response_set_body(response, json, strlen(json));
    wf_xrpc_response_set_content_type(response, "application/did+ld+json");
    free(json);
    return WF_OK;
}

/*
 * Serve the DID document for a path-form did:web account hosted here:
 *
 *   did:web:example.com:acct:alice  ->  GET /acct/alice/did.json
 *
 * The hostname form (did:web:alice.example.com) is already handled by
 * handle_well_known_did via the Host header, but it needs a wildcard DNS entry
 * and ingress route per account. The path form works over the PDS's single
 * existing hostname, which is what makes did:web accounts practical to
 * self-host.
 *
 * The document is built from the repo's own signing key, so it agrees with the
 * commits that repo signs by construction.
 */
static wf_status handle_account_did_web(void *ctx,
                                        const wf_xrpc_request *request,
                                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    const char *path = request->path ? request->path : "";
    static const char prefix[] = "/acct/";
    static const char suffix[] = "/did.json";
    size_t len = strlen(path);
    size_t plen = sizeof(prefix) - 1, slen = sizeof(suffix) - 1;
    if (len <= plen + slen || strncmp(path, prefix, plen) != 0 ||
        strcmp(path + len - slen, suffix) != 0) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No DID document at this path");
        return WF_OK;
    }
    size_t name_len = len - plen - slen;
    /* One path segment only: nested segments are a different DID. */
    if (name_len == 0 || memchr(path + plen, '/', name_len)) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No DID document at this path");
        return WF_OK;
    }

    const char *host =
        server->service_did && strncmp(server->service_did, "did:web:", 8) == 0
            ? server->service_did + 8
            : NULL;
    if (!host) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "Server does not host did:web accounts");
        return WF_OK;
    }

    char did[512];
    int n = snprintf(did, sizeof(did), "did:web:%s:acct:%.*s", host,
                     (int)name_len, path + plen);
    if (n < 0 || (size_t)n >= sizeof(did)) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No DID document at this path");
        return WF_OK;
    }

    metalbear_account_context *acct = context_for_did(server, did);
    if (!acct) {
        wf_xrpc_response_set_error(response, 404, "NotFound",
                                   "No such account");
        return WF_OK;
    }
    cJSON *doc = build_did_doc(server, acct);
    if (!doc) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not build DID document");
        return WF_OK;
    }
    char *json = cJSON_PrintUnformatted(doc);
    cJSON_Delete(doc);
    if (!json) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not serialize DID document");
        return WF_OK;
    }
    wf_xrpc_response_set_body(response, json, strlen(json));
    wf_xrpc_response_set_content_type(response, "application/did+ld+json");
    free(json);
    return WF_OK;
}

wf_status metalbear_register_identity_documents(metalbear_server *server) {
    if (!server->public_url)
        server->public_url =
            metalbear_public_url_from_service_did(server->service_did);
    if (!server->public_url) return WF_ERR_INVALID_ARG;
    wf_status status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/.well-known/did.json", handle_well_known_did,
        server);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_http_route(server->xrpc, "GET",
                                                "/.well-known/atproto-did",
                                                handle_atproto_did, server);
    if (status != WF_OK) return status;
    /* Path-form did:web accounts: /acct/<name>/did.json. */
    status = wf_xrpc_server_register_http_prefix(
        server->xrpc, "GET", "/acct/", handle_account_did_web, server);
    if (status != WF_OK) return status;
    status = metalbear_status_register(server);
    if (status != WF_OK) return status;
    static const char robots[] = "User-agent: *\nAllow: /\n";
    status = wf_xrpc_server_register_static_get(server->xrpc, "/robots.txt",
                                                "text/plain; charset=utf-8",
                                                robots, sizeof(robots) - 1);
    if (status != WF_OK) return status;

    status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/tls-check", tls_check_handler, server);
    if (status != WF_OK) return status;

    status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/operator.json", operator_info, server);
    return status;
}
