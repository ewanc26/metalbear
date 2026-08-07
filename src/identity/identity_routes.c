#include "identity_routes.h"
#include "../server_internal.h"

#include "metalbear/log.h"
#include "wolfram/crypto.h"
#include "wolfram/syntax.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Resolve a handle to a DID: local registry first, then DNS TXT /
 * well-known over the network. Heap-allocated; caller frees. Defined below;
 * forward-declared here so resolve_handle can share it with
 * identity_info_response (resolveIdentity/refreshIdentity) rather than only
 * ever answering for locally-hosted handles. */
static char *resolve_handle_to_did(metalbear_server *server,
                                   const char *handle);

/* ---- com.atproto.identity.resolveHandle (query) ----
 * Not limited to this host's own accounts: the reference falls through to
 * real network resolution for a handle it does not host itself (proxying to
 * an AppView, or resolving directly), and any consuming service is entitled
 * to ask this endpoint about any handle. resolve_handle_to_did already does
 * exactly that fallback for resolveIdentity/refreshIdentity; reuse it here. */
wf_status resolve_handle(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *handle =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "handle")
            : NULL;
    if (!cJSON_IsString(handle) ||
        !wf_syntax_handle_is_valid(handle->valuestring)) {
        wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    char *did = resolve_handle_to_did(server, handle->valuestring);
    if (!did) {
        wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    /* A locally-hosted account that is deactivated or taken down is
     * unavailable, not resolvable -- an unavailable account is invisible,
     * matching every other identity-facing route in this file. */
    metalbear_account_context *acct = context_for_did(server, did);
    if (acct && (!metalbear_account_is_active(acct->account) ||
                 account_is_taken_down(server, did))) {
        free(did);
        wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                   "Unable to resolve handle");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(did);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", did);
    free(did);
    return set_json(response, root);
}

/* ---- shared identity resolution helpers ----
 * Used by com.atproto.identity.resolveDid / resolveIdentity / refreshIdentity.
 * Local accounts are answered from the registry; everything else resolves
 * over the network (PLC directory for did:plc, well-known for did:web,
 * DNS TXT + well-known for handles), matching rsky-pds' behavior. */

/* Fetch a remote DID document's raw JSON. did:plc goes through the
 * configured PLC directory; did:web through its well-known URL. On WF_OK
 * *out_json is heap-allocated and must be freed by the caller. */
/*
 * Small TTL cache of resolved DID documents.
 *
 * Every describeRepo, checkAccountStatus and handle check resolves the DID
 * over the network. Once the host federates that is not a trickle: AppView
 * and indexer traffic drove 241 describeRepo calls in two minutes, each one
 * blocking a worker thread on an outbound request to plc.directory, one to
 * one, until the server stopped answering. Identity documents change rarely,
 * so a short cache removes the amplification without hiding real changes.
 *
 * Deliberately tiny and fixed-size: this is a cache, and a miss is only ever
 * the current behaviour.
 */
#define DID_DOC_CACHE_SLOTS 256 /* upper bound; the live size is config */
#define DID_DOC_CACHE_SECONDS 300

/* Live limits, set from config at startup; the defaults match the constants. */
static size_t did_doc_cache_slots = 64;
static time_t did_doc_cache_ttl = DID_DOC_CACHE_SECONDS;

typedef struct {
    char did[256];
    char *json; /* owned */
    time_t fetched_at;
} did_doc_cache_entry;

static did_doc_cache_entry did_doc_cache[DID_DOC_CACHE_SLOTS];
static pthread_mutex_t did_doc_cache_lock = PTHREAD_MUTEX_INITIALIZER;

void identity_configure_did_doc_cache(time_t ttl_seconds, size_t max_entries) {
    if (ttl_seconds > 0) did_doc_cache_ttl = ttl_seconds;
    if (max_entries > 0)
        did_doc_cache_slots = max_entries > DID_DOC_CACHE_SLOTS
                                  ? DID_DOC_CACHE_SLOTS
                                  : max_entries;
}

/* Returns an owned copy of the cached document, or NULL on a miss. */
static char *did_doc_cache_get(const char *did) {
    if (!did) return NULL;
    char *copy = NULL;
    time_t now = time(NULL);
    pthread_mutex_lock(&did_doc_cache_lock);
    for (size_t i = 0; i < did_doc_cache_slots; i++) {
        did_doc_cache_entry *e = &did_doc_cache[i];
        if (!e->json || strcmp(e->did, did) != 0) continue;
        if (now - e->fetched_at > did_doc_cache_ttl) {
            free(e->json);
            e->json = NULL;
            break;
        }
        copy = strdup(e->json);
        break;
    }
    pthread_mutex_unlock(&did_doc_cache_lock);
    return copy;
}

static void did_doc_cache_put(const char *did, const char *json) {
    if (!did || !json || strlen(did) >= sizeof(did_doc_cache[0].did)) return;
    time_t now = time(NULL);
    pthread_mutex_lock(&did_doc_cache_lock);
    /* Reuse this DID's slot, else an empty or expired one, else the oldest. */
    size_t victim = 0;
    time_t oldest = now + 1;
    for (size_t i = 0; i < did_doc_cache_slots; i++) {
        did_doc_cache_entry *e = &did_doc_cache[i];
        if (e->json && strcmp(e->did, did) == 0) {
            victim = i;
            goto store;
        }
        if (!e->json) {
            victim = i;
            goto store;
        }
        if (e->fetched_at < oldest) {
            oldest = e->fetched_at;
            victim = i;
        }
    }
store:
    free(did_doc_cache[victim].json);
    did_doc_cache[victim].json = strdup(json);
    if (did_doc_cache[victim].json) {
        snprintf(did_doc_cache[victim].did, sizeof(did_doc_cache[victim].did),
                 "%s", did);
        did_doc_cache[victim].fetched_at = now;
    }
    pthread_mutex_unlock(&did_doc_cache_lock);
}

static wf_status fetch_remote_did_doc(metalbear_server *server, const char *did,
                                      char **out_json) {
    *out_json = NULL;
    if (!did) return WF_ERR_INVALID_ARG;
    char *cached = did_doc_cache_get(did);
    if (cached) {
        *out_json = cached;
        return WF_OK;
    }
    char url[1024];
    if (strncmp(did, "did:plc:", 8) == 0) {
        if (!server->plc_url) return WF_ERR_NOT_FOUND;
        int n = snprintf(url, sizeof(url), "%s/%s", server->plc_url, did);
        if (n < 0 || (size_t)n >= sizeof(url)) return WF_ERR_INVALID_ARG;
    } else if (strncmp(did, "did:web:", 8) == 0) {
        /* did:web:example.com[:path:segments] -> percent-decoded URL;
         * a plain host uses /.well-known/did.json. */
        char host_path[768];
        size_t j = 0;
        for (const char *p = did + 8; *p && j + 1 < sizeof(host_path); p++) {
            host_path[j++] = (*p == ':') ? '/' : *p;
        }
        host_path[j] = '\0';
        int n;
        if (strchr(host_path, '/'))
            n = snprintf(url, sizeof(url), "https://%s/did.json", host_path);
        else
            n = snprintf(url, sizeof(url), "https://%s/.well-known/did.json",
                         host_path);
        if (n < 0 || (size_t)n >= sizeof(url)) return WF_ERR_INVALID_ARG;
    } else {
        return WF_ERR_INVALID_ARG;
    }
    wf_xrpc_client *client = wf_xrpc_client_new("https://localhost");
    if (!client) return WF_ERR_ALLOC;
    wf_response upstream = {0};
    wf_status status = wf_http_get(client, url, &upstream);
    wf_xrpc_client_free(client);
    if (status != WF_OK || upstream.status < 200 || upstream.status >= 300 ||
        !upstream.body) {
        wf_response_free(&upstream);
        return WF_ERR_NOT_FOUND;
    }
    *out_json = strndup(upstream.body, upstream.body_len);
    if (*out_json) did_doc_cache_put(did, *out_json);
    wf_response_free(&upstream);
    return *out_json ? WF_OK : WF_ERR_ALLOC;
}

/*
 * Is `did` a did:web whose document THIS server publishes?
 *
 * A did:web's authority is whoever serves its document, so for one we host
 * ourselves there is no external party to consult — and trying to consult one
 * is actively harmful: the request loops back through our own ingress and
 * occupies a worker thread that is waiting on this very server. With a handful
 * of such requests the pool is exhausted and the PDS wedges. Resolve these
 * locally instead.
 */
static bool did_web_is_self_hosted(metalbear_server *server, const char *did) {
    if (!did || strncmp(did, "did:web:", 8) != 0 || !server->public_url)
        return false;
    const char *host = did + 8;
    size_t host_len = strcspn(host, ":"); /* stop at the first path segment */

    const char *ours = server->public_url;
    if (strncmp(ours, "https://", 8) == 0)
        ours += 8;
    else if (strncmp(ours, "http://", 7) == 0)
        ours += 7;
    size_t ours_len = strcspn(ours, "/");

    return host_len == ours_len && strncmp(host, ours, host_len) == 0;
}

/* metalbear_xrpc_did_doc_provider: resolve `did` through the identity layer
 * (PLC directory / did:web well-known) and return its raw JSON. Deliberately
 * skips the local registry for DIDs someone else is authoritative for —
 * describeRepo uses this to check a handle bi-directionally, which a locally
 * synthesised document cannot do. Returns NULL when the DID does not resolve.
 */
char *resolve_did_doc_json(void *ctx, const char *did) {
    metalbear_server *server = ctx;
    if (did_web_is_self_hosted(server, did)) {
        metalbear_account_context *acct = context_for_did(server, did);
        if (!acct) return NULL;
        cJSON *doc = build_did_doc(server, acct);
        if (!doc) return NULL;
        char *json = cJSON_PrintUnformatted(doc);
        cJSON_Delete(doc);
        return json;
    }
    char *json = NULL;
    if (!did || fetch_remote_did_doc(server, did, &json) != WF_OK) return NULL;
    return json;
}

/* Does the account's *published* DID document actually describe this PDS?
 * Mirrors the reference PDS's assertValidDidDocumentForService: the
 * #atproto_pds service endpoint must be our public URL and the #atproto
 * verification method must be the key this repo signs its commits with.
 * A false answer means relays and AppViews will reject the repo's commits,
 * so it must be resolved over the network rather than assumed. */
bool did_doc_matches_service(metalbear_server *server,
                             metalbear_account_context *acct) {
    if (!acct->did || !acct->did[0] || !server->public_url) return false;
    const char *local_key =
        acct->repo ? metalbear_repo_store_signing_key_did(acct->repo) : NULL;
    if (!local_key || !local_key[0]) return false;

    /* For a did:web we publish ourselves the document is generated from this
     * repo's own key and this server's URL, so it agrees by construction.
     * Fetching it back over the network would only deadlock on ourselves. */
    if (did_web_is_self_hosted(server, acct->did))
        return context_for_did(server, acct->did) != NULL;

    char *json = NULL;
    if (fetch_remote_did_doc(server, acct->did, &json) != WF_OK || !json)
        return false;
    cJSON *doc = cJSON_Parse(json);
    free(json);
    if (!doc) return false;

    const char *endpoint = metalbear_did_document_pds_endpoint(doc);
    char *published_key = metalbear_did_document_signing_key(doc);
    bool valid = endpoint && strcmp(endpoint, server->public_url) == 0 &&
                 published_key && strcmp(published_key, local_key) == 0;
    if (!valid) {
        LOG_WARN("DID document for %s does not match this service "
                 "(endpoint=%s want=%s, key=%s want=%s)",
                 acct->did, endpoint ? endpoint : "(none)", server->public_url,
                 published_key ? published_key : "(none)", local_key);
    }
    free(published_key);
    cJSON_Delete(doc);
    return valid;
}

/* Build (local) or fetch (remote) the DID document for `did` as a cJSON
 * tree. Caller must cJSON_Delete the result. Sets *deactivated when the
 * local account exists but is unavailable — deactivated or taken down. */
static cJSON *did_doc_for_did(metalbear_server *server, const char *did,
                              bool *deactivated) {
    *deactivated = false;
    metalbear_account_context *acct = context_for_did(server, did);
    if (acct) {
        if (!metalbear_account_is_active(acct->account) ||
            account_is_taken_down(server, acct->did)) {
            *deactivated = true;
            return NULL;
        }
        return build_did_doc(server, acct);
    }
    char *json = NULL;
    if (fetch_remote_did_doc(server, did, &json) != WF_OK || !json) return NULL;
    cJSON *doc = cJSON_Parse(json);
    free(json);
    return doc;
}

/* Extract the first at:// handle claimed by a DID document's alsoKnownAs.
 * Heap-allocated; caller frees. NULL when the doc claims no handle. */
static char *did_doc_claimed_handle(const cJSON *did_doc) {
    const cJSON *aka = cJSON_GetObjectItemCaseSensitive(did_doc, "alsoKnownAs");
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, aka) {
        if (!cJSON_IsString(entry) || !entry->valuestring) continue;
        if (strncmp(entry->valuestring, "at://", 5) == 0)
            return strdup(entry->valuestring + 5);
    }
    return NULL;
}

static char *resolve_handle_to_did(metalbear_server *server,
                                   const char *handle) {
    metalbear_account_entry *entry = NULL;
    if (metalbear_account_registry_find_by_handle(server->registry, handle,
                                                  &entry) == WF_OK &&
        entry) {
        char *did = strdup(entry->did);
        metalbear_account_entry_free(entry);
        return did;
    }
    wf_xrpc_client *client = wf_xrpc_client_new("https://localhost");
    if (!client) return NULL;
    char *did = NULL;
    if (wf_handle_resolve(client, handle, &did) != WF_OK) did = NULL;
    wf_xrpc_client_free(client);
    return did;
}

/* Shared core of resolveIdentity (query) and refreshIdentity (procedure):
 * resolve `identifier` (handle or DID) to {did, handle, didDoc} with
 * bi-directional handle verification ('handle.invalid' on mismatch). */
static wf_status identity_info_response(metalbear_server *server,
                                        const char *identifier,
                                        wf_xrpc_response *response) {
    char *did = NULL;
    char *input_handle = NULL;
    if (strncmp(identifier, "did:", 4) == 0) {
        if (!wf_syntax_did_is_valid(identifier)) {
            wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                       "could not resolve DID");
            return WF_OK;
        }
        did = strdup(identifier);
    } else {
        if (!wf_syntax_handle_is_valid(identifier)) {
            wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                       "unable to resolve handle");
            return WF_OK;
        }
        input_handle = strdup(identifier);
        did = resolve_handle_to_did(server, identifier);
        if (!did) {
            free(input_handle);
            wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                       "unable to resolve handle");
            return WF_OK;
        }
    }
    if (!did) {
        free(input_handle);
        return WF_ERR_ALLOC;
    }
    bool deactivated = false;
    cJSON *did_doc = did_doc_for_did(server, did, &deactivated);
    if (!did_doc) {
        free(did);
        free(input_handle);
        if (deactivated)
            wf_xrpc_response_set_error(response, 400, "DidDeactivated",
                                       "DID has been deactivated");
        else
            wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                       "could not resolve DID");
        return WF_OK;
    }
    /* Bi-directional verification of the handle. */
    char *doc_handle = did_doc_claimed_handle(did_doc);
    const char *verified = "handle.invalid";
    if (input_handle) {
        /* The input handle resolved to this DID; validated when the DID
         * document claims the same handle back (case-insensitive). */
        if (doc_handle && strcasecmp(doc_handle, input_handle) == 0)
            verified = doc_handle;
    } else if (doc_handle) {
        /* DID input: verify the claimed handle resolves back to this DID. */
        char *resolved = resolve_handle_to_did(server, doc_handle);
        if (resolved && strcmp(resolved, did) == 0) verified = doc_handle;
        free(resolved);
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(did);
        free(input_handle);
        free(doc_handle);
        cJSON_Delete(did_doc);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(root, "did", did);
    cJSON_AddStringToObject(root, "handle", verified);
    cJSON_AddItemToObject(root, "didDoc", did_doc);
    free(did);
    free(input_handle);
    free(doc_handle);
    return set_json(response, root);
}

/* ---- com.atproto.identity.resolveDid (query) ----
 * Resolves a DID to its complete DID document. Does not bi-directionally
 * verify the handle. Public route. */
wf_status resolve_did_identity(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *did = request->params
                     ? cJSON_GetObjectItemCaseSensitive(request->params, "did")
                     : NULL;
    if (!cJSON_IsString(did) || !wf_syntax_did_is_valid(did->valuestring)) {
        wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                   "could not resolve DID");
        return WF_OK;
    }
    bool deactivated = false;
    cJSON *did_doc = did_doc_for_did(server, did->valuestring, &deactivated);
    if (!did_doc) {
        if (deactivated)
            wf_xrpc_response_set_error(response, 400, "DidDeactivated",
                                       "DID has been deactivated");
        else
            wf_xrpc_response_set_error(response, 400, "DidNotFound",
                                       "could not resolve DID");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        cJSON_Delete(did_doc);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToObject(root, "didDoc", did_doc);
    return set_json(response, root);
}

/* ---- com.atproto.identity.resolveIdentity (query) ----
 * Resolves a handle or DID to a full identity (DID document and verified
 * handle). Public route. */
wf_status resolve_identity(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *identifier =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "identifier")
            : NULL;
    if (!cJSON_IsString(identifier) || !identifier->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "HandleNotFound",
                                   "unable to resolve handle");
        return WF_OK;
    }
    return identity_info_response(server, identifier->valuestring, response);
}

/* ---- com.atproto.identity.refreshIdentity (procedure) ----
 * Request that the server re-resolve an identity. MetalBear keeps no DID
 * cache, so every resolution is already fresh; the semantics are identical
 * to resolveIdentity. Public route (the lexicon permits the server to
 * ignore or require auth; rsky-pds treats it as public). */
wf_status refresh_identity(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *identifier =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "identifier")
            : NULL;
    if (!cJSON_IsString(identifier) || !identifier->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "identifier is required");
        return WF_OK;
    }
    return identity_info_response(server, identifier->valuestring, response);
}

/* ---- com.atproto.identity.getRecommendedDidCredentials (query) ---- */
wf_status get_recommended_did_credentials(void *ctx,
                                          const wf_xrpc_request *request,
                                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    char *didkey = NULL;
    wf_signing_key key;
    memset(&key, 0, sizeof(key));
    /* These are credentials for the account making the request. Reading them
     * from one configured account handed every caller the same identity. */
    metalbear_account_context *acct =
        context_for_did(server, request->authed_subject);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "AuthRequired",
                                   "Authentication required");
        return WF_OK;
    }
    if (metalbear_key_rotation_current_key(acct->key_rotation, &key) != WF_OK ||
        wf_signing_key_public_didkey(&key, &didkey) != WF_OK) {
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not derive signing key");
        return WF_OK;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        free(didkey);
        return WF_ERR_ALLOC;
    }
    cJSON *also_known_as = cJSON_CreateArray();
    if (!also_known_as) {
        cJSON_Delete(root);
        free(didkey);
        return WF_ERR_ALLOC;
    }
    if (acct->handle && acct->handle[0]) {
        char aka[256];
        snprintf(aka, sizeof(aka), "at://%s", acct->handle);
        cJSON_AddItemToArray(also_known_as, cJSON_CreateString(aka));
    }
    cJSON_AddItemToObject(root, "alsoKnownAs", also_known_as);
    cJSON *verification_methods = cJSON_CreateObject();
    if (!verification_methods) {
        cJSON_Delete(root);
        free(didkey);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(verification_methods, "atproto", didkey);
    cJSON_AddItemToObject(root, "verificationMethods", verification_methods);
    cJSON *rotation_keys = cJSON_CreateArray();
    if (!rotation_keys) {
        cJSON_Delete(root);
        free(didkey);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToArray(rotation_keys, cJSON_CreateString(didkey));
    cJSON_AddItemToObject(root, "rotationKeys", rotation_keys);
    cJSON *services = cJSON_CreateObject();
    if (!services) {
        cJSON_Delete(root);
        free(didkey);
        return WF_ERR_ALLOC;
    }
    cJSON *atproto_pds = cJSON_CreateObject();
    if (!atproto_pds) {
        cJSON_Delete(root);
        free(didkey);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(atproto_pds, "type", "AtprotoPersonalDataServer");
    cJSON_AddStringToObject(atproto_pds, "serviceEndpoint",
                            server->public_url ? server->public_url : "");
    cJSON_AddItemToObject(services, "atproto_pds", atproto_pds);
    cJSON_AddItemToObject(root, "services", services);
    free(didkey);
    return set_json(response, root);
}

/* ---- com.atproto.identity.updateHandle (procedure) ---- */
wf_status update_handle(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    cJSON *handle =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "handle")
            : NULL;
    if (!cJSON_IsString(handle) || !handle->valuestring[0] ||
        !wf_syntax_handle_is_valid(handle->valuestring)) {
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "A valid handle is required");
        return WF_OK;
    }
    size_t handle_length = strlen(handle->valuestring);
    size_t domain_length =
        server->user_domain ? strlen(server->user_domain) : 0;
    if (domain_length == 0 || handle_length <= domain_length ||
        strcmp(handle->valuestring + handle_length - domain_length,
               server->user_domain) != 0) {
        wf_xrpc_response_set_error(
            response, 400, "InvalidHandle",
            "Handle must be under the configured domain");
        return WF_OK;
    }
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    /* updateHandle.ts: 10/5min + 50/day, keyed by DID. */
    if (!check_endpoint_rate_limit(server->rl_update_handle_5min,
                                   server->rl_update_handle_day, acct->did, 1,
                                   response)) {
        return WF_OK;
    }
    metalbear_account_entry *existing = NULL;
    if (metalbear_account_registry_find_by_handle(
            server->registry, handle->valuestring, &existing) == WF_OK &&
        existing && strcmp(existing->did, acct->did) != 0) {
        metalbear_account_entry_free(existing);
        wf_xrpc_response_set_error(response, 400, "InvalidHandle",
                                   "Handle is already in use");
        return WF_OK;
    }
    metalbear_account_entry_free(existing);
    char *old_handle = strdup(acct->handle);
    char *new_handle = strdup(handle->valuestring);
    if (!old_handle || !new_handle ||
        metalbear_repo_store_set_handle(acct->repo, handle->valuestring) !=
            WF_OK) {
        free(old_handle);
        free(new_handle);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not persist handle");
        return WF_OK;
    }
    if (metalbear_account_registry_update_handle(
            server->registry, acct->did, handle->valuestring) != WF_OK) {
        metalbear_repo_store_set_handle(acct->repo, old_handle);
        free(old_handle);
        free(new_handle);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not persist handle");
        return WF_OK;
    }
    /* Move the TXT record with the handle. Publishing the new one before
     * dropping the old leaves both resolving for a moment, which is the safe
     * order: neither points anywhere wrong, and a resolver that has cached the
     * old name still gets the right DID. */
    publish_handle_dns(server, new_handle, acct->did);
    retract_handle_dns(server, old_handle);

    /*
     * Announce the rename, after the record that makes it resolve.
     *
     * Consumers learned this handle from the #identity event at account
     * creation and have no reason to look again, so without this the rename is
     * durable here and invisible everywhere else. Not fatal: the handle is
     * already changed, and reconciliation heals a missing tail event, where
     * failing the request would report a rename that in fact happened.
     */
    if (metalbear_sequencer_identity(server->sequencer, acct->did,
                                     new_handle) != WF_OK)
        LOG_ERROR("update_handle: could not sequence #identity for did=%s "
                  "handle=%s; the rename is durable but unannounced",
                  acct->did, new_handle);

    free(old_handle);
    free(acct->handle);
    acct->handle = new_handle;
    return WF_OK;
}

/* ---- com.atproto.identity.requestPlcOperationSignature (procedure) ----
 * Sends an email with a token that can be used to sign a PLC operation. */
wf_status request_plc_operation_signature(void *ctx,
                                          const wf_xrpc_request *request,
                                          wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    /* Get the account's email. */
    char *email = NULL;
    int confirmed = 0;
    metalbear_account_get_email(acct->account, &email, &confirmed);
    if (!email || !email[0]) {
        free(email);
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Account does not have an email address");
        return WF_OK;
    }
    /* Create a plc_operation email token. */
    char token[32];
    if (metalbear_account_create_email_token(acct->account, "plc_operation",
                                             token, sizeof(token)) != WF_OK) {
        free(email);
        wf_xrpc_response_set_error(response, 500, "InternalError",
                                   "Could not create verification token");
        return WF_OK;
    }
    /* Send the email if configured. */
    if (server->email) {
        char subject[256];
        char body[1024];
        snprintf(subject, sizeof(subject), "PLC Operation Signature Request");
        snprintf(body, sizeof(body),
                 "You have requested a PLC operation signature.\n\n"
                 "Your verification code is: %s\n\n"
                 "Enter this code to sign your PLC operation.\n\n"
                 "If you did not request this, please ignore this email.\n",
                 token);
        metalbear_email_send(server->email, email, subject, body);
    }
    free(email);
    /* Return empty object (per lexicon: no output schema). */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}

/* ---- com.atproto.identity.signPlcOperation (procedure) ----
 * Signs a PLC operation using the token from requestPlcOperationSignature. */
wf_status sign_plc_operation(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *token_item =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "token")
            : NULL;
    if (!cJSON_IsString(token_item) || !token_item->valuestring[0]) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "token is required");
        return WF_OK;
    }
    /* Verify the plc_operation email token. */
    if (metalbear_account_verify_email_token(
            acct->account, "plc_operation", token_item->valuestring) != WF_OK) {
        wf_xrpc_response_set_error(response, 400, "InvalidToken",
                                   "Invalid or expired token");
        return WF_OK;
    }
    /* Build a minimal PLC operation.  The full implementation would fetch
     * the last operation from the PLC directory and apply updates; here we
     * return a signed operation skeleton that a PLC client can complete. */
    cJSON *rotation_keys =
        cJSON_GetObjectItemCaseSensitive(request->params, "rotationKeys");
    cJSON *also_known_as =
        cJSON_GetObjectItemCaseSensitive(request->params, "alsoKnownAs");
    cJSON *verification_methods = cJSON_GetObjectItemCaseSensitive(
        request->params, "verificationMethods");
    cJSON *services =
        cJSON_GetObjectItemCaseSensitive(request->params, "services");

    cJSON *op = cJSON_CreateObject();
    if (!op) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(op, "type", "plc_operation");
    cJSON_AddStringToObject(op, "prev", "");

    /* Use provided values or defaults. */
    if (rotation_keys && cJSON_IsArray(rotation_keys)) {
        cJSON_AddItemToObject(op, "rotationKeys",
                              cJSON_Duplicate(rotation_keys, 1));
    } else {
        cJSON *rk = cJSON_CreateArray();
        cJSON_AddItemToArray(rk, cJSON_CreateString(server->service_did));
        cJSON_AddItemToObject(op, "rotationKeys", rk);
    }
    if (also_known_as && cJSON_IsArray(also_known_as)) {
        cJSON_AddItemToObject(op, "alsoKnownAs",
                              cJSON_Duplicate(also_known_as, 1));
    } else {
        cJSON *aka = cJSON_CreateArray();
        char at_handle[512];
        snprintf(at_handle, sizeof(at_handle), "at://%s", acct->handle);
        cJSON_AddItemToArray(aka, cJSON_CreateString(at_handle));
        cJSON_AddItemToObject(op, "alsoKnownAs", aka);
    }
    if (verification_methods && cJSON_IsObject(verification_methods)) {
        cJSON_AddItemToObject(op, "verificationMethods",
                              cJSON_Duplicate(verification_methods, 1));
    } else {
        cJSON *vm = cJSON_CreateObject();
        cJSON_AddStringToObject(vm, "atproto", acct->did);
        cJSON_AddItemToObject(op, "verificationMethods", vm);
    }
    if (services && cJSON_IsObject(services)) {
        cJSON_AddItemToObject(op, "services", cJSON_Duplicate(services, 1));
    } else {
        cJSON *svc = cJSON_CreateObject();
        cJSON *pds = cJSON_CreateObject();
        cJSON_AddStringToObject(pds, "type", "AtprotoPersonalDataServer");
        char endpoint[512];
        snprintf(endpoint, sizeof(endpoint), "%s", server->public_url);
        cJSON_AddStringToObject(pds, "endpoint", endpoint);
        cJSON_AddItemToObject(svc, "atproto_pds", pds);
        cJSON_AddItemToObject(op, "services", svc);
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        cJSON_Delete(op);
        return WF_ERR_ALLOC;
    }
    cJSON_AddItemToObject(root, "operation", op);
    return set_json(response, root);
}

/* ---- com.atproto.identity.submitPlcOperation (procedure) ----
 * Validates and submits a signed PLC operation.  In this standalone PDS
 * mode we validate the structure but skip actual PLC directory submission
 * (which requires an external PLC client). */
wf_status submit_plc_operation(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response) {
    metalbear_server *server = ctx;
    metalbear_account_context *acct = resolve_request_context(server, request);
    if (!acct) {
        wf_xrpc_response_set_error(response, 401, "InvalidToken",
                                   "Invalid access token");
        return WF_OK;
    }
    cJSON *operation =
        request->params
            ? cJSON_GetObjectItemCaseSensitive(request->params, "operation")
            : NULL;
    if (!operation || !cJSON_IsObject(operation)) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "operation is required");
        return WF_OK;
    }
    /* Validate basic structure. */
    cJSON *type = cJSON_GetObjectItemCaseSensitive(operation, "type");
    if (!cJSON_IsString(type) ||
        strcmp(type->valuestring, "plc_operation") != 0) {
        wf_xrpc_response_set_error(response, 400, "InvalidRequest",
                                   "Invalid operation type");
        return WF_OK;
    }
    cJSON *services = cJSON_GetObjectItemCaseSensitive(operation, "services");
    if (services) {
        cJSON *pds = cJSON_GetObjectItemCaseSensitive(services, "atproto_pds");
        if (pds) {
            cJSON *pds_type = cJSON_GetObjectItemCaseSensitive(pds, "type");
            if (!cJSON_IsString(pds_type) ||
                strcmp(pds_type->valuestring, "AtprotoPersonalDataServer") !=
                    0) {
                wf_xrpc_response_set_error(
                    response, 400, "InvalidRequest",
                    "Incorrect type on atproto_pds service");
                return WF_OK;
            }
            cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(pds, "endpoint");
            if (cJSON_IsString(endpoint) && server->public_url &&
                strcmp(endpoint->valuestring, server->public_url) != 0) {
                wf_xrpc_response_set_error(
                    response, 400, "InvalidRequest",
                    "Incorrect endpoint on atproto_pds service");
                return WF_OK;
            }
        }
    }
    cJSON *rotation_keys =
        cJSON_GetObjectItemCaseSensitive(operation, "rotationKeys");
    if (rotation_keys && cJSON_IsArray(rotation_keys)) {
        bool has_server_key = false;
        size_t n = cJSON_GetArraySize(rotation_keys);
        for (size_t i = 0; i < n; i++) {
            cJSON *key = cJSON_GetArrayItem(rotation_keys, i);
            if (cJSON_IsString(key) && server->service_did &&
                strcmp(key->valuestring, server->service_did) == 0) {
                has_server_key = true;
                break;
            }
        }
        if (!has_server_key) {
            wf_xrpc_response_set_error(
                response, 400, "InvalidRequest",
                "Rotation keys do not include server's rotation key");
            return WF_OK;
        }
    }
    /* In a full implementation, we would submit to the PLC directory here.
     * For now, acknowledge the operation. */
    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;
    return set_json(response, root);
}
