/* Where an AppView proxy request goes: the configured AppView, or the service
 * an `atproto-proxy` header names, found through its did:web document. */

#include "appview_resolve.h"
#include "appview_proxy_http.h"

#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "wolfram/identity.h"

#include <cJSON.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Service ids that have been renamed on the network. The AppView's did:web
 * document now names `#bsky_appview` where legacy proxies named the same
 * service `#atproto_bsky_app` (and chat `#atproto_bsky_chat` vs `#bsky_chat`).
 * Accept both so an `atproto-proxy` header written for either era resolves. */
static const char *service_id_alias(const char *id) {
    if (!id) return NULL;
    static const struct {
        const char *a;
        const char *b;
    } aliases[] = {
        {"atproto_bsky_app", "bsky_appview"},
        {"atproto_bsky_chat", "bsky_chat"},
    };
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++) {
        if (strcmp(id, aliases[i].a) == 0) return aliases[i].b;
        if (strcmp(id, aliases[i].b) == 0) return aliases[i].a;
    }
    return NULL;
}

/* Service ids accepted as `atproto-proxy` destinations (issue #251). The
 * protocol guide names `bsky_chat` and `atproto_labeler`; the two AppView ids
 * stay accepted so clients proxying app.bsky traffic through their own AppView
 * keep working. A bare DID with no fragment is treated as "default service". */
static bool proxy_service_id_known(const char *id) {
    static const char *known[] = {
        "bsky_chat",    "atproto_bsky_chat", "atproto_labeler",
        "bsky_appview", "atproto_bsky_app",
    };
    if (!id || !id[0]) return true;
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++)
        if (strcmp(id, known[i]) == 0) return true;
    return false;
}

static bool is_chat_service_id(const char *id) {
    return id && (strcmp(id, "bsky_chat") == 0 ||
                  strcmp(id, "atproto_bsky_chat") == 0);
}

static bool is_labeler_service_id(const char *id) {
    return id && strcmp(id, "atproto_labeler") == 0;
}

/* Strip an optional `#fragment` from a configured DID (the mod-service DID
 * may be written either way) into `buf`. NULL when it is unusable. */
static const char *did_without_fragment(const char *id, char *buf, size_t cap) {
    if (!id || !id[0]) return NULL;
    const char *hash = strchr(id, '#');
    size_t len = hash ? (size_t)(hash - id) : strlen(id);
    if (len == 0 || len >= cap) return NULL;
    memcpy(buf, id, len);
    buf[len] = '\0';
    return buf;
}

/* Does one comma-separated item of `appview.proxy_destinations` allow this
 * destination? A bare DID allows any known service id; `<did>#<service>`
 * narrows it to that service (including a custom id an operator names). */
static bool proxy_allowlist_entry_allows(const char *entry, size_t len,
                                         const char *did, const char *svc_id) {
    while (len && (entry[0] == ' ' || entry[0] == '\t')) {
        entry++;
        len--;
    }
    while (len && (entry[len - 1] == ' ' || entry[len - 1] == '\t' ||
                   entry[len - 1] == '\r' || entry[len - 1] == '\n'))
        len--;
    if (len == 0) return false;

    size_t hash = len;
    for (size_t i = 0; i < len; i++)
        if (entry[i] == '#') hash = i;
    if (strlen(did) != hash || strncmp(did, entry, hash) != 0) return false;

    if (hash == len) return proxy_service_id_known(svc_id);
    const char *entry_svc = entry + hash + 1;
    size_t svc_len = len - hash - 1;
    if (!svc_id || strlen(svc_id) != svc_len ||
        strncmp(svc_id, entry_svc, svc_len) != 0) {
        const char *alias = service_id_alias(svc_id);
        if (!alias || strlen(alias) != svc_len ||
            strncmp(alias, entry_svc, svc_len) != 0)
            return false;
    }
    return true;
}

/* Is this destination one this PDS is willing to forward to (issue #251)?
 * The default set is the well-known Bluesky chat and labeler, the configured
 * AppView and the configured moderator service; `appview.proxy_destinations`
 * adds operator-supplied DIDs. Everything else is an open-relay risk and is
 * refused before any upstream request is made. */
static bool proxy_destination_allowed(const metalbear_server *server,
                                      const char *did, const char *svc_id) {
    if (server->appview_did && strcmp(did, server->appview_did) == 0)
        return proxy_service_id_known(svc_id);
    if (strcmp(did, "did:web:api.bsky.chat") == 0 && is_chat_service_id(svc_id))
        return true;
    if (strcmp(did, "did:plc:ar7c4by46qjdydhdevvrndac") == 0 &&
        is_labeler_service_id(svc_id))
        return true;
    if (server->mod_service_did && server->mod_service_did[0]) {
        char bare[256];
        if (did_without_fragment(server->mod_service_did, bare, sizeof(bare)) &&
            strcmp(did, bare) == 0 && is_labeler_service_id(svc_id))
            return true;
    }

    const char *list = server->proxy_destinations;
    if (list && list[0]) {
        const char *p = list;
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t len = comma ? (size_t)(comma - p) : strlen(p);
            if (proxy_allowlist_entry_allows(p, len, did, svc_id)) return true;
            p = comma ? comma + 1 : p + len;
        }
    }
    return false;
}

static char *resolve_did_web_service(const char *did, const char *service_id) {
    /* "did:web:" is 8 characters; comparing 9 also compares the literal's NUL,
     * which only matches the bare prefix, and skipping 9 eats the first
     * character of the host. Together they made this return NULL for every
     * real did:web, so `atproto-proxy` never resolved anywhere. */
    static const size_t prefix_len = sizeof("did:web:") - 1;
    const char *hash;
    char *host = NULL;
    size_t host_len;
    char url[512];
    int n;
    if (strncmp(did, "did:web:", prefix_len) != 0) return NULL;

    /* The header arrives as "<did:web:host>#<service_id>"; the fragment must
     * not become part of the host when building the well-known URL, or the
     * fetch hits the site root and the document never parses. */
    hash = strchr(did + prefix_len, '#');
    host_len =
        hash ? (size_t)(hash - (did + prefix_len)) : strlen(did + prefix_len);
    if (host_len == 0) return NULL;
    host = malloc(host_len + 1);
    if (!host) return NULL;
    memcpy(host, did + prefix_len, host_len);
    host[host_len] = '\0';

    n = snprintf(url, sizeof(url), "https://%s/.well-known/did.json", host);
    free(host);
    if (n < 0 || (size_t)n >= sizeof(url)) return NULL;

    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    proxy_buf_t body = {0};
    proxy_headers hdrs = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, appview_proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, appview_proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdrs);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || !body.data) {
        free(body.data);
        appview_proxy_headers_free(&hdrs);
        return NULL;
    }

    cJSON *doc = cJSON_Parse(body.data);
    free(body.data);
    if (!doc) {
        appview_proxy_headers_free(&hdrs);
        return NULL;
    }

    const char *alias = service_id ? service_id_alias(service_id) : NULL;
    cJSON *services = cJSON_GetObjectItemCaseSensitive(doc, "service");
    char *endpoint = NULL;
    if (cJSON_IsArray(services)) {
        size_t count = cJSON_GetArraySize(services);
        for (size_t i = 0; i < count; i++) {
            cJSON *svc = cJSON_GetArrayItem(services, i);
            if (!cJSON_IsObject(svc)) continue;
            cJSON *id = cJSON_GetObjectItemCaseSensitive(svc, "id");
            cJSON *type = cJSON_GetObjectItemCaseSensitive(svc, "type");
            if (cJSON_IsString(id) && cJSON_IsString(type)) {
                const char *id_name = id->valuestring[0] == '#'
                                          ? id->valuestring + 1
                                          : id->valuestring;
                bool match =
                    (service_id && service_id[0])
                        ? (strcmp(id_name, service_id) == 0 ||
                           (alias && strcmp(id_name, alias) == 0))
                        : (strcmp(type->valuestring, "HttpUrl") == 0 ||
                           strcmp(type->valuestring, "WebSocket") == 0);
                if (match) {
                    cJSON *ep = cJSON_GetObjectItemCaseSensitive(
                        svc, "serviceEndpoint");
                    if (cJSON_IsString(ep) && ep->valuestring[0]) {
                        endpoint = strdup(ep->valuestring);
                        break;
                    }
                }
            }
        }
    }
    cJSON_Delete(doc);
    appview_proxy_headers_free(&hdrs);
    return endpoint;
}

/* Where an `atproto-proxy: <did>#<service id>` request should go, and the
 * audience its service-auth must carry. Honouring the header is what lets one
 * PDS front several services: chat, for one, lives at did:web:api.bsky.chat and
 * is not served by the AppView, so without this every chat call would be
 * answered by whichever host appview_url happens to name.
 *
 * A header naming our own configured AppView maps straight to its URL, whatever
 * service id the client used (both eras of id appear on the network); other
 * hosts are resolved through their did:web document. With no header the
 * configured AppView is the upstream.
 *
 * Returns a malloc'd upstream URL the caller frees, with `*audience` set (to
 * `audience_buf` when the header named a service, otherwise the AppView's own
 * DID). On failure returns NULL with the error already set on `resp`. */
char *appview_resolve_upstream(const metalbear_server *server,
                               const wf_xrpc_request *req,
                               wf_xrpc_response *resp, const char **audience,
                               char audience_buf[256]) {
    char *upstream = NULL;
    const char *proxy_header = req->atproto_proxy;

    *audience = server->appview_did;
    if (proxy_header && proxy_header[0]) {
        const char *hash = strrchr(proxy_header, '#');
        const char *svc_id = hash ? hash + 1 : NULL;
        size_t did_len =
            hash ? (size_t)(hash - proxy_header) : strlen(proxy_header);
        char did_buf[256];
        const char *bare_did = proxy_header;
        if (did_len > 0 && did_len < sizeof(did_buf)) {
            memcpy(did_buf, proxy_header, did_len);
            did_buf[did_len] = '\0';
            bare_did = did_buf;
        }
        if (did_len == 0 || did_len >= 256 ||
            !proxy_destination_allowed(server, bare_did, svc_id)) {
            metalbear_metrics_inc(METALBEAR_METRIC_PROXY_REFUSALS);
            LOG_INFO("Refusing atproto-proxy destination: %s", proxy_header);
            wf_xrpc_response_set_error(
                resp, 403, "Forbidden",
                "atproto-proxy destination is not allowed");
            return NULL;
        }
        if (did_len > 0 && did_len < 256) {
            memcpy(audience_buf, bare_did, did_len);
            audience_buf[did_len] = '\0';
            *audience = audience_buf;
        }
        if (server->appview_did && strcmp(bare_did, server->appview_did) == 0) {
            upstream = strdup(server->appview_url);
        } else {
            upstream = resolve_did_web_service(proxy_header, svc_id);
        }
        if (!upstream) {
            wf_xrpc_response_set_error(
                resp, 502, "BadGateway",
                "Could not resolve atproto-proxy target");
            return NULL;
        }
        return upstream;
    }
    upstream = strdup(server->appview_url);
    if (!upstream) {
        wf_xrpc_response_set_error(resp, 500, "InternalError", "Out of memory");
    }
    return upstream;
}

/* `<upstream>/xrpc/<nsid>[?query]` into `out`, freeing `upstream`. False, with
 * the error set on `resp`, when it does not fit. */
bool appview_target_url(char *out, size_t cap, char *upstream,
                        const wf_xrpc_request *req, wf_xrpc_response *resp) {
    int n = snprintf(out, cap, "%s/xrpc/%s%s%s", upstream,
                     req->nsid ? req->nsid : "",
                     req->raw_query && req->raw_query[0] ? "?" : "",
                     req->raw_query ? req->raw_query : "");
    free(upstream);
    if (n < 0 || (size_t)n >= cap) {
        wf_xrpc_response_set_error(resp, 414, "UriTooLong",
                                   "Proxied URI exceeds 8KB limit");
        return false;
    }
    return true;
}
