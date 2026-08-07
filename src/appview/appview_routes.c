#include "appview_routes.h"
#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/oauth/auth.h"

#include <cJSON.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* AppView proxy fallback                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} proxy_buf_t;

static size_t proxy_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userdata) {
    proxy_buf_t *buf = (proxy_buf_t *)userdata;
    size_t total = size * nmemb;
    if (buf->len + total + 1 > buf->cap) {
        size_t newcap = (buf->cap + total) * 2;
        char *grown = realloc(buf->data, newcap);
        if (!grown) return 0;
        buf->data = grown;
        buf->cap = newcap;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

/* Case-insensitive "does this header line start with `name`" test. HTTP header
 * names are case-insensitive and upstreams differ in what they send. */
static const char *proxy_header_value(const char *line, size_t len,
                                      const char *name) {
    size_t name_len = strlen(name);
    if (len <= name_len || strncasecmp(line, name, name_len) != 0 ||
        line[name_len] != ':')
        return NULL;
    const char *val = line + name_len + 1;
    while (*val == ' ' || *val == '\t') val++;
    return val;
}

/* Trim the trailing CRLF curl leaves on each header line. */
static char *proxy_header_dup(const char *val, const char *line_end) {
    size_t n = (size_t)(line_end - val);
    while (n > 0 && (val[n - 1] == '\r' || val[n - 1] == '\n')) n--;
    return strndup(val, n);
}

typedef struct proxy_headers {
    char *content_type;
    char *repo_rev; /* `atproto-repo-rev`: how far the upstream has indexed */
} proxy_headers;

static void proxy_headers_free(proxy_headers *h) {
    if (!h) return;
    free(h->content_type);
    free(h->repo_rev);
    h->content_type = NULL;
    h->repo_rev = NULL;
}

static size_t proxy_header_cb(char *ptr, size_t size, size_t nmemb,
                              void *userdata) {
    proxy_headers *out = (proxy_headers *)userdata;
    size_t total = size * nmemb;
    const char *val;
    if ((val = proxy_header_value(ptr, total, "Content-Type")) != NULL) {
        free(out->content_type);
        out->content_type = proxy_header_dup(val, ptr + total);
    } else if ((val = proxy_header_value(ptr, total, "atproto-repo-rev")) !=
               NULL) {
        free(out->repo_rev);
        out->repo_rev = proxy_header_dup(val, ptr + total);
    }
    return total;
}

/* Service ids that have been renamed on the network. The AppView's did:web
 * document now names `#bsky_appview` where legacy proxies named the same
 * service `#atproto_bsky_app` (and chat `#atproto_bsky_chat` vs `#bsky_chat`).
 * Accept both so an `atproto-proxy` header written for either era resolves. */
static const char *service_id_alias(const char *id) {
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
    char *ct = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &ct);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || !body.data) {
        free(body.data);
        free(ct);
        return NULL;
    }

    cJSON *doc = cJSON_Parse(body.data);
    free(body.data);
    if (!doc) {
        free(ct);
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
    free(ct);
    return endpoint;
}

/* ------------------------------------------------------------------ */
/* Read-after-write                                                     */
/* ------------------------------------------------------------------ */
/*
 * An AppView reports how far it has indexed a repo with the `atproto-repo-rev`
 * response header. Anything the account has written past that rev exists here
 * but not there yet, so a user who has just posted would not see their own
 * post. The reference PDS patches the proxied response with those local
 * records before returning it (packages/pds/src/read-after-write); this is the
 * same idea against the same set of endpoints.
 *
 * Everything here degrades to "return the upstream response unchanged": if the
 * body is not the shape we expect, or the rev looks like it belongs to another
 * repo, a stale view is always preferable to a wrong one.
 */

/* Build the PostView the AppView would have produced for a local post.
 * Counts are zero because the post is, by construction, brand new. */
static cJSON *local_post_view(const char *uri, const char *cid,
                              const char *indexed_at, const cJSON *record,
                              const cJSON *author) {
    cJSON *post = cJSON_CreateObject();
    if (!post) return NULL;
    cJSON_AddStringToObject(post, "uri", uri ? uri : "");
    cJSON_AddStringToObject(post, "cid", cid ? cid : "");
    if (author) {
        cJSON *dup = cJSON_Duplicate(author, 1);
        if (dup) cJSON_AddItemToObject(post, "author", dup);
    }
    cJSON *rec = cJSON_Duplicate(record, 1);
    if (rec) cJSON_AddItemToObject(post, "record", rec);
    cJSON_AddNumberToObject(post, "replyCount", 0);
    cJSON_AddNumberToObject(post, "repostCount", 0);
    cJSON_AddNumberToObject(post, "likeCount", 0);
    cJSON_AddNumberToObject(post, "quoteCount", 0);
    cJSON_AddStringToObject(post, "indexedAt", indexed_at ? indexed_at : "");
    return post;
}

/* The author view to attach to local posts: reuse one the upstream already
 * returned for this DID so avatars and labels stay consistent, rather than
 * fabricating a half-populated one. */
static const cJSON *find_author_view(const cJSON *root, const char *did) {
    if (!cJSON_IsObject(root) && !cJSON_IsArray(root)) return NULL;
    const cJSON *self_did = cJSON_GetObjectItemCaseSensitive(root, "did");
    const cJSON *handle = cJSON_GetObjectItemCaseSensitive(root, "handle");
    if (cJSON_IsString(self_did) && cJSON_IsString(handle) &&
        strcmp(self_did->valuestring, did) == 0)
        return root;
    const cJSON *child = NULL;
    cJSON_ArrayForEach(child, root) {
        const cJSON *found = find_author_view(child, did);
        if (found) return found;
    }
    return NULL;
}

/* Insert local posts into a feed array, newest first, mirroring
 * LocalViewer.formatAndInsertPostsInFeed. */
static void insert_local_posts(cJSON *feed, const cJSON *local_records,
                               const char *did, const cJSON *author) {
    if (!cJSON_IsArray(feed)) return;

    /* The upstream page ends at some timestamp; anything older than that
     * belongs on a later page, not spliced into this one. */
    const char *last_time = NULL;
    int feed_len = cJSON_GetArraySize(feed);
    if (feed_len > 0) {
        const cJSON *last = cJSON_GetArrayItem(feed, feed_len - 1);
        const cJSON *post = cJSON_GetObjectItemCaseSensitive(last, "post");
        const cJSON *at = cJSON_GetObjectItemCaseSensitive(post, "indexedAt");
        if (cJSON_IsString(at)) last_time = at->valuestring;
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, local_records) {
        const cJSON *coll =
            cJSON_GetObjectItemCaseSensitive(entry, "collection");
        if (!cJSON_IsString(coll) ||
            strcmp(coll->valuestring, "app.bsky.feed.post") != 0)
            continue;
        const cJSON *uri = cJSON_GetObjectItemCaseSensitive(entry, "uri");
        const cJSON *cid = cJSON_GetObjectItemCaseSensitive(entry, "cid");
        const cJSON *at = cJSON_GetObjectItemCaseSensitive(entry, "indexedAt");
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(entry, "value");
        if (!cJSON_IsString(uri) || !cJSON_IsString(at) || !value) continue;
        if (last_time && strcmp(at->valuestring, last_time) <= 0) continue;

        /* Skip anything the upstream already returned. */
        bool already = false;
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, feed) {
            const cJSON *p = cJSON_GetObjectItemCaseSensitive(item, "post");
            const cJSON *u = cJSON_GetObjectItemCaseSensitive(p, "uri");
            if (cJSON_IsString(u) &&
                strcmp(u->valuestring, uri->valuestring) == 0) {
                already = true;
                break;
            }
        }
        if (already) continue;

        cJSON *post = local_post_view(
            uri->valuestring, cJSON_IsString(cid) ? cid->valuestring : "",
            at->valuestring, value, author);
        if (!post) continue;
        cJSON *wrapper = cJSON_CreateObject();
        if (!wrapper) {
            cJSON_Delete(post);
            continue;
        }
        cJSON_AddItemToObject(wrapper, "post", post);

        /* Keep the feed ordered newest-first. */
        int idx = -1;
        for (int i = 0; i < cJSON_GetArraySize(feed); i++) {
            const cJSON *fi = cJSON_GetArrayItem(feed, i);
            const cJSON *p = cJSON_GetObjectItemCaseSensitive(fi, "post");
            const cJSON *pa = cJSON_GetObjectItemCaseSensitive(p, "indexedAt");
            if (cJSON_IsString(pa) &&
                strcmp(pa->valuestring, at->valuestring) < 0) {
                idx = i;
                break;
            }
        }
        if (idx >= 0)
            cJSON_InsertItemInArray(feed, idx, wrapper);
        else
            cJSON_AddItemToArray(feed, wrapper);
        (void)did;
    }
}

/* Overlay a locally-written profile record onto a profile view. */
static void overlay_local_profile(cJSON *view, const cJSON *record) {
    if (!cJSON_IsObject(view) || !cJSON_IsObject(record)) return;
    static const char *const fields[] = {"displayName", "description"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(record, fields[i]);
        cJSON_DeleteItemFromObjectCaseSensitive(view, fields[i]);
        if (cJSON_IsString(v))
            cJSON_AddStringToObject(view, fields[i], v->valuestring);
    }
}

/*
 * Patch `body` with the requester's records newer than `repo_rev`. Returns a
 * heap-allocated replacement body, or NULL to send the upstream response
 * through untouched.
 */
static char *read_after_write_munge(metalbear_server *server,
                                    const char *requester_did, const char *nsid,
                                    const char *repo_rev, const char *body,
                                    size_t body_len, wf_xrpc_response *resp) {
    static const char *const feed_methods[] = {
        "app.bsky.feed.getTimeline",
        "app.bsky.feed.getAuthorFeed",
        "app.bsky.feed.getActorLikes",
    };
    bool is_feed = false;
    for (size_t i = 0; i < sizeof(feed_methods) / sizeof(feed_methods[0]); i++)
        if (strcmp(nsid, feed_methods[i]) == 0) is_feed = true;
    bool is_profile = strcmp(nsid, "app.bsky.actor.getProfile") == 0;
    bool is_profiles = strcmp(nsid, "app.bsky.actor.getProfiles") == 0;
    if (!is_feed && !is_profile && !is_profiles) return NULL;

    metalbear_account_context *acct = context_for_did(server, requester_did);
    if (!acct || !acct->repo) return NULL;

    char *local_json = NULL;
    if (metalbear_repo_store_records_since_rev(acct->repo, repo_rev, 10,
                                               &local_json) != WF_OK ||
        !local_json)
        return NULL;
    cJSON *local = cJSON_Parse(local_json);
    free(local_json);
    if (!local) return NULL;
    cJSON *records = cJSON_GetObjectItemCaseSensitive(local, "records");
    if (!cJSON_IsArray(records) || cJSON_GetArraySize(records) == 0) {
        cJSON_Delete(local);
        return NULL; /* upstream is caught up; nothing to add */
    }

    cJSON *root = cJSON_ParseWithLength(body, body_len);
    if (!root) {
        cJSON_Delete(local);
        return NULL;
    }

    bool changed = false;
    if (is_feed) {
        cJSON *feed = cJSON_GetObjectItemCaseSensitive(root, "feed");
        if (cJSON_IsArray(feed)) {
            const cJSON *author = find_author_view(root, requester_did);
            int before = cJSON_GetArraySize(feed);
            insert_local_posts(feed, records, requester_did, author);
            changed = cJSON_GetArraySize(feed) != before;
        }
    } else {
        /* Profile record edits: overlay onto the requester's own view. */
        const cJSON *entry = NULL;
        const cJSON *profile_record = NULL;
        cJSON_ArrayForEach(entry, records) {
            const cJSON *coll =
                cJSON_GetObjectItemCaseSensitive(entry, "collection");
            if (cJSON_IsString(coll) &&
                strcmp(coll->valuestring, "app.bsky.actor.profile") == 0)
                profile_record =
                    cJSON_GetObjectItemCaseSensitive(entry, "value");
        }
        if (profile_record) {
            if (is_profile) {
                const cJSON *did =
                    cJSON_GetObjectItemCaseSensitive(root, "did");
                if (cJSON_IsString(did) &&
                    strcmp(did->valuestring, requester_did) == 0) {
                    overlay_local_profile(root, profile_record);
                    changed = true;
                }
            } else {
                cJSON *profiles =
                    cJSON_GetObjectItemCaseSensitive(root, "profiles");
                cJSON *p = NULL;
                cJSON_ArrayForEach(p, profiles) {
                    const cJSON *did =
                        cJSON_GetObjectItemCaseSensitive(p, "did");
                    if (cJSON_IsString(did) &&
                        strcmp(did->valuestring, requester_did) == 0) {
                        overlay_local_profile(p, profile_record);
                        changed = true;
                    }
                }
            }
        }
    }

    char *out = changed ? cJSON_PrintUnformatted(root) : NULL;
    if (changed) {
        /* Tell the client the view was completed locally, as the reference
         * does, so a debugging client can tell this apart from a fresh
         * upstream response. */
        wf_xrpc_response_add_header(resp, "Atproto-Upstream-Lag", "0");
    }
    cJSON_Delete(root);
    cJSON_Delete(local);
    return out;
}

/* Proxy an app.bsky.* request to the AppView, minting service-auth from the
 * requester's own account (iss=requester DID, aud=AppView DID). Returns 502
 * on network failure, otherwise mirrors the upstream status/body. */
static wf_status proxy_appview(metalbear_server *server,
                               const char *requester_did,
                               const wf_xrpc_request *req,
                               wf_xrpc_response *resp, bool send_auth) {
    if (!server->appview_url || !server->appview_url[0] ||
        !server->appview_did || !server->appview_did[0]) {
        wf_xrpc_response_set_error(resp, 501, "MethodNotImplemented",
                                   "No AppView configured");
        return WF_OK;
    }

    /*
     * `atproto-proxy: <did>#<service_id>` names the service the client wants
     * this request delivered to, and the audience its service-auth must carry.
     * Honouring it is what lets one PDS front several services — chat, for
     * one, lives at did:web:api.bsky.chat and is not served by the AppView, so
     * without this every chat call is answered by whichever host appview_url
     * happens to name.
     */
    char *upstream = NULL;
    const char *audience = server->appview_did;
    char audience_buf[256];
    const char *proxy_header = req->atproto_proxy;
    if (proxy_header && proxy_header[0]) {
        const char *hash = strrchr(proxy_header, '#');
        size_t did_len =
            hash ? (size_t)(hash - proxy_header) : strlen(proxy_header);
        if (did_len < sizeof(audience_buf)) {
            memcpy(audience_buf, proxy_header, did_len);
            audience_buf[did_len] = '\0';
            audience = audience_buf;
        }
        /* A header naming our own configured AppView maps straight to its URL,
         * whatever service id the client used (both eras of id appear on the
         * network). Resolving the did:web document is only for other hosts. */
        if (server->appview_did && strcmp(audience, server->appview_did) == 0) {
            upstream = strdup(server->appview_url);
            if (!upstream) {
                wf_xrpc_response_set_error(resp, 500, "InternalError",
                                           "Out of memory");
                return WF_OK;
            }
        } else {
            upstream =
                resolve_did_web_service(proxy_header, hash ? hash + 1 : NULL);
        }
        if (!upstream) {
            wf_xrpc_response_set_error(
                resp, 502, "BadGateway",
                "Could not resolve atproto-proxy target");
            return WF_OK;
        }
    } else {
        upstream = strdup(server->appview_url);
        if (!upstream) {
            wf_xrpc_response_set_error(resp, 500, "InternalError",
                                       "Out of memory");
            return WF_OK;
        }
    }

    char target[1024];
    int n = snprintf(target, sizeof(target), "%s/xrpc/%s%s%s", upstream,
                     req->nsid ? req->nsid : "",
                     req->raw_query && req->raw_query[0] ? "?" : "",
                     req->raw_query ? req->raw_query : "");
    free(upstream);
    if (n < 0 || (size_t)n >= sizeof(target)) {
        wf_xrpc_response_set_error(resp, 414, "UriTooLong",
                                   "Proxied URI exceeds limit");
        return WF_OK;
    }

    char *service_token = NULL;
    if (send_auth && requester_did && requester_did[0]) {
        metalbear_account_context *acct =
            context_for_did(server, requester_did);
        if (acct && acct->repo) {
            metalbear_repo_store_create_service_auth(acct->repo, audience,
                                                     (int64_t)time(NULL) + 300,
                                                     req->nsid, &service_token);
        }
    }

    struct curl_slist *hdrs = NULL;
    if (req->content_type && req->content_type[0]) {
        char ct[256];
        snprintf(ct, sizeof(ct), "Content-Type: %s", req->content_type);
        hdrs = curl_slist_append(hdrs, ct);
    }
    if (service_token) {
        char auth[512];
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", service_token);
        hdrs = curl_slist_append(hdrs, auth);
    }
    if (req->client_ip && req->client_ip[0]) {
        char xff[128];
        snprintf(xff, sizeof(xff), "X-Forwarded-For: %s", req->client_ip);
        hdrs = curl_slist_append(hdrs, xff);
    }

    proxy_buf_t body_out = {0};
    proxy_headers hdrs_out = {0};
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(service_token);
        curl_slist_free_all(hdrs);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Could not initialise HTTP client");
        return WF_OK;
    }
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,
                     req->method ? req->method : "GET");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body_out);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdrs_out);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (req->body && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
    }
    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);
    free(service_token);

    if (rc != CURLE_OK) {
        free(body_out.data);
        proxy_headers_free(&hdrs_out);
        wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                   "Upstream request failed");
        return WF_OK;
    }

    resp->http_status = status;
    if (hdrs_out.content_type) {
        wf_xrpc_response_set_content_type(resp, hdrs_out.content_type);
    }
    /* Read-after-write: splice in the requester's own records that the
     * upstream has not indexed yet, so a just-written post is visible to its
     * author immediately rather than only once the AppView catches up. */
    char *munged = NULL;
    if (status == 200 && body_out.data && body_out.len > 0 &&
        hdrs_out.repo_rev && hdrs_out.repo_rev[0] && requester_did &&
        (!hdrs_out.content_type ||
         strstr(hdrs_out.content_type, "application/json") != NULL)) {
        munged = read_after_write_munge(
            server, requester_did, req->nsid ? req->nsid : "",
            hdrs_out.repo_rev, body_out.data, body_out.len, resp);
    }
    if (munged) {
        wf_xrpc_response_set_body(resp, munged, strlen(munged));
        free(munged);
    } else if (body_out.data && body_out.len > 0) {
        wf_xrpc_response_set_body(resp, body_out.data, body_out.len);
    }
    free(body_out.data);
    proxy_headers_free(&hdrs_out);
    return WF_OK;
}

/* Generic fallback for unmatched NSIDs. Runs before MetalBear's own auth
 * callback (the framework invokes it in place of route dispatch, not
 * alongside it -- see xrpc_server.c's dispatch), so a Bearer token offered
 * here has never been checked by anything: verify it the same way
 * authenticate_request does for a registered route (decode the unverified
 * `sub` claim to find which account's store should check the signature,
 * then verify against that store), then mint the same kind of
 * self-signed service-auth JWT proxy_appview mints for explicitly
 * registered routes. Without this, every unregistered app.bsky./chat.bsky.
 * route reached the AppView with no credential at all and any endpoint
 * needing the caller's identity failed -- this function's own doc comment
 * already promised "signed by the account the request resolves to" before
 * this fix, it just never actually happened. */
wf_status proxy_fallback(void *ctx, const wf_xrpc_request *req,
                         wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (!server->appview_url || !server->appview_url[0]) {
        wf_xrpc_response_set_error(resp, 501, "MethodNotImplemented",
                                   "No AppView configured");
        return WF_OK;
    }

    char *upstream = NULL;
    const char *audience = server->appview_did;
    char audience_buf[256];
    const char *proxy_header = req->atproto_proxy;
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
        if (did_len > 0 && did_len < sizeof(audience_buf)) {
            memcpy(audience_buf, bare_did, did_len);
            audience_buf[did_len] = '\0';
            audience = audience_buf;
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
            return WF_OK;
        }
    } else {
        upstream = strdup(server->appview_url);
    }
    if (!upstream) {
        wf_xrpc_response_set_error(resp, 500, "InternalError", "Out of memory");
        return WF_OK;
    }

    char target[1024];
    int n = snprintf(target, sizeof(target), "%s/xrpc/%s%s%s", upstream,
                     req->nsid ? req->nsid : "",
                     req->raw_query && req->raw_query[0] ? "?" : "",
                     req->raw_query ? req->raw_query : "");
    free(upstream);
    if (n < 0 || (size_t)n >= sizeof(target)) {
        wf_xrpc_response_set_error(resp, 414, "UriTooLong",
                                   "Proxied URI exceeds limit");
        return WF_OK;
    }

    /* A token was offered but has never been checked by anything at this
     * point -- verify it now, or refuse outright. Silently falling back to
     * an anonymous proxy on a bad token would let a client downgrade its
     * own auth requirement just by sending garbage, which registered
     * routes never allow. */
    char *service_token = NULL;
    const char *provided = bearer_token(req->auth_header);
    if (provided) {
        char *sub = jwt_subject(provided);
        metalbear_account_context *acct =
            sub ? context_for_did(server, sub) : NULL;
        metalbear_access_scope scope = METALBEAR_ACCESS_FULL;
        if (!acct || metalbear_auth_verify_access_scope(acct->auth, provided,
                                                        &scope) != WF_OK) {
            free(sub);
            wf_xrpc_response_set_error(resp, 401, "InvalidToken",
                                       "Token could not be verified");
            return WF_OK;
        }
        if (acct->repo)
            metalbear_repo_store_create_service_auth(acct->repo, audience,
                                                     (int64_t)time(NULL) + 300,
                                                     req->nsid, &service_token);
        free(sub);
    }

    struct curl_slist *hdrs = NULL;
    if (req->content_type && req->content_type[0]) {
        char ct[256];
        snprintf(ct, sizeof(ct), "Content-Type: %s", req->content_type);
        hdrs = curl_slist_append(hdrs, ct);
    }
    if (service_token) {
        char auth[512];
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s", service_token);
        hdrs = curl_slist_append(hdrs, auth);
    }
    if (req->client_ip && req->client_ip[0]) {
        char xff[128];
        snprintf(xff, sizeof(xff), "X-Forwarded-For: %s", req->client_ip);
        hdrs = curl_slist_append(hdrs, xff);
    }
    /* libcurl sets Host from the target URL; do not override it with the
     * original request's Host or Cloudflare-style frontends will reject the
     * proxied connection. */

    proxy_buf_t body_out = {0};
    proxy_headers hdrs_out = {0};
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(service_token);
        curl_slist_free_all(hdrs);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Could not initialise HTTP client");
        return WF_OK;
    }
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,
                     req->method ? req->method : "GET");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body_out);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hdrs_out);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (req->body && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
    }
    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);
    free(service_token);

    if (rc != CURLE_OK) {
        free(body_out.data);
        proxy_headers_free(&hdrs_out);
        wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                   "Upstream request failed");
        return WF_OK;
    }

    resp->http_status = status;
    if (hdrs_out.content_type) {
        wf_xrpc_response_set_content_type(resp, hdrs_out.content_type);
    }
    if (body_out.data && body_out.len > 0) {
        wf_xrpc_response_set_body(resp, body_out.data, body_out.len);
    }
    free(body_out.data);
    proxy_headers_free(&hdrs_out);
    return WF_OK;
}
/* ---- app.bsky.* AppView proxy handlers ----------------------------------
 *
 * Other PDS implementations (rsky-pds, ref-pds) implement these endpoints
 * as first-class handlers and proxy them to an AppView with service-auth
 * minted from the requester's account. The auth callback runs first, so
 * req->authed_subject contains the requester DID.
 */

static wf_status appview_proxy(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp, bool send_auth) {
    metalbear_server *server = ctx;
    const char *requester_did = req->authed_subject;
    return proxy_appview(server, requester_did, req, resp, send_auth);
}

/* Public read endpoints — proxy without service-auth so the public
 * AppView (api.bsky.app) serves public content. A local AppView that
 * trusts the PDS can be configured later by re-enabling auth. */
static wf_status appview_public(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    return appview_proxy(ctx, req, resp, false);
}

/* User-specific endpoints — send service-auth JWT so a trusted AppView
 * can return per-user data. The public AppView will reject these. */
static wf_status appview_private(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    return appview_proxy(ctx, req, resp, true);
}

/* Feed endpoints — public reads */
wf_status appview_get_feed(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_feed_skeleton(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_author_feed(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_actor_feeds(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_feed_generators(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_feed_generator(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_posts(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Actor endpoints — public reads */
wf_status appview_get_profile(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    metalbear_server *server = ctx;

    // Check for local profile parameter (did=...
    if (req->params && cJSON_IsObject(req->params)) {
        cJSON *did_param = cJSON_GetObjectItemCaseSensitive(req->params, "did");
        if (cJSON_IsString(did_param) && did_param->valuestring[0]) {
            const char *provided_did = did_param->valuestring;
            metalbear_account_context *acct =
                context_for_did(server, provided_did);
            if (acct && metalbear_account_is_active(acct->account)) {
                LOG_DEBUG("Handling local profile for did:%s", provided_did);

                cJSON *root = cJSON_CreateObject();
                if (!root) {
                    wf_xrpc_response_set_error(
                        resp, 500, "InternalError",
                        "Failed to create local profile");
                    return WF_OK;
                }

                cJSON_AddStringToObject(root, "did", provided_did);
                cJSON_AddStringToObject(
                    root, "handle", acct->handle ? acct->handle : "unknown");
                // Add other local profile fields as needed

                return set_json(resp, root);
            }
        }
    }

    // Fallback to public proxy for external profiles
    return appview_public(ctx, req, resp);
}
wf_status appview_get_profiles(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
/* An actor's likes are gated on the viewer, so this needs the requester's
 * identity rather than an anonymous read. */
wf_status appview_get_actor_likes(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* The requester's own following feed — meaningless without their identity. */
wf_status appview_get_timeline(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Thread content is public; viewer state is a bonus the public AppView omits.
 */
wf_status appview_get_post_thread(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Push registration is per-account state on the AppView. */
wf_status appview_register_push(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

wf_status appview_unregister_push(void *ctx, const wf_xrpc_request *req,
                                  wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_actor_statistics(void *ctx, const wf_xrpc_request *req,
                                       wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_actor_rankings(void *ctx, const wf_xrpc_request *req,
                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Graph endpoints — public reads */
wf_status appview_get_follows(void *ctx, const wf_xrpc_request *req,
                              wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_followers(void *ctx, const wf_xrpc_request *req,
                                wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_blocks(void *ctx, const wf_xrpc_request *req,
                             wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_list(void *ctx, const wf_xrpc_request *req,
                           wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_lists(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_list_items(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_starter_pack(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_get_starter_packs(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Notification endpoints — user-specific */
wf_status appview_get_unread_notifications(void *ctx,
                                           const wf_xrpc_request *req,
                                           wf_xrpc_response *resp) {
    (void)ctx;
    (void)req;
    // Return empty unread count for public AppView; local AppView can be
    // implemented later
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Failed to create response");
        return WF_OK;
    }
    cJSON_AddNumberToObject(root, "count", 0);
    return set_json(resp, root);
}
wf_status appview_get_notifications(void *ctx, const wf_xrpc_request *req,
                                    wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Chat/Convo endpoints — user-specific */
wf_status appview_get_convo(void *ctx, const wf_xrpc_request *req,
                            wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_convos(void *ctx, const wf_xrpc_request *req,
                             wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}
wf_status appview_get_messages(void *ctx, const wf_xrpc_request *req,
                               wf_xrpc_response *resp) {
    return appview_private(ctx, req, resp);
}

/* Labeler endpoints — public reads */
wf_status appview_get_labeler_info(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}

/* Unsafe/unspecced endpoints — public reads */
wf_status appview_unspecced_get_age_assurance_state(void *ctx,
                                                    const wf_xrpc_request *req,
                                                    wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_unspecced_get_age_assurance_config(void *ctx,
                                                     const wf_xrpc_request *req,
                                                     wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
wf_status appview_unspecced_get_age_assurance(void *ctx,
                                              const wf_xrpc_request *req,
                                              wf_xrpc_response *resp) {
    return appview_public(ctx, req, resp);
}
