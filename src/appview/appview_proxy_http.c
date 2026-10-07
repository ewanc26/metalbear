/* The HTTP half of the AppView proxy: the libcurl callbacks, which request and
 * response headers travel across, and one exchange with the upstream. */

#include "appview_proxy_http.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

size_t appview_proxy_write_cb(char *ptr, size_t size, size_t nmemb,
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

void appview_proxy_headers_free(proxy_headers *h) {
    if (!h) return;
    free(h->content_type);
    free(h->content_encoding);
    free(h->content_language);
    free(h->repo_rev);
    free(h->content_labelers);
    free(h->retry_after);
    h->content_type = NULL;
    h->content_encoding = NULL;
    h->content_language = NULL;
    h->repo_rev = NULL;
    h->content_labelers = NULL;
    h->retry_after = NULL;
}

/* Captured upstream response headers that must reach the client, matching the
 * reference PDS's responseHeaders() forward list (content-* + atproto-content-
 * labelers/retry-after) plus atproto-repo-rev (used internally for the
 * read-after-write munge and forwarded like the reference). */
size_t appview_proxy_header_cb(char *ptr, size_t size, size_t nmemb,
                              void *userdata) {
    proxy_headers *out = (proxy_headers *)userdata;
    size_t total = size * nmemb;
    const char *val;
    if ((val = proxy_header_value(ptr, total, "Content-Type")) != NULL) {
        free(out->content_type);
        out->content_type = proxy_header_dup(val, ptr + total);
    } else if ((val = proxy_header_value(ptr, total, "Content-Encoding")) !=
               NULL) {
        free(out->content_encoding);
        out->content_encoding = proxy_header_dup(val, ptr + total);
    } else if ((val = proxy_header_value(ptr, total, "Content-Language")) !=
               NULL) {
        free(out->content_language);
        out->content_language = proxy_header_dup(val, ptr + total);
    } else if ((val = proxy_header_value(ptr, total, "atproto-repo-rev")) !=
               NULL) {
        free(out->repo_rev);
        out->repo_rev = proxy_header_dup(val, ptr + total);
    } else if ((val = proxy_header_value(ptr, total,
                                         "atproto-content-labelers")) != NULL) {
        free(out->content_labelers);
        out->content_labelers = proxy_header_dup(val, ptr + total);
    } else if ((val = proxy_header_value(ptr, total, "Retry-After")) != NULL) {
        free(out->retry_after);
        out->retry_after = proxy_header_dup(val, ptr + total);
    }
    return total;
}

/* Add the captured upstream response headers to the outbound XRPC response,
 * so the caller sees the proxied endpoint's real content metadata and
 * labeler/retry signalling. Content-Type is owned by the response's own
 * content_type field; the rest ride the generic header list. */
void appview_proxy_forward_response_headers(wf_xrpc_response *resp,
                                           const proxy_headers *h) {
    if (!resp || !h) return;
    if (h->content_encoding)
        (void)wf_xrpc_response_add_header(resp, "Content-Encoding",
                                          h->content_encoding);
    if (h->content_language)
        (void)wf_xrpc_response_add_header(resp, "Content-Language",
                                          h->content_language);
    if (h->repo_rev)
        (void)wf_xrpc_response_add_header(resp, "atproto-repo-rev",
                                          h->repo_rev);
    if (h->content_labelers)
        (void)wf_xrpc_response_add_header(resp, "atproto-content-labelers",
                                          h->content_labelers);
    if (h->retry_after)
        (void)wf_xrpc_response_add_header(resp, "Retry-After", h->retry_after);
}

/* Append the AppView-forwarding request headers to the curl header list,
 * matching the reference PDS pipethrough's request header set (accept-encoding
 * defaulting to identity, accept-language, atproto-accept-labelers, x-bsky-
 * topics, and every x-atproto-* header verbatim). Returns true on success. */
bool appview_proxy_forward_request_headers(const wf_xrpc_request *req,
                                          struct curl_slist **hdrs) {
    const char *enc = (req->accept_encoding && req->accept_encoding[0])
                          ? req->accept_encoding
                          : "identity";
    char enc_hdr[256];
    snprintf(enc_hdr, sizeof(enc_hdr), "Accept-Encoding: %s", enc);
    *hdrs = curl_slist_append(*hdrs, enc_hdr);
    if (req->accept_language && req->accept_language[0]) {
        char lang[512];
        snprintf(lang, sizeof(lang), "Accept-Language: %s",
                 req->accept_language);
        *hdrs = curl_slist_append(*hdrs, lang);
    }
    if (req->atproto_accept_labelers && req->atproto_accept_labelers[0]) {
        char labelers[1024];
        snprintf(labelers, sizeof(labelers), "atproto-accept-labelers: %s",
                 req->atproto_accept_labelers);
        *hdrs = curl_slist_append(*hdrs, labelers);
    }
    if (req->x_bsky_topics && req->x_bsky_topics[0]) {
        char topics[512];
        snprintf(topics, sizeof(topics), "X-Bsky-Topics: %s",
                 req->x_bsky_topics);
        *hdrs = curl_slist_append(*hdrs, topics);
    }
    if (req->atproto_headers) {
        for (size_t i = 0; i < req->atproto_headers_count; i++) {
            char line[2048];
            int n = snprintf(line, sizeof(line), "%s: %s",
                             req->atproto_headers[i].name,
                             req->atproto_headers[i].value);
            if (n < 0 || (size_t)n >= sizeof(line)) continue;
            *hdrs = curl_slist_append(*hdrs, line);
        }
    }
    return *hdrs != NULL;
}

/* Send `req` to `target` with an optional service-auth token, capturing the
 * upstream status, body and the headers worth passing on. On a failure to send
 * (no HTTP client, no answer) the error is already set on `resp`: return false
 * and let the caller return WF_OK. */
bool appview_proxy_exchange(const wf_xrpc_request *req, const char *target,
                            const char *service_token, wf_xrpc_response *resp,
                            appview_proxy_reply *out) {
    memset(out, 0, sizeof(*out));
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
    appview_proxy_forward_request_headers(req, &hdrs);

    CURL *curl = curl_easy_init();
    if (!curl) {
        curl_slist_free_all(hdrs);
        wf_xrpc_response_set_error(resp, 500, "InternalError",
                                   "Could not initialise HTTP client");
        return false;
    }
    curl_easy_setopt(curl, CURLOPT_URL, target);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,
                     req->method ? req->method : "GET");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, appview_proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out->body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, appview_proxy_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &out->headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (req->body && req->body_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
    }
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out->status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);

    if (rc != CURLE_OK) {
        appview_proxy_reply_free(out);
        wf_xrpc_response_set_error(resp, 502, "BadGateway",
                                   "Upstream request failed");
        return false;
    }
    return true;
}

void appview_proxy_reply_free(appview_proxy_reply *r) {
    if (!r) return;
    free(r->body.data);
    appview_proxy_headers_free(&r->headers);
    memset(r, 0, sizeof(*r));
}

/* Mirror the upstream reply onto `resp`: its status, content type, the headers
 * worth passing on and its body, or `body_override` (a NUL-terminated string)
 * when the caller rewrote the body. */
void appview_proxy_reply_send(wf_xrpc_response *resp,
                              const appview_proxy_reply *r,
                              const char *body_override) {
    resp->http_status = r->status;
    if (r->headers.content_type) {
        wf_xrpc_response_set_content_type(resp, r->headers.content_type);
    }
    appview_proxy_forward_response_headers(resp, &r->headers);
    if (body_override) {
        wf_xrpc_response_set_body(resp, body_override, strlen(body_override));
    } else if (r->body.data && r->body.len > 0) {
        wf_xrpc_response_set_body(resp, r->body.data, r->body.len);
    }
}
