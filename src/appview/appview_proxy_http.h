#ifndef METALBEAR_APPVIEW_PROXY_HTTP_H
#define METALBEAR_APPVIEW_PROXY_HTTP_H

/* The HTTP half of the AppView proxy (appview_proxy_http.c): one exchange with
 * an upstream and the headers that cross it. Not part of the public API. */

#include "wolfram/xrpc_server.h"

#include <curl/curl.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} proxy_buf_t;

typedef struct proxy_headers {
    char *content_type;
    char *content_encoding;
    char *content_language;
    char *repo_rev; /* `atproto-repo-rev`: how far the upstream has indexed */
    char *content_labelers; /* `atproto-content-labelers` */
    char *retry_after;
} proxy_headers;

/* What an upstream answered: the status, the body and the captured headers. */
typedef struct appview_proxy_reply {
    long status;
    proxy_buf_t body;
    proxy_headers headers;
} appview_proxy_reply;

size_t appview_proxy_write_cb(char *ptr, size_t size, size_t nmemb,
                              void *userdata);
size_t appview_proxy_header_cb(char *buffer, size_t size, size_t nitems,
                               void *userdata);
void appview_proxy_headers_free(proxy_headers *h);
bool appview_proxy_forward_request_headers(const wf_xrpc_request *req,
                                           struct curl_slist **hdrs);
void appview_proxy_forward_response_headers(wf_xrpc_response *resp,
                                            const proxy_headers *h);

/* See appview_proxy_http.c. */
bool appview_proxy_exchange(const wf_xrpc_request *req, const char *target,
                            const char *service_token, wf_xrpc_response *resp,
                            appview_proxy_reply *out);
void appview_proxy_reply_free(appview_proxy_reply *r);
void appview_proxy_reply_send(wf_xrpc_response *resp,
                              const appview_proxy_reply *r,
                              const char *body_override);

#ifdef __cplusplus
}
#endif

#endif
