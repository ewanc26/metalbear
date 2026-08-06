#ifndef METALBEAR_SYNC_ROUTES_H
#define METALBEAR_SYNC_ROUTES_H

/* com.atproto.sync.* / com.atproto.repo.listMissingBlobs XRPC handlers
 * (getRepo, getBlocks, getRepoStatus, listBlobs, listMissingBlobs,
 * getRecord, requestCrawl), registered by server.c's
 * metalbear_server_start against these definitions in sync_routes.c. Not
 * part of the public API. */

#include "wolfram/xrpc_server.h"

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Apply the configured crawler-notify interval. 0 leaves the default in
 * place. Called once at startup, before any commit can trigger a notify. */
void sync_configure_crawler_notify(time_t seconds);

/* metalbear_sequencer_notify_fn: rate-limited best-effort ping of every
 * configured crawler/relay after a commit. `ctx` is the metalbear_server. */
void notify_crawlers(void *ctx);

wf_status get_repo(void *ctx, const wf_xrpc_request *request,
                   wf_xrpc_response *response);
wf_status get_blocks(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response);
wf_status get_repo_status(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response);
wf_status list_blobs(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response);
wf_status list_missing_blobs(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);
wf_status get_record(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response);
wf_status request_crawl(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response);
wf_status get_head(void *ctx, const wf_xrpc_request *request,
                   wf_xrpc_response *response);
wf_status get_checkout(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response);
wf_status get_blob(void *ctx, const wf_xrpc_request *request,
                   wf_xrpc_response *response);
wf_status list_repos_by_collection(void *ctx, const wf_xrpc_request *request,
                                   wf_xrpc_response *response);
wf_status list_repos(void *ctx, const wf_xrpc_request *request,
                     wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_SYNC_ROUTES_H */
