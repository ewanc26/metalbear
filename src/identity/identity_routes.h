#ifndef METALBEAR_IDENTITY_ROUTES_H
#define METALBEAR_IDENTITY_ROUTES_H

/* com.atproto.identity.* XRPC handlers, DID document resolution, and the PLC
 * operation flow, registered by server.c's metalbear_server_start against
 * these definitions in identity_routes.c. Not part of the public API. */

#include "wolfram/xrpc_server.h"

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Apply configured limits to the DID document cache. 0 leaves the
 * corresponding default in place. Called once at startup, before any
 * request can populate the cache. */
void identity_configure_did_doc_cache(time_t ttl_seconds, size_t max_entries);

wf_status resolve_handle(void *ctx, const wf_xrpc_request *request,
                         wf_xrpc_response *response);

/* PDS repo resolver's DID-document callback: builds or fetches `did`'s
 * document as raw JSON. Heap-allocated; caller frees. NULL on failure. */
char *resolve_did_doc_json(void *ctx, const char *did);

wf_status resolve_did_identity(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response);
wf_status resolve_identity(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response);
wf_status refresh_identity(void *ctx, const wf_xrpc_request *request,
                           wf_xrpc_response *response);
wf_status get_recommended_did_credentials(void *ctx,
                                          const wf_xrpc_request *request,
                                          wf_xrpc_response *response);
wf_status update_handle(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response);
wf_status request_plc_operation_signature(void *ctx,
                                          const wf_xrpc_request *request,
                                          wf_xrpc_response *response);
wf_status sign_plc_operation(void *ctx, const wf_xrpc_request *request,
                             wf_xrpc_response *response);
wf_status submit_plc_operation(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_IDENTITY_ROUTES_H */
