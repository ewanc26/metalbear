#ifndef METALBEAR_OPS_ROUTES_H
#define METALBEAR_OPS_ROUTES_H

/* com.atproto.server.describeServer, GET /operator.json, and _health --
 * registered by server.c's metalbear_server_start against these definitions
 * in ops_routes.c. Not part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status describe_server(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response);

wf_status operator_info(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response);

wf_status health(void *ctx, const wf_xrpc_request *request,
                 wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_OPS_ROUTES_H */
