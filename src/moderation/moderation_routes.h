#ifndef METALBEAR_MODERATION_ROUTES_H
#define METALBEAR_MODERATION_ROUTES_H

/* com.atproto.moderation.* XRPC handlers, registered by server.c's
 * metalbear_server_start against these definitions in
 * moderation_routes.c. Not part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status create_report(void *ctx, const wf_xrpc_request *request,
                        wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_MODERATION_ROUTES_H */
