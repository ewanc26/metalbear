#ifndef METALBEAR_OPS_STATUS_H
#define METALBEAR_OPS_STATUS_H

/* The operator-facing status surface (GET /metrics, GET /_debug/health, GET /
 * landing page) and the per-request observer that feeds the per-route
 * counters they report. Registered by server.c's metalbear_server_start
 * against these definitions in status.c. Not part of the public API. */

#include "metalbear/server.h"
#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register the status endpoints and the request observer. Call once from
 * metalbear_server_start, after the XRPC routes are registered so the
 * observer counts them. */
wf_status metalbear_status_register(metalbear_server *server);

/* GET /_ops/audit — admin-only, paginated admin action audit trail (#160).
 * Exposed for the offline seam test; the real server registers it as an HTTP
 * route, so it performs its own admin check rather than using the XRPC
 * auth callback. */
wf_status admin_audit_handler(void *ctx, const wf_xrpc_request *request,
                              wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_OPS_STATUS_H */
