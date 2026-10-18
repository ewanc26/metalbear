#ifndef METALBEAR_OPS_FRONTEND_STATIC_H
#define METALBEAR_OPS_FRONTEND_STATIC_H

/* Serves a built frontend directory (METALBEAR_FRONTEND_DIR) as fixed GET
 * routes. Each file is read once at startup and registered at its path:
 * index.html at "/", and every other file at "/<relative path>". An .html file
 * is also reachable without its extension, so /account and /account.html both
 * answer. robots.txt is left to the server, which already serves one.
 *
 * Not part of the public API. Called from metalbear_register_identity_documents
 * after the status routes, so that a frontend "/" replaces the C landing page
 * (see status.c, which then registers the landing page at /landing). */

#include <stddef.h>

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register every file under `dir`. Returns WF_ERR_NOT_FOUND if `dir` cannot
 * be opened, so a misconfigured directory stops startup rather than serving
 * nothing. `*out_routes` receives the number of routes registered. */
wf_status metalbear_frontend_register(wf_xrpc_server *xrpc, const char *dir,
                                      size_t *out_routes);

#ifdef __cplusplus
}
#endif

#endif
