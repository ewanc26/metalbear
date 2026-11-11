#ifndef METALBEAR_LEXICON_ROUTES_H
#define METALBEAR_LEXICON_ROUTES_H

/* com.atproto.lexicon.resolveLexicon -- registered by server.c's
 * metalbear_server_start against the definition in lexicon_routes.c.
 * Serves the lexicon document from Wolfram's vendored corpus (loaded into
 * server->lexicons at startup); there is deliberately no second copy of the
 * lexicons in MetalBear (tools/check-drift.sh forbids it). Not part of the
 * public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status resolve_lexicon(void *ctx, const wf_xrpc_request *request,
                          wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_LEXICON_ROUTES_H */
