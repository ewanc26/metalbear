#ifndef METALBEAR_APPVIEW_RESOLVE_H
#define METALBEAR_APPVIEW_RESOLVE_H

/* Where an AppView proxy request goes (appview_resolve.c). Not part of the
 * public API. */

#include "../server_internal.h"

#include "wolfram/xrpc_server.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *appview_resolve_upstream(const metalbear_server *server,
                               const wf_xrpc_request *req,
                               wf_xrpc_response *resp, const char **audience,
                               char audience_buf[256]);
bool appview_target_url(char *out, size_t cap, char *upstream,
                        const wf_xrpc_request *req, wf_xrpc_response *resp);

#ifdef __cplusplus
}
#endif

#endif
