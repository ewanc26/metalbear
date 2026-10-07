#ifndef METALBEAR_APPVIEW_RAW_H
#define METALBEAR_APPVIEW_RAW_H

/* Read-after-write for proxied AppView reads (appview_raw.c). Not part of the
 * public API. */

#include "../server_internal.h"

#include "wolfram/xrpc_server.h"

#include <cJSON.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Copy the fields an app.bsky.actor.profile record carries onto a locally
 * served profile view. */
void append_profile_record_fields(cJSON *view, const cJSON *record);

/* Patch `body` with the requester's records newer than `repo_rev`. Returns a
 * heap-allocated replacement body, or NULL to send the upstream response
 * through untouched. */
char *read_after_write_munge(metalbear_server *server, const char *requester_did,
                             const char *nsid, const char *repo_rev,
                             const char *body, size_t body_len,
                             wf_xrpc_response *resp);

#ifdef __cplusplus
}
#endif

#endif
