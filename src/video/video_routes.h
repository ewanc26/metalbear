#ifndef METALBEAR_VIDEO_ROUTES_H
#define METALBEAR_VIDEO_ROUTES_H

/* app.bsky.video.* XRPC handlers, registered by server.c's
 * metalbear_server_start against these definitions in video_routes.c.
 * Not part of the public API. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status video_upload(void *ctx, const wf_xrpc_request *request,
                       wf_xrpc_response *response);

wf_status video_get_job_status(void *ctx, const wf_xrpc_request *request,
                               wf_xrpc_response *response);

wf_status video_get_upload_limits(void *ctx, const wf_xrpc_request *request,
                                  wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_VIDEO_ROUTES_H */
