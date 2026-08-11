#ifndef METALBEAR_BLOB_STORE_SERVER_H
#define METALBEAR_BLOB_STORE_SERVER_H

/* com.atproto.repo.uploadBlob XRPC handler for the full PDS server context
 * (account resolution, blob_upload_limit enforcement, takedown checks),
 * registered by server.c's metalbear_server_start against the definition in
 * blob_store_server.c. Not part of the public API — the resolver-less and
 * resolver-based single-store registrations embedders use directly are
 * declared in metalbear/repo/blob_store.h instead. */

#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status upload_blob(void *ctx, const wf_xrpc_request *request,
                      wf_xrpc_response *response);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_BLOB_STORE_SERVER_H */
