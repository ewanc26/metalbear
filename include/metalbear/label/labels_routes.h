#ifndef METALBEAR_LABELS_ROUTES_H
#define METALBEAR_LABELS_ROUTES_H

/* com.atproto.label.queryLabels, served from the server's own label store.
 * The store is not owned by the route: the caller keeps it open for the
 * server's lifetime and frees it after the XRPC server stops. */

#include "metalbear/label/label_store.h"
#include "wolfram/xrpc_server.h"

#ifdef __cplusplus
extern "C" {
#endif

wf_status metalbear_labels_register(wf_xrpc_server *server,
                                    metalbear_label_store *store);

#ifdef __cplusplus
}
#endif

#endif
