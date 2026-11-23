#ifndef METALBEAR_OPS_PUBLIC_STATUS_H
#define METALBEAR_OPS_PUBLIC_STATUS_H

/*
 * public_status.h — the opt-in, aggregate-only resource snapshot on
 * /operator.json (issue #267).
 *
 * Nothing here is built unless the caller asks for it: /operator.json calls
 * this only with [server] public_status / METALBEAR_PUBLIC_STATUS enabled.
 * The snapshot deliberately contains no account identifiers, handles, DIDs,
 * client addresses or raw request paths. Route labels are reduced to NSIDs;
 * anything that looks like a path is folded into `other`.
 */

#include <cJSON.h>

typedef struct metalbear_server metalbear_server;

/*
 * Build the `publicStatus` object, or NULL when a field could not be built at
 * all. The caller owns the returned cJSON value. Never call this for a server
 * with public status disabled: the gate belongs to the caller so the field is
 * absent rather than zeroed.
 */
cJSON *metalbear_public_status_json(metalbear_server *server);

#endif /* METALBEAR_OPS_PUBLIC_STATUS_H */
