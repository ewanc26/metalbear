#ifndef METALBEAR_SERVER_DRAIN_H
#define METALBEAR_SERVER_DRAIN_H

/* Graceful-shutdown write gate (issue #164).
 *
 * One XRPC server per process is the supported deployment, so the drain
 * latch and in-flight count live here rather than being threaded through
 * every route bundle. metalbear_server_start() resets the state.
 */

#include "wolfram/xrpc.h"
#include "wolfram/xrpc_server.h"
#include <time.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Register a mutating XRPC procedure through the drain gate. Once a drain
 * begins, new calls get 503 ServiceUnavailable; calls already inside the
 * wrapped handler are allowed to finish. The wrapper context is owned by the
 * drain module and released by metalbear_drain_reset(). */
wf_status metalbear_register_write_procedure(wf_xrpc_server *server,
                                             const char *nsid,
                                             wf_xrpc_procedure_handler handler,
                                             void *ctx);

/* Latched by metalbear_server_drain(). Write handlers consult this to turn
 * away late arrivals. */
bool metalbear_drain_is_active(void);

/* Reset the gate for a new server instance. Called from metalbear_server_start
 * before any route is registered; frees all wrapper contexts. */
void metalbear_drain_reset(int64_t timeout_seconds);

/* Set the drain latch and wait up to the configured timeout (a negative
 * timeout waits forever) for in-flight writes to finish. Returns the number
 * of writes still running when it returns. */
int metalbear_drain_begin(void);

/* Stop the listener without draining (used by free() after a drain already
 * ran). Cancels any waiters. */
void metalbear_drain_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_SERVER_DRAIN_H */
