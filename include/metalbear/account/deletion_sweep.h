#ifndef METALBEAR_ACCOUNT_DELETION_SWEEP_H
#define METALBEAR_ACCOUNT_DELETION_SWEEP_H

#include "metalbear/server.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_deletion_sweep metalbear_deletion_sweep;

/*
 * Run one pass over the account registry. Every account whose per-account
 * store says it is deactivated, and whose deactivation timestamp is at least
 * `hold_seconds` before `now`, is hard-deleted with the same event sequence as
 * com.atproto.server.deleteAccount. Accounts with no deactivation timestamp
 * are skipped: without one there is no honest way to decide the hold has
 * elapsed, so an old deactivated database is left for the operator.
 *
 * `now` is a Unix epoch supplied by the caller so the hold is testable without
 * sleeping; pass 0 to use the real clock. `hold_seconds <= 0` is a no-op (the
 * sweep is disabled). Returns the number of accounts deleted.
 */
int metalbear_deletion_sweep_run(metalbear_server *server, int64_t hold_seconds,
                                 int64_t now);

/*
 * Background timer, on the backup_schedule.c pattern. NULL when
 * `hold_seconds <= 0` or the thread cannot start. `interval_seconds` is how
 * often a pass runs; it is independent of the hold itself so a long hold does
 * not make the check rare enough to miss a deletion window.
 */
metalbear_deletion_sweep *
metalbear_deletion_sweep_start(metalbear_server *server, int64_t hold_seconds,
                               long interval_seconds);
void metalbear_deletion_sweep_free(metalbear_deletion_sweep *sweep);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_ACCOUNT_DELETION_SWEEP_H */
