#ifndef METALBEAR_REPO_GC_SCHEDULE_H
#define METALBEAR_REPO_GC_SCHEDULE_H

#include "metalbear/server.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_repo_gc_schedule metalbear_repo_gc_schedule;

/*
 * Run one repo-GC pass over every account in the registry. For each account
 * that is active and not taken down, the pass compacts its repo store: every
 * block not reachable from the current head commit (the commit itself plus
 * every CID in its MST) is removed from both the durable block table and the
 * in-memory CAR. Accounts that are deactivated or taken down are skipped: the
 * former may be freed by the deletion sweep, and the latter are held for
 * moderation, so neither should have its block table rewritten behind the
 * operator's back.
 *
 * Returns the number of accounts whose repo was compacted; accounts already in
 * a consistent state count only if GC reported removing at least one block.
 * A failure on one account is logged and does not stop the pass.
 */
size_t metalbear_repo_gc_run(metalbear_server *server);

/*
 * Background timer, on the backup_schedule.c pattern. NULL when
 * `interval_seconds < 1` or the thread cannot start; the first pass runs one
 * interval after start. `free` stops the timer and waits for an in-flight pass
 * to finish, so it is safe to call before the account cache is torn down.
 */
metalbear_repo_gc_schedule *
metalbear_repo_gc_schedule_start(metalbear_server *server,
                                 long interval_seconds);
void metalbear_repo_gc_schedule_free(metalbear_repo_gc_schedule *schedule);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_REPO_GC_SCHEDULE_H */
