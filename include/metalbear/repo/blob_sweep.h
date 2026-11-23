#ifndef METALBEAR_BLOB_SWEEP_H
#define METALBEAR_BLOB_SWEEP_H

/*
 * blob_sweep.h -- server-side scheduling for the issue #253 blob lifecycle.
 *
 * The sweep reconciles on-disk blobs with the host-wide lifecycle database,
 * drops references whose repository revision has been collected, deletes
 * expired temporaries and unreferenced durables, and can run in dry-run mode
 * for pdsadmin. All current-state counters are exposed live at /metrics.
 */

#include "metalbear/repo/blob_lifecycle.h"
#include "metalbear/server.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Run one pass over every hosted account. `dry_run` only fills `out` with
 * counts; it never deletes payloads or lifecycle rows. Returns WF_OK when the
 * pass completed, even if individual accounts failed (those are logged).
 */
wf_status metalbear_blob_sweep_run(metalbear_server *server, bool dry_run,
                                   metalbear_blob_sweep_summary *out);

/* Scrape-time counters for /metrics. Uses the server's repo stores to tell
 * live references from collected revisions, but reconciles nothing. */
wf_status metalbear_blob_sweep_stats(metalbear_server *server,
                                     metalbear_blob_sweep_summary *out);

typedef struct metalbear_blob_sweep_schedule metalbear_blob_sweep_schedule;

/* NULL when interval_seconds < 1 or the thread cannot start. */
metalbear_blob_sweep_schedule *
metalbear_blob_sweep_schedule_start(metalbear_server *server,
                                    long interval_seconds);
void metalbear_blob_sweep_schedule_free(metalbear_blob_sweep_schedule *s);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_BLOB_SWEEP_H */
