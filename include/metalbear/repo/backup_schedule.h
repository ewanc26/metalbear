#ifndef METALBEAR_BACKUP_SCHEDULE_H
#define METALBEAR_BACKUP_SCHEDULE_H

/* Scheduled backups of the data directory, with retention.
 *
 * One run copies the data directory into a staging directory, takes a
 * consistent copy of every SQLite database with VACUUM INTO (so a live server
 * does not have to stop, and a WAL database is copied whole), writes an
 * archive with metalbear_backup_create, reads it back with
 * metalbear_backup_verify, and only then deletes the oldest archives beyond the
 * retention count. A run that fails at any step removes its own partial files
 * and leaves every existing archive in place. */

#include <stddef.h>

#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_backup_schedule metalbear_backup_schedule;

/* One backup run. Archives are named metalbear-<UTC time>.bak in backup_dir.
 * backup_dir must not be inside data_dir, or each archive would back up the
 * previous ones. retain < 1 keeps every archive. On WF_OK, *out_archive is the
 * new archive's path (caller frees). */
wf_status metalbear_backup_run(const char *data_dir, const char *backup_dir,
                               int retain, char **out_archive);

/* Start a timer that runs metalbear_backup_run every interval_seconds on a
 * background thread. The first run is one interval after start. Returns NULL
 * and does nothing when interval_seconds < 1. */
metalbear_backup_schedule *
metalbear_backup_schedule_start(const char *data_dir, const char *backup_dir,
                                int retain, long interval_seconds);

/* Stop the timer and wait for a run in progress to finish. */
void metalbear_backup_schedule_free(metalbear_backup_schedule *schedule);

#ifdef __cplusplus
}
#endif

#endif
