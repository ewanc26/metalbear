#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

/*
 * account_deletion.c -- the one hard-delete sequence, shared by the admin
 * deleteAccount route and the scheduled deletion sweep (issue #159).
 *
 * Both paths must produce identical observable effects: the removal is
 * announced on the host sequencer before any state goes away, the account's
 * earlier firehose history is purged, registry and moderation state are
 * dropped, the handle's DNS record is retracted, and the data directory is
 * removed. Keeping it in one place means the sweep cannot silently drift from
 * what an operator-triggered delete does.
 */

#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"

#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int rmtree_remove_cb(const char *path, const struct stat *st, int type,
                            struct FTW *ftwbuf) {
    (void)st;
    (void)type;
    (void)ftwbuf;
    return remove(path);
}

static void remove_tree(const char *path) {
    nftw(path, rmtree_remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

void metalbear_hard_delete_account(metalbear_server *server, const char *did,
                                   const char *data_dir, const char *handle) {
    if (!server || !did || !did[0]) return;

    /* Announce against the host log first: resolving a context after the
     * registry row is gone only worked when the account happened to be in the
     * in-memory cache, so relays could miss the deletion entirely. */
    metalbear_sequencer_account_status(server->sequencer, did, 0, "deleted");
    int64_t purged = 0;
    metalbear_sequencer_purge_account(server->sequencer, did, &purged);
    metalbear_metrics_inc(METALBEAR_METRIC_ACCOUNTS_DELETED);
    LOG_INFO("hard_delete_account: purged %lld firehose events for did=%s",
             (long long)purged, did);

    /* Drop any cached context first: a request must not be able to resolve a
     * context whose data directory is about to be removed. A context still
     * referenced by an in-flight request is closed when that reference goes. */
    metalbear_account_cache_drop(server->account_cache, did);
    metalbear_account_registry_remove(server->registry, did);
    metalbear_account_registry_clear_takedowns_for_did(server->registry, did);
    /* A stale TXT record would keep resolving a handle this host no longer
     * serves. */
    retract_handle_dns(server, handle);
    if (data_dir && data_dir[0]) remove_tree(data_dir);
}
