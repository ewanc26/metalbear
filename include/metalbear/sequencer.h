#ifndef METALBEAR_SEQUENCER_H
#define METALBEAR_SEQUENCER_H

#include "metalbear/repo_store.h"
#include "wolfram/xrpc_server.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_sequencer metalbear_sequencer;

/*
 * Open the host-wide firehose log.
 *
 * Takes no account: subscribeRepos is one stream for the server, and the log
 * exists before any account does. It used to seed the configured bootstrap
 * account's #identity/#account into a fresh log, which is now emitted by
 * createAccount for every account alike.
 */
wf_status metalbear_sequencer_open(const char *path,
                                   metalbear_sequencer **out);
void metalbear_sequencer_free(metalbear_sequencer *sequencer);

/* Callback installed on metalbear_repo_store; persists a framed firehose event. */
void metalbear_sequencer_repo_event(const metalbear_repo_store_event *event,
                                    void *context);

wf_status metalbear_sequencer_register(metalbear_sequencer *sequencer,
                                       wf_xrpc_server *server);
int64_t metalbear_sequencer_current(metalbear_sequencer *sequencer);

/* Heal a missing tail event after a crash or when adopting an existing repo. */
wf_status metalbear_sequencer_reconcile_repo(metalbear_sequencer *sequencer,
                                             metalbear_repo_store *repo);
wf_status metalbear_sequencer_reconcile_account(
    metalbear_sequencer *sequencer, const char *did, int active);
wf_status metalbear_sequencer_account_status(metalbear_sequencer *sequencer,
                                             const char *did, int active,
                                             const char *status);
wf_status metalbear_sequencer_account_activation(
    metalbear_sequencer *sequencer, const char *did, const char *handle,
    metalbear_repo_store *repo);

/* Prune events older than max_age_seconds. Keeps at least min_events. */
/*
 * Called after an event is durably sequenced, so the PDS can tell its relays
 * it has new data. The reference PDS does this from its sequencer for the same
 * reason: a relay that has not dialled a quiet host has no other prompt to.
 * Invoked on the writing thread — keep it cheap and do not block.
 */
typedef void (*metalbear_sequencer_notify_cb)(void *ctx);

void metalbear_sequencer_set_notify(metalbear_sequencer *sequencer,
                                    metalbear_sequencer_notify_cb cb,
                                    void *ctx);

wf_status metalbear_sequencer_retain(metalbear_sequencer *sequencer,
                                     int64_t max_age_seconds,
                                     int64_t min_events);

#ifdef __cplusplus
}
#endif

#endif
