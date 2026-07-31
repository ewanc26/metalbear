#ifndef METALBEAR_UPDATE_WATCHER_H
#define METALBEAR_UPDATE_WATCHER_H

#include "wolfram/xrpc.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_update_watcher metalbear_update_watcher;

typedef struct metalbear_update_watcher_config {
    bool enabled;
    int64_t interval_seconds;
    const char *metalbear_repo;
    const char *wolfram_repo;
    const char *current_metalbear_version;
    const char *current_wolfram_version;
} metalbear_update_watcher_config;

wf_status metalbear_update_watcher_open(
    const metalbear_update_watcher_config *config,
    metalbear_update_watcher **out);

void metalbear_update_watcher_free(metalbear_update_watcher *watcher);

#ifdef __cplusplus
}
#endif

#endif
