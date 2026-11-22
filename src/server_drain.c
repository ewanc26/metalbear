/*
 * server_drain.c — graceful-shutdown write gate (issue #164).
 *
 * Wolfram v0.45.0 has no global quiesce hook, and its auth callback maps
 * failures to 400/401 only. The one seam that can produce a 503 is the
 * registered procedure itself, so mutating XRPC procedures are registered
 * through metalbear_register_write_procedure(), which wraps the real handler.
 *
 * The wrapper latches an in-flight count. metalbear_drain_begin() flips the
 * draining flag, refuses new writes with 503, then waits for the count to
 * reach zero (bounded by the configured timeout) before the caller flushes
 * the sequencer and lets the listener stop. A write that entered before the
 * latch is therefore always allowed to commit; a write that arrives after it
 * never touches the repo.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/server_drain.h"
#include "metalbear/log.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct write_wrapper {
    wf_xrpc_procedure_handler handler;
    void *ctx;
    struct write_wrapper *next;
} write_wrapper;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_idle = PTHREAD_COND_INITIALIZER;
static atomic_bool g_draining;
static atomic_int g_inflight;
static int64_t g_timeout_seconds = 5;
static write_wrapper *g_wrappers;
static bool g_shutdown;

static wf_status wrapped_procedure(void *ctx, const wf_xrpc_request *req,
                                   wf_xrpc_response *resp) {
    write_wrapper *w = ctx;
    bool draining;

    pthread_mutex_lock(&g_mutex);
    draining = atomic_load(&g_draining) || g_shutdown;
    if (!draining) atomic_fetch_add(&g_inflight, 1);
    pthread_mutex_unlock(&g_mutex);

    if (draining) {
        wf_xrpc_response_set_error(resp, 503, "ServiceUnavailable",
                                   "Server is shutting down; retry the write");
        return WF_OK;
    }

    wf_status status = w->handler(w->ctx, req, resp);

    pthread_mutex_lock(&g_mutex);
    if (atomic_fetch_sub(&g_inflight, 1) == 1) pthread_cond_broadcast(&g_idle);
    pthread_mutex_unlock(&g_mutex);
    return status;
}

wf_status metalbear_register_write_procedure(wf_xrpc_server *server,
                                             const char *nsid,
                                             wf_xrpc_procedure_handler handler,
                                             void *ctx) {
    if (!server || !nsid || !handler) return WF_ERR_INVALID_ARG;
    write_wrapper *w = calloc(1, sizeof(*w));
    if (!w) return WF_ERR_ALLOC;
    w->handler = handler;
    w->ctx = ctx;

    wf_status status =
        wf_xrpc_server_register_procedure(server, nsid, wrapped_procedure, w);
    if (status != WF_OK) {
        free(w);
        return status;
    }
    pthread_mutex_lock(&g_mutex);
    w->next = g_wrappers;
    g_wrappers = w;
    pthread_mutex_unlock(&g_mutex);
    return WF_OK;
}

bool metalbear_drain_is_active(void) {
    return atomic_load(&g_draining) || g_shutdown;
}

void metalbear_drain_reset(int64_t timeout_seconds) {
    /* Wrapper contexts are handed to Wolfram as handler ctx and stay live for
     * the process lifetime: a MetalBear daemon starts one server, and freeing
     * them here could leave a still-running listener holding a dangling
     * pointer. The set is bounded by the number of registered write routes. */
    pthread_mutex_lock(&g_mutex);
    g_shutdown = false;
    atomic_store(&g_draining, false);
    atomic_store(&g_inflight, 0);
    g_timeout_seconds = timeout_seconds;
    pthread_cond_broadcast(&g_idle);
    pthread_mutex_unlock(&g_mutex);
}

int metalbear_drain_begin(void) {
    pthread_mutex_lock(&g_mutex);
    if (!atomic_exchange(&g_draining, true)) {
        int inflight = atomic_load(&g_inflight);
        LOG_INFO(
            "drain: refusing new writes, waiting for %d in flight (timeout "
            "%llds)",
            inflight, (long long)g_timeout_seconds);
    }
    while (atomic_load(&g_inflight) > 0) {
        if (g_timeout_seconds == 0) break;
        if (g_timeout_seconds > 0) {
            struct timespec deadline;
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += g_timeout_seconds;
            int rc = pthread_cond_timedwait(&g_idle, &g_mutex, &deadline);
            if (rc == ETIMEDOUT) break;
        } else {
            pthread_cond_wait(&g_idle, &g_mutex);
        }
    }
    int remaining = atomic_load(&g_inflight);
    pthread_mutex_unlock(&g_mutex);
    if (remaining > 0)
        LOG_WARN("drain: %d write(s) still in flight after timeout", remaining);
    else
        LOG_INFO("drain: all writes quiescent");
    return remaining;
}

void metalbear_drain_shutdown(void) {
    pthread_mutex_lock(&g_mutex);
    g_shutdown = true;
    atomic_store(&g_draining, true);
    pthread_cond_broadcast(&g_idle);
    pthread_mutex_unlock(&g_mutex);
}
