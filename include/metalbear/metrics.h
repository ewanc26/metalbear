#ifndef METALBEAR_METRICS_H
#define METALBEAR_METRICS_H

/*
 * metrics.h — process-wide counters, exposed at `GET /metrics` in the
 * Prometheus text format.
 *
 * Only counters live here: values that start at zero and never go down, so a
 * scrape that is missed loses resolution rather than information. Everything
 * that describes the host's current state — how many accounts it holds, where
 * the firehose has got to — is read from the real thing at scrape time instead
 * of being mirrored here, because a mirrored gauge is a second copy of the
 * truth and drifts from the first.
 *
 * Counters are atomic and lock-free. They are written on the request path, and
 * a metric that could contend with a commit being signed would be worth less
 * than it costs.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum metalbear_metric {
    /* Every XRPC request that reached the auth callback, which is all of them
     * except the plain HTTP routes. */
    METALBEAR_METRIC_XRPC_REQUESTS = 0,
    /* Requests refused before a handler ran: no token, a bad one, the wrong
     * scope, or an account that may not act. A rate of these against the
     * total is the first sign of a misconfigured client or a credential
     * stuffing run. */
    METALBEAR_METRIC_XRPC_REJECTED,
    METALBEAR_METRIC_ACCOUNTS_CREATED,
    METALBEAR_METRIC_ACCOUNTS_DELETED,
    METALBEAR_METRIC_SESSIONS_CREATED,
    METALBEAR_METRIC_LOGIN_FAILURES,
    METALBEAR_METRIC_COMMITS_SEQUENCED,
    METALBEAR_METRIC_BLOBS_UPLOADED,
    METALBEAR_METRIC_TAKEDOWNS_APPLIED,
    /* A firehose subscriber that connected, and one that went away. The
     * difference is the number attached now; both are counters so a
     * connection storm is still visible after it ends. */
    METALBEAR_METRIC_FIREHOSE_SUBSCRIBES,
    METALBEAR_METRIC_FIREHOSE_DISCONNECTS,
    /* A DNS record that could not be written. Silent failure here is what
     * leaves every handle showing as handle.invalid. */
    METALBEAR_METRIC_DNS_FAILURES,
    /* A relay that could not be told there was new data. */
    METALBEAR_METRIC_CRAWL_FAILURES,
    METALBEAR_METRIC_COUNT
} metalbear_metric;

void metalbear_metrics_inc(metalbear_metric metric);
uint64_t metalbear_metrics_get(metalbear_metric metric);

/* The metric's Prometheus name, without the `metalbear_` prefix, and its HELP
 * text. Both are static strings; NULL for an out-of-range metric. */
const char *metalbear_metric_name(metalbear_metric metric);
const char *metalbear_metric_help(metalbear_metric metric);

/* Reset every counter. For tests; a running server never calls it, since a
 * counter that can go down breaks every rate() over it. */
void metalbear_metrics_reset(void);

#ifdef __cplusplus
}
#endif

#endif
