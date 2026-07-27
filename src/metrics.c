/*
 * metrics.c — the counter table behind `GET /metrics`.
 *
 * One atomic per metric, incremented from the request path. Relaxed ordering
 * is deliberate: a counter carries no happens-before relationship with
 * anything else, and a scrape reading a value one increment stale is
 * indistinguishable from a scrape that arrived a microsecond earlier.
 */

#include "metalbear/metrics.h"

#include <stdatomic.h>
#include <stddef.h>

static _Atomic uint64_t counters[METALBEAR_METRIC_COUNT];

/* Name and help text, in enum order. Kept beside the enum rather than built
 * at the call site so a metric cannot be exported under two spellings. */
static const struct {
    const char *name;
    const char *help;
} descriptions[METALBEAR_METRIC_COUNT] = {
    [METALBEAR_METRIC_XRPC_REQUESTS] =
        { "xrpc_requests_total", "XRPC requests received." },
    [METALBEAR_METRIC_XRPC_REJECTED] =
        { "xrpc_rejected_total",
          "XRPC requests refused before a handler ran." },
    [METALBEAR_METRIC_ACCOUNTS_CREATED] =
        { "accounts_created_total", "Accounts created on this host." },
    [METALBEAR_METRIC_ACCOUNTS_DELETED] =
        { "accounts_deleted_total", "Accounts deleted from this host." },
    [METALBEAR_METRIC_SESSIONS_CREATED] =
        { "sessions_created_total", "Sessions issued." },
    [METALBEAR_METRIC_LOGIN_FAILURES] =
        { "login_failures_total", "Logins refused." },
    [METALBEAR_METRIC_COMMITS_SEQUENCED] =
        { "commits_sequenced_total",
          "Signed repository commits published to the firehose." },
    [METALBEAR_METRIC_BLOBS_UPLOADED] =
        { "blobs_uploaded_total", "Blobs stored." },
    [METALBEAR_METRIC_TAKEDOWNS_APPLIED] =
        { "takedowns_applied_total", "Takedowns applied to a subject." },
    [METALBEAR_METRIC_FIREHOSE_SUBSCRIBES] =
        { "firehose_subscribes_total",
          "Firehose subscribers that have connected." },
    [METALBEAR_METRIC_FIREHOSE_DISCONNECTS] =
        { "firehose_disconnects_total",
          "Firehose subscribers that have disconnected." },
    [METALBEAR_METRIC_DNS_FAILURES] =
        { "dns_failures_total", "Handle DNS records that could not be written." },
    [METALBEAR_METRIC_CRAWL_FAILURES] =
        { "crawl_failures_total", "requestCrawl announcements that failed." },
};

void metalbear_metrics_inc(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return;
    atomic_fetch_add_explicit(&counters[metric], 1, memory_order_relaxed);
}

uint64_t metalbear_metrics_get(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return 0;
    return atomic_load_explicit(&counters[metric], memory_order_relaxed);
}

const char *metalbear_metric_name(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return NULL;
    return descriptions[metric].name;
}

const char *metalbear_metric_help(metalbear_metric metric) {
    if (metric < 0 || metric >= METALBEAR_METRIC_COUNT) return NULL;
    return descriptions[metric].help;
}

void metalbear_metrics_reset(void) {
    for (int i = 0; i < METALBEAR_METRIC_COUNT; i++)
        atomic_store_explicit(&counters[i], 0, memory_order_relaxed);
}
