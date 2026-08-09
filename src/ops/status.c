#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "status.h"

#include "../server_internal.h"

#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "wolfram/xrpc.h"

#include <cJSON.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ---- Dynamic landing page (GET /) ---- */

/* Minimal HTML escaping for untrusted display strings (handles/DIDs). */
static char *html_escape(const char *s) {
    if (!s) return strdup("");
    size_t need = 1;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '&':
                need += 5;
                break; /* &amp;  */
            case '<':
                need += 4;
                break; /* &lt;   */
            case '>':
                need += 4;
                break; /* &gt;   */
            case '"':
                need += 6;
                break; /* &quot; */
            default:
                need += 1;
                break;
        }
    }
    char *out = malloc(need);
    if (!out) return NULL;
    char *q = out;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '&':
                memcpy(q, "&amp;", 5);
                q += 5;
                break;
            case '<':
                memcpy(q, "&lt;", 4);
                q += 4;
                break;
            case '>':
                memcpy(q, "&gt;", 4);
                q += 4;
                break;
            case '"':
                memcpy(q, "&quot;", 6);
                q += 6;
                break;
            default:
                *q++ = *p;
                break;
        }
    }
    *q = '\0';
    return out;
}

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} sb_t;

static bool sb_append(sb_t *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) return false;
    if (sb->len + (size_t)need + 1 > sb->cap) {
        size_t ncap = sb->cap ? sb->cap * 2 : 4096;
        while (ncap < sb->len + (size_t)need + 1) ncap *= 2;
        char *nb = realloc(sb->buf, ncap);
        if (!nb) return false;
        sb->buf = nb;
        sb->cap = ncap;
    }
    va_start(ap, fmt);
    vsnprintf(sb->buf + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);
    sb->len += (size_t)need;
    return true;
}

/* ---- /metrics (admin-gated Prometheus exposition) ----
 * Behind the admin password. An open endpoint would publish the account count
 * and the write rate of a private host to anyone who asked, and hand an
 * unauthenticated caller an unbounded amount of work per request. Prometheus
 * has had basic_auth in its scrape config for as long as it has existed.
 */
/* Prometheus label values may not contain a raw quote, backslash or newline;
 * a route name arrives from the network and could hold any of them, and one
 * bad character loses the whole exposition rather than one series. */
static bool append_escaped_label(sb_t *sb, const char *value) {
    char escaped[256];
    size_t o = 0;
    for (const char *p = value; *p && o + 2 < sizeof(escaped); p++) {
        if (*p == '"' || *p == '\\')
            escaped[o++] = '\\';
        else if (*p == '\n') {
            escaped[o++] = '\\';
            escaped[o++] = 'n';
            continue;
        }
        escaped[o++] = *p;
    }
    escaped[o] = '\0';
    return sb_append(sb, "%s", escaped);
}

typedef struct route_render {
    sb_t *sb;
    bool ok;
} route_render;

static void render_route(void *ctx, const char *route, uint64_t requests,
                         uint64_t errors) {
    route_render *out = ctx;
    if (!out->ok) return;
    out->ok = sb_append(out->sb, "metalbear_route_requests_total{route=\"") &&
              append_escaped_label(out->sb, route) &&
              sb_append(out->sb, "\"} %llu\n", (unsigned long long)requests) &&
              sb_append(out->sb, "metalbear_route_errors_total{route=\"") &&
              append_escaped_label(out->sb, route) &&
              sb_append(out->sb, "\"} %llu\n", (unsigned long long)errors);
}

#ifdef WF_XRPC_HAS_REQUEST_OBSERVER
/*
 * Every finished request, with the status it answered.
 *
 * Counted here rather than in the auth callback, which is where the totals
 * used to come from: that callback runs before the status is known, never
 * runs for the plain HTTP routes, and never runs for a request the rate
 * limiter refused — so the old totals were a subset that could not be named
 * and carried no outcome at all.
 */
static void observe_request(void *ctx, const char *nsid, const char *path,
                            const char *method, unsigned int status) {
    (void)ctx;
    (void)method;
    metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS);
    if (status >= 400) metalbear_metrics_inc(METALBEAR_METRIC_REQUESTS_FAILED);
    metalbear_metrics_record_request(nsid, path, status);
}
#endif

static wf_status metrics_handler(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (!admin_authenticated(server, req)) {
        wf_xrpc_response_set_error(resp, 401, "AuthenticationRequired",
                                   "Authentication required");
        return WF_OK;
    }

    sb_t sb = {0};
    bool ok =
        sb_append(&sb,
                  "# HELP metalbear_build_info Version of the running server.\n"
                  "# TYPE metalbear_build_info gauge\n"
                  "metalbear_build_info{version=\"%s\"} 1\n",
                  METALBEAR_VERSION);

    for (int i = 0; ok && i < METALBEAR_METRIC_COUNT; i++) {
        const char *name = metalbear_metric_name(i);
        const char *help = metalbear_metric_help(i);
        if (!name) continue;
        ok = sb_append(&sb,
                       "# HELP metalbear_%s %s\n"
                       "# TYPE metalbear_%s counter\n"
                       "metalbear_%s %llu\n",
                       name, help ? help : "", name, name,
                       (unsigned long long)metalbear_metrics_get(i));
    }

    /*
     * Per-route series. The label is escaped because a route name reaches
     * here from the network — the AppView proxy forwards NSIDs this server
     * has never heard of — and a quote inside a label value produces an
     * exposition Prometheus rejects wholesale, losing every other metric with
     * it.
     */
    if (ok) {
        ok = sb_append(
            &sb, "# HELP metalbear_route_requests_total Requests per route.\n"
                 "# TYPE metalbear_route_requests_total counter\n"
                 "# HELP metalbear_route_errors_total 4xx and 5xx responses "
                 "per route.\n"
                 "# TYPE metalbear_route_errors_total counter\n");
        route_render ctx_render = {&sb, ok};
        metalbear_metrics_visit_routes(render_route, &ctx_render);
        ok = ctx_render.ok;
    }

    /* Account counts, read from the registry at scrape time. */
    size_t total = 0, active = 0, taken_down = 0;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) ==
        WF_OK) {
        total = count;
        for (size_t i = 0; i < count; i++) {
            if (account_is_taken_down(server, entries[i].did))
                taken_down++;
            else if (entries[i].active)
                active++;
        }
        metalbear_account_entries_free(entries, count);
    }
    if (ok)
        ok = sb_append(
            &sb,
            "# HELP metalbear_accounts Accounts on this host by status.\n"
            "# TYPE metalbear_accounts gauge\n"
            "metalbear_accounts{status=\"active\"} %zu\n"
            "metalbear_accounts{status=\"inactive\"} %zu\n"
            "metalbear_accounts{status=\"takendown\"} %zu\n",
            active, total - active - taken_down, taken_down);

    /*
     * The firehose cursor. A relay that has stopped consuming shows up as this
     * climbing while nothing downstream moves, and it is the single number
     * worth alerting on: a PDS whose sequence has stalled is one nobody can
     * tell apart from a PDS that is down.
     */
    if (ok)
        ok = sb_append(
            &sb,
            "# HELP metalbear_firehose_seq Most recent firehose sequence "
            "number.\n"
            "# TYPE metalbear_firehose_seq gauge\n"
            "metalbear_firehose_seq %lld\n",
            (long long)metalbear_sequencer_current(server->sequencer));

    if (ok)
        ok = sb_append(&sb,
                       "# HELP metalbear_uptime_seconds Seconds since this "
                       "process began serving.\n"
                       "# TYPE metalbear_uptime_seconds gauge\n"
                       "metalbear_uptime_seconds %lld\n",
                       (long long)(time(NULL) - server->started_at));

    if (!ok) {
        free(sb.buf);
        return WF_ERR_ALLOC;
    }
    wf_xrpc_response_set_content_type(resp, "text/plain; version=0.0.4");
    wf_xrpc_response_set_body(resp, sb.buf, sb.len);
    free(sb.buf);
    return WF_OK;
}

static wf_status landing_handler(void *ctx, const wf_xrpc_request *req,
                                 wf_xrpc_response *resp) {
    (void)req;
    metalbear_server *server = ctx;

    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) !=
        WF_OK) {
        entries = NULL;
        count = 0;
    }

    sb_t sb = {0};
    if (!sb_append(&sb,
                   "<!DOCTYPE html>\n"
                   "<html lang=\"en\">\n"
                   "<head><meta charset=\"utf-8\">\n"
                   "<title>MetalBear — hosted accounts</title>\n"
                   "</head>\n"
                   "<body>\n"
                   "<h1>MetalBear " METALBEAR_VERSION
                   " — built on Wolfram " WOLFRAM_VERSION_STRING "</h1>\n"
                   "<p><small>" METALBEAR_RELEASE_STAGE
                   " · commit " METALBEAR_BUILD_COMMIT
                   " · built " METALBEAR_BUILD_TIME "</small></p>\n"
                   "<p>An AT Protocol Personal Data Server built on Wolfram. "
                   "The XRPC API lives under <code>/xrpc/</code>. Identity "
                   "documents are published at "
                   "<code>/.well-known/did.json</code> and "
                   "<code>/.well-known/atproto-did</code>.</p>\n"
                   "<h2>Hosted accounts</h2>\n")) {
        metalbear_account_entries_free(entries, count);
        return WF_ERR_ALLOC;
    }

    if (count == 0) {
        if (!sb_append(&sb,
                       "<p>No accounts are hosted on this server yet.</p>\n")) {
            metalbear_account_entries_free(entries, count);
            return WF_ERR_ALLOC;
        }
    } else {
        if (!sb_append(&sb, "<ul>\n")) {
            metalbear_account_entries_free(entries, count);
            return WF_ERR_ALLOC;
        }
        for (size_t i = 0; i < count; i++) {
            char *handle = html_escape(entries[i].handle);
            char *did = html_escape(entries[i].did);
            const char *state = account_is_taken_down(server, entries[i].did)
                                    ? "takendown"
                                : entries[i].active ? "active"
                                                    : "deactivated";
            bool ok = handle && did &&
                      sb_append(&sb,
                                "<li><code>%s</code> — <code>%s</code> "
                                "(<span class=\"state\">%s</span>)</li>\n",
                                handle, did, state);
            free(handle);
            free(did);
            if (!ok) {
                metalbear_account_entries_free(entries, count);
                return WF_ERR_ALLOC;
            }
        }
        if (!sb_append(&sb, "</ul>\n")) {
            metalbear_account_entries_free(entries, count);
            return WF_ERR_ALLOC;
        }
    }

    if (!sb_append(&sb, "</body>\n</html>\n")) {
        metalbear_account_entries_free(entries, count);
        return WF_ERR_ALLOC;
    }

    wf_xrpc_response_set_body(resp, sb.buf, sb.len);
    wf_xrpc_response_set_content_type(resp, "text/html; charset=utf-8");
    free(sb.buf);
    metalbear_account_entries_free(entries, count);
    return WF_OK;
}

/* ---- /_debug/health (admin-gated) ----
 * A JSON dump of everything an operator needs to triage a host: what versions
 * are running, how long it has been up, what it believes its identity and
 * configuration are, how many accounts it holds, where the firehose has got
 * to, and the request counters. Every state value is read from the real
 * object at request time rather than mirrored, for the same reason the
 * /metrics gauges are: a mirrored copy is a second version of the truth and
 * drifts from the first. Gated behind the admin password like /metrics,
 * because the identity and capability details are an operator's own.
 */
typedef struct debug_route_render {
    cJSON *routes;
    bool ok;
} debug_route_render;

static void render_debug_route(void *ctx, const char *route, uint64_t requests,
                               uint64_t errors) {
    debug_route_render *out = ctx;
    if (!out->ok) return;
    cJSON *entry = cJSON_CreateObject();
    if (!entry) {
        out->ok = false;
        return;
    }
    cJSON_AddNumberToObject(entry, "requests", (double)requests);
    cJSON_AddNumberToObject(entry, "errors", (double)errors);
    if (!cJSON_AddItemToObject(out->routes, route, entry)) {
        cJSON_Delete(entry);
        out->ok = false;
    }
}

static wf_status debug_health_handler(void *ctx, const wf_xrpc_request *req,
                                      wf_xrpc_response *resp) {
    metalbear_server *server = ctx;
    if (!admin_authenticated(server, req)) {
        wf_xrpc_response_set_error(resp, 401, "AuthenticationRequired",
                                   "Authentication required");
        return WF_OK;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return WF_ERR_ALLOC;

    cJSON *build = cJSON_CreateObject();
    if (build) {
        cJSON_AddStringToObject(build, "name", "MetalBear");
        cJSON_AddStringToObject(build, "metalbearVersion", METALBEAR_VERSION);
        cJSON_AddStringToObject(build, "wolframVersion",
                                WOLFRAM_VERSION_STRING);
        cJSON_AddStringToObject(build, "commit", METALBEAR_BUILD_COMMIT);
        cJSON_AddStringToObject(build, "builtAt", METALBEAR_BUILD_TIME);
        cJSON_AddStringToObject(build, "releaseStage", METALBEAR_RELEASE_STAGE);
        cJSON_AddItemToObject(root, "build", build);
    }

    cJSON *process = cJSON_CreateObject();
    if (process) {
        char started_iso[40];
        struct tm started_tm;
        gmtime_r(&server->started_at, &started_tm);
        strftime(started_iso, sizeof(started_iso), "%Y-%m-%dT%H:%M:%SZ",
                 &started_tm);
        cJSON_AddNumberToObject(process, "pid", (double)getpid());
        cJSON_AddNumberToObject(process, "startedAt",
                                (double)server->started_at);
        cJSON_AddStringToObject(process, "startedAtIso", started_iso);
        cJSON_AddNumberToObject(process, "uptimeSeconds",
                                (double)(time(NULL) - server->started_at));
        cJSON_AddItemToObject(root, "process", process);
    }

    cJSON *identity = cJSON_CreateObject();
    if (identity) {
        if (server->service_did)
            cJSON_AddStringToObject(identity, "serviceDid",
                                    server->service_did);
        if (server->public_url)
            cJSON_AddStringToObject(identity, "publicUrl", server->public_url);
        if (server->user_domain)
            cJSON_AddStringToObject(identity, "userDomain",
                                    server->user_domain);
        if (server->data_directory)
            cJSON_AddStringToObject(identity, "dataDirectory",
                                    server->data_directory);
        if (server->plc_url)
            cJSON_AddStringToObject(identity, "plcUrl", server->plc_url);
        if (server->appview_url)
            cJSON_AddStringToObject(identity, "appviewUrl",
                                    server->appview_url);
        if (server->appview_did)
            cJSON_AddStringToObject(identity, "appviewDid",
                                    server->appview_did);
        /* Crawlers arrive as a comma-separated list; a client should not have
         * to split a string to read the configuration. */
        if (server->crawlers) {
            cJSON *crawlers = cJSON_CreateArray();
            if (crawlers) {
                char *copy = strdup(server->crawlers);
                char *save = NULL;
                for (char *tok = copy ? strtok_r(copy, ",", &save) : NULL; tok;
                     tok = strtok_r(NULL, ",", &save)) {
                    while (*tok == ' ' || *tok == '\t') tok++;
                    size_t len = strlen(tok);
                    while (len > 0 &&
                           (tok[len - 1] == ' ' || tok[len - 1] == '\t'))
                        tok[--len] = '\0';
                    if (*tok)
                        cJSON_AddItemToArray(crawlers, cJSON_CreateString(tok));
                }
                free(copy);
                cJSON_AddItemToObject(identity, "crawlers", crawlers);
            }
        }
        cJSON_AddBoolToObject(identity, "development", server->development);
        cJSON_AddBoolToObject(identity, "inviteRequired",
                              server->invite_required);
        cJSON_AddNumberToObject(identity, "blobUploadLimit",
                                (double)server->blob_upload_limit);
        cJSON_AddBoolToObject(identity, "adminConfigured",
                              server->admin_password &&
                                  server->admin_password[0]);
        cJSON_AddItemToObject(root, "identity", identity);
    }

    cJSON *retention = cJSON_CreateObject();
    if (retention) {
        cJSON_AddNumberToObject(retention, "maxAgeSeconds",
                                (double)server->retention_max_age);
        cJSON_AddNumberToObject(retention, "minEvents",
                                (double)server->retention_min_events);
        cJSON_AddItemToObject(root, "retention", retention);
    }

    size_t total = 0, active = 0, taken_down = 0;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) ==
        WF_OK) {
        total = count;
        for (size_t i = 0; i < count; i++) {
            if (account_is_taken_down(server, entries[i].did))
                taken_down++;
            else if (entries[i].active)
                active++;
        }
        metalbear_account_entries_free(entries, count);
    }
    cJSON *accounts = cJSON_CreateObject();
    if (accounts) {
        cJSON_AddNumberToObject(accounts, "total", (double)total);
        cJSON_AddNumberToObject(accounts, "active", (double)active);
        cJSON_AddNumberToObject(accounts, "inactive",
                                (double)(total - active - taken_down));
        cJSON_AddNumberToObject(accounts, "takenDown", (double)taken_down);
        cJSON_AddItemToObject(root, "accounts", accounts);
    }

    cJSON *firehose = cJSON_CreateObject();
    if (firehose) {
        cJSON_AddNumberToObject(
            firehose, "sequence",
            (double)metalbear_sequencer_current(server->sequencer));
        cJSON_AddItemToObject(root, "firehose", firehose);
    }

    cJSON *capabilities = cJSON_CreateObject();
    if (capabilities) {
        cJSON_AddBoolToObject(capabilities, "lexiconValidation",
                              server->lexicons != NULL);
        cJSON_AddBoolToObject(capabilities, "handleDnsConfigured",
                              server->handle_dns != NULL);
        cJSON_AddBoolToObject(capabilities, "oauthStoreConfigured",
                              server->oauth != NULL);
        cJSON_AddBoolToObject(capabilities, "plcRotationKeyConfigured",
                              server->plc_rotation != NULL);
        cJSON_AddBoolToObject(capabilities, "emailConfigured",
                              server->email != NULL);
        cJSON_AddBoolToObject(capabilities, "updateWatcherConfigured",
                              server->update_watcher != NULL);
        cJSON_AddItemToObject(root, "capabilities", capabilities);
    }

    cJSON *rate_limits = cJSON_CreateObject();
    if (rate_limits) {
        cJSON *general = cJSON_CreateObject();
        if (general) {
            cJSON_AddBoolToObject(general, "configured",
                                  server->rate_limiter != NULL);
            cJSON_AddNumberToObject(general, "requestsPerWindow",
                                    (double)server->rate_limit_budget);
            cJSON_AddNumberToObject(general, "windowSeconds",
                                    (double)server->rate_limit_window);
            cJSON_AddItemToObject(rate_limits, "general", general);
        }
        /* The endpoint-specific budgets are the reference PDS's exact values,
         * and they are not configurable (see server_start, where each rl_*
         * limiter is created). This table mirrors those literals so an
         * operator can see which security-sensitive endpoints are throttled
         * and how. */
        static const struct {
            const char *name;
            unsigned int points;
            unsigned int duration_seconds;
        } tiers[] = {
            {"createSessionDay", 300, 86400},
            {"createSession5min", 30, 300},
            {"requestPasswordResetDay", 50, 86400},
            {"requestPasswordResetHour", 15, 3600},
            {"requestAccountDeleteDay", 15, 86400},
            {"requestAccountDeleteHour", 5, 3600},
            {"requestEmailConfirmationDay", 15, 86400},
            {"requestEmailConfirmationHour", 5, 3600},
            {"requestEmailUpdateDay", 15, 86400},
            {"requestEmailUpdateHour", 5, 3600},
        };
        for (size_t i = 0; i < sizeof(tiers) / sizeof(tiers[0]); i++) {
            cJSON *tier = cJSON_CreateObject();
            if (tier) {
                cJSON_AddBoolToObject(tier, "configured", true);
                cJSON_AddNumberToObject(tier, "requestsPerWindow",
                                        (double)tiers[i].points);
                cJSON_AddNumberToObject(tier, "windowSeconds",
                                        (double)tiers[i].duration_seconds);
                cJSON_AddItemToObject(rate_limits, tiers[i].name, tier);
            }
        }
        cJSON_AddItemToObject(root, "rateLimits", rate_limits);
    }

    cJSON *metrics = cJSON_CreateObject();
    if (metrics) {
        for (int i = 0; i < METALBEAR_METRIC_COUNT; i++) {
            const char *name = metalbear_metric_name(i);
            if (!name) continue;
            cJSON_AddNumberToObject(metrics, name,
                                    (double)metalbear_metrics_get(i));
        }
        cJSON_AddItemToObject(root, "metrics", metrics);
    }

    cJSON *routes = cJSON_CreateObject();
    if (routes) {
        debug_route_render render = {routes, true};
        metalbear_metrics_visit_routes(render_debug_route, &render);
        if (render.ok)
            cJSON_AddItemToObject(root, "routes", routes);
        else
            cJSON_Delete(routes);
    }

    return set_json(resp, root);
}

wf_status metalbear_status_register(metalbear_server *server) {
    wf_status status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/metrics", metrics_handler, server);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_http_route(
        server->xrpc, "GET", "/_debug/health", debug_health_handler, server);
    if (status != WF_OK) return status;
    status = wf_xrpc_server_register_http_route(server->xrpc, "GET", "/",
                                                landing_handler, server);
    if (status != WF_OK) return status;
#ifdef WF_XRPC_HAS_REQUEST_OBSERVER
    /* Guarded so this still builds against a Wolfram without the observer;
     * without it the per-route breakdown is simply absent rather than the
     * build being broken. */
    wf_xrpc_server_set_request_observer(server->xrpc, observe_request, server);
#endif
    return WF_OK;
}
