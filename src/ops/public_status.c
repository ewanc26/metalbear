#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

/*
 * public_status.c — the opt-in, aggregate-only resource snapshot behind
 * [server] public_status / METALBEAR_PUBLIC_STATUS (issue #267).
 *
 * Every number here describes the host or the process, never an individual
 * account. Route labels are the NSID the XRPC observer already recorded; raw
 * HTTP paths, which can carry a DID or handle, are folded into `other`. The
 * fuller per-account and per-status view stays behind /metrics' admin check.
 *
 * Sampling a whole directory tree on each request is acceptable because the
 * surface is opt-in and aimed at small hosts. Callers must gate on the flag:
 * disabled servers omit the object entirely rather than publishing zeroes.
 */

#include "metalbear/ops/public_status.h"

#include "../server_internal.h"

#include "metalbear/account/account.h"
#include "metalbear/account/account_registry.h"
#include "metalbear/log.h"
#include "metalbear/ops/metrics.h"
#include "metalbear/sequencer.h"

#include <cJSON.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#endif

static uint64_t add_u64(uint64_t a, uint64_t b) {
    return (UINT64_MAX - a < b) ? UINT64_MAX : a + b;
}

/* Sum file bytes under `path` without following symlinks. Directory entries
 * are walked depth-first with a hard depth cap: a hostile or merely unusual
 * data directory must not turn a status request into a stack overflow. */
static uint64_t directory_bytes(const char *path, unsigned int depth) {
    if (!path || depth > 32) return 0;
    DIR *dir = opendir(path);
    if (!dir) return 0;

    uint64_t total = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char *child = join_path(path, entry->d_name);
        if (!child) continue;
        struct stat st;
        if (lstat(child, &st) == 0) {
            if (S_ISREG(st.st_mode))
                total = add_u64(total, (uint64_t)st.st_size);
            else if (S_ISDIR(st.st_mode))
                total = add_u64(total, directory_bytes(child, depth + 1));
        }
        free(child);
    }
    closedir(dir);
    return total;
}

static uint64_t current_rss_bytes(void) {
#if defined(__linux__)
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            unsigned long kb = 0;
            if (strncmp(line, "VmRSS:", 6) == 0 &&
                sscanf(line + 6, "%lu", &kb) == 1) {
                fclose(f);
                return (uint64_t)kb * 1024;
            }
        }
        fclose(f);
    }
#elif defined(__APPLE__)
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info,
                  &count) == KERN_SUCCESS)
        return (uint64_t)info.resident_size;
#endif
    /* Peak RSS is the best portable fallback. It is an upper bound rather
     * than a sample, but never a fabricated number. */
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#if defined(__APPLE__)
        return (uint64_t)usage.ru_maxrss;
#else
        return (uint64_t)usage.ru_maxrss * 1024;
#endif
    }
    return 0;
}

static uint64_t open_fd_count(void) {
#ifdef __APPLE__
    const char *fd_dir = "/dev/fd";
#else
    const char *fd_dir = "/proc/self/fd";
#endif
    DIR *dir = opendir(fd_dir);
    if (!dir) return 0;
    uint64_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        count++;
    }
    closedir(dir);
    /* The scan's own directory descriptor is in the listing on both Linux
     * and macOS; report the count that existed before it was opened. */
    return count > 0 ? count - 1 : 0;
}

static unsigned int effective_thread_count(const metalbear_server *server) {
    if (server->thread_count > 0) return server->thread_count;
    /* Match Wolfram's auto-sizing heuristic so the public figure describes
     * the workers actually started rather than the configured zero. */
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus <= 0 || cpus > 64) return 8;
    return (unsigned int)(cpus * 2);
}

/* Only NSIDs are public route labels. Plain HTTP paths can contain a DID, a
 * handle or a CID, so they are counted under `other` instead of being echoed.
 * This is a deliberately narrow check: a dot-separated label with no slash,
 * colon, query or whitespace cannot be a request path. */
static bool is_public_route(const char *name) {
    if (!name || !name[0] || strchr(name, '/') || strchr(name, ':') ||
        strchr(name, '?') || strchr(name, '#'))
        return false;
    bool dot = false;
    for (const char *p = name; *p; p++) {
        if (*p == '.') dot = true;
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') return false;
    }
    return dot;
}

typedef struct {
    cJSON *routes;
    uint64_t other_requests;
    uint64_t other_errors;
} route_accumulator;

static void collect_route(void *ctx, const char *route, uint64_t requests,
                          uint64_t errors) {
    route_accumulator *acc = ctx;
    if (!is_public_route(route)) {
        acc->other_requests = add_u64(acc->other_requests, requests);
        acc->other_errors = add_u64(acc->other_errors, errors);
        return;
    }
    cJSON *entry = cJSON_GetObjectItemCaseSensitive(acc->routes, route);
    if (!entry) {
        entry = cJSON_CreateObject();
        if (!entry) return;
        cJSON_AddItemToObject(acc->routes, route, entry);
    }
    cJSON_AddNumberToObject(entry, "requests", (double)requests);
    cJSON_AddNumberToObject(entry, "errors", (double)errors);
}

static void add_disk(cJSON *root, const metalbear_server *server) {
    cJSON *disk = cJSON_CreateObject();
    if (!disk) return;

    cJSON *fs = cJSON_CreateObject();
    if (fs) {
        struct statvfs vfs;
        if (server->data_directory &&
            statvfs(server->data_directory, &vfs) == 0) {
            uint64_t block =
                vfs.f_frsize ? (uint64_t)vfs.f_frsize : (uint64_t)vfs.f_bsize;
            uint64_t total = (uint64_t)vfs.f_blocks * block;
            uint64_t free_bytes = (uint64_t)vfs.f_bfree * block;
            uint64_t available = (uint64_t)vfs.f_bavail * block;
            cJSON_AddNumberToObject(fs, "totalBytes", (double)total);
            cJSON_AddNumberToObject(fs, "usedBytes",
                                    (double)(total - free_bytes));
            cJSON_AddNumberToObject(fs, "availableBytes", (double)available);
        }
        cJSON_AddItemToObject(disk, "filesystem", fs);
    }

    cJSON_AddNumberToObject(disk, "dataDirectoryBytes",
                            (double)directory_bytes(server->data_directory, 0));

    uint64_t blob_bytes = 0;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) ==
        WF_OK) {
        for (size_t i = 0; i < count; i++) {
            char *blobs = join_path(entries[i].data_directory, "blobs");
            if (blobs) {
                blob_bytes = add_u64(blob_bytes, directory_bytes(blobs, 0));
                free(blobs);
            }
        }
        metalbear_account_entries_free(entries, count);
    }
    cJSON_AddNumberToObject(disk, "blobStoreBytes", (double)blob_bytes);
    cJSON_AddItemToObject(root, "disk", disk);
}

static void add_storage(cJSON *root, const metalbear_server *server) {
    cJSON *storage = cJSON_CreateObject();
    if (!storage) return;

    uint64_t repo_bytes = 0;
    uint64_t blob_bytes = 0;
    metalbear_account_entry *entries = NULL;
    size_t count = 0;
    if (metalbear_account_registry_list(server->registry, &entries, &count) ==
        WF_OK) {
        for (size_t i = 0; i < count; i++) {
            char *account_path =
                join_path(entries[i].data_directory, "account.sqlite3");
            if (!account_path) continue;
            metalbear_account_store *store = NULL;
            if (metalbear_account_store_open(account_path, "", &store) ==
                    WF_OK &&
                store) {
                uint64_t repo = 0;
                uint64_t blob = 0;
                if (metalbear_account_get_usage(store, &repo, &blob) == WF_OK) {
                    repo_bytes = add_u64(repo_bytes, repo);
                    blob_bytes = add_u64(blob_bytes, blob);
                }
                metalbear_account_store_free(store);
            }
            free(account_path);
        }
        metalbear_account_entries_free(entries, count);
    }
    cJSON_AddNumberToObject(storage, "repoBytes", (double)repo_bytes);
    cJSON_AddNumberToObject(storage, "blobBytes", (double)blob_bytes);
    cJSON_AddItemToObject(root, "storage", storage);
}

static void add_firehose(cJSON *root, metalbear_server *server) {
    cJSON *firehose = cJSON_CreateObject();
    if (!firehose) return;
    int64_t sequence = metalbear_sequencer_current(server->sequencer);
    int64_t last = metalbear_sequencer_last_event_epoch(server->sequencer);
    cJSON_AddNumberToObject(firehose, "sequence", (double)sequence);
    cJSON *age =
        last > 0 ? cJSON_CreateNumber((double)((int64_t)time(NULL) > last
                                                   ? (int64_t)time(NULL) - last
                                                   : 0))
                 : cJSON_CreateNull();
    if (age) cJSON_AddItemToObject(firehose, "lastEventAgeSeconds", age);
    cJSON_AddItemToObject(root, "firehose", firehose);
}

cJSON *metalbear_public_status_json(metalbear_server *server) {
    if (!server) return NULL;
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddNumberToObject(root, "uptimeSeconds",
                            (double)(time(NULL) - server->started_at));
    cJSON_AddNumberToObject(root, "workerThreads",
                            (double)effective_thread_count(server));
    cJSON_AddNumberToObject(root, "openFdCount", (double)open_fd_count());
    cJSON_AddNumberToObject(root, "rssBytes", (double)current_rss_bytes());

    double loads[3] = {0, 0, 0};
    if (getloadavg(loads, 3) == 3) {
        cJSON *load = cJSON_CreateObject();
        if (load) {
            cJSON_AddNumberToObject(load, "oneMinute", loads[0]);
            cJSON_AddNumberToObject(load, "fiveMinute", loads[1]);
            cJSON_AddNumberToObject(load, "fifteenMinute", loads[2]);
            cJSON_AddItemToObject(root, "cpuLoad", load);
        }
    }

    add_disk(root, server);
    add_storage(root, server);
    add_firehose(root, server);

    cJSON *requests = cJSON_CreateObject();
    if (requests) {
        cJSON_AddNumberToObject(
            requests, "total",
            (double)metalbear_metrics_get(METALBEAR_METRIC_REQUESTS));
        cJSON_AddNumberToObject(
            requests, "failed",
            (double)metalbear_metrics_get(METALBEAR_METRIC_REQUESTS_FAILED));
        cJSON *routes = cJSON_CreateObject();
        if (routes) {
            route_accumulator acc = {routes, 0, 0};
            metalbear_metrics_visit_routes(collect_route, &acc);
            cJSON *other = cJSON_CreateObject();
            if (other) {
                cJSON_AddNumberToObject(other, "requests",
                                        (double)acc.other_requests);
                cJSON_AddNumberToObject(other, "errors",
                                        (double)acc.other_errors);
                cJSON_AddItemToObject(routes, "other", other);
            }
            cJSON_AddItemToObject(requests, "byRoute", routes);
        }
        cJSON_AddItemToObject(root, "requests", requests);
    }

    LOG_DEBUG("public status snapshot: uptime=%lld worker_threads=%u",
              (long long)(time(NULL) - server->started_at),
              effective_thread_count(server));
    return root;
}
