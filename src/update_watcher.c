#define _POSIX_C_SOURCE 200809L

#include "metalbear/update_watcher.h"
#include "metalbear/log.h"

#ifndef METALBEAR_VERSION
#define METALBEAR_VERSION "0.0.0"
#endif

#include <cJSON.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct metalbear_update_watcher {
    pthread_t thread;
    bool stop;
    int64_t interval_seconds;
    char *metalbear_repo;
    char *wolfram_repo;
    char *current_metalbear_version;
    char *current_wolfram_version;
};

/* ---- helper: semver comparison ---- */

typedef struct {
    int major, minor, patch;
} semver;

static bool parse_semver(const char *s, semver *v) {
    if (!s || !s[0]) return false;
    while (*s && (*s < '0' || *s > '9')) s++;
    if (!*s) return false;
    v->major = v->minor = v->patch = 0;
    if (sscanf(s, "%d.%d.%d", &v->major, &v->minor, &v->patch) < 1)
        return false;
    return true;
}

static bool is_newer(const char *current, const char *latest) {
    semver cur = {0}, lat = {0};
    if (!parse_semver(current, &cur)) return true;
    if (!parse_semver(latest, &lat)) return false;
    if (lat.major != cur.major) return lat.major > cur.major;
    if (lat.minor != cur.minor) return lat.minor > cur.minor;
    return lat.patch > cur.patch;
}

/* ---- HTTP GET helper ---- */

struct write_buf {
    char *data;
    size_t len;
    size_t cap;
};

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *user) {
    size_t total = size * nmemb;
    struct write_buf *buf = user;
    if (buf->len + total + 1 > buf->cap) {
        size_t ncap = buf->cap ? buf->cap * 2 : 4096;
        while (ncap < buf->len + total + 1) ncap *= 2;
        char *nb = realloc(buf->data, ncap);
        if (!nb) return 0;
        buf->data = nb;
        buf->cap = ncap;
    }
    memcpy(buf->data + buf->len, contents, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

static char *http_get(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct write_buf buf = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     "MetalBear-update-watcher/" METALBEAR_VERSION);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        free(buf.data);
        return NULL;
    }
    return buf.data;
}

/* ---- fetch latest tag from GitHub ---- */

static char *fetch_latest_tag(const char *repo) {
    if (!repo || !repo[0]) return NULL;
    char url[512];
    int n = snprintf(url, sizeof(url),
                     "https://api.github.com/repos/%s/releases/latest", repo);
    if (n < 0 || (size_t)n >= sizeof(url)) return NULL;
    char *body = http_get(url);
    if (!body) return NULL;
    cJSON *json = cJSON_Parse(body);
    free(body);
    if (!json) return NULL;
    cJSON *tag = cJSON_GetObjectItem(json, "tag_name");
    char *result = NULL;
    if (cJSON_IsString(tag) && tag->valuestring)
        result = strdup(tag->valuestring);
    cJSON_Delete(json);
    return result;
}

/* ---- main loop ---- */

static void check_updates(metalbear_update_watcher *w) {
    if (w->metalbear_repo && w->metalbear_repo[0]) {
        char *latest = fetch_latest_tag(w->metalbear_repo);
        if (latest) {
            if (is_newer(w->current_metalbear_version, latest)) {
                LOG_WARN("MetalBear %s is available (running %s) — "
                         "https://github.com/%s/releases/tag/%s",
                         latest, w->current_metalbear_version,
                         w->metalbear_repo, latest);
            } else {
                LOG_INFO("MetalBear is up-to-date (%s)",
                         w->current_metalbear_version);
            }
            free(latest);
        } else {
            LOG_DEBUG("update-watcher: could not fetch latest MetalBear tag");
        }
    }
    if (w->wolfram_repo && w->wolfram_repo[0]) {
        char *latest = fetch_latest_tag(w->wolfram_repo);
        if (latest) {
            if (is_newer(w->current_wolfram_version, latest)) {
                LOG_WARN("Wolfram %s is available (running %s) — "
                         "https://github.com/%s/releases/tag/%s",
                         latest, w->current_wolfram_version, w->wolfram_repo,
                         latest);
            } else {
                LOG_INFO("Wolfram is up-to-date (%s)",
                         w->current_wolfram_version);
            }
            free(latest);
        } else {
            LOG_DEBUG("update-watcher: could not fetch latest Wolfram tag");
        }
    }
}

static void *update_watcher_main(void *arg) {
    metalbear_update_watcher *w = arg;
    /* first check 10 seconds after start */
    struct timespec ts = {.tv_sec = 10, .tv_nsec = 0};
    while (!w->stop) {
        struct timespec rem;
        int ret = nanosleep(&ts, &rem);
        if (ret != 0 && w->stop) break;
        if (w->stop) break;
        check_updates(w);
        ts.tv_sec = w->interval_seconds;
        ts.tv_nsec = 0;
    }
    return NULL;
}

/* ---- public API ---- */

wf_status
metalbear_update_watcher_open(const metalbear_update_watcher_config *config,
                              metalbear_update_watcher **out) {
    if (!config || !out || !config->enabled) {
        *out = NULL;
        return WF_OK;
    }
    metalbear_update_watcher *w = calloc(1, sizeof(*w));
    if (!w) return WF_ERR_ALLOC;
    w->interval_seconds =
        config->interval_seconds > 0 ? config->interval_seconds : 86400;
    if (config->metalbear_repo && config->metalbear_repo[0])
        w->metalbear_repo = strdup(config->metalbear_repo);
    if (config->wolfram_repo && config->wolfram_repo[0])
        w->wolfram_repo = strdup(config->wolfram_repo);
    if (config->current_metalbear_version)
        w->current_metalbear_version =
            strdup(config->current_metalbear_version);
    if (config->current_wolfram_version)
        w->current_wolfram_version = strdup(config->current_wolfram_version);
    if (pthread_create(&w->thread, NULL, update_watcher_main, w) != 0) {
        free(w->metalbear_repo);
        free(w->wolfram_repo);
        free(w->current_metalbear_version);
        free(w->current_wolfram_version);
        free(w);
        return WF_ERR_INTERNAL;
    }
    *out = w;
    return WF_OK;
}

void metalbear_update_watcher_free(metalbear_update_watcher *w) {
    if (!w) return;
    w->stop = true;
    pthread_join(w->thread, NULL);
    free(w->metalbear_repo);
    free(w->wolfram_repo);
    free(w->current_metalbear_version);
    free(w->current_wolfram_version);
    free(w);
}
