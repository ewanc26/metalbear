#define _POSIX_C_SOURCE 200809L

/*
 * handle_dns.c — Cloudflare-backed `_atproto` TXT record publishing.
 *
 * Every operation goes through the zone's dns_records collection:
 *
 *   GET    /zones/{zone}/dns_records?type=TXT&name=_atproto.<handle>
 *   POST   /zones/{zone}/dns_records
 *   PATCH  /zones/{zone}/dns_records/{id}
 *   DELETE /zones/{zone}/dns_records/{id}
 *
 * Reading before writing is what makes this idempotent. Creating blindly would
 * leave two TXT records at the same name on the second call, and a handle with
 * two conflicting DIDs resolves to neither.
 */

#include "metalbear/handle_dns.h"

#include <cJSON.h>
#include <curl/curl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_API "https://api.cloudflare.com/client/v4"
#define DNS_TIMEOUT_SECONDS 15L
#define DEFAULT_TTL 300

struct metalbear_handle_dns {
    char *api_base;
    char *api_token;
    char *zone_id;
    int ttl;
    char last_error[256];
};

typedef struct {
    char *data;
    size_t len;
} buf;

static size_t collect(void *ptr, size_t size, size_t nmemb, void *userdata) {
    buf *b = userdata;
    size_t n = size * nmemb;
    char *grown = realloc(b->data, b->len + n + 1);
    if (!grown) return 0;
    b->data = grown;
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

static void set_error(metalbear_handle_dns *dns, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dns->last_error, sizeof(dns->last_error), fmt, ap);
    va_end(ap);
}

/*
 * One Cloudflare call. Returns the parsed body on a 2xx with `"success": true`,
 * NULL otherwise with last_error set.
 *
 * Cloudflare answers 200 with `success: false` for some failures, so the HTTP
 * status alone is not enough to know whether the record was written.
 */
static cJSON *cf_call(metalbear_handle_dns *dns, const char *method,
                      const char *url, const char *body) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        set_error(dns, "could not initialise HTTP client");
        return NULL;
    }

    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", dns->api_token);
    struct curl_slist *hdrs = curl_slist_append(NULL, auth);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    buf out = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, DNS_TIMEOUT_SECONDS);
    if (body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }

    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);

    if (rc != CURLE_OK) {
        set_error(dns, "%s %s: %s", method, url, curl_easy_strerror(rc));
        free(out.data);
        return NULL;
    }

    cJSON *doc = out.data ? cJSON_Parse(out.data) : NULL;
    free(out.data);
    if (!doc) {
        set_error(dns, "%s: HTTP %ld with an unparseable body", method, status);
        return NULL;
    }

    cJSON *success = cJSON_GetObjectItemCaseSensitive(doc, "success");
    if (!cJSON_IsTrue(success)) {
        /* Cloudflare reports what was wrong in `errors[].message`; carrying it
         * through is the difference between "DNS failed" and "token lacks
         * Zone.DNS:Edit", which is the same log line an operator has to act
         * on. */
        const char *detail = NULL;
        cJSON *errors = cJSON_GetObjectItemCaseSensitive(doc, "errors");
        if (cJSON_IsArray(errors) && cJSON_GetArraySize(errors) > 0) {
            cJSON *first = cJSON_GetArrayItem(errors, 0);
            cJSON *msg = cJSON_GetObjectItemCaseSensitive(first, "message");
            if (cJSON_IsString(msg)) detail = msg->valuestring;
        }
        set_error(dns, "%s: HTTP %ld: %s", method, status,
                  detail ? detail : "request rejected");
        cJSON_Delete(doc);
        return NULL;
    }
    return doc;
}

wf_status metalbear_handle_dns_open(const char *provider, const char *api_token,
                                    const char *zone_id, int ttl,
                                    metalbear_handle_dns **out) {
    if (!out) return WF_ERR_INVALID_ARG;
    *out = NULL;

    if (!provider || !provider[0]) return WF_OK;
    if (strcmp(provider, "cloudflare") != 0) return WF_ERR_INVALID_ARG;

    /* Half a credential is worse than none: the operator believes records are
     * being written and every handle silently fails to resolve. */
    if (!api_token || !api_token[0] || !zone_id || !zone_id[0])
        return WF_ERR_INVALID_ARG;

    metalbear_handle_dns *dns = calloc(1, sizeof(*dns));
    if (!dns) return WF_ERR_ALLOC;
    /* Overridable so the tests can point at a local stand-in for the API.
     * Nothing in a deployment should set it. */
    const char *base = getenv("METALBEAR_DNS_API_BASE");
    dns->api_base = strdup(base && base[0] ? base : CF_API);
    dns->api_token = strdup(api_token);
    dns->zone_id = strdup(zone_id);
    dns->ttl = ttl > 0 ? ttl : DEFAULT_TTL;
    if (!dns->api_base || !dns->api_token || !dns->zone_id) {
        metalbear_handle_dns_free(dns);
        return WF_ERR_ALLOC;
    }
    *out = dns;
    return WF_OK;
}

void metalbear_handle_dns_free(metalbear_handle_dns *dns) {
    if (!dns) return;
    if (dns->api_token) {
        /* Clear before freeing: the token edits DNS for the whole zone. */
        memset(dns->api_token, 0, strlen(dns->api_token));
        free(dns->api_token);
    }
    free(dns->zone_id);
    free(dns->api_base);
    free(dns);
}

const char *metalbear_handle_dns_last_error(const metalbear_handle_dns *dns) {
    return dns ? dns->last_error : "";
}

/*
 * Find the existing `_atproto.<handle>` TXT record.
 *
 * `found` distinguishes "no such record" from "could not ask", which the
 * callers need: the first means create it, the second means stop.
 */
static wf_status lookup(metalbear_handle_dns *dns, const char *name,
                        char **id_out, char **content_out, int *found) {
    *found = 0;
    if (id_out) *id_out = NULL;
    if (content_out) *content_out = NULL;

    char *escaped = curl_easy_escape(NULL, name, 0);
    if (!escaped) return WF_ERR_ALLOC;
    char url[768];
    snprintf(url, sizeof(url), "%s/zones/%s/dns_records?type=TXT&name=%s",
             dns->api_base, dns->zone_id, escaped);
    curl_free(escaped);

    cJSON *doc = cf_call(dns, "GET", url, NULL);
    if (!doc) return WF_ERR_NETWORK;

    wf_status st = WF_OK;
    cJSON *result = cJSON_GetObjectItemCaseSensitive(doc, "result");
    if (cJSON_IsArray(result) && cJSON_GetArraySize(result) > 0) {
        cJSON *rec = cJSON_GetArrayItem(result, 0);
        cJSON *id = cJSON_GetObjectItemCaseSensitive(rec, "id");
        cJSON *content = cJSON_GetObjectItemCaseSensitive(rec, "content");
        if (cJSON_IsString(id)) {
            *found = 1;
            if (id_out) {
                *id_out = strdup(id->valuestring);
                if (!*id_out) st = WF_ERR_ALLOC;
            }
            if (st == WF_OK && content_out && cJSON_IsString(content)) {
                *content_out = strdup(content->valuestring);
                if (!*content_out) st = WF_ERR_ALLOC;
            }
        }
    }
    cJSON_Delete(doc);
    return st;
}

/* `_atproto.<handle>`, the name the resolver asks for. */
static wf_status record_name(const char *handle, char *out, size_t out_len) {
    if (!handle || !handle[0]) return WF_ERR_INVALID_ARG;
    int n = snprintf(out, out_len, "_atproto.%s", handle);
    if (n < 0 || (size_t)n >= out_len) return WF_ERR_INVALID_ARG;
    return WF_OK;
}

wf_status metalbear_handle_dns_publish(metalbear_handle_dns *dns,
                                       const char *handle, const char *did) {
    if (!dns) return WF_OK;
    if (!handle || !did || !did[0]) return WF_ERR_INVALID_ARG;

    char name[512];
    wf_status st = record_name(handle, name, sizeof(name));
    if (st != WF_OK) {
        set_error(dns, "handle too long to form a record name");
        return st;
    }

    char want[512];
    snprintf(want, sizeof(want), "did=%s", did);

    char *id = NULL, *have = NULL;
    int found = 0;
    st = lookup(dns, name, &id, &have, &found);
    if (st != WF_OK) return st;

    if (found && have && strcmp(have, want) == 0) {
        /* Already correct. Re-writing it would churn the zone's history for
         * nothing on every restart-time reconciliation. */
        free(id);
        free(have);
        return WF_OK;
    }
    free(have);

    cJSON *body = cJSON_CreateObject();
    if (!body) {
        free(id);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(body, "type", "TXT");
    cJSON_AddStringToObject(body, "name", name);
    cJSON_AddStringToObject(body, "content", want);
    cJSON_AddNumberToObject(body, "ttl", dns->ttl);
    cJSON_AddStringToObject(body, "comment", "atproto handle, written by MetalBear");
    char *json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!json) {
        free(id);
        return WF_ERR_ALLOC;
    }

    char url[768];
    if (found)
        snprintf(url, sizeof(url), "%s/zones/%s/dns_records/%s", dns->api_base,
                 dns->zone_id, id);
    else
        snprintf(url, sizeof(url), "%s/zones/%s/dns_records", dns->api_base,
                 dns->zone_id);

    cJSON *doc = cf_call(dns, found ? "PATCH" : "POST", url, json);
    free(json);
    free(id);
    if (!doc) return WF_ERR_NETWORK;
    cJSON_Delete(doc);
    return WF_OK;
}

wf_status metalbear_handle_dns_retract(metalbear_handle_dns *dns,
                                       const char *handle) {
    if (!dns) return WF_OK;
    if (!handle) return WF_ERR_INVALID_ARG;

    char name[512];
    wf_status st = record_name(handle, name, sizeof(name));
    if (st != WF_OK) return st;

    char *id = NULL;
    int found = 0;
    st = lookup(dns, name, &id, NULL, &found);
    if (st != WF_OK) return st;
    if (!found) return WF_OK;

    char url[768];
    snprintf(url, sizeof(url), "%s/zones/%s/dns_records/%s", dns->api_base,
             dns->zone_id, id);
    free(id);

    cJSON *doc = cf_call(dns, "DELETE", url, NULL);
    if (!doc) return WF_ERR_NETWORK;
    cJSON_Delete(doc);
    return WF_OK;
}
