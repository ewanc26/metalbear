#define _POSIX_C_SOURCE 200809L

/*
 * handle_dns.c — publish the `_atproto` TXT records that make handles resolve.
 *
 * Three providers are implemented behind one interface. They agree on what has
 * to happen — read the record, write it if it differs, delete it when the
 * account goes — and disagree about nearly everything else: how a record is
 * addressed, whether TXT content is quoted, whether a record even has an
 * identity of its own, and how a failure is reported.
 *
 *   cloudflare  Bearer token. Records are individually addressed by an opaque
 *               id from a list query. A rejected-but-well-formed request comes
 *               back 200 with `"success": false`, so the HTTP status alone
 *               never tells you whether the record was written.
 *   digitalocean
 *               Bearer token. `zone_id` is the domain name. Record ids are
 *               integers, and a delete answers 204 with no body at all.
 *   desec       `Token` rather than `Bearer`. There are no individual records:
 *               a name/type pair is one RRset replaced wholesale, TXT content
 *               is stored quoted, absence is a 404 rather than an empty list,
 *               and the minimum TTL is an hour.
 *
 * Reading before writing is what makes all three idempotent. Creating blindly
 * would leave two TXT records at the same name on the second call, and a
 * handle with two conflicting DIDs resolves to neither.
 */

#include "metalbear/dns/handle_dns.h"
#include "metalbear/dns/handle_dns_rfc2136.h"

#include <cJSON.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DNS_TIMEOUT_SECONDS 15L
#define DEFAULT_TTL 300

typedef struct dns_provider dns_provider;

struct metalbear_handle_dns {
    const dns_provider *provider;
    char *api_base;
    char *api_token;
    char *zone_id;
    int ttl;
    char last_error[256];
    /* rfc2136 only: the nameserver to update, and the decoded TSIG key. */
    char *server_host;
    char *server_port;
    char *key_name;
    unsigned char *key_secret;
    size_t key_secret_len;
};

/*
 * A record as the provider describes it. `id` is the handle a later update or
 * delete needs and is NULL where the provider has no such notion; `content` is
 * the TXT value with any provider quoting already removed, so every caller
 * compares the same thing.
 */
typedef struct dns_record {
    char *id;
    char *content;
    bool found;
} dns_record;

static void dns_record_free(dns_record *rec) {
    if (!rec) return;
    free(rec->id);
    free(rec->content);
    rec->id = NULL;
    rec->content = NULL;
    rec->found = false;
}

struct dns_provider {
    const char *name;
    const char *api_base;
    /* "Bearer" for the OAuth-style providers, "Token" for deSEC. */
    const char *auth_scheme;
    int min_ttl;
    wf_status (*lookup)(metalbear_handle_dns *dns, const char *name,
                        dns_record *out);
    wf_status (*publish)(metalbear_handle_dns *dns, const char *name,
                         const char *content, const dns_record *existing);
    wf_status (*retract)(metalbear_handle_dns *dns, const char *name,
                         const dns_record *existing);
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
 * One HTTP call to the provider.
 *
 * Returns the parsed body, or NULL — which is not on its own a failure, since
 * a 204 carries none. `*out_status` is the HTTP status and is set whenever the
 * request reached the server at all; `*out_ok` is false only when it did not.
 * Interpreting the status is the provider's job, because they do not agree on
 * what a failure looks like.
 */
static cJSON *http_call(metalbear_handle_dns *dns, const char *method,
                        const char *url, const char *body, long *out_status,
                        bool *out_ok) {
    *out_status = 0;
    *out_ok = false;
    CURL *curl = curl_easy_init();
    if (!curl) {
        set_error(dns, "could not initialise HTTP client");
        return NULL;
    }

    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: %s %s",
             dns->provider->auth_scheme, dns->api_token);
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
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, out_status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(hdrs);

    if (rc != CURLE_OK) {
        set_error(dns, "%s %s: %s", method, url, curl_easy_strerror(rc));
        free(out.data);
        return NULL;
    }
    *out_ok = true;
    cJSON *doc = out.data && out.data[0] ? cJSON_Parse(out.data) : NULL;
    free(out.data);
    return doc;
}

/* Percent-encode one path or query component. Caller frees with curl_free. */
static char *url_escape(const char *value) {
    return curl_easy_escape(NULL, value, 0);
}

/* Copy `value` with one layer of surrounding double quotes removed, which is
 * how deSEC (and any provider following the TXT presentation format) stores
 * the content that Cloudflare returns bare. */
static char *unquote(const char *value) {
    if (!value) return NULL;
    size_t len = strlen(value);
    if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
        char *out = malloc(len - 1);
        if (!out) return NULL;
        memcpy(out, value + 1, len - 2);
        out[len - 2] = '\0';
        return out;
    }
    return strdup(value);
}

/* ------------------------------------------------------------------ */
/* Cloudflare                                                          */
/* ------------------------------------------------------------------ */

/*
 * Cloudflare answers 200 with `success: false` for a rejected but well-formed
 * request, so the HTTP status alone never says whether the record was written.
 * The reason lives in `errors[].message`, and carrying it through is the
 * difference between "DNS failed" and "token lacks Zone.DNS:Edit" — which is
 * the same log line an operator has to act on.
 */
static cJSON *cf_call(metalbear_handle_dns *dns, const char *method,
                      const char *url, const char *body) {
    long status = 0;
    bool reached = false;
    cJSON *doc = http_call(dns, method, url, body, &status, &reached);
    if (!reached) return NULL;
    if (!doc) {
        set_error(dns, "%s: HTTP %ld with an unparseable body", method, status);
        return NULL;
    }
    if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(doc, "success"))) {
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

static wf_status cf_lookup(metalbear_handle_dns *dns, const char *name,
                           dns_record *out) {
    char *escaped = url_escape(name);
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
            out->found = true;
            out->id = strdup(id->valuestring);
            if (!out->id) st = WF_ERR_ALLOC;
            if (st == WF_OK && cJSON_IsString(content)) {
                out->content = unquote(content->valuestring);
                if (!out->content) st = WF_ERR_ALLOC;
            }
        }
    }
    cJSON_Delete(doc);
    return st;
}

static wf_status cf_publish(metalbear_handle_dns *dns, const char *name,
                            const char *content, const dns_record *existing) {
    cJSON *body = cJSON_CreateObject();
    if (!body) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(body, "type", "TXT");
    cJSON_AddStringToObject(body, "name", name);
    cJSON_AddStringToObject(body, "content", content);
    cJSON_AddNumberToObject(body, "ttl", dns->ttl);
    cJSON_AddStringToObject(body, "comment",
                            "atproto handle, written by MetalBear");
    char *json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!json) return WF_ERR_ALLOC;

    char url[768];
    if (existing->found)
        snprintf(url, sizeof(url), "%s/zones/%s/dns_records/%s", dns->api_base,
                 dns->zone_id, existing->id);
    else
        snprintf(url, sizeof(url), "%s/zones/%s/dns_records", dns->api_base,
                 dns->zone_id);

    cJSON *doc = cf_call(dns, existing->found ? "PATCH" : "POST", url, json);
    free(json);
    if (!doc) return WF_ERR_NETWORK;
    cJSON_Delete(doc);
    return WF_OK;
}

static wf_status cf_retract(metalbear_handle_dns *dns, const char *name,
                            const dns_record *existing) {
    (void)name;
    char url[768];
    snprintf(url, sizeof(url), "%s/zones/%s/dns_records/%s", dns->api_base,
             dns->zone_id, existing->id);
    cJSON *doc = cf_call(dns, "DELETE", url, NULL);
    if (!doc) return WF_ERR_NETWORK;
    cJSON_Delete(doc);
    return WF_OK;
}

/* ------------------------------------------------------------------ */
/* DigitalOcean                                                        */
/* ------------------------------------------------------------------ */

/*
 * Status-driven, unlike Cloudflare: any 2xx succeeded. A delete answers 204
 * with no body, so an absent document is not on its own an error here.
 */
static bool do_ok(metalbear_handle_dns *dns, const char *method, long status,
                  cJSON *doc) {
    if (status >= 200 && status < 300) return true;
    const char *detail = NULL;
    cJSON *msg = doc ? cJSON_GetObjectItemCaseSensitive(doc, "message") : NULL;
    if (cJSON_IsString(msg)) detail = msg->valuestring;
    set_error(dns, "%s: HTTP %ld: %s", method, status,
              detail ? detail : "request rejected");
    return false;
}

static wf_status do_lookup(metalbear_handle_dns *dns, const char *name,
                           dns_record *out) {
    char *escaped = url_escape(name);
    if (!escaped) return WF_ERR_ALLOC;
    char url[768];
    snprintf(url, sizeof(url), "%s/domains/%s/records?type=TXT&name=%s",
             dns->api_base, dns->zone_id, escaped);
    curl_free(escaped);

    long status = 0;
    bool reached = false;
    cJSON *doc = http_call(dns, "GET", url, NULL, &status, &reached);
    if (!reached) return WF_ERR_NETWORK;
    if (!do_ok(dns, "GET", status, doc)) {
        cJSON_Delete(doc);
        return WF_ERR_NETWORK;
    }

    wf_status st = WF_OK;
    cJSON *records = cJSON_GetObjectItemCaseSensitive(doc, "domain_records");
    if (cJSON_IsArray(records) && cJSON_GetArraySize(records) > 0) {
        cJSON *rec = cJSON_GetArrayItem(records, 0);
        cJSON *id = cJSON_GetObjectItemCaseSensitive(rec, "id");
        cJSON *data = cJSON_GetObjectItemCaseSensitive(rec, "data");
        /* Record ids are integers here, and are formatted back into the URL
         * of the update and delete that follow. */
        if (cJSON_IsNumber(id)) {
            char id_buf[32];
            snprintf(id_buf, sizeof(id_buf), "%lld",
                     (long long)id->valuedouble);
            out->found = true;
            out->id = strdup(id_buf);
            if (!out->id) st = WF_ERR_ALLOC;
            if (st == WF_OK && cJSON_IsString(data)) {
                out->content = unquote(data->valuestring);
                if (!out->content) st = WF_ERR_ALLOC;
            }
        }
    }
    cJSON_Delete(doc);
    return st;
}

static wf_status do_publish(metalbear_handle_dns *dns, const char *name,
                            const char *content, const dns_record *existing) {
    cJSON *body = cJSON_CreateObject();
    if (!body) return WF_ERR_ALLOC;
    cJSON_AddStringToObject(body, "type", "TXT");
    /* Fully qualified, with the trailing dot that stops the API appending the
     * domain to a name that already ends with it. */
    char fqdn[512];
    snprintf(fqdn, sizeof(fqdn), "%s.", name);
    cJSON_AddStringToObject(body, "name", fqdn);
    cJSON_AddStringToObject(body, "data", content);
    cJSON_AddNumberToObject(body, "ttl", dns->ttl);
    char *json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!json) return WF_ERR_ALLOC;

    char url[768];
    if (existing->found)
        snprintf(url, sizeof(url), "%s/domains/%s/records/%s", dns->api_base,
                 dns->zone_id, existing->id);
    else
        snprintf(url, sizeof(url), "%s/domains/%s/records", dns->api_base,
                 dns->zone_id);

    long status = 0;
    bool reached = false;
    const char *method = existing->found ? "PUT" : "POST";
    cJSON *doc = http_call(dns, method, url, json, &status, &reached);
    free(json);
    bool ok = reached && do_ok(dns, method, status, doc);
    cJSON_Delete(doc);
    return ok ? WF_OK : WF_ERR_NETWORK;
}

static wf_status do_retract(metalbear_handle_dns *dns, const char *name,
                            const dns_record *existing) {
    (void)name;
    char url[768];
    snprintf(url, sizeof(url), "%s/domains/%s/records/%s", dns->api_base,
             dns->zone_id, existing->id);
    long status = 0;
    bool reached = false;
    cJSON *doc = http_call(dns, "DELETE", url, NULL, &status, &reached);
    bool ok = reached && do_ok(dns, "DELETE", status, doc);
    cJSON_Delete(doc);
    return ok ? WF_OK : WF_ERR_NETWORK;
}

/* ------------------------------------------------------------------ */
/* deSEC                                                               */
/* ------------------------------------------------------------------ */

/*
 * deSEC has no individual records: a name and type together are one RRset,
 * replaced wholesale. That makes publishing a single PUT with no create/update
 * distinction, and retracting a PUT of an empty record list.
 *
 * The RRset is addressed by `subname`, which is the record name relative to
 * the domain — `_atproto.alice` under `example.com`, not the full name.
 */
static wf_status desec_subname(metalbear_handle_dns *dns, const char *name,
                               char *out, size_t out_len) {
    size_t name_len = strlen(name);
    size_t zone_len = strlen(dns->zone_id);
    if (name_len <= zone_len + 1 ||
        strcmp(name + name_len - zone_len, dns->zone_id) != 0 ||
        name[name_len - zone_len - 1] != '.') {
        set_error(dns, "%s is not inside the configured domain %s", name,
                  dns->zone_id);
        return WF_ERR_INVALID_ARG;
    }
    size_t sub_len = name_len - zone_len - 1;
    if (sub_len >= out_len) return WF_ERR_INVALID_ARG;
    memcpy(out, name, sub_len);
    out[sub_len] = '\0';
    return WF_OK;
}

static bool desec_ok(metalbear_handle_dns *dns, const char *method, long status,
                     cJSON *doc) {
    if (status >= 200 && status < 300) return true;
    const char *detail = NULL;
    cJSON *msg = doc ? cJSON_GetObjectItemCaseSensitive(doc, "detail") : NULL;
    if (cJSON_IsString(msg)) detail = msg->valuestring;
    set_error(dns, "%s: HTTP %ld: %s", method, status,
              detail ? detail : "request rejected");
    return false;
}

static wf_status desec_lookup(metalbear_handle_dns *dns, const char *name,
                              dns_record *out) {
    char subname[512];
    wf_status st = desec_subname(dns, name, subname, sizeof(subname));
    if (st != WF_OK) return st;
    char *escaped = url_escape(subname);
    if (!escaped) return WF_ERR_ALLOC;
    char url[768];
    snprintf(url, sizeof(url), "%s/domains/%s/rrsets/%s/TXT/", dns->api_base,
             dns->zone_id, escaped);
    curl_free(escaped);

    long status = 0;
    bool reached = false;
    cJSON *doc = http_call(dns, "GET", url, NULL, &status, &reached);
    if (!reached) return WF_ERR_NETWORK;
    /* Absence is a 404 here, not an empty list. */
    if (status == 404) {
        cJSON_Delete(doc);
        return WF_OK;
    }
    if (!desec_ok(dns, "GET", status, doc)) {
        cJSON_Delete(doc);
        return WF_ERR_NETWORK;
    }
    cJSON *records = cJSON_GetObjectItemCaseSensitive(doc, "records");
    if (cJSON_IsArray(records) && cJSON_GetArraySize(records) > 0) {
        cJSON *first = cJSON_GetArrayItem(records, 0);
        if (cJSON_IsString(first)) {
            out->found = true;
            out->content = unquote(first->valuestring);
            if (!out->content) st = WF_ERR_ALLOC;
        }
    }
    cJSON_Delete(doc);
    return st;
}

/* Replace the RRset with `records` — one quoted value, or none to remove it. */
static wf_status desec_put(metalbear_handle_dns *dns, const char *name,
                           const char *content) {
    char subname[512];
    wf_status st = desec_subname(dns, name, subname, sizeof(subname));
    if (st != WF_OK) return st;

    cJSON *body = cJSON_CreateObject();
    cJSON *records = cJSON_CreateArray();
    if (!body || !records) {
        cJSON_Delete(body);
        cJSON_Delete(records);
        return WF_ERR_ALLOC;
    }
    cJSON_AddStringToObject(body, "subname", subname);
    cJSON_AddStringToObject(body, "type", "TXT");
    cJSON_AddNumberToObject(body, "ttl", dns->ttl);
    if (content) {
        /* TXT content is stored in presentation format, quotes included. */
        char quoted[512];
        snprintf(quoted, sizeof(quoted), "\"%s\"", content);
        cJSON_AddItemToArray(records, cJSON_CreateString(quoted));
    }
    cJSON_AddItemToObject(body, "records", records);
    char *json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!json) return WF_ERR_ALLOC;

    char *escaped = url_escape(subname);
    if (!escaped) {
        free(json);
        return WF_ERR_ALLOC;
    }
    char url[768];
    snprintf(url, sizeof(url), "%s/domains/%s/rrsets/%s/TXT/", dns->api_base,
             dns->zone_id, escaped);
    curl_free(escaped);

    long status = 0;
    bool reached = false;
    cJSON *doc = http_call(dns, "PUT", url, json, &status, &reached);
    free(json);
    /* Deleting an RRset that is not there answers 404, and the desired state
     * — no record — already holds. */
    bool ok = reached && (desec_ok(dns, "PUT", status, doc) ||
                          (!content && status == 404));
    cJSON_Delete(doc);
    return ok ? WF_OK : WF_ERR_NETWORK;
}

static wf_status desec_publish(metalbear_handle_dns *dns, const char *name,
                               const char *content,
                               const dns_record *existing) {
    (void)existing;
    return desec_put(dns, name, content);
}

static wf_status desec_retract(metalbear_handle_dns *dns, const char *name,
                               const dns_record *existing) {
    (void)existing;
    return desec_put(dns, name, NULL);
}

/* ------------------------------------------------------------------ */
/* RFC 2136                                                            */
/* ------------------------------------------------------------------ */

/*
 * Not an HTTP API at all: this speaks the update protocol the nameservers
 * themselves implement, so one implementation covers BIND, Knot, PowerDNS,
 * NSD and anything else standards-compliant. See handle_dns_rfc2136.c.
 */
static void rfc2136_config(metalbear_handle_dns *dns,
                           metalbear_rfc2136_config *out) {
    out->server = dns->server_host;
    out->port = dns->server_port;
    out->zone = dns->zone_id;
    out->key_name = dns->key_name;
    out->secret = dns->key_secret;
    out->secret_len = dns->key_secret_len;
}

static wf_status rfc2136_lookup(metalbear_handle_dns *dns, const char *name,
                                dns_record *out) {
    metalbear_rfc2136_config config;
    rfc2136_config(dns, &config);
    char value[512];
    bool found = false;
    char error[256] = "";
    wf_status st = metalbear_rfc2136_query_txt(
        &config, name, value, sizeof(value), &found, error, sizeof(error));
    if (st != WF_OK) {
        set_error(dns, "%s", error[0] ? error : "query failed");
        return st;
    }
    if (found) {
        out->found = true;
        /* The wire form carries no quotes, so nothing to strip — but it goes
         * through the same helper so every provider's content compares alike.
         */
        out->content = unquote(value);
        if (!out->content) return WF_ERR_ALLOC;
    }
    return WF_OK;
}

static wf_status rfc2136_publish(metalbear_handle_dns *dns, const char *name,
                                 const char *content,
                                 const dns_record *existing) {
    (void)existing; /* one message deletes the RRset and adds the new value */
    metalbear_rfc2136_config config;
    rfc2136_config(dns, &config);
    char error[256] = "";
    wf_status st = metalbear_rfc2136_update_txt(&config, name, content,
                                                dns->ttl, error, sizeof(error));
    if (st != WF_OK) set_error(dns, "%s", error[0] ? error : "update failed");
    return st;
}

static wf_status rfc2136_retract(metalbear_handle_dns *dns, const char *name,
                                 const dns_record *existing) {
    (void)existing;
    metalbear_rfc2136_config config;
    rfc2136_config(dns, &config);
    char error[256] = "";
    wf_status st = metalbear_rfc2136_update_txt(&config, name, NULL, dns->ttl,
                                                error, sizeof(error));
    if (st != WF_OK) set_error(dns, "%s", error[0] ? error : "update failed");
    return st;
}

/*
 * Split the credential into a TSIG key name and its secret.
 *
 * `<name>:<base64 secret>`, which is how every tool that speaks this protocol
 * writes it — nsupdate's -y, certbot's rfc2136 plugin, and the key stanza in
 * a BIND config all use the same pair.
 */
static bool parse_tsig_credential(metalbear_handle_dns *dns,
                                  const char *credential) {
    const char *colon = strchr(credential, ':');
    if (!colon || colon == credential || !colon[1]) return false;
    size_t name_len = (size_t)(colon - credential);
    dns->key_name = malloc(name_len + 1);
    if (!dns->key_name) return false;
    memcpy(dns->key_name, credential, name_len);
    dns->key_name[name_len] = '\0';

    const char *b64 = colon + 1;
    size_t b64_len = strlen(b64);
    dns->key_secret = malloc(b64_len); /* decoded is always shorter */
    if (!dns->key_secret) return false;
    int decoded = EVP_DecodeBlock(dns->key_secret, (const unsigned char *)b64,
                                  (int)b64_len);
    if (decoded <= 0) return false;
    /* EVP_DecodeBlock pads to a multiple of three and counts the padding, so
     * the trailing '=' have to be subtracted back off. A secret one byte too
     * long produces a MAC the server rejects with no hint as to why. */
    size_t len = (size_t)decoded;
    for (size_t i = b64_len; i > 0 && b64[i - 1] == '='; i--) len--;
    dns->key_secret_len = len;
    return len > 0;
}

/* `host` or `host:port`, defaulting to the standard DNS port. */
static bool parse_server(metalbear_handle_dns *dns, const char *server) {
    const char *colon = strrchr(server, ':');
    if (colon && colon != server && strchr(server, ':') == colon) {
        size_t host_len = (size_t)(colon - server);
        dns->server_host = malloc(host_len + 1);
        if (!dns->server_host) return false;
        memcpy(dns->server_host, server, host_len);
        dns->server_host[host_len] = '\0';
        dns->server_port = strdup(colon + 1);
    } else {
        dns->server_host = strdup(server);
        dns->server_port = strdup("53");
    }
    return dns->server_host && dns->server_port;
}

/* ------------------------------------------------------------------ */

static const dns_provider providers[] = {
    {"cloudflare", "https://api.cloudflare.com/client/v4", "Bearer", 60,
     cf_lookup, cf_publish, cf_retract},
    {"digitalocean", "https://api.digitalocean.com/v2", "Bearer", 30, do_lookup,
     do_publish, do_retract},
    /* deSEC refuses anything under an hour, and rejecting the write is worse
     * than serving a handle change slowly. */
    {"desec", "https://desec.io/api/v1", "Token", 3600, desec_lookup,
     desec_publish, desec_retract},
    /* No API base and no auth scheme: this one is not HTTP. */
    {"rfc2136", "", "", 1, rfc2136_lookup, rfc2136_publish, rfc2136_retract},
};

wf_status metalbear_handle_dns_open(const char *provider, const char *api_token,
                                    const char *zone_id, int ttl,
                                    metalbear_handle_dns **out) {
    return metalbear_handle_dns_open_ex(provider, api_token, zone_id, NULL, ttl,
                                        out);
}

wf_status metalbear_handle_dns_open_ex(const char *provider,
                                       const char *api_token,
                                       const char *zone_id, const char *server,
                                       int ttl, metalbear_handle_dns **out) {
    if (!out) return WF_ERR_INVALID_ARG;
    *out = NULL;

    if (!provider || !provider[0]) return WF_OK;
    const dns_provider *chosen = NULL;
    for (size_t i = 0; i < sizeof(providers) / sizeof(providers[0]); i++)
        if (strcmp(provider, providers[i].name) == 0) chosen = &providers[i];
    if (!chosen) return WF_ERR_INVALID_ARG;

    /* Half a credential is worse than none: the operator believes records are
     * being written and every handle silently fails to resolve. */
    if (!api_token || !api_token[0] || !zone_id || !zone_id[0])
        return WF_ERR_INVALID_ARG;

    metalbear_handle_dns *dns = calloc(1, sizeof(*dns));
    if (!dns) return WF_ERR_ALLOC;
    dns->provider = chosen;
    /* Overridable so the tests can point at a local stand-in for the API.
     * Nothing in a deployment should set it. */
    const char *base = getenv("METALBEAR_DNS_API_BASE");
    dns->api_base = strdup(base && base[0] ? base : chosen->api_base);
    dns->api_token = strdup(api_token);
    dns->zone_id = strdup(zone_id);
    dns->ttl = ttl > 0 ? ttl : DEFAULT_TTL;
    /* Raised rather than refused: a provider's floor is its business, and
     * failing every write over a configured value it dislikes would take the
     * whole host's handle resolution down. */
    if (dns->ttl < chosen->min_ttl) dns->ttl = chosen->min_ttl;
    if (!dns->api_base || !dns->api_token || !dns->zone_id) {
        metalbear_handle_dns_free(dns);
        return WF_ERR_ALLOC;
    }
    /*
     * rfc2136 needs a nameserver to talk to and a TSIG key to sign with, and
     * neither has anywhere else to come from. Refused rather than defaulted:
     * a host that mints accounts and silently writes no records is only found
     * when every handle shows as handle.invalid.
     */
    if (strcmp(chosen->name, "rfc2136") == 0) {
        if (!server || !server[0] || !parse_server(dns, server) ||
            !parse_tsig_credential(dns, api_token)) {
            metalbear_handle_dns_free(dns);
            return WF_ERR_INVALID_ARG;
        }
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
    if (dns->key_secret) {
        /* Cleared for the same reason as the API token: it authorises
         * updates to the whole zone. */
        memset(dns->key_secret, 0, dns->key_secret_len);
        free(dns->key_secret);
    }
    free(dns->key_name);
    free(dns->server_host);
    free(dns->server_port);
    free(dns->zone_id);
    free(dns->api_base);
    free(dns);
}

const char *metalbear_handle_dns_last_error(const metalbear_handle_dns *dns) {
    return dns ? dns->last_error : "";
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

    dns_record existing = {0};
    st = dns->provider->lookup(dns, name, &existing);
    if (st != WF_OK) {
        dns_record_free(&existing);
        return st;
    }
    if (existing.found && existing.content &&
        strcmp(existing.content, want) == 0) {
        /* Already correct. Re-writing it would churn the zone's history for
         * nothing on every restart-time reconciliation. */
        dns_record_free(&existing);
        return WF_OK;
    }
    st = dns->provider->publish(dns, name, want, &existing);
    dns_record_free(&existing);
    return st;
}

wf_status metalbear_handle_dns_retract(metalbear_handle_dns *dns,
                                       const char *handle) {
    if (!dns) return WF_OK;
    if (!handle) return WF_ERR_INVALID_ARG;

    char name[512];
    wf_status st = record_name(handle, name, sizeof(name));
    if (st != WF_OK) return st;

    dns_record existing = {0};
    st = dns->provider->lookup(dns, name, &existing);
    if (st != WF_OK) {
        dns_record_free(&existing);
        return st;
    }
    /* An absent record is the desired state already — including on deSEC,
     * whose lookup reports a missing RRset as not found rather than empty. */
    if (!existing.found) {
        dns_record_free(&existing);
        return WF_OK;
    }
    st = dns->provider->retract(dns, name, &existing);
    dns_record_free(&existing);
    return st;
}
