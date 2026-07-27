#define _POSIX_C_SOURCE 200809L

#include "metalbear/config_file.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A TOML subset, deliberately small. See config_file.h for what is supported
 * and why. The parser is strict: anything it does not understand is an error
 * with a line number, never a silently skipped setting.
 */

#define MAX_OWNED 64

struct metalbear_config_file {
    char *owned[MAX_OWNED];
    size_t count;
};

static char *own(metalbear_config_file *o, char *s) {
    if (!s) return NULL;
    if (o->count >= MAX_OWNED) { free(s); return NULL; }
    o->owned[o->count++] = s;
    return s;
}

void metalbear_config_file_free(metalbear_config_file *o) {
    if (!o) return;
    for (size_t i = 0; i < o->count; i++) free(o->owned[i]);
    free(o);
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Strip a trailing comment that is not inside a quoted string. */
static void strip_comment(char *s) {
    bool in_quotes = false;
    for (char *p = s; *p; p++) {
        if (*p == '"') in_quotes = !in_quotes;
        else if (*p == '#' && !in_quotes) { *p = '\0'; return; }
    }
}

/* Copy a `"quoted string"`, resolving \" and \\. Returns NULL if not quoted. */
static char *parse_string(const char *v) {
    size_t n = strlen(v);
    if (n < 2 || v[0] != '"' || v[n - 1] != '"') return NULL;
    char *out = malloc(n);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 1; i + 1 < n; i++) {
        if (v[i] == '\\' && i + 2 < n) {
            i++;
            out[j++] = (v[i] == 'n') ? '\n' : (v[i] == 't') ? '\t' : v[i];
        } else {
            out[j++] = v[i];
        }
    }
    out[j] = '\0';
    return out;
}

/*
 * Flatten `["a", "b"]` to `a,b`.
 *
 * The crawler list is carried as a comma-separated string everywhere else, so
 * an array in the file becomes that same string rather than introducing a
 * second representation for one setting.
 */
static char *parse_string_array(const char *v) {
    size_t n = strlen(v);
    if (n < 2 || v[0] != '[' || v[n - 1] != ']') return NULL;
    char *out = calloc(1, n + 1);
    if (!out) return NULL;
    size_t j = 0;
    bool in_str = false, wrote_any = false;
    for (size_t i = 1; i + 1 < n; i++) {
        char c = v[i];
        if (c == '"') {
            if (in_str) { in_str = false; }
            else { in_str = true; if (wrote_any) out[j++] = ','; wrote_any = true; }
            continue;
        }
        if (in_str) out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

static bool parse_int(const char *v, int64_t *out) {
    char *end = NULL;
    long long parsed = strtoll(v, &end, 10);
    if (end == v || (end && *end)) return false;
    *out = (int64_t)parsed;
    return true;
}

static bool parse_bool(const char *v, bool *out) {
    if (strcmp(v, "true") == 0) { *out = true; return true; }
    if (strcmp(v, "false") == 0) { *out = false; return true; }
    return false;
}

#define FAIL(line, fmt, ...)                                                  \
    do {                                                                      \
        if (err && err_len)                                                   \
            snprintf(err, err_len, "%s:%d: " fmt, path, (line), ##__VA_ARGS__); \
        goto fail;                                                            \
    } while (0)

wf_status metalbear_config_file_load(const char *path,
                                     metalbear_config *config,
                                     metalbear_config_file **out_owner,
                                     char *err, size_t err_len) {
    if (!path || !config || !out_owner) return WF_ERR_INVALID_ARG;
    *out_owner = NULL;

    FILE *f = fopen(path, "r");
    if (!f) {
        if (err && err_len) snprintf(err, err_len, "%s: cannot open", path);
        return WF_ERR_NOT_FOUND;
    }

    metalbear_config_file *owner = calloc(1, sizeof(*owner));
    if (!owner) { fclose(f); return WF_ERR_ALLOC; }

    char line[2048];
    char section[64] = "";
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        strip_comment(line);
        char *s = trim(line);
        if (!*s) continue;

        if (*s == '[') {
            char *close = strchr(s, ']');
            if (!close) FAIL(lineno, "unterminated section header");
            *close = '\0';
            snprintf(section, sizeof(section), "%s", trim(s + 1));
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) FAIL(lineno, "expected 'key = value'");
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);
        if (!*key) FAIL(lineno, "empty key");
        if (!*val) FAIL(lineno, "empty value for '%s'", key);

        /* Fully-qualified name so [section] key lands in one switch. */
        char full[128];
        snprintf(full, sizeof(full), "%s%s%s", section, *section ? "." : "", key);

        int64_t iv = 0;
        bool bv = false;

        #define STR(name, field)                                              \
            if (strcmp(full, name) == 0) {                                    \
                char *copy = parse_string(val);                               \
                if (!copy) FAIL(lineno, "'%s' expects a quoted string", key); \
                config->field = own(owner, copy);                             \
                continue;                                                     \
            }
        #define INT(name, field)                                              \
            if (strcmp(full, name) == 0) {                                    \
                if (!parse_int(val, &iv)) FAIL(lineno, "'%s' expects an integer", key); \
                config->field = iv;                                           \
                continue;                                                     \
            }
        #define U16(name, field)                                              \
            if (strcmp(full, name) == 0) {                                    \
                if (!parse_int(val, &iv) || iv < 0 || iv > 65535)             \
                    FAIL(lineno, "'%s' expects a port number", key);          \
                config->field = (uint16_t)iv;                                 \
                continue;                                                     \
            }
        #define UINT(name, field)                                             \
            if (strcmp(full, name) == 0) {                                    \
                if (!parse_int(val, &iv) || iv <= 0)                          \
                    FAIL(lineno, "'%s' expects a positive integer", key);     \
                config->field = (unsigned int)iv;                             \
                continue;                                                     \
            }
        #define BOOL(name, field)                                             \
            if (strcmp(full, name) == 0) {                                    \
                if (!parse_bool(val, &bv)) FAIL(lineno, "'%s' expects true or false", key); \
                config->field = bv;                                           \
                continue;                                                     \
            }

        STR ("server.listen",            listen_address)
        U16 ("server.port",              port)
        UINT("server.threads",           thread_count)
        STR ("server.data",              data_directory)
        STR ("server.service_did",       service_did)
        STR ("server.public_url",        public_url)
        STR ("server.user_domain",       user_domain)
        STR ("server.contact_email",     account_email)
        STR ("server.lexicon_dir",       lexicon_dir)

        STR ("identity.plc_url",              plc_url)
        STR ("identity.plc_rotation_key",     plc_rotation_key)
        INT ("identity.did_cache_ttl_seconds", did_cache_ttl_seconds)
        INT ("identity.did_cache_entries",     did_cache_entries)

        STR ("accounts.admin_password",  admin_password)
        BOOL("accounts.invite_required", invite_required)

        INT ("limits.rate_limit",                rate_limit)
        INT ("limits.rate_limit_window_seconds", rate_limit_window)
        INT ("limits.blob_upload_bytes",         blob_upload_limit)

        INT ("firehose.retention_max_age_seconds", retention_max_age_seconds)
        INT ("firehose.retention_min_events",      retention_min_events)
        INT ("firehose.crawl_notify_seconds",      crawl_notify_seconds)
        INT ("firehose.ping_seconds",              firehose_ping_seconds)

        STR ("operator.name",             operator_name)
        STR ("operator.email",            account_email)
        STR ("operator.url",              operator_url)
        STR ("operator.support_url",      support_url)
        STR ("operator.description",      instance_description)
        STR ("operator.privacy_policy",   privacy_policy_url)
        STR ("operator.terms_of_service", terms_of_service_url)
        BOOL("operator.development",      development)

        STR ("appview.url", appview_url)
        STR ("appview.did", appview_did)

        STR ("smtp.host",         smtp_host)
        U16 ("smtp.port",         smtp_port)
        STR ("smtp.username",     smtp_username)
        STR ("smtp.password",     smtp_password)
        STR ("smtp.from_address", from_address)
        STR ("smtp.from_name",    from_name)
        BOOL("smtp.starttls",     smtp_starttls)

        #undef STR
        #undef INT
        #undef BOOL
        #undef U16
        #undef UINT

        if (strcmp(full, "firehose.crawlers") == 0) {
            char *joined = parse_string_array(val);
            if (!joined) {
                joined = parse_string(val);
                if (!joined) FAIL(lineno, "'crawlers' expects an array or string");
            }
            config->crawlers = own(owner, joined);
            continue;
        }

        FAIL(lineno, "unknown setting '%s'", full);
    }

    fclose(f);
    *out_owner = owner;
    return WF_OK;

fail:
    fclose(f);
    metalbear_config_file_free(owner);
    return WF_ERR_PARSE;
}
