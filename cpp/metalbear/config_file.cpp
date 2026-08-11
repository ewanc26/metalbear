#include "metalbear/config_file.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

struct metalbear_config_file {
    std::vector<std::string> owned;
    metalbear_config_file() {
        owned.reserve(64);
    }
};

static const char *own(metalbear_config_file *o, std::string s) {
    if (s.empty()) return nullptr;
    if (o->owned.size() >= 64) return nullptr;
    o->owned.push_back(std::move(s));
    return o->owned.back().c_str();
}

void metalbear_config_file_free(metalbear_config_file *o) {
    if (!o) return;
    delete o;
}

static std::string trim(std::string s) {
    size_t start = 0;
    while (start < s.size() &&
           std::isspace(static_cast<unsigned char>(s[start])))
        start++;
    if (start >= s.size()) return {};
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
        end--;
    return s.substr(start, end - start);
}

static void strip_comment(std::string &s) {
    bool in_quotes = false;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '"')
            in_quotes = !in_quotes;
        else if (s[i] == '#' && !in_quotes) {
            s.resize(i);
            return;
        }
    }
}

static bool parse_int(const char *v, int64_t *out) {
    char *end = nullptr;
    long long parsed = std::strtoll(v, &end, 10);
    if (end == v || (end && *end)) return false;
    *out = static_cast<int64_t>(parsed);
    return true;
}

static bool parse_bool(const char *v, bool *out) {
    if (std::strcmp(v, "true") == 0) {
        *out = true;
        return true;
    }
    if (std::strcmp(v, "false") == 0) {
        *out = false;
        return true;
    }
    return false;
}

/*
 * The full configurable surface, in one place. Both the TOML and YAML loaders
 * below expand this same list, so a setting added to one dialect can never be
 * silently missing from the other. STR/INT/U16/UINT/BOOL/ARR are supplied by
 * each loader as macros that parse a raw value in that dialect's syntax and
 * assign it into `config`.
 */
#define METALBEAR_CONFIG_FIELDS(STR, INT, U16, UINT, BOOL, ARR)                \
    STR("server.listen", listen_address)                                       \
    U16("server.port", port)                                                   \
    UINT("server.threads", thread_count)                                       \
    STR("server.data", data_directory)                                         \
    STR("server.service_did", service_did)                                     \
    STR("server.public_url", public_url)                                       \
    STR("server.user_domain", user_domain)                                     \
    STR("server.contact_email", account_email)                                 \
    STR("server.lexicon_dir", lexicon_dir)                                     \
                                                                               \
    STR("identity.plc_url", plc_url)                                           \
    STR("identity.plc_rotation_key", plc_rotation_key)                         \
    INT("identity.did_cache_ttl_seconds", did_cache_ttl_seconds)               \
    INT("identity.did_cache_entries", did_cache_entries)                       \
                                                                               \
    STR("accounts.admin_password", admin_password)                             \
    BOOL("accounts.invite_required", invite_required)                          \
                                                                               \
    INT("limits.rate_limit", rate_limit)                                       \
    INT("limits.rate_limit_window_seconds", rate_limit_window)                 \
    INT("limits.blob_upload_bytes", blob_upload_limit)                         \
    INT("limits.max_import_bytes", max_import_size)                            \
                                                                               \
    BOOL("repo.accepting_imports", accepting_imports)                          \
                                                                               \
    INT("firehose.retention_max_age_seconds", retention_max_age_seconds)       \
    INT("firehose.retention_min_events", retention_min_events)                 \
    INT("firehose.crawl_notify_seconds", crawl_notify_seconds)                 \
    INT("firehose.ping_seconds", firehose_ping_seconds)                        \
                                                                               \
    STR("operator.name", operator_name)                                        \
    STR("operator.email", account_email)                                       \
    STR("operator.url", operator_url)                                          \
    STR("operator.support_url", support_url)                                   \
    STR("operator.description", instance_description)                          \
    STR("operator.privacy_policy", privacy_policy_url)                         \
    STR("operator.terms_of_service", terms_of_service_url)                     \
    BOOL("operator.development", development)                                  \
                                                                               \
    STR("appview.url", appview_url)                                            \
    STR("appview.did", appview_did)                                            \
                                                                               \
    STR("dns.provider", dns_provider)                                          \
    STR("dns.api_token", dns_api_token)                                        \
    STR("dns.zone_id", dns_zone_id)                                            \
    STR("dns.server", dns_server)                                              \
    INT("dns.ttl", dns_record_ttl)                                             \
                                                                               \
    STR("smtp.host", smtp_host)                                                \
    U16("smtp.port", smtp_port)                                                \
    STR("smtp.username", smtp_username)                                        \
    STR("smtp.password", smtp_password)                                        \
    STR("smtp.from_address", from_address)                                     \
    STR("smtp.from_name", from_name)                                           \
    BOOL("smtp.starttls", smtp_starttls)                                       \
                                                                               \
    BOOL("updates.check_enabled", update_check_enabled)                        \
    INT("updates.check_interval_seconds", update_check_interval)               \
    STR("updates.metalbear_repo", update_metalbear_repo)                       \
    STR("updates.wolfram_repo", update_wolfram_repo)                           \
                                                                               \
    ARR("firehose.crawlers", crawlers)

/* ---------------------------------------------------------------- TOML -- */

static std::string toml_parse_string(const char *v) {
    size_t n = std::strlen(v);
    if (n < 2 || v[0] != '"' || v[n - 1] != '"') return {};
    std::string out;
    out.reserve(n);
    for (size_t i = 1; i + 1 < n; i++) {
        if (v[i] == '\\' && i + 2 < n) {
            i++;
            if (v[i] == 'n')
                out.push_back('\n');
            else if (v[i] == 't')
                out.push_back('\t');
            else
                out.push_back(v[i]);
        } else {
            out.push_back(v[i]);
        }
    }
    return out;
}

static std::string toml_parse_string_array(const char *v) {
    size_t n = std::strlen(v);
    if (n < 2 || v[0] != '[' || v[n - 1] != ']') return {};
    std::string out;
    out.reserve(n);
    bool in_str = false, wrote_any = false;
    for (size_t i = 1; i + 1 < n; i++) {
        char c = v[i];
        if (c == '"') {
            if (in_str) {
                in_str = false;
            } else {
                in_str = true;
                if (wrote_any) out.push_back(',');
                wrote_any = true;
            }
            continue;
        }
        if (in_str) out.push_back(c);
    }
    return out;
}

static wf_status load_toml(const char *path, metalbear_config *config,
                           metalbear_config_file **out_owner, char *err,
                           size_t err_len) {
    std::ifstream f(path);
    if (!f) {
        if (err && err_len)
            std::snprintf(err, err_len, "%s: cannot open", path);
        return WF_ERR_NOT_FOUND;
    }

    auto *owner = new metalbear_config_file();
    std::string line;
    std::string section;
    int lineno = 0;
    bool failed = false;

    while (std::getline(f, line)) {
        lineno++;
        strip_comment(line);
        std::string s = trim(line);
        if (s.empty()) continue;

        if (s[0] == '[') {
            auto close = s.find(']');
            if (close == std::string::npos) {
                if (err && err_len)
                    std::snprintf(err, err_len,
                                  "%s:%d: unterminated section header", path,
                                  lineno);
                failed = true;
                break;
            }
            section = trim(s.substr(1, close - 1));
            continue;
        }

        auto eq = s.find('=');
        if (eq == std::string::npos) {
            if (err && err_len)
                std::snprintf(err, err_len, "%s:%d: expected 'key = value'",
                              path, lineno);
            failed = true;
            break;
        }
        std::string key = trim(s.substr(0, eq));
        std::string val = trim(s.substr(eq + 1));
        if (key.empty()) {
            if (err && err_len)
                std::snprintf(err, err_len, "%s:%d: empty key", path, lineno);
            failed = true;
            break;
        }
        if (val.empty()) {
            if (err && err_len)
                std::snprintf(err, err_len, "%s:%d: empty value for '%s'", path,
                              lineno, key.c_str());
            failed = true;
            break;
        }

        std::string full = section;
        if (!section.empty()) full.push_back('.');
        full += key;

        int64_t iv = 0;
        bool bv = false;

#define STR(name, field)                                                       \
    if (full == name) {                                                        \
        std::string copy = toml_parse_string(val.c_str());                     \
        if (copy.empty()) {                                                    \
            if (err && err_len)                                                \
                std::snprintf(err, err_len,                                    \
                              "%s:%d: '%s' expects a quoted string", path,     \
                              lineno, key.c_str());                            \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = own(owner, std::move(copy));                           \
        continue;                                                              \
    }
#define INT(name, field)                                                       \
    if (full == name) {                                                        \
        if (!parse_int(val.c_str(), &iv)) {                                    \
            if (err && err_len)                                                \
                std::snprintf(err, err_len, "%s:%d: '%s' expects an integer",  \
                              path, lineno, key.c_str());                      \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = iv;                                                    \
        continue;                                                              \
    }
#define U16(name, field)                                                       \
    if (full == name) {                                                        \
        if (!parse_int(val.c_str(), &iv) || iv < 0 || iv > 65535) {            \
            if (err && err_len)                                                \
                std::snprintf(err, err_len,                                    \
                              "%s:%d: '%s' expects a port number", path,       \
                              lineno, key.c_str());                            \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = static_cast<uint16_t>(iv);                             \
        continue;                                                              \
    }
#define UINT(name, field)                                                      \
    if (full == name) {                                                        \
        if (!parse_int(val.c_str(), &iv) || iv <= 0) {                         \
            if (err && err_len)                                                \
                std::snprintf(err, err_len,                                    \
                              "%s:%d: '%s' expects a positive integer", path,  \
                              lineno, key.c_str());                            \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = static_cast<unsigned int>(iv);                         \
        continue;                                                              \
    }
#define BOOL(name, field)                                                      \
    if (full == name) {                                                        \
        if (!parse_bool(val.c_str(), &bv)) {                                   \
            if (err && err_len)                                                \
                std::snprintf(err, err_len,                                    \
                              "%s:%d: '%s' expects true or false", path,       \
                              lineno, key.c_str());                            \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = bv;                                                    \
        continue;                                                              \
    }
#define ARR(name, field)                                                       \
    if (full == name) {                                                        \
        std::string joined = toml_parse_string_array(val.c_str());             \
        if (joined.empty()) {                                                  \
            joined = toml_parse_string(val.c_str());                           \
            if (joined.empty()) {                                              \
                if (err && err_len)                                            \
                    std::snprintf(err, err_len,                                \
                                  "%s:%d: '%s' expects an array or string",    \
                                  path, lineno, key.c_str());                  \
                failed = true;                                                 \
                break;                                                         \
            }                                                                  \
        }                                                                      \
        config->field = own(owner, std::move(joined));                         \
        continue;                                                              \
    }

        METALBEAR_CONFIG_FIELDS(STR, INT, U16, UINT, BOOL, ARR)

#undef STR
#undef INT
#undef U16
#undef UINT
#undef BOOL
#undef ARR

        if (err && err_len)
            std::snprintf(err, err_len, "%s:%d: unknown setting '%s'", path,
                          lineno, full.c_str());
        failed = true;
        break;
    }

    if (failed) {
        delete owner;
        return WF_ERR_PARSE;
    }

    *out_owner = owner;
    return WF_OK;
}

/* ---------------------------------------------------------------- YAML -- */

/*
 * A deliberate subset of YAML, chosen so every file accepted here is also a
 * valid document under a real YAML parser (nothing here is YAML-illegal,
 * this simply refuses to interpret constructs it does not need): a top-level
 * `section:` key per [section] in the TOML dialect, its settings indented
 * exactly two spaces as `key: value`, `#` comments, and flow arrays
 * (`[a, b]`) for the one setting that needs a list. No block sequences,
 * multi-line scalars, anchors, tags, or arbitrary indentation depths --
 * exactly the same "reject loudly rather than misinterpret" policy the TOML
 * loader already follows.
 */

static std::string yaml_parse_string(const std::string &v) {
    size_t n = v.size();
    if (n >= 2 && v.front() == '"' && v.back() == '"') {
        std::string out;
        out.reserve(n);
        for (size_t i = 1; i + 1 < n; i++) {
            if (v[i] == '\\' && i + 2 < n) {
                i++;
                if (v[i] == 'n')
                    out.push_back('\n');
                else if (v[i] == 't')
                    out.push_back('\t');
                else
                    out.push_back(v[i]);
            } else {
                out.push_back(v[i]);
            }
        }
        return out;
    }
    if (n >= 2 && v.front() == '\'' && v.back() == '\'') {
        std::string out;
        out.reserve(n);
        for (size_t i = 1; i + 1 < n; i++) {
            if (v[i] == '\'' && i + 2 < n && v[i + 1] == '\'') {
                out.push_back('\'');
                i++;
            } else {
                out.push_back(v[i]);
            }
        }
        return out;
    }
    /* A bare scalar -- idiomatic YAML for a plain string. */
    return v;
}

static std::vector<std::string> yaml_split_flow_items(const std::string &v) {
    std::vector<std::string> items;
    std::string cur;
    bool in_dq = false, in_sq = false;
    for (size_t i = 0; i < v.size(); i++) {
        char c = v[i];
        if (c == '"' && !in_sq) in_dq = !in_dq;
        if (c == '\'' && !in_dq) in_sq = !in_sq;
        if (c == ',' && !in_dq && !in_sq) {
            items.push_back(trim(cur));
            cur.clear();
            continue;
        }
        cur.push_back(c);
    }
    std::string last = trim(cur);
    if (!last.empty()) items.push_back(last);
    return items;
}

/* Empty return signals "not a flow array"; distinct from a valid empty list,
 * which this configuration surface never needs (an unset crawlers list is
 * expressed by omitting the setting, not by `crawlers: []`). */
static std::string yaml_parse_string_array(const std::string &v) {
    if (v.size() < 2 || v.front() != '[' || v.back() != ']') return {};
    std::string inner = v.substr(1, v.size() - 2);
    std::string out;
    bool wrote_any = false;
    for (auto &item : yaml_split_flow_items(inner)) {
        if (item.empty()) continue;
        std::string parsed = yaml_parse_string(item);
        if (parsed.empty()) continue;
        if (wrote_any) out.push_back(',');
        out += parsed;
        wrote_any = true;
    }
    return out;
}

static size_t leading_spaces(const std::string &s, bool *has_tab) {
    size_t n = 0;
    *has_tab = false;
    for (; n < s.size(); n++) {
        if (s[n] == '\t') {
            *has_tab = true;
        } else if (s[n] != ' ') {
            break;
        }
    }
    return n;
}

static wf_status load_yaml(const char *path, metalbear_config *config,
                           metalbear_config_file **out_owner, char *err,
                           size_t err_len) {
    std::ifstream f(path);
    if (!f) {
        if (err && err_len)
            std::snprintf(err, err_len, "%s: cannot open", path);
        return WF_ERR_NOT_FOUND;
    }

    auto *owner = new metalbear_config_file();
    std::string raw;
    std::string section;
    int lineno = 0;
    bool failed = false;

    while (std::getline(f, raw)) {
        lineno++;
        std::string line = raw;
        strip_comment(line);
        if (trim(line).empty()) continue;

        bool has_tab = false;
        size_t indent = leading_spaces(line, &has_tab);
        if (has_tab) {
            if (err && err_len)
                std::snprintf(err, err_len, "%s:%d: tabs are not allowed", path,
                              lineno);
            failed = true;
            break;
        }
        std::string content = trim(line.substr(indent));

        if (indent == 0) {
            auto colon = content.find(':');
            if (colon == std::string::npos) {
                if (err && err_len)
                    std::snprintf(err, err_len, "%s:%d: expected 'section:'",
                                  path, lineno);
                failed = true;
                break;
            }
            std::string key = trim(content.substr(0, colon));
            std::string rest = trim(content.substr(colon + 1));
            if (key.empty()) {
                if (err && err_len)
                    std::snprintf(err, err_len, "%s:%d: empty section name",
                                  path, lineno);
                failed = true;
                break;
            }
            if (!rest.empty()) {
                if (err && err_len)
                    std::snprintf(
                        err, err_len,
                        "%s:%d: '%s:' is a section header and takes no value",
                        path, lineno, key.c_str());
                failed = true;
                break;
            }
            section = key;
            continue;
        }

        if (indent != 2) {
            if (err && err_len)
                std::snprintf(
                    err, err_len,
                    "%s:%d: expected 2-space indentation under a section", path,
                    lineno);
            failed = true;
            break;
        }
        if (section.empty()) {
            if (err && err_len)
                std::snprintf(err, err_len,
                              "%s:%d: setting outside any section", path,
                              lineno);
            failed = true;
            break;
        }

        auto colon = content.find(':');
        if (colon == std::string::npos) {
            if (err && err_len)
                std::snprintf(err, err_len, "%s:%d: expected 'key: value'",
                              path, lineno);
            failed = true;
            break;
        }
        std::string key = trim(content.substr(0, colon));
        std::string val = trim(content.substr(colon + 1));
        if (key.empty()) {
            if (err && err_len)
                std::snprintf(err, err_len, "%s:%d: empty key", path, lineno);
            failed = true;
            break;
        }
        if (val.empty()) {
            if (err && err_len)
                std::snprintf(err, err_len, "%s:%d: empty value for '%s'", path,
                              lineno, key.c_str());
            failed = true;
            break;
        }

        std::string full = section + "." + key;
        int64_t iv = 0;
        bool bv = false;

#define STR(name, field)                                                       \
    if (full == name) {                                                        \
        std::string copy = yaml_parse_string(val);                             \
        if (copy.empty()) {                                                    \
            if (err && err_len)                                                \
                std::snprintf(err, err_len, "%s:%d: '%s' expects a string",    \
                              path, lineno, key.c_str());                      \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = own(owner, std::move(copy));                           \
        continue;                                                              \
    }
#define INT(name, field)                                                       \
    if (full == name) {                                                        \
        if (!parse_int(val.c_str(), &iv)) {                                    \
            if (err && err_len)                                                \
                std::snprintf(err, err_len, "%s:%d: '%s' expects an integer",  \
                              path, lineno, key.c_str());                      \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = iv;                                                    \
        continue;                                                              \
    }
#define U16(name, field)                                                       \
    if (full == name) {                                                        \
        if (!parse_int(val.c_str(), &iv) || iv < 0 || iv > 65535) {            \
            if (err && err_len)                                                \
                std::snprintf(err, err_len,                                    \
                              "%s:%d: '%s' expects a port number", path,       \
                              lineno, key.c_str());                            \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = static_cast<uint16_t>(iv);                             \
        continue;                                                              \
    }
#define UINT(name, field)                                                      \
    if (full == name) {                                                        \
        if (!parse_int(val.c_str(), &iv) || iv <= 0) {                         \
            if (err && err_len)                                                \
                std::snprintf(err, err_len,                                    \
                              "%s:%d: '%s' expects a positive integer", path,  \
                              lineno, key.c_str());                            \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = static_cast<unsigned int>(iv);                         \
        continue;                                                              \
    }
#define BOOL(name, field)                                                      \
    if (full == name) {                                                        \
        if (!parse_bool(val.c_str(), &bv)) {                                   \
            if (err && err_len)                                                \
                std::snprintf(err, err_len,                                    \
                              "%s:%d: '%s' expects true or false", path,       \
                              lineno, key.c_str());                            \
            failed = true;                                                     \
            break;                                                             \
        }                                                                      \
        config->field = bv;                                                    \
        continue;                                                              \
    }
#define ARR(name, field)                                                       \
    if (full == name) {                                                        \
        std::string joined = yaml_parse_string_array(val);                     \
        if (joined.empty()) {                                                  \
            joined = yaml_parse_string(val);                                   \
            if (joined.empty()) {                                              \
                if (err && err_len)                                            \
                    std::snprintf(err, err_len,                                \
                                  "%s:%d: '%s' expects an array or string",    \
                                  path, lineno, key.c_str());                  \
                failed = true;                                                 \
                break;                                                         \
            }                                                                  \
        }                                                                      \
        config->field = own(owner, std::move(joined));                         \
        continue;                                                              \
    }

        METALBEAR_CONFIG_FIELDS(STR, INT, U16, UINT, BOOL, ARR)

#undef STR
#undef INT
#undef U16
#undef UINT
#undef BOOL
#undef ARR

        if (err && err_len)
            std::snprintf(err, err_len, "%s:%d: unknown setting '%s'", path,
                          lineno, full.c_str());
        failed = true;
        break;
    }

    if (failed) {
        delete owner;
        return WF_ERR_PARSE;
    }

    *out_owner = owner;
    return WF_OK;
}

/* ------------------------------------------------------------ dispatch -- */

static bool has_suffix(const char *path, const char *suffix) {
    size_t pn = std::strlen(path), sn = std::strlen(suffix);
    if (pn < sn) return false;
    return std::strcmp(path + (pn - sn), suffix) == 0;
}

extern "C" {

wf_status metalbear_config_file_load(const char *path, metalbear_config *config,
                                     metalbear_config_file **out_owner,
                                     char *err, size_t err_len) {
    if (!path || !config || !out_owner) return WF_ERR_INVALID_ARG;
    *out_owner = nullptr;

    if (has_suffix(path, ".yml") || has_suffix(path, ".yaml"))
        return load_yaml(path, config, out_owner, err, err_len);
    return load_toml(path, config, out_owner, err, err_len);
}

} // extern "C"
