#include "metalbear/log.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

static metalbear_log_level log_level = METALBEAR_LOG_INFO;
static FILE *log_file = nullptr;
static bool log_json = false;

static metalbear_log_level metalbear_log_level_from_env(void) {
    const char *level = std::getenv("METALBEAR_LOG_LEVEL");
    if (!level || !level[0]) return METALBEAR_LOG_INFO;
    if (std::strcmp(level, "debug") == 0 || std::strcmp(level, "DEBUG") == 0)
        return METALBEAR_LOG_DEBUG;
    if (std::strcmp(level, "info") == 0 || std::strcmp(level, "INFO") == 0)
        return METALBEAR_LOG_INFO;
    if (std::strcmp(level, "warn") == 0 || std::strcmp(level, "WARN") == 0)
        return METALBEAR_LOG_WARN;
    if (std::strcmp(level, "error") == 0 || std::strcmp(level, "ERROR") == 0)
        return METALBEAR_LOG_ERROR;
    char *end = nullptr;
    long v = std::strtol(level, &end, 10);
    if (end && *end == '\0' && v >= 0 && v <= 3)
        return static_cast<metalbear_log_level>(v);
    return METALBEAR_LOG_INFO;
}

static FILE *metalbear_log_file_from_env(void) {
    const char *path = std::getenv("METALBEAR_LOG_FILE");
    if (!path || !path[0]) return nullptr;
    return std::fopen(path, "a");
}

static bool metalbear_log_json_from_env(void) {
    const char *format = std::getenv("METALBEAR_LOG_FORMAT");
    return format && (std::strcmp(format, "json") == 0 ||
                      std::strcmp(format, "JSON") == 0);
}

static void json_escape_into(FILE *out, const char *text) {
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(text);
         *p; p++) {
        switch (*p) {
            case '"':
                std::fputs("\\\"", out);
                break;
            case '\\':
                std::fputs("\\\\", out);
                break;
            case '\n':
                std::fputs("\\n", out);
                break;
            case '\r':
                std::fputs("\\r", out);
                break;
            case '\t':
                std::fputs("\\t", out);
                break;
            default:
                if (*p < 0x20)
                    std::fprintf(out, "\\u%04x", *p);
                else
                    std::fputc(*p, out);
        }
    }
}

void metalbear_log(metalbear_log_level level, const char *fmt, ...) {
    if (level < log_level) return;
    static const char *level_names[] = {"debug", "info", "warn", "error"};
    va_list args;
    FILE *out = log_file ? log_file : stderr;
    std::time_t now = std::time(nullptr);
    std::tm tm;
    gmtime_r(&now, &tm);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    if (log_json) {
        char message[2048];
        va_start(args, fmt);
        std::vsnprintf(message, sizeof(message), fmt, args);
        va_end(args);
        std::fprintf(out,
                     "{\"time\":\"%s\",\"level\":\"%s\",\"service\":"
                     "\"metalbear\",\"message\":\"",
                     ts, level_names[level]);
        json_escape_into(out, message);
        std::fputs("\"}\n", out);
    } else {
        static const char *display[] = {"DEBUG", "INFO", "WARN", "ERROR"};
        std::fprintf(out, "MetalBear [%s] [%s] ", display[level], ts);
        va_start(args, fmt);
        std::vfprintf(out, fmt, args);
        va_end(args);
        std::fprintf(out, "\n");
    }
    if (log_file) std::fflush(log_file);
}

void metalbear_log_configure(void) {
    log_level = metalbear_log_level_from_env();
    log_json = metalbear_log_json_from_env();
    FILE *opened = metalbear_log_file_from_env();
    if (opened) {
        if (log_file) std::fclose(log_file);
        log_file = opened;
    }
}

void metalbear_log_close(void) {
    if (!log_file) return;
    std::fclose(log_file);
    log_file = nullptr;
}
