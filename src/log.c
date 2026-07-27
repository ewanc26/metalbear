/*
 * log.c — the process's log.
 *
 * Extracted from the server so the daemon writes its startup and shutdown
 * messages the same way: a bare fprintf to stderr alongside a JSON stream
 * produces a line no collector accepts, and it is invariably the line saying
 * why the server would not start.
 */

#include "metalbear/log.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static metalbear_log_level log_level = METALBEAR_LOG_INFO;
static FILE *log_file = NULL;

static metalbear_log_level metalbear_log_level_from_env(void) {
    const char *level = getenv("METALBEAR_LOG_LEVEL");
    if (!level || !level[0]) return METALBEAR_LOG_INFO;
    if (strcmp(level, "debug") == 0 || strcmp(level, "DEBUG") == 0) return METALBEAR_LOG_DEBUG;
    if (strcmp(level, "info") == 0 || strcmp(level, "INFO") == 0) return METALBEAR_LOG_INFO;
    if (strcmp(level, "warn") == 0 || strcmp(level, "WARN") == 0) return METALBEAR_LOG_WARN;
    if (strcmp(level, "error") == 0 || strcmp(level, "ERROR") == 0) return METALBEAR_LOG_ERROR;
    char *end = NULL;
    long v = strtol(level, &end, 10);
    if (end && *end == '\0' && v >= 0 && v <= 3) return (int)v;
    return METALBEAR_LOG_INFO;
}

static FILE *metalbear_log_file_from_env(void) {
    const char *path = getenv("METALBEAR_LOG_FILE");
    if (!path || !path[0]) return NULL;
    return fopen(path, "a");
}

/*
 * Whether to emit one JSON object per line instead of the human-readable
 * form. Log collectors parse the former; a person reading a terminal wants
 * the latter, so it stays the default.
 */
static bool log_json = false;

static bool metalbear_log_json_from_env(void) {
    const char *format = getenv("METALBEAR_LOG_FORMAT");
    return format && (strcmp(format, "json") == 0 ||
                      strcmp(format, "JSON") == 0);
}

/* Escape a log message into a JSON string body (without the quotes). Control
 * characters are escaped rather than passed through: a message carrying a
 * newline would otherwise split one event into two malformed ones. */
static void json_escape_into(FILE *out, const char *text) {
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        default:
            if (*p < 0x20) fprintf(out, "\\u%04x", *p);
            else fputc(*p, out);
        }
    }
}

void metalbear_log(metalbear_log_level level, const char *fmt, ...) {
    if (level < log_level) return;
    static const char *level_names[] = {"debug", "info", "warn", "error"};
    va_list args;
    FILE *out = log_file ? log_file : stderr;
    time_t now = time(NULL);
    struct tm tm;
    /*
     * UTC, because the line says so. This used to format local time and
     * append a `Z`, which reads as a correct timestamp in the wrong zone —
     * the kind of error that only surfaces when two hosts' logs are lined up
     * against each other during an incident.
     */
    gmtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    if (log_json) {
        char message[2048];
        va_start(args, fmt);
        vsnprintf(message, sizeof(message), fmt, args);
        va_end(args);
        fprintf(out, "{\"time\":\"%s\",\"level\":\"%s\",\"service\":"
                     "\"metalbear\",\"message\":\"", ts,
                level_names[level]);
        json_escape_into(out, message);
        fputs("\"}\n", out);
    } else {
        static const char *display[] = {"DEBUG", "INFO", "WARN", "ERROR"};
        fprintf(out, "MetalBear [%s] [%s] ", display[level], ts);
        va_start(args, fmt);
        vfprintf(out, fmt, args);
        va_end(args);
        fprintf(out, "\n");
    }
    if (log_file) fflush(log_file);
}

void metalbear_log_configure(void) {
    log_level = metalbear_log_level_from_env();
    log_json = metalbear_log_json_from_env();
    FILE *opened = metalbear_log_file_from_env();
    if (opened) {
        if (log_file) fclose(log_file);
        log_file = opened;
    }
}

void metalbear_log_close(void) {
    if (!log_file) return;
    fclose(log_file);
    log_file = NULL;
}
