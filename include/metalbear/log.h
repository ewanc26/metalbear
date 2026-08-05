#ifndef METALBEAR_LOG_H
#define METALBEAR_LOG_H

/*
 * log.h — the process's log, in one of two formats.
 *
 * `METALBEAR_LOG_FORMAT=json` emits one JSON object per line for a collector
 * to parse; anything else keeps the human-readable form, which is what a
 * person watching a terminal wants and so stays the default.
 *
 * Everything that writes a log line goes through here, including the daemon's
 * own startup and shutdown messages: a single fprintf to stderr alongside a
 * JSON stream produces a line no parser accepts, and the operator loses
 * exactly the message that says why the server would not start.
 *
 * `METALBEAR_LOG_LEVEL` is debug/info/warn/error (or 0-3), and
 * `METALBEAR_LOG_FILE` a path to append to instead of stderr.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum metalbear_log_level {
    METALBEAR_LOG_DEBUG = 0,
    METALBEAR_LOG_INFO,
    METALBEAR_LOG_WARN,
    METALBEAR_LOG_ERROR,
} metalbear_log_level;

/* Read METALBEAR_LOG_LEVEL / _FORMAT / _FILE. Safe to call more than once;
 * the server calls it at startup and the daemon before that, so a failure to
 * start is reported in the format the operator configured. */
void metalbear_log_configure(void);

void metalbear_log(metalbear_log_level level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

/* Close a configured log file. The next line falls back to stderr, so a
 * caller that logs after this still gets its message somewhere. */
void metalbear_log_close(void);

#define LOG_DEBUG(...) metalbear_log(METALBEAR_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) metalbear_log(METALBEAR_LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...) metalbear_log(METALBEAR_LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) metalbear_log(METALBEAR_LOG_ERROR, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
