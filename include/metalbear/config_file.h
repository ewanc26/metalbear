#ifndef METALBEAR_CONFIG_FILE_H
#define METALBEAR_CONFIG_FILE_H

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * config_file.h — populate a metalbear_config from a TOML file.
 *
 * This reads a deliberate subset of TOML: `[section]` headers, and
 * `key = value` where a value is a quoted string, an integer, a boolean, or a
 * flat array of quoted strings (joined with commas, which is how the crawler
 * list is carried elsewhere). Comments run from `#` to end of line.
 *
 * That subset covers everything a PDS needs to be configured with, and keeping
 * it in-tree avoids adding a parser dependency to a project whose point is
 * that it is plain C with few of them. Anything outside the subset — nested
 * tables, multi-line strings, dates — is rejected loudly rather than
 * misinterpreted, because a configuration file that is silently half-read is
 * worse than one that will not load.
 *
 * Precedence: the file supplies values, and the environment overrides them.
 * An operator can therefore keep a checked-in config.toml and override a
 * single value per-deployment without editing it.
 */

/* Owns every string the config points at; freed by metalbear_config_free. */
typedef struct metalbear_config_file metalbear_config_file;

/*
 * Read `path` into `config`, leaving fields absent from the file untouched.
 * On failure returns non-WF_OK and writes a human-readable reason (including
 * the offending line number) into `err`, which may be NULL.
 */
wf_status metalbear_config_file_load(const char *path, metalbear_config *config,
                                     metalbear_config_file **out_owner,
                                     char *err, size_t err_len);

/* Release the strings the loaded config points at. Safe with NULL. */
void metalbear_config_file_free(metalbear_config_file *owner);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_CONFIG_FILE_H */
