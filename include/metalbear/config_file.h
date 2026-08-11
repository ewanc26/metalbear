#ifndef METALBEAR_CONFIG_FILE_H
#define METALBEAR_CONFIG_FILE_H

#include "metalbear/server.h"
#include "wolfram/xrpc.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * config_file.h — populate a metalbear_config from a TOML or YAML file.
 *
 * The dialect is chosen by extension: `.yml`/`.yaml` reads a deliberate
 * subset of YAML, anything else reads a deliberate subset of TOML. Both
 * dialects expose the exact same settings (see METALBEAR_CONFIG_FIELDS in
 * config_file.cpp, the single table both loaders expand) and share the same
 * strictness:
 *
 *   TOML: `[section]` headers, and `key = value` where a value is a quoted
 *   string, an integer, a boolean, or a flat array of quoted strings (joined
 *   with commas, which is how the crawler list is carried elsewhere).
 *
 *   YAML: a top-level `section:` key per TOML `[section]`, its settings
 *   indented exactly two spaces as `key: value` (a quoted string, a bare
 *   string, an integer, a boolean, or a flow array `[a, b]`). Every file this
 *   accepts is valid YAML under a real parser too — this just declines to
 *   interpret constructs it does not need (block sequences, multi-line
 *   scalars, anchors, arbitrary indentation).
 *
 * Comments run from `#` to end of line in both. That subset covers everything
 * a PDS needs to be configured with, and keeping it in-tree avoids adding a
 * parser dependency to a project whose point is that it is plain C with few
 * of them. Anything outside the subset is rejected loudly rather than
 * misinterpreted, because a configuration file that is silently half-read is
 * worse than one that will not load.
 *
 * Precedence: the file supplies values, and the environment overrides them.
 * An operator can therefore keep a checked-in config file and override a
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
