#ifndef METALBEAR_SCHEMA_VERSION_H
#define METALBEAR_SCHEMA_VERSION_H

#include "wolfram/xrpc.h"

#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The schema version this build understands, for every MetalBear database.
 *
 * Each database records its version in SQLite's `PRAGMA user_version`. A
 * database created before versions existed reads 0, which is version 1: all
 * migrations so far are idempotent `CREATE TABLE IF NOT EXISTS` and
 * `ALTER TABLE ... ADD COLUMN` statements run at open. Raise this constant in
 * the same change that adds a migration an older binary could misread, and
 * state the new number in CHANGELOG.md.
 */
#define METALBEAR_SCHEMA_VERSION 1

/*
 * Call right after opening `db`, before any migration. Returns WF_OK and
 * stamps a version-0 database with METALBEAR_SCHEMA_VERSION. Returns
 * WF_ERR_INTERNAL, and logs which database and which versions, if the
 * database was written by a newer build: opening it could corrupt it, so the
 * server refuses to start rather than guess. `name` is for the log only.
 */
wf_status metalbear_schema_open(sqlite3 *db, const char *name);

#ifdef __cplusplus
}
#endif

#endif
