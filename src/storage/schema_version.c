#include "metalbear/schema_version.h"

#include "metalbear/log.h"

#include <stdio.h>

wf_status metalbear_schema_open(sqlite3 *db, const char *name) {
    sqlite3_stmt *stmt = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, NULL) !=
        SQLITE_OK)
        return WF_ERR_INTERNAL;
    if (sqlite3_step(stmt) == SQLITE_ROW) found = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (found > METALBEAR_SCHEMA_VERSION) {
        LOG_ERROR("database '%s' is schema version %d, but this build only "
                  "understands up to %d: it was written by a newer MetalBear. "
                  "Refusing to open it; run the newer release, or restore the "
                  "snapshot taken before the update (docs/updating.md)",
                  name ? name : "?", found, METALBEAR_SCHEMA_VERSION);
        return WF_ERR_INTERNAL;
    }
    if (found == 0) {
        char sql[48];
        snprintf(sql, sizeof(sql), "PRAGMA user_version=%d;",
                 METALBEAR_SCHEMA_VERSION);
        if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
            return WF_ERR_INTERNAL;
    }
    return WF_OK;
}
