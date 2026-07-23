#define _POSIX_C_SOURCE 200809L

#include "metalbear/sequencer.h"

#include "wolfram/sync_publish.h"

#include <cJSON.h>
#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct metalbear_sequencer {
    sqlite3 *db;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int closing;
};

typedef struct subscriber_worker {
    metalbear_sequencer *sequencer;
    wf_xrpc_ws_stream *stream;
    int64_t cursor;
    const char *error;
    const char *message;
} subscriber_worker;

static void timestamp_now(char out[64]) {
    struct timespec ts;
    struct tm utc;
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &utc);
    snprintf(out, 64, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
             utc.tm_hour, utc.tm_min, utc.tm_sec, ts.tv_nsec / 1000000L);
}

static int64_t current_locked(metalbear_sequencer *s) {
    sqlite3_stmt *stmt = NULL;
    int64_t seq = 0;
    if (sqlite3_prepare_v2(s->db, "SELECT COALESCE(MAX(seq),0) FROM events;",
                           -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW)
        seq = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return seq;
}

int64_t metalbear_sequencer_current(metalbear_sequencer *s) {
    if (!s) return 0;
    pthread_mutex_lock(&s->mutex);
    int64_t seq = current_locked(s);
    pthread_mutex_unlock(&s->mutex);
    return seq;
}

static wf_status append_event(metalbear_sequencer *s,
                              wf_subscribe_event *event) {
    sqlite3_stmt *stmt = NULL;
    unsigned char *frame = NULL;
    size_t frame_len = 0;
    wf_status status = WF_ERR_INTERNAL;
    pthread_mutex_lock(&s->mutex);
    if (s->closing || sqlite3_exec(s->db, "BEGIN IMMEDIATE;", NULL, NULL,
                                   NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO events(frame,created_at) VALUES(zeroblob(0),?);",
            -1, &stmt, NULL) != SQLITE_OK)
        goto rollback;
    char now[64];
    timestamp_now(now);
    sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) goto rollback;
    sqlite3_finalize(stmt);
    stmt = NULL;

    event->seq = sqlite3_last_insert_rowid(s->db);
    switch (event->type) {
    case WF_SUBSCRIBE_EVENT_COMMIT:
        event->data.commit.seq = event->seq;
        snprintf(event->data.commit.time, sizeof(event->data.commit.time),
                 "%s", now);
        break;
    case WF_SUBSCRIBE_EVENT_SYNC:
        event->data.sync.seq = event->seq;
        snprintf(event->data.sync.time, sizeof(event->data.sync.time),
                 "%s", now);
        break;
    case WF_SUBSCRIBE_EVENT_IDENTITY:
        event->data.identity.seq = event->seq;
        snprintf(event->data.identity.time, sizeof(event->data.identity.time),
                 "%s", now);
        break;
    case WF_SUBSCRIBE_EVENT_ACCOUNT:
        event->data.account.seq = event->seq;
        snprintf(event->data.account.time, sizeof(event->data.account.time),
                 "%s", now);
        break;
    default:
        goto rollback;
    }
    status = wf_sync_publish_event(event, &frame, &frame_len);
    if (status != WF_OK) goto rollback;
    if (sqlite3_prepare_v2(s->db, "UPDATE events SET frame=? WHERE seq=?;",
                           -1, &stmt, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_blob(stmt, 1, frame, (int)frame_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, event->seq);
    if (sqlite3_step(stmt) != SQLITE_DONE) goto rollback;
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (sqlite3_exec(s->db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback;
    status = WF_OK;
    pthread_cond_broadcast(&s->changed);
    goto done;

rollback:
    sqlite3_finalize(stmt);
    stmt = NULL;
    sqlite3_exec(s->db, "ROLLBACK;", NULL, NULL, NULL);
    if (status == WF_OK) status = WF_ERR_INTERNAL;
done:
    sqlite3_finalize(stmt);
    free(frame);
    pthread_mutex_unlock(&s->mutex);
    return status;
}

static wf_status seed_account(metalbear_sequencer *s, const char *did,
                              const char *handle) {
    if (metalbear_sequencer_current(s) != 0) return WF_OK;
    wf_subscribe_event identity = {.type = WF_SUBSCRIBE_EVENT_IDENTITY};
    snprintf(identity.data.identity.did, sizeof(identity.data.identity.did),
             "%s", did);
    snprintf(identity.data.identity.handle,
             sizeof(identity.data.identity.handle), "%s", handle);
    identity.data.identity.has_handle = 1;
    wf_status status = append_event(s, &identity);
    if (status != WF_OK) return status;
    wf_subscribe_event account = {.type = WF_SUBSCRIBE_EVENT_ACCOUNT};
    snprintf(account.data.account.did, sizeof(account.data.account.did),
             "%s", did);
    account.data.account.active = 1;
    return append_event(s, &account);
}

wf_status metalbear_sequencer_account_status(metalbear_sequencer *s,
                                             const char *did, int active,
                                             const char *status_text) {
    if (!s || !did) return WF_ERR_INVALID_ARG;
    wf_subscribe_event event = {.type = WF_SUBSCRIBE_EVENT_ACCOUNT};
    snprintf(event.data.account.did, sizeof(event.data.account.did), "%s",
             did);
    event.data.account.active = active ? 1 : 0;
    if (status_text && status_text[0]) {
        snprintf(event.data.account.status,
                 sizeof(event.data.account.status), "%s", status_text);
        event.data.account.has_status = 1;
    }
    return append_event(s, &event);
}

wf_status metalbear_sequencer_account_activation(
        metalbear_sequencer *s, const char *did, const char *handle,
        metalbear_repo_store *repo) {
    if (!s || !did || !handle || !repo) return WF_ERR_INVALID_ARG;
    wf_subscribe_event identity = {.type = WF_SUBSCRIBE_EVENT_IDENTITY};
    snprintf(identity.data.identity.did, sizeof(identity.data.identity.did),
             "%s", did);
    snprintf(identity.data.identity.handle,
             sizeof(identity.data.identity.handle), "%s", handle);
    identity.data.identity.has_handle = 1;
    wf_status status = append_event(s, &identity);
    if (status != WF_OK) return status;
    status = metalbear_sequencer_account_status(s, did, 1, NULL);
    if (status != WF_OK) return status;

    char *rev = NULL, *cid = NULL;
    status = metalbear_repo_store_get_head(repo, &rev, &cid);
    free(cid);
    if (status == WF_ERR_NOT_FOUND) return WF_OK;
    if (status != WF_OK) return status;
    unsigned char *blocks = NULL;
    size_t blocks_len = 0;
    status = metalbear_repo_store_export(repo, NULL, &blocks, &blocks_len);
    if (status == WF_OK) {
        wf_subscribe_event sync = {.type = WF_SUBSCRIBE_EVENT_SYNC};
        snprintf(sync.data.sync.did, sizeof(sync.data.sync.did), "%s", did);
        snprintf(sync.data.sync.rev, sizeof(sync.data.sync.rev), "%s", rev);
        sync.data.sync.blocks = blocks;
        sync.data.sync.blocks_len = blocks_len;
        status = append_event(s, &sync);
    }
    free(blocks);
    free(rev);
    return status;
}

wf_status metalbear_sequencer_open(const char *path, const char *did,
                                   const char *handle,
                                   metalbear_sequencer **out) {
    if (!path || !did || !handle || !out) return WF_ERR_INVALID_ARG;
    *out = NULL;
    metalbear_sequencer *s = calloc(1, sizeof(*s));
    if (!s) return WF_ERR_ALLOC;
    if (pthread_mutex_init(&s->mutex, NULL) != 0) {
        free(s);
        return WF_ERR_INTERNAL;
    }
    if (pthread_cond_init(&s->changed, NULL) != 0) {
        pthread_mutex_destroy(&s->mutex);
        free(s);
        return WF_ERR_INTERNAL;
    }
    if (sqlite3_open(path, &s->db) != SQLITE_OK ||
        sqlite3_exec(s->db,
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE IF NOT EXISTS events("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            "frame BLOB NOT NULL,created_at TEXT NOT NULL);",
            NULL, NULL, NULL) != SQLITE_OK ||
        seed_account(s, did, handle) != WF_OK) {
        metalbear_sequencer_free(s);
        return WF_ERR_INTERNAL;
    }
    *out = s;
    return WF_OK;
}

void metalbear_sequencer_repo_event(const metalbear_repo_store_event *repo_event,
                                    void *context) {
    metalbear_sequencer *s = context;
    if (!s || !repo_event) return;
    wf_subscribe_event event = {0};
    /* `op` and `path` must live at function scope: append_event (below)
     * serialises commit->ops -> &op and op.path -> path after the else
     * block ends; block scope would leave both dangling. */
    wf_subscribe_repo_op op = {0};
    char path[512];
    if (repo_event->kind == METALBEAR_REPO_STORE_EVENT_SYNC) {
        event.type = WF_SUBSCRIBE_EVENT_SYNC;
        snprintf(event.data.sync.did, sizeof(event.data.sync.did), "%s",
                 repo_event->did);
        snprintf(event.data.sync.rev, sizeof(event.data.sync.rev), "%s",
                 repo_event->rev);
        event.data.sync.blocks = (unsigned char *)repo_event->blocks;
        event.data.sync.blocks_len = repo_event->blocks_len;
    } else {
        event.type = WF_SUBSCRIBE_EVENT_COMMIT;
        wf_subscribe_commit *commit = &event.data.commit;
        snprintf(commit->did, sizeof(commit->did), "%s", repo_event->did);
        commit->commit_cid = repo_event->commit_cid;
        snprintf(commit->rev, sizeof(commit->rev), "%s", repo_event->rev);
        if (repo_event->since)
            snprintf(commit->since, sizeof(commit->since), "%s",
                     repo_event->since);
        commit->blocks = (unsigned char *)repo_event->blocks;
        commit->blocks_len = repo_event->blocks_len;
        commit->prev_data = repo_event->prev_data;
        commit->has_prev_data = repo_event->has_prev_data;
        snprintf(op.action, sizeof(op.action), "%s", repo_event->action);
        snprintf(path, sizeof(path), "%s/%s", repo_event->collection,
                 repo_event->rkey);
        op.path = path;
        op.cid = repo_event->cid;
        op.has_cid = repo_event->has_cid;
        op.prev = repo_event->prev;
        op.has_prev = repo_event->has_prev;
        commit->ops = &op;
        commit->ops_count = 1;
    }
    if (append_event(s, &event) != WF_OK)
        fprintf(stderr, "MetalBear: failed to persist repository event\n");
}

wf_status metalbear_sequencer_reconcile_repo(metalbear_sequencer *s,
                                             metalbear_repo_store *repo) {
    if (!s || !repo) return WF_ERR_INVALID_ARG;
    char *head_rev = NULL;
    char *head_cid = NULL;
    wf_status status = metalbear_repo_store_get_head(repo, &head_rev, &head_cid);
    if (status == WF_ERR_NOT_FOUND) return WF_OK;
    if (status != WF_OK) return status;

    int matched = 0;
    pthread_mutex_lock(&s->mutex);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT frame FROM events ORDER BY seq DESC;",
                           -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *frame = sqlite3_column_blob(stmt, 0);
            int length = sqlite3_column_bytes(stmt, 0);
            wf_subscribe_event event = {0};
            if (frame && length > 0 &&
                wf_subscribe_decode_frame(frame, (size_t)length, &event) ==
                    WF_OK) {
                const char *rev = event.type == WF_SUBSCRIBE_EVENT_COMMIT
                                      ? event.data.commit.rev
                                  : event.type == WF_SUBSCRIBE_EVENT_SYNC
                                      ? event.data.sync.rev : NULL;
                if (rev) {
                    matched = strcmp(rev, head_rev) == 0;
                    wf_subscribe_event_free(&event);
                    break;
                }
                wf_subscribe_event_free(&event);
            }
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->mutex);
    if (matched) {
        free(head_rev);
        free(head_cid);
        return WF_OK;
    }

    unsigned char *blocks = NULL;
    size_t blocks_len = 0;
    status = metalbear_repo_store_export(repo, NULL, &blocks, &blocks_len);
    if (status == WF_OK) {
        wf_subscribe_event event = {.type = WF_SUBSCRIBE_EVENT_SYNC};
        snprintf(event.data.sync.did, sizeof(event.data.sync.did), "%s",
                 metalbear_repo_store_did(repo));
        snprintf(event.data.sync.rev, sizeof(event.data.sync.rev), "%s",
                 head_rev);
        event.data.sync.blocks = blocks;
        event.data.sync.blocks_len = blocks_len;
        status = append_event(s, &event);
    }
    free(blocks);
    free(head_rev);
    free(head_cid);
    return status;
}

wf_status metalbear_sequencer_reconcile_account(metalbear_sequencer *s,
                                                const char *did, int active) {
    if (!s || !did) return WF_ERR_INVALID_ARG;
    int matched = 0;
    pthread_mutex_lock(&s->mutex);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT frame FROM events ORDER BY seq DESC;",
                           -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *frame = sqlite3_column_blob(stmt, 0);
            int length = sqlite3_column_bytes(stmt, 0);
            wf_subscribe_event event = {0};
            if (frame && length > 0 &&
                wf_subscribe_decode_frame(frame, (size_t)length, &event) ==
                    WF_OK) {
                if (event.type == WF_SUBSCRIBE_EVENT_ACCOUNT) {
                    matched = strcmp(event.data.account.did, did) == 0 &&
                              event.data.account.active == (active ? 1 : 0);
                    wf_subscribe_event_free(&event);
                    break;
                }
                wf_subscribe_event_free(&event);
            }
        }
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->mutex);
    if (matched) return WF_OK;
    return metalbear_sequencer_account_status(
        s, did, active, active ? NULL : "deactivated");
}

static int read_next_locked(metalbear_sequencer *s, int64_t cursor,
                            int64_t *seq, unsigned char **frame,
                            size_t *frame_len) {
    sqlite3_stmt *stmt = NULL;
    int found = 0;
    *frame = NULL;
    *frame_len = 0;
    if (sqlite3_prepare_v2(s->db,
            "SELECT seq,frame FROM events WHERE seq>? ORDER BY seq LIMIT 1;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(stmt, 1, cursor);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int length = sqlite3_column_bytes(stmt, 1);
        const void *data = sqlite3_column_blob(stmt, 1);
        unsigned char *copy = malloc(length > 0 ? (size_t)length : 1);
        if (copy) {
            if (length > 0) memcpy(copy, data, (size_t)length);
            *seq = sqlite3_column_int64(stmt, 0);
            *frame = copy;
            *frame_len = (size_t)length;
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

static void *subscriber_main(void *raw) {
    subscriber_worker *worker = raw;
    metalbear_sequencer *s = worker->sequencer;
    if (worker->error) {
        unsigned char *frame = NULL;
        size_t length = 0;
        if (wf_sync_publish_error(worker->cursor, worker->error,
                                  worker->message, &frame, &length) == WF_OK) {
            wf_xrpc_server_ws_send(worker->stream, frame, length);
            free(frame);
        }
        wf_xrpc_server_ws_close(worker->stream, 1008);
    } else {
        while (!wf_xrpc_server_ws_is_closed(worker->stream)) {
            unsigned char *frame = NULL;
            size_t length = 0;
            int64_t seq = 0;
            pthread_mutex_lock(&s->mutex);
            while (!s->closing &&
                   !read_next_locked(s, worker->cursor, &seq, &frame,
                                     &length)) {
                struct timespec deadline;
                clock_gettime(CLOCK_REALTIME, &deadline);
                deadline.tv_nsec += 250000000L;
                if (deadline.tv_nsec >= 1000000000L) {
                    deadline.tv_sec++;
                    deadline.tv_nsec -= 1000000000L;
                }
                pthread_cond_timedwait(&s->changed, &s->mutex, &deadline);
                if (wf_xrpc_server_ws_is_closed(worker->stream)) break;
            }
            int closing = s->closing;
            pthread_mutex_unlock(&s->mutex);
            if (closing || wf_xrpc_server_ws_is_closed(worker->stream)) {
                free(frame);
                break;
            }
            if (frame) {
                if (wf_xrpc_server_ws_send(worker->stream, frame, length) !=
                    WF_OK) {
                    free(frame);
                    break;
                }
                worker->cursor = seq;
                free(frame);
            }
        }
    }
    wf_xrpc_server_ws_release(worker->stream);
    free(worker);
    return NULL;
}

static wf_status subscribe_repos(void *context,
                                 const wf_xrpc_request *request,
                                 wf_xrpc_ws_stream *stream) {
    metalbear_sequencer *s = context;
    int has_cursor = 0;
    int64_t cursor = 0;
    const cJSON *item = request->params
        ? cJSON_GetObjectItemCaseSensitive(request->params, "cursor") : NULL;
    if (cJSON_IsString(item)) {
        char *end = NULL;
        errno = 0;
        long long parsed = strtoll(item->valuestring, &end, 10);
        if (!errno && end && *end == '\0' && parsed >= 0) {
            cursor = (int64_t)parsed;
            has_cursor = 1;
        }
    }
    int64_t current = metalbear_sequencer_current(s);
    subscriber_worker *worker = calloc(1, sizeof(*worker));
    if (!worker) return WF_ERR_ALLOC;
    worker->sequencer = s;
    worker->stream = stream;
    worker->cursor = has_cursor ? cursor : current;
    if (item && !has_cursor) {
        worker->error = "InvalidRequest";
        worker->message = "Cursor must be a non-negative integer.";
    } else if (cursor > current) {
        worker->error = "FutureCursor";
        worker->message = "Cursor in the future.";
    }
    if (wf_xrpc_server_ws_retain(stream) != WF_OK) {
        free(worker);
        return WF_ERR_INVALID_ARG;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, subscriber_main, worker) != 0) {
        wf_xrpc_server_ws_release(stream);
        free(worker);
        return WF_ERR_INTERNAL;
    }
    pthread_detach(thread);
    return WF_OK;
}

wf_status metalbear_sequencer_register(metalbear_sequencer *sequencer,
                                       wf_xrpc_server *server) {
    if (!sequencer || !server) return WF_ERR_INVALID_ARG;
    return wf_xrpc_server_register_ws(server,
        "com.atproto.sync.subscribeRepos", subscribe_repos, sequencer);
}

wf_status metalbear_sequencer_retain(metalbear_sequencer *s,
                                     int64_t max_age_seconds,
                                     int64_t min_events) {
    if (!s) return WF_ERR_INVALID_ARG;
    pthread_mutex_lock(&s->mutex);
    int64_t current = current_locked(s);
    int64_t cutoff = current - min_events;
    if (cutoff <= 0) {
        pthread_mutex_unlock(&s->mutex);
        return WF_OK;
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
            "DELETE FROM events WHERE seq <= ? AND "
            "created_at < datetime('now', ?);",
            -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->mutex);
        return WF_ERR_INTERNAL;
    }
    char age_str[64];
    snprintf(age_str, sizeof(age_str), "-%lld seconds", (long long)max_age_seconds);
    sqlite3_bind_int64(stmt, 1, cutoff);
    sqlite3_bind_text(stmt, 2, age_str, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->mutex);
    return WF_OK;
}

void metalbear_sequencer_free(metalbear_sequencer *s) {
    if (!s) return;
    pthread_mutex_lock(&s->mutex);
    s->closing = 1;
    pthread_cond_broadcast(&s->changed);
    pthread_mutex_unlock(&s->mutex);
    sqlite3_close(s->db);
    pthread_cond_destroy(&s->changed);
    pthread_mutex_destroy(&s->mutex);
    free(s);
}
