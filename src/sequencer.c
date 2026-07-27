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
    metalbear_sequencer_notify_cb notify;
    void *notify_ctx;
};

void metalbear_sequencer_set_notify(metalbear_sequencer *s,
                                    metalbear_sequencer_notify_cb cb,
                                    void *ctx) {
    if (!s) return;
    pthread_mutex_lock(&s->mutex);
    s->notify = cb;
    s->notify_ctx = ctx;
    pthread_mutex_unlock(&s->mutex);
}

typedef struct subscriber_worker {
    metalbear_sequencer *sequencer;
    wf_xrpc_ws_stream *stream;
    int64_t cursor;
    const char *error;
    const char *message;
    /* The requested cursor pointed before the oldest retained event, so the
     * span between them can never be delivered. The subscriber is told with
     * #info{OutdatedCursor} before the replay starts, rather than being
     * silently repositioned. */
    int outdated;
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

/*
 * The highest sequence number retention has deleted, or 0 if it never has.
 *
 * This is the only honest basis for OutdatedCursor. "Older than the oldest
 * surviving event" is not the same question: sequence numbers are seeded from
 * wall-clock time so a brand-new log legitimately starts in the billions, and
 * a client asking from 0 there has missed nothing — the events it is asking
 * about never existed. Only events this server actually deleted represent a
 * gap it can never serve.
 */
static int64_t pruned_through(metalbear_sequencer *s) {
    sqlite3_stmt *stmt = NULL;
    int64_t pruned = 0;
    if (!s) return 0;
    pthread_mutex_lock(&s->mutex);
    if (sqlite3_prepare_v2(s->db,
            "SELECT value FROM meta WHERE key='pruned_through';",
            -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        pruned = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->mutex);
    return pruned;
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
    metalbear_sequencer_notify_cb notify = s->notify;
    void *notify_ctx = s->notify_ctx;
    pthread_mutex_unlock(&s->mutex);
    /* Outside the lock: the callback may do I/O, and it must never be able to
     * deadlock the write path it was triggered from. */
    if (status == WF_OK && notify) notify(notify_ctx);
    return status;
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

wf_status metalbear_sequencer_identity(metalbear_sequencer *s, const char *did,
                                       const char *handle) {
    if (!s || !did || !handle || !handle[0]) return WF_ERR_INVALID_ARG;
    wf_subscribe_event identity = {.type = WF_SUBSCRIBE_EVENT_IDENTITY};
    snprintf(identity.data.identity.did, sizeof(identity.data.identity.did),
             "%s", did);
    snprintf(identity.data.identity.handle,
             sizeof(identity.data.identity.handle), "%s", handle);
    identity.data.identity.has_handle = 1;
    return append_event(s, &identity);
}

wf_status metalbear_sequencer_account_activation(
        metalbear_sequencer *s, const char *did, const char *handle,
        metalbear_repo_store *repo) {
    if (!s || !did || !handle || !repo) return WF_ERR_INVALID_ARG;
    wf_status status = metalbear_sequencer_identity(s, did, handle);
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
    status = metalbear_repo_store_export_commit(repo, &blocks, &blocks_len);
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

/*
 * Start a brand-new event log above any sequence number this host can plausibly
 * have issued before.
 *
 * Firehose cursors are per-host and consumers persist them. A sequence that
 * restarts at 1 — after a restore from backup, a rebuilt data directory, or a
 * migration — hands out numbers the host has already used. Every consumer
 * holding a higher cursor then asks for events that will not exist for a long
 * time, gets FutureCursor, and retries forever: observed here as a relay stuck
 * reconnecting on cursor=390 against a log that had restarted at 1, never
 * ingesting anything.
 *
 * Seeding from the wall clock makes the sequence monotonic across the lifetime
 * of the host rather than the lifetime of the file, so an old cursor lands in
 * the past — where it is served normally — instead of the future. The
 * reference PDS uses a bare autoincrement and has the same hazard; nothing in
 * the protocol requires seq to start at 1, only that it increase.
 *
 * Only applied to an empty log, so an existing sequence is never disturbed.
 */
static wf_status seed_sequence_floor(metalbear_sequencer *s) {
    sqlite3_stmt *stmt = NULL;
    int64_t existing = 0;
    if (sqlite3_prepare_v2(s->db, "SELECT COUNT(*) FROM events;", -1, &stmt,
                           NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW)
        existing = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    if (existing > 0) return WF_OK;

    /* Seconds since the epoch: comfortably above any counter a previous
     * incarnation reached, and still far inside the int64 the frame uses. */
    int64_t floor_seq = (int64_t)time(NULL);
    if (floor_seq <= 0) return WF_OK;

    /*
     * Insert a placeholder at the target seq, then delete it. AUTOINCREMENT
     * keeps its high-water mark after the row goes, so the next real event
     * lands at floor_seq + 1. Writing sqlite_sequence directly would be
     * shorter but that table does not exist until the first AUTOINCREMENT
     * insert has happened, and it carries no unique index to upsert against.
     */
    stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
            "INSERT INTO events(seq,frame,created_at) VALUES(?,zeroblob(0),'');",
            -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return WF_OK;   /* not fatal: a sequence from 1 still works */
    }
    sqlite3_bind_int64(stmt, 1, floor_seq);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return WF_OK;

    sqlite3_exec(s->db, "DELETE FROM events WHERE frame = zeroblob(0)"
                        " AND created_at = '';", NULL, NULL, NULL);
    return WF_OK;
}

wf_status metalbear_sequencer_open(const char *path,
                                   metalbear_sequencer **out) {
    if (!path || !out) return WF_ERR_INVALID_ARG;
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
            "frame BLOB NOT NULL,created_at TEXT NOT NULL);"
            /* Retention's high-water mark lives here: see pruned_through(). */
            "CREATE TABLE IF NOT EXISTS meta("
            "key TEXT PRIMARY KEY,value INTEGER NOT NULL);",
            NULL, NULL, NULL) != SQLITE_OK ||
        seed_sequence_floor(s) != WF_OK) {
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
    /* `ops` and the path buffers must live at function scope: append_event
     * (below) serialises commit->ops and each op.path after the else block
     * ends; block scope would leave them dangling. */
    wf_subscribe_repo_op *ops = NULL;
    char (*paths)[512] = NULL;
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
        /* A batched applyWrites is one commit carrying several ops; the
         * #commit frame must list all of them. */
        size_t count = repo_event->ops_count;
        if (count > 0) {
            ops = calloc(count, sizeof(*ops));
            paths = calloc(count, sizeof(*paths));
            if (!ops || !paths) {
                free(ops);
                free(paths);
                fprintf(stderr,
                        "MetalBear: out of memory sequencing repository event\n");
                return;
            }
            for (size_t i = 0; i < count; i++) {
                const metalbear_repo_store_op *src = &repo_event->ops[i];
                snprintf(ops[i].action, sizeof(ops[i].action), "%s",
                         src->action ? src->action : "");
                snprintf(paths[i], sizeof(paths[i]), "%s/%s",
                         src->collection ? src->collection : "",
                         src->rkey ? src->rkey : "");
                ops[i].path = paths[i];
                ops[i].cid = src->cid;
                ops[i].has_cid = src->has_cid;
                ops[i].prev = src->prev;
                ops[i].has_prev = src->has_prev;
            }
        }
        commit->ops = ops;
        commit->ops_count = count;
    }
    if (append_event(s, &event) != WF_OK)
        fprintf(stderr, "MetalBear: failed to persist repository event\n");
    free(ops);
    free(paths);
}

wf_status metalbear_sequencer_reconcile_repo(metalbear_sequencer *s,
                                             metalbear_repo_store *repo) {
    if (!s || !repo) return WF_ERR_INVALID_ARG;
    char *head_rev = NULL;
    char *head_cid = NULL;
    wf_status status = metalbear_repo_store_get_head(repo, &head_rev, &head_cid);
    if (status == WF_ERR_NOT_FOUND) return WF_OK;
    if (status != WF_OK) return status;

    /*
     * Find this repo's own newest commit/sync, not the log's.
     *
     * The log is host-wide, so the newest event carrying a rev almost always
     * belongs to a different account. Stopping at the first one found compared
     * somebody else's rev against this head, decided they differed, and
     * published a redundant #sync for this repo on nearly every startup.
     * Skip events for other DIDs instead of stopping at them.
     */
    const char *repo_did = metalbear_repo_store_did(repo);
    int matched = 0;
    pthread_mutex_lock(&s->mutex);
    sqlite3_stmt *stmt = NULL;
    if (repo_did &&
        sqlite3_prepare_v2(s->db, "SELECT frame FROM events ORDER BY seq DESC;",
                           -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *frame = sqlite3_column_blob(stmt, 0);
            int length = sqlite3_column_bytes(stmt, 0);
            wf_subscribe_event event = {0};
            if (frame && length > 0 &&
                wf_subscribe_decode_frame(frame, (size_t)length, &event) ==
                    WF_OK) {
                const char *rev = NULL;
                const char *event_did = NULL;
                if (event.type == WF_SUBSCRIBE_EVENT_COMMIT) {
                    rev = event.data.commit.rev;
                    event_did = event.data.commit.did;
                } else if (event.type == WF_SUBSCRIBE_EVENT_SYNC) {
                    rev = event.data.sync.rev;
                    event_did = event.data.sync.did;
                }
                if (rev && event_did && strcmp(event_did, repo_did) == 0) {
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
    status = metalbear_repo_store_export_commit(repo, &blocks, &blocks_len);
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
                /* Only this account's own #account events say anything about
                 * its state. Breaking at the first one of any DID compared
                 * against a stranger's record and re-announced this account on
                 * nearly every startup. */
                if (event.type == WF_SUBSCRIBE_EVENT_ACCOUNT &&
                    strcmp(event.data.account.did, did) == 0) {
                    matched = event.data.account.active == (active ? 1 : 0);
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

/*
 * Fetch the first event after `cursor`.
 *
 * Returns 1 with an owned frame, 0 when the stream is simply up to date, and
 * -1 when the log could not be read at all. That last case used to be folded
 * into 0: a failing query — a corrupt database, most obviously — looked
 * identical to "no new events", so a subscriber sat there being told nothing
 * had happened, forever, while every later event piled up behind the
 * unreadable one. The connection stayed open and healthy-looking and the
 * stream was silently dead, which is a great deal worse than an error.
 */
static int read_next_locked(metalbear_sequencer *s, int64_t cursor,
                            int64_t *seq, unsigned char **frame,
                            size_t *frame_len) {
    sqlite3_stmt *stmt = NULL;
    int found = 0;
    *frame = NULL;
    *frame_len = 0;
    if (sqlite3_prepare_v2(s->db,
            "SELECT seq,frame FROM events WHERE seq>? ORDER BY seq LIMIT 1;",
            -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, cursor);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
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
    } else if (rc != SQLITE_DONE) {
        found = -1;
    }
    sqlite3_finalize(stmt);
    return found;
}

/* Keepalive cadence for an idle firehose. Must stay well under the tightest
 * idle timeout in a typical deployment path (nginx defaults to 60s). */
#define METALBEAR_FIREHOSE_PING_SECONDS 20

/* Live value, set from config at startup. */
static int firehose_ping_seconds = METALBEAR_FIREHOSE_PING_SECONDS;

void metalbear_sequencer_set_ping_seconds(int64_t seconds) {
    if (seconds > 0) firehose_ping_seconds = (int)seconds;
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
        /*
         * A firehose is idle most of the time on a small server, and an idle
         * connection looks dead to every proxy in the path — nginx's
         * proxy_read_timeout defaults to 60s, CDNs impose their own. Relays
         * were observed reconnecting every ~60s against this PDS for exactly
         * that reason, never staying attached long enough to be useful.
         * Ping periodically so the connection survives the quiet.
         */
        /* Announce a gap before any event goes out, so the subscriber can
         * attribute the jump to retention rather than to lost frames. */
        if (worker->outdated) {
            wf_subscribe_event info = {.type = WF_SUBSCRIBE_EVENT_INFO};
            snprintf(info.data.info.name, sizeof(info.data.info.name), "%s",
                     "OutdatedCursor");
            snprintf(info.data.info.message, sizeof(info.data.info.message),
                     "%s", "Requested cursor exceeded limit. Possibly missing "
                           "events");
            info.data.info.has_message = 1;
            unsigned char *frame = NULL;
            size_t length = 0;
            if (wf_sync_publish_event(&info, &frame, &length) == WF_OK) {
                wf_xrpc_server_ws_send(worker->stream, frame, length);
                free(frame);
            }
        }

        time_t last_activity = time(NULL);
        while (!wf_xrpc_server_ws_is_closed(worker->stream)) {
            unsigned char *frame = NULL;
            size_t length = 0;
            int64_t seq = 0;
            pthread_mutex_lock(&s->mutex);
            /* Bounded wait: hand control back to the outer loop even when no
             * event arrives, so the keepalive below actually gets a turn. An
             * unbounded wait here would park this thread until the next write
             * and never ping — which is exactly what an idle firehose does. */
            int read_rc = 0;
            for (int wait = 0; wait < 4 && !s->closing &&
                    (read_rc = read_next_locked(s, worker->cursor, &seq, &frame,
                                                &length)) == 0; wait++) {
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
            if (read_rc < 0) {
                /* The log is unreadable. Say so and close, rather than hold a
                 * connection open that will never carry another event. */
                fprintf(stderr,
                        "MetalBear: firehose log unreadable at cursor %lld: %s\n",
                        (long long)worker->cursor, sqlite3_errmsg(s->db));
                free(frame);
                unsigned char *err = NULL;
                size_t err_len = 0;
                if (wf_sync_publish_error(worker->cursor, "InternalServerError",
                                          "event log unreadable", &err,
                                          &err_len) == WF_OK) {
                    wf_xrpc_server_ws_send(worker->stream, err, err_len);
                    free(err);
                }
                wf_xrpc_server_ws_close(worker->stream, 1011);
                break;
            }
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
                last_activity = time(NULL);
            } else {
                /* Comfortably inside a 60s proxy idle timeout. */
                time_t now = time(NULL);
                if (now - last_activity >= firehose_ping_seconds) {
                    if (wf_xrpc_server_ws_ping(worker->stream) != WF_OK) break;
                    last_activity = now;
                }
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
    } else if (has_cursor) {
        /*
         * Events are delivered with seq > cursor, so a cursor below the last
         * seq retention deleted is asking for events this server can never
         * serve again. Say so with #info before the replay, rather than
         * resuming at the first surviving event and letting the subscriber
         * believe its stream is continuous.
         */
        int64_t pruned = pruned_through(s);
        if (pruned > 0 && cursor < pruned) {
            worker->outdated = 1;
        }
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
    /* Compute the cutoff timestamp in the same ISO-8601 format
     * timestamp_now() stores, so the string comparison in the DELETE matches.
     * SQLite's strftime produces 'YYYY-MM-DD HH:MM:SS' (space-separated);
     * the T and Z matter for lexicographic ordering against stored values. */
    char cutoff_ts[64];
    {
        time_t t = time(NULL) - max_age_seconds;
        struct tm utc;
        gmtime_r(&t, &utc);
        snprintf(cutoff_ts, sizeof(cutoff_ts),
                 "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
                 utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                 utc.tm_hour, utc.tm_min, utc.tm_sec);
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
            "DELETE FROM events WHERE seq <= ? AND created_at < ?;",
            -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->mutex);
        return WF_ERR_INTERNAL;
    }
    sqlite3_bind_int64(stmt, 1, cutoff);
    sqlite3_bind_text(stmt, 2, cutoff_ts, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    /*
     * Remember how far the log has been pruned.
     *
     * A subscriber's cursor outlives the events it names, and once a row is
     * gone there is nothing left to infer the deletion from — the log just
     * starts later. Recording the high-water mark is what lets subscribe_repos
     * answer OutdatedCursor instead of silently skipping the span.
     */
    if (sqlite3_changes(s->db) > 0) {
        sqlite3_stmt *mark = NULL;
        if (sqlite3_prepare_v2(s->db,
                "INSERT INTO meta(key,value) VALUES('pruned_through',?1) "
                "ON CONFLICT(key) DO UPDATE SET value=MAX(value,?1);",
                -1, &mark, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(mark, 1, cutoff);
            sqlite3_step(mark);
        }
        sqlite3_finalize(mark);
    }
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
