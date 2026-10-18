#define _POSIX_C_SOURCE 200809L
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include "metalbear/repo/repo_store.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>

static int rmtree_remove_cb(const char *path, const struct stat *sb, int type,
                            struct FTW *ftwbuf) {
    (void)sb;
    (void)type;
    (void)ftwbuf;
    return remove(path);
}

static void rmtree(const char *path) {
    nftw(path, rmtree_remove_cb, 16, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
}

#define NUM_THREADS 4
#define RECORDS_PER_THREAD 10

struct worker_ctx {
    metalbear_repo_store *store;
    const char *did;
    int thread_id;
    int success;
};

static void *worker_thread(void *arg) {
    struct worker_ctx *ctx = (struct worker_ctx *)arg;
    metalbear_repo_store *s = ctx->store;
    int ok = 0;
    for (int i = 0; i < RECORDS_PER_THREAD; i++) {
        char rkey[32];
        snprintf(rkey, sizeof(rkey), "t%d-%d", ctx->thread_id, i);
        char body[256];
        snprintf(body, sizeof(body),
                 "{\"$type\":\"app.bsky.feed.post\","
                 "\"text\":\"thread%d-%d\","
                 "\"createdAt\":\"2024-01-01T00:00:00.000Z\"}",
                 ctx->thread_id, i);
        char *uri = NULL;
        char *cid = NULL;
        wf_status st = metalbear_repo_store_create_record(
            s, "app.bsky.feed.post", rkey, body, NULL, &uri, &cid);
        if (st == WF_OK) ok++;
        free(uri);
        free(cid);
    }
    ctx->success = ok;
    return NULL;
}

/*
 * Two writers apply batches to one store while a reader walks it. The batch
 * writers must not interleave: every batch is one commit with all its ops,
 * and the walk must see only whole batches, never a torn one. The probe is
 * written from the event callback, which runs under the store mutex, so it is
 * read only after the threads are joined.
 */
#define BATCH_WRITERS 2
#define BATCHES_PER_WRITER 10
#define OPS_PER_BATCH 3
#define READER_PASSES 200

struct batch_probe {
    int commits;
    int bad_ops_count;
};

static void batch_probe_event(const metalbear_repo_store_event *event,
                              void *context) {
    struct batch_probe *probe = context;
    if (event->kind != METALBEAR_REPO_STORE_EVENT_COMMIT) return;
    probe->commits++;
    if (event->ops_count != OPS_PER_BATCH) probe->bad_ops_count++;
}

struct batch_writer_ctx {
    metalbear_repo_store *store;
    int writer_id;
    int batches_ok;
};

static void *batch_writer_thread(void *arg) {
    struct batch_writer_ctx *ctx = arg;
    for (int b = 0; b < BATCHES_PER_WRITER; b++) {
        char writes[1024];
        size_t used = 0;
        used += (size_t)snprintf(writes + used, sizeof(writes) - used, "[");
        for (int op = 0; op < OPS_PER_BATCH; op++) {
            used += (size_t)snprintf(
                writes + used, sizeof(writes) - used,
                "%s{\"$type\":\"com.atproto.repo.applyWrites#create\","
                "\"collection\":\"com.example.batch\","
                "\"rkey\":\"w%d-%d-%d\","
                "\"value\":{\"$type\":\"com.example.batch\",\"n\":%d}}",
                op ? "," : "", ctx->writer_id, b, op, op);
        }
        snprintf(writes + used, sizeof(writes) - used, "]");
        char *cid = NULL, *rev = NULL, *results = NULL;
        wf_status st = metalbear_repo_store_apply_writes(
            ctx->store, writes, NULL, &cid, &rev, &results);
        if (st == WF_OK) ctx->batches_ok++;
        free(cid);
        free(rev);
        free(results);
    }
    return NULL;
}

static wf_status count_visit(const char *collection, const char *rkey,
                             const char *value_json, void *ctx) {
    (void)collection;
    (void)rkey;
    (void)value_json;
    (*(int *)ctx)++;
    return WF_OK;
}

static void *batch_reader_thread(void *arg) {
    metalbear_repo_store *s = arg;
    for (int pass = 0; pass < READER_PASSES; pass++) {
        char *json = NULL;
        metalbear_repo_store_list_records(s, "com.example.batch", NULL, false,
                                          100, &json);
        free(json);
        int seen = 0;
        metalbear_repo_store_foreach_record(s, count_visit, &seen);
    }
    return NULL;
}

static int run_batch_threads(const char *dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/batch.sqlite3", dir);
    metalbear_repo_store *store = NULL;
    if (metalbear_repo_store_open(path, "did:plc:batchthreads",
                                  "batch.example.com", &store) != WF_OK ||
        !store) {
        fprintf(stderr, "FAIL: batch repo store open\n");
        return 1;
    }
    struct batch_probe probe = {0, 0};
    metalbear_repo_store_set_event_callback(store, batch_probe_event, &probe);

    pthread_t writers[BATCH_WRITERS];
    struct batch_writer_ctx wctx[BATCH_WRITERS];
    pthread_t reader;
    int failed = 0;
    for (int i = 0; i < BATCH_WRITERS; i++) {
        wctx[i].store = store;
        wctx[i].writer_id = i;
        wctx[i].batches_ok = 0;
        if (pthread_create(&writers[i], NULL, batch_writer_thread, &wctx[i]) !=
            0) {
            fprintf(stderr, "FAIL: pthread_create writer %d\n", i);
            failed = 1;
        }
    }
    if (pthread_create(&reader, NULL, batch_reader_thread, store) != 0) {
        fprintf(stderr, "FAIL: pthread_create reader\n");
        failed = 1;
    }
    for (int i = 0; i < BATCH_WRITERS; i++) pthread_join(writers[i], NULL);
    pthread_join(reader, NULL);

    int expected_batches = BATCH_WRITERS * BATCHES_PER_WRITER;
    int batches_ok = 0;
    for (int i = 0; i < BATCH_WRITERS; i++) batches_ok += wctx[i].batches_ok;
    int records = 0;
    metalbear_repo_store_foreach_record(store, count_visit, &records);

    if (failed || batches_ok != expected_batches) {
        fprintf(stderr, "FAIL: batches ok %d, expected %d\n", batches_ok,
                expected_batches);
        failed = 1;
    }
    if (probe.commits != expected_batches || probe.bad_ops_count != 0) {
        fprintf(stderr,
                "FAIL: %d commits for %d batches, %d with a wrong op count\n",
                probe.commits, expected_batches, probe.bad_ops_count);
        failed = 1;
    }
    if (records != expected_batches * OPS_PER_BATCH) {
        fprintf(stderr, "FAIL: %d records, expected %d\n", records,
                expected_batches * OPS_PER_BATCH);
        failed = 1;
    }
    int verified = 0;
    wf_commit head;
    if (metalbear_repo_store_verify_head(store, &verified, &head) != WF_OK ||
        verified != 1) {
        fprintf(stderr,
                "FAIL: head does not verify after concurrent batches\n");
        failed = 1;
    }
    metalbear_repo_store_free(store);
    return failed;
}

int main(void) {
    char directory[] = "/tmp/metalbear-parallel-repo-XXXXXX";
    char *dir = mkdtemp(directory);
    if (!dir) {
        fprintf(stderr, "FAIL: mkdtemp\n");
        return 1;
    }
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/repo.sqlite3", dir);

    metalbear_repo_store *store = NULL;
    const char *did = "did:plc:testparallel123";
    wf_status st =
        metalbear_repo_store_open(db_path, did, "alice.example.com", &store);
    if (st != WF_OK || !store) {
        fprintf(stderr, "FAIL: repo store open\n");
        rmtree(directory);
        return 1;
    }

    pthread_t threads[NUM_THREADS];
    struct worker_ctx ctxs[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        ctxs[i].store = store;
        ctxs[i].did = did;
        ctxs[i].thread_id = i;
        ctxs[i].success = 0;
        if (pthread_create(&threads[i], NULL, worker_thread, &ctxs[i]) != 0) {
            fprintf(stderr, "FAIL: pthread_create %d\n", i);
            metalbear_repo_store_free(store);
            rmtree(directory);
            return 1;
        }
    }

    int total = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total += ctxs[i].success;
    }

    int expected = NUM_THREADS * RECORDS_PER_THREAD;
    int result = 0;
    if (total != expected) {
        fprintf(stderr, "FAIL: expected %d successful creates, got %d\n",
                expected, total);
        result = 1;
    }

    /* Verify all rkeys are present. */
    for (int i = 0; i < NUM_THREADS; i++) {
        for (int j = 0; j < RECORDS_PER_THREAD; j++) {
            char rkey[32];
            snprintf(rkey, sizeof(rkey), "t%d-%d", i, j);
            char *json = NULL;
            char *cid = NULL;
            st = metalbear_repo_store_get_record(store, "app.bsky.feed.post",
                                                 rkey, &json, &cid);
            if (st != WF_OK) {
                fprintf(stderr, "FAIL: missing record t%d-%d\n", i, j);
                result = 1;
            }
            free(json);
            free(cid);
        }
    }

    if (run_batch_threads(dir) != 0) result = 1;

    if (result == 0) {
        printf("PASS: parallel repo writes (%d/%d), concurrent batches\n",
               total, expected);
    }

    metalbear_repo_store_free(store);
    rmtree(directory);
    return result;
}
