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
        char uri[64];
        char cid[200];
        wf_status st = metalbear_repo_store_create_record(
            s, "app.bsky.feed.post", rkey, body, NULL, uri, cid);
        if (st == WF_OK) ok++;
    }
    ctx->success = ok;
    return NULL;
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

    if (result == 0) {
        printf("PASS: parallel repo writes (%d/%d)\n", total, expected);
    }

    metalbear_repo_store_free(store);
    rmtree(directory);
    return result;
}
