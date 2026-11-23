/*
 * test_blob_lifecycle.c — offline tests for the host-wide blob lifecycle
 * (issue #253): temporary uploads stay hidden until a record references them,
 * expiry and stale references are swept, and the counters used by /metrics and
 * `blob-sweep --dry-run` agree with what the sweep actually removes.
 *
 * Uses the lifecycle database directly plus an in-memory blob store; no
 * server, no network. Reuses the tiny test.h harness from test_blob_gc.c.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/repo/blob_lifecycle.h"
#include "metalbear/repo/blob_store.h"

#include "test.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *DID = "did:plc:lifecycletest";
static const char *DID_B = "did:plc:lifecycletestb";
static const char *REV_LIVE = "3liverevision000";
static const char *REV_STALE = "3stalerevision00";
static const char *URI_A = "at://did:plc:lifecycletest/app.bsky.feed.post/aaa";
static const char *URI_B = "at://did:plc:lifecycletest/app.bsky.feed.post/bbb";
static const char *URI_B_ACCOUNT =
    "at://did:plc:lifecycletestb/app.bsky.feed.post/aaa";
#define TEMP_SECONDS ((int64_t)86400)

typedef struct lifecycle_fixture {
    char data_dir[256];
    metalbear_blob_lifecycle *life;
    metalbear_blob_store *blobs;
    metalbear_blob_store *blobs_b; /* second account sharing a CID */
    int live_rev_calls;
    int stale_rev_calls;
    int deleted_count;
    char deleted[8][64];
} lifecycle_fixture;

static void reset_counters(lifecycle_fixture *f) {
    f->live_rev_calls = 0;
    f->stale_rev_calls = 0;
    f->deleted_count = 0;
    memset(f->deleted, 0, sizeof(f->deleted));
}

static wf_status revision_exists_cb(const char *did, const char *rev,
                                    void *ctx) {
    lifecycle_fixture *f = ctx;
    (void)did;
    if (strcmp(rev, REV_LIVE) == 0) {
        f->live_rev_calls++;
        return WF_OK;
    }
    f->stale_rev_calls++;
    return WF_ERR_NOT_FOUND; /* any other revision has been repo-GC'd */
}

static wf_status delete_blob_cb(const char *did, const char *cid, void *ctx) {
    lifecycle_fixture *f = ctx;
    if (f->deleted_count < (int)(sizeof(f->deleted) / sizeof(f->deleted[0])))
        snprintf(f->deleted[f->deleted_count], sizeof(f->deleted[0]), "%s",
                 cid);
    f->deleted_count++;
    /* Physical copies are per account, so the correct store must be selected
     * by DID — the same CID can exist independently for two accounts. */
    metalbear_blob_store *store =
        did && strcmp(did, DID_B) == 0 ? f->blobs_b : f->blobs;
    /* A lifecycle-only row has no payload; the sweep accepts NOT_FOUND too. */
    return metalbear_blob_store_delete(store, cid);
}

static bool deleted_contains(const lifecycle_fixture *f, const char *cid) {
    for (int i = 0; i < f->deleted_count; i++)
        if (strcmp(f->deleted[i], cid) == 0) return true;
    return false;
}

static void run(void) {
    char tmpl[] = "/tmp/metalbear_blob_lifecycle_XXXXXX";
    char *dir = mkdtemp(tmpl);
    WF_CHECK(dir != NULL);
    if (!dir) return;

    lifecycle_fixture f = {0};
    snprintf(f.data_dir, sizeof(f.data_dir), "%s", dir);
    f.life = metalbear_blob_lifecycle_open(f.data_dir);
    WF_CHECK(f.life != NULL);
    f.blobs = metalbear_blob_store_new(NULL);
    f.blobs_b = metalbear_blob_store_new(NULL);
    WF_CHECK(f.blobs != NULL);
    WF_CHECK(f.blobs_b != NULL);
    if (!f.life || !f.blobs || !f.blobs_b) goto cleanup;
    metalbear_blob_store_set_lifecycle(f.blobs, f.life, DID);
    metalbear_blob_store_set_lifecycle(f.blobs_b, f.life, DID_B);

    int64_t now = (int64_t)time(NULL);
    metalbear_blob_sweep_summary s = {0};
    unsigned char *data = NULL;
    size_t len = 0;
    char *mime = NULL;
    char **cids = NULL;
    size_t cids_count = 0;

    /* ── Temporary upload: on disk, but not visible until promoted ─────── */
    const char *cid_visible = "bafyvisible";
    const unsigned char payload_a[] = {'a', 'b', 'c'};
    WF_CHECK(metalbear_blob_store_put_temporary(f.blobs, cid_visible,
                                                "image/png", payload_a,
                                                sizeof(payload_a)) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_visible) ==
             0);
    WF_CHECK(metalbear_blob_store_get(f.blobs, cid_visible, &data, &len,
                                      &mime) == WF_ERR_NOT_FOUND);
    WF_CHECK(data == NULL && mime == NULL);
    /* exists() is a physical presences check used by upload dedup and sync;
     * it deliberately ignores lifecycle visibility (only get/list filter). */
    WF_CHECK(metalbear_blob_store_exists(f.blobs, cid_visible) == WF_OK);
    WF_CHECK(metalbear_blob_store_list(f.blobs, &cids, &cids_count) == WF_OK);
    WF_CHECK(cids_count == 0 && cids == NULL);
    metalbear_blob_store_list_free(cids, cids_count);

    WF_CHECK(metalbear_blob_store_associate_at(f.blobs, cid_visible, URI_A,
                                               REV_LIVE) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_visible) ==
             1);
    data = NULL;
    len = 0;
    mime = NULL;
    WF_CHECK(metalbear_blob_store_get(f.blobs, cid_visible, &data, &len,
                                      &mime) == WF_OK);
    WF_CHECK(data && len == sizeof(payload_a) &&
             memcmp(data, payload_a, len) == 0 && mime &&
             strcmp(mime, "image/png") == 0);
    free(data);
    free(mime);
    cids = NULL;
    cids_count = 0;
    WF_CHECK(metalbear_blob_store_list(f.blobs, &cids, &cids_count) == WF_OK);
    WF_CHECK(cids_count == 1 && cids && strcmp(cids[0], cid_visible) == 0);
    metalbear_blob_store_list_free(cids, cids_count);

    memset(&s, 0, sizeof(s));
    reset_counters(&f);
    WF_CHECK(metalbear_blob_lifecycle_stats(f.life, now, TEMP_SECONDS,
                                            revision_exists_cb, &f,
                                            &s) == WF_OK);
    WF_CHECK(s.temporary == 0 && s.expiring == 0 &&
             s.unreferenced_durable == 0);

    /* ── Two revisions reference one blob; one of them is stale ───────── */
    const char *cid_refs = "bafytworevs";
    const unsigned char payload_refs[] = {1, 2};
    WF_CHECK(metalbear_blob_lifecycle_mark_uploaded(f.life, DID, cid_refs,
                                                    sizeof(payload_refs),
                                                    now - 10) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_add_ref(f.life, DID, cid_refs, URI_A,
                                              REV_LIVE) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_add_ref(f.life, DID, cid_refs, URI_B,
                                              REV_STALE) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_refs) == 1);

    reset_counters(&f);
    memset(&s, 0, sizeof(s));
    WF_CHECK(metalbear_blob_lifecycle_sweep(f.life, now, TEMP_SECONDS, false,
                                            revision_exists_cb, delete_blob_cb,
                                            &f, &s) == WF_OK);
    WF_CHECK(s.refs_pruned == 1); /* stale row dropped */
    WF_CHECK(s.deleted == 0);     /* the live revision still names the blob */
    WF_CHECK(f.live_rev_calls >= 1 && f.stale_rev_calls >= 1);
    WF_CHECK(f.deleted_count == 0);

    /* ── Stats: expired temp, fresh temp, unreferenced durable ────────── */
    const char *cid_expired = "bafyexpired";
    const char *cid_seedtemp = "bafyseedtemp";
    const char *cid_orphan = "bafyorphan";
    WF_CHECK(metalbear_blob_lifecycle_mark_uploaded(
                 f.life, DID, cid_expired, 5, now - TEMP_SECONDS - 1) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_mark_uploaded(f.life, DID, cid_seedtemp,
                                                    7, now) == WF_OK);
    /* A restart scan must not promote a live temporary upload. */
    WF_CHECK(metalbear_blob_lifecycle_seed_blob(f.life, DID, cid_seedtemp, 999,
                                                now - 2 * TEMP_SECONDS) ==
             WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_seedtemp) ==
             0);

    /* A real payload for the orphan, so the delete callback removes bytes. */
    const unsigned char payload_orphan[] = {'o', 'r', 'p', 'h'};
    WF_CHECK(metalbear_blob_store_put(f.blobs, cid_orphan, "text/plain",
                                      payload_orphan,
                                      sizeof(payload_orphan)) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_seed_blob(f.life, DID, cid_orphan, 11,
                                                now) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_orphan) == 1);

    memset(&s, 0, sizeof(s));
    reset_counters(&f);
    WF_CHECK(metalbear_blob_lifecycle_stats(f.life, now, TEMP_SECONDS,
                                            revision_exists_cb, &f,
                                            &s) == WF_OK);
    WF_CHECK(s.temporary == 2); /* expired + seed-protected fresh upload */
    WF_CHECK(s.temporary_bytes == 12);
    WF_CHECK(s.expiring == 1);
    WF_CHECK(s.unreferenced_durable == 1);

    /* ── Dry run checks refs but changes nothing ──────────────────────── */
    reset_counters(&f);
    memset(&s, 0, sizeof(s));
    WF_CHECK(metalbear_blob_lifecycle_sweep(f.life, now, TEMP_SECONDS, true,
                                            revision_exists_cb, delete_blob_cb,
                                            &f, &s) == WF_OK);
    WF_CHECK(s.temporary == 2 && s.temporary_bytes == 12);
    WF_CHECK(s.expiring == 1 && s.unreferenced_durable == 1);
    WF_CHECK(s.deleted == 0 && s.refs_pruned == 0);
    /* A dry run must query revisions to count unreferenced durables honestly,
     * but never delete a payload or prune a ref (both are pure reads here). */
    WF_CHECK(f.deleted_count == 0 && f.live_rev_calls >= 1);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_orphan) == 1);

    /* ── Real sweep: expired temp + stale-only durable are deleted ─────── */
    const char *cid_stale_only = "bafystaleonly";
    const unsigned char payload_stale[] = {'s', 't', 'a', 'l', 'e'};
    WF_CHECK(metalbear_blob_store_put(f.blobs, cid_stale_only, "text/plain",
                                      payload_stale,
                                      sizeof(payload_stale)) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_mark_uploaded(f.life, DID, cid_stale_only,
                                                    3, now - 10) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_add_ref(f.life, DID, cid_stale_only,
                                              URI_A, REV_STALE) == WF_OK);

    reset_counters(&f);
    memset(&s, 0, sizeof(s));
    WF_CHECK(metalbear_blob_lifecycle_sweep(f.life, now, TEMP_SECONDS, false,
                                            revision_exists_cb, delete_blob_cb,
                                            &f, &s) == WF_OK);
    WF_CHECK(s.temporary == 2 && s.temporary_bytes == 12 && s.expiring == 1);
    WF_CHECK(s.deleted == 3 && s.refs_pruned == 1);
    WF_CHECK(f.deleted_count == 3);
    WF_CHECK(deleted_contains(&f, cid_expired));
    WF_CHECK(deleted_contains(&f, cid_orphan));
    WF_CHECK(deleted_contains(&f, cid_stale_only));
    WF_CHECK(f.live_rev_calls >= 1 && f.stale_rev_calls >= 1);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_orphan) == 0);
    WF_CHECK(metalbear_blob_lifecycle_is_durable(f.life, DID, cid_stale_only) ==
             0);

    memset(&s, 0, sizeof(s));
    reset_counters(&f);
    WF_CHECK(metalbear_blob_lifecycle_stats(f.life, now, TEMP_SECONDS,
                                            revision_exists_cb, &f,
                                            &s) == WF_OK);
    WF_CHECK(s.temporary == 1 && s.temporary_bytes == 7);
    WF_CHECK(s.expiring == 0 && s.unreferenced_durable == 0);

    /* ── forget removes both the state row and its revision refs ──────── */
    const char *cid_forget = "bafyforget";
    WF_CHECK(metalbear_blob_lifecycle_mark_uploaded(f.life, DID, cid_forget, 13,
                                                    now) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_add_ref(f.life, DID, cid_forget, URI_B,
                                              REV_STALE) == WF_OK);
    WF_CHECK(metalbear_blob_lifecycle_forget(f.life, DID, cid_forget) == WF_OK);
    int changed = -1;
    WF_CHECK(metalbear_blob_lifecycle_promote(f.life, DID, cid_forget,
                                              &changed) == WF_OK &&
             changed == 1); /* only a missing row is inserted as a change */
    WF_CHECK(metalbear_blob_lifecycle_forget(f.life, DID, cid_forget) == WF_OK);

    reset_counters(&f);
    memset(&s, 0, sizeof(s));
    WF_CHECK(metalbear_blob_lifecycle_sweep(f.life, now, TEMP_SECONDS, false,
                                            revision_exists_cb, delete_blob_cb,
                                            &f, &s) == WF_OK);
    WF_CHECK(f.stale_rev_calls == 0); /* the forgotten ref was removed too */
    WF_CHECK(s.deleted == 0 && s.refs_pruned == 0);

cleanup:
    metalbear_blob_store_free(f.blobs);
    metalbear_blob_lifecycle_free(f.life);
    {
        char db_path[300];
        snprintf(db_path, sizeof(db_path), "%s/blob_lifecycle.sqlite3", dir);
        remove(db_path);
    }
    rmdir(dir);
}

int main(void) {
    run();
    WF_TEST_SUMMARY();
}
