/*
 * metalbear_maint.c -- offline operator commands for a stopped MetalBear.
 *
 * Opens the same durable stores the server uses, without starting a listener
 * or touching the network except for rotate-keys (which must update did:plc).
 * The shell wrapper in pdsadmin/ refuses a live instance before calling this.
 */

#define _POSIX_C_SOURCE 200809L

#include "metalbear/account/account_registry.h"
#include "metalbear/plc_publish.h"
#include "metalbear/repo/blob_lifecycle.h"
#include "metalbear/repo/blob_store.h"
#include "metalbear/repo/key_rotation.h"
#include "metalbear/repo/repo_store.h"
#include "metalbear/sequencer.h"
#include "wolfram/xrpc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static void usage(void) {
    fprintf(
        stderr,
        "usage: metalbear-maint --data-dir DIR [--plc-url URL] COMMAND\n"
        "\n"
        "  publish-identity DID       sequence an #identity event\n"
        "  sequencer-recover          heal missing account/repo tail events\n"
        "  rebuild-repo DID           verify the head, rebuild the SQL "
        "indexes\n"
        "  rotate-keys DID...         publish each repo key to did:plc\n"
        "  blob-sweep [--dry-run]     expire temporary uploads and prune "
        "stale refs\n"
        "\n"
        "blob-sweep uses METALBEAR_BLOB_TEMP_SECONDS (default 86400).\n");
}

static char *join(const char *a, const char *b) {
    size_t n = strlen(a) + strlen(b) + 2;
    char *out = malloc(n);
    if (!out) return NULL;
    snprintf(out, n, "%s/%s", a, b);
    return out;
}

static wf_status open_registry(const char *data_dir,
                               metalbear_account_registry **out) {
    char *path = join(data_dir, "accounts.sqlite3");
    if (!path) return WF_ERR_ALLOC;
    wf_status st = metalbear_account_registry_open(path, out);
    free(path);
    return st;
}

static wf_status open_sequencer(const char *data_dir,
                                metalbear_sequencer **out) {
    char *path = join(data_dir, "sequencer.sqlite3");
    if (!path) return WF_ERR_ALLOC;
    wf_status st = metalbear_sequencer_open(path, out);
    free(path);
    return st;
}

static wf_status open_repo(metalbear_account_entry *account,
                           metalbear_repo_store **out) {
    char *path = join(account->data_directory, "repo.sqlite3");
    if (!path) return WF_ERR_ALLOC;
    wf_status st =
        metalbear_repo_store_open(path, account->did, account->handle, out);
    free(path);
    return st;
}

static int fail(const char *command, const char *what, wf_status st) {
    fprintf(stderr, "%s: %s failed (status=%d)\n", command, what, st);
    return 1;
}

/* One entry per account, all opened before the single host-wide sweep. The
 * lifecycle database holds every account's rows, so callbacks must resolve the
 * DID to that account's already-open stores rather than assume a single one. */
typedef struct blob_sweep_ctx {
    const char *did; /* borrowed from the account registry list */
    metalbear_blob_store *blobs;
    metalbear_repo_store *repo;
} blob_sweep_ctx;

typedef struct blob_sweep_all_ctx {
    blob_sweep_ctx *accounts;
    size_t count;
} blob_sweep_all_ctx;

static blob_sweep_ctx *blob_sweep_find(const blob_sweep_all_ctx *all,
                                       const char *did) {
    if (!all || !did) return NULL;
    for (size_t i = 0; i < all->count; i++)
        if (all->accounts[i].did && strcmp(all->accounts[i].did, did) == 0)
            return &all->accounts[i];
    return NULL;
}

static wf_status blob_sweep_revision_exists(const char *did, const char *rev,
                                            void *ctx) {
    blob_sweep_ctx *c = blob_sweep_find(ctx, did);
    if (!c || !c->repo) return WF_ERR_INTERNAL; /* unknown: retain the ref */
    return metalbear_repo_store_revision_exists(c->repo, rev);
}

static wf_status blob_sweep_delete(const char *did, const char *cid,
                                   void *ctx) {
    blob_sweep_ctx *c = blob_sweep_find(ctx, did);
    if (!c || !c->blobs) return WF_ERR_INTERNAL;
    return metalbear_blob_store_delete(c->blobs, cid);
}

static int64_t blob_temp_seconds(void) {
    const char *env = getenv("METALBEAR_BLOB_TEMP_SECONDS");
    int64_t seconds = 86400;
    if (env && *env) {
        char *end = NULL;
        long long parsed = strtoll(env, &end, 10);
        if (end != env && *end == '\0' && parsed >= 0)
            seconds = (int64_t)parsed;
        else
            fprintf(stderr,
                    "blob-sweep: ignoring invalid "
                    "METALBEAR_BLOB_TEMP_SECONDS (using %lld)\n",
                    (long long)seconds);
    }
    return seconds;
}

/*
 * An upgraded host has blobs on disk but no lifecycle rows for them. Seed each
 * visible copy as durable so the sweep does not mistake a live blob for an
 * abandoned upload. seed_blob is INSERT-safe: a temporary upload that raced
 * the restart scan keeps its temporary state.
 */
static wf_status seed_existing_blobs(const char *did, const char *blobs_dir,
                                     metalbear_blob_store *blobs,
                                     metalbear_blob_lifecycle *life,
                                     int64_t now) {
    (void)blobs_dir; /* physical size and refs come from the opened store */
    char **cids = NULL;
    size_t count = 0;
    wf_status st = metalbear_blob_store_list_physical(blobs, &cids, &count);
    if (st != WF_OK) return st;
    for (size_t i = 0; i < count && st == WF_OK; i++) {
        size_t size = 0;
        if (metalbear_blob_store_get_size(blobs, cids[i], &size) != WF_OK)
            continue;
        st = metalbear_blob_lifecycle_seed_blob(life, did, cids[i], size, now);
        if (st != WF_OK) break;

        /* Pre-schema-7 sidecars are the only source of historical refs. Seed
         * them into the revision-aware table; add_ref's INSERT OR REPLACE and
         * seed_blob's INSERT OR IGNORE keep live temporary state untouched. */
        char **uris = NULL;
        size_t uri_count = 0;
        if (metalbear_blob_store_get_refs(blobs, cids[i], &uris, &uri_count) ==
            WF_OK) {
            char *rev = NULL;
            if (metalbear_blob_store_get_revision(blobs, cids[i], &rev) !=
                WF_OK)
                rev = NULL;
            for (size_t j = 0; j < uri_count && st == WF_OK; j++)
                st = metalbear_blob_lifecycle_add_ref(life, did, cids[i],
                                                      uris[j], rev);
            metalbear_blob_store_list_free(uris, uri_count);
            free(rev);
        }
    }
    metalbear_blob_store_list_free(cids, count);
    return st;
}

static int publish_identity(const char *data_dir, const char *did) {
    metalbear_account_registry *registry = NULL;
    metalbear_sequencer *sequencer = NULL;
    metalbear_account_entry *account = NULL;
    wf_status st = open_registry(data_dir, &registry);
    if (st != WF_OK)
        return fail("publish-identity", "open account registry", st);
    st = metalbear_account_registry_find_by_did(registry, did, &account);
    if (st != WF_OK) {
        fprintf(stderr, "publish-identity: unknown DID %s\n", did);
        metalbear_account_registry_free(registry);
        return 1;
    }
    st = open_sequencer(data_dir, &sequencer);
    if (st == WF_OK)
        st = metalbear_sequencer_identity(sequencer, account->did,
                                          account->handle);
    if (st == WF_OK) printf("sequenced #identity for %s\n", account->did);
    metalbear_sequencer_free(sequencer);
    metalbear_account_entry_free(account);
    metalbear_account_registry_free(registry);
    return st == WF_OK ? 0 : fail("publish-identity", "sequence identity", st);
}

static int sequencer_recover(const char *data_dir) {
    metalbear_account_registry *registry = NULL;
    metalbear_sequencer *sequencer = NULL;
    metalbear_account_entry *accounts = NULL;
    size_t count = 0;
    wf_status st = open_registry(data_dir, &registry);
    if (st != WF_OK)
        return fail("sequencer-recover", "open account registry", st);
    st = metalbear_account_registry_list(registry, &accounts, &count);
    if (st != WF_OK) {
        metalbear_account_registry_free(registry);
        return fail("sequencer-recover", "list accounts", st);
    }
    st = open_sequencer(data_dir, &sequencer);
    if (st != WF_OK) {
        metalbear_account_entries_free(accounts, count);
        metalbear_account_registry_free(registry);
        return fail("sequencer-recover", "open sequencer", st);
    }
    for (size_t i = 0; st == WF_OK && i < count; i++) {
        metalbear_repo_store *repo = NULL;
        st = metalbear_sequencer_reconcile_account(sequencer, accounts[i].did,
                                                   accounts[i].active);
        if (st != WF_OK) break;
        st = open_repo(&accounts[i], &repo);
        if (st != WF_OK) break;
        st = metalbear_sequencer_reconcile_repo(sequencer, repo);
        if (st == WF_OK)
            st = metalbear_sequencer_identity(sequencer, accounts[i].did,
                                              accounts[i].handle);
        metalbear_repo_store_free(repo);
        if (st == WF_OK) printf("reconciled %s\n", accounts[i].did);
    }
    metalbear_sequencer_free(sequencer);
    metalbear_account_entries_free(accounts, count);
    metalbear_account_registry_free(registry);
    return st == WF_OK ? 0
                       : fail("sequencer-recover", "reconcile accounts", st);
}

static int rebuild_repo(const char *data_dir, const char *did) {
    metalbear_account_registry *registry = NULL;
    metalbear_account_entry *account = NULL;
    metalbear_repo_store *repo = NULL;
    wf_status st = open_registry(data_dir, &registry);
    if (st != WF_OK) return fail("rebuild-repo", "open account registry", st);
    st = metalbear_account_registry_find_by_did(registry, did, &account);
    if (st != WF_OK) {
        fprintf(stderr, "rebuild-repo: unknown DID %s\n", did);
        metalbear_account_registry_free(registry);
        return 1;
    }
    st = open_repo(account, &repo);
    if (st == WF_OK) {
        char *rev = NULL, *cid = NULL;
        st = metalbear_repo_store_get_head(repo, &rev, &cid);
        bool empty = st == WF_ERR_NOT_FOUND;
        free(rev);
        free(cid);
        if (empty) st = WF_OK;
        if (st == WF_OK && !empty) {
            int verified = 0;
            st = metalbear_repo_store_verify_head(repo, &verified, NULL);
            if (st == WF_OK && !verified) {
                fprintf(stderr, "rebuild-repo: head does not verify for %s\n",
                        did);
                st = WF_ERR_PARSE;
            }
        }
    }
    if (st == WF_OK) st = metalbear_repo_store_reindex(repo);
    if (st == WF_OK) {
        char *rev = NULL, *cid = NULL;
        wf_status head_st = metalbear_repo_store_get_head(repo, &rev, &cid);
        if (head_st == WF_OK)
            printf("reindexed %s head=%s rev=%s\n", did, cid ? cid : "(empty)",
                   rev ? rev : "(none)");
        else if (head_st == WF_ERR_NOT_FOUND)
            printf("reindexed %s head=(empty) rev=(none)\n", did);
        else
            st = head_st;
        free(rev);
        free(cid);
    }
    metalbear_repo_store_free(repo);
    metalbear_account_entry_free(account);
    metalbear_account_registry_free(registry);
    return st == WF_OK ? 0
                       : fail("rebuild-repo", "rebuild from current head", st);
}

static int rotate_keys(const char *data_dir, const char *plc_url, int did_count,
                       char **dids) {
    if (!plc_url || !*plc_url) {
        fprintf(stderr, "rotate-keys: --plc-url is required\n");
        return 1;
    }
    metalbear_account_registry *registry = NULL;
    metalbear_sequencer *sequencer = NULL;
    metalbear_key_rotation *rotation = NULL;
    wf_status st = WF_OK;
    char *keys_path = join(data_dir, "server_keys.sqlite3");
    if (!keys_path) return fail("rotate-keys", "allocate path", WF_ERR_ALLOC);
    st = metalbear_key_rotation_open(keys_path, &rotation);
    free(keys_path);
    if (st != WF_OK) return fail("rotate-keys", "open rotation key", st);
    st = open_registry(data_dir, &registry);
    if (st != WF_OK) {
        metalbear_key_rotation_free(rotation);
        return fail("rotate-keys", "open account registry", st);
    }
    st = open_sequencer(data_dir, &sequencer);
    if (st != WF_OK) {
        metalbear_account_registry_free(registry);
        metalbear_key_rotation_free(rotation);
        return fail("rotate-keys", "open sequencer", st);
    }
    for (int i = 0; st == WF_OK && i < did_count; i++) {
        metalbear_account_entry *account = NULL;
        metalbear_repo_store *repo = NULL;
        st =
            metalbear_account_registry_find_by_did(registry, dids[i], &account);
        if (st != WF_OK) {
            fprintf(stderr, "rotate-keys: unknown DID %s\n", dids[i]);
            st = WF_ERR_NOT_FOUND;
            break;
        }
        st = open_repo(account, &repo);
        if (st == WF_OK) {
            const char *key = metalbear_repo_store_signing_key_did(repo);
            st = metalbear_plc_publish_signing_key(rotation, plc_url,
                                                   account->did, key);
            if (st == WF_OK)
                st = metalbear_sequencer_identity(sequencer, account->did,
                                                  account->handle);
        }
        if (st == WF_OK) printf("published repo key for %s\n", account->did);
        metalbear_repo_store_free(repo);
        metalbear_account_entry_free(account);
    }
    metalbear_sequencer_free(sequencer);
    metalbear_account_registry_free(registry);
    metalbear_key_rotation_free(rotation);
    return st == WF_OK ? 0 : fail("rotate-keys", "publish signing key", st);
}

static int blob_sweep(const char *data_dir, bool dry_run) {
    metalbear_account_registry *registry = NULL;
    metalbear_account_entry *accounts = NULL;
    metalbear_blob_lifecycle *life = NULL;
    blob_sweep_all_ctx all = {0};
    size_t count = 0;
    wf_status st = WF_OK;
    int64_t now = (int64_t)time(NULL);
    int64_t temp_seconds = blob_temp_seconds();
    metalbear_blob_sweep_summary summary = {0};

    life = metalbear_blob_lifecycle_open(data_dir);
    if (!life)
        return fail("blob-sweep", "open blob lifecycle store", WF_ERR_INTERNAL);
    st = open_registry(data_dir, &registry);
    if (st == WF_OK)
        st = metalbear_account_registry_list(registry, &accounts, &count);
    if (count) {
        all.accounts = calloc(count, sizeof(*all.accounts));
        if (!all.accounts) st = WF_ERR_ALLOC;
        all.count = count;
    }

    /* Open each account's stores once: seeding is per account, but the
     * lifecycle sweep itself walks every account's rows in one pass. */
    for (size_t i = 0; st == WF_OK && i < count; i++) {
        char *blobs_dir = NULL;
        all.accounts[i].did = accounts[i].did;
        blobs_dir = join(accounts[i].data_directory, "blobs");
        if (!blobs_dir) {
            st = WF_ERR_ALLOC;
            break;
        }
        all.accounts[i].blobs = metalbear_blob_store_new(blobs_dir);
        if (!all.accounts[i].blobs) {
            free(blobs_dir);
            st = WF_ERR_INTERNAL;
            break;
        }
        metalbear_blob_store_set_lifecycle(all.accounts[i].blobs, life,
                                           accounts[i].did);
        st = open_repo(&accounts[i], &all.accounts[i].repo);
        if (st == WF_OK)
            st = seed_existing_blobs(accounts[i].did, blobs_dir,
                                     all.accounts[i].blobs, life, now);
        free(blobs_dir);
    }
    if (st == WF_OK)
        st = metalbear_blob_lifecycle_sweep(life, now, temp_seconds, dry_run,
                                            blob_sweep_revision_exists,
                                            blob_sweep_delete, &all, &summary);
    if (st == WF_OK)
        printf("%saccounts=%zu temporary=%zu temporary_bytes=%llu "
               "expiring=%zu unreferenced_durable=%zu deleted=%zu "
               "refs_pruned=%zu\n",
               dry_run ? "dry-run " : "", count, summary.temporary,
               (unsigned long long)summary.temporary_bytes, summary.expiring,
               summary.unreferenced_durable, summary.deleted,
               summary.refs_pruned);

    for (size_t i = 0; i < count; i++) {
        metalbear_blob_store_free(all.accounts[i].blobs);
        metalbear_repo_store_free(all.accounts[i].repo);
    }
    free(all.accounts);
    metalbear_account_entries_free(accounts, count);
    metalbear_account_registry_free(registry);
    metalbear_blob_lifecycle_free(life);
    return st == WF_OK ? 0 : fail("blob-sweep", "sweep account blobs", st);
}

int main(int argc, char **argv) {
    const char *data_dir = NULL, *plc_url = NULL;
    int i = 1;
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(argv[i], "--plc-url") == 0 && i + 1 < argc) {
            plc_url = argv[++i];
        } else {
            usage();
            return 2;
        }
    }
    if (!data_dir || i >= argc) {
        usage();
        return 2;
    }
    struct stat sb;
    if (stat(data_dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        fprintf(stderr, "metalbear-maint: not a data directory: %s\n",
                data_dir);
        return 2;
    }
    const char *command = argv[i++];
    int remaining = argc - i;
    char **args = argv + i;
    if (strcmp(command, "publish-identity") == 0 && remaining == 1)
        return publish_identity(data_dir, args[0]);
    if (strcmp(command, "sequencer-recover") == 0 && remaining == 0)
        return sequencer_recover(data_dir);
    if (strcmp(command, "rebuild-repo") == 0 && remaining == 1)
        return rebuild_repo(data_dir, args[0]);
    if (strcmp(command, "rotate-keys") == 0 && remaining >= 1)
        return rotate_keys(data_dir, plc_url, remaining, args);
    if (strcmp(command, "blob-sweep") == 0 && remaining <= 1) {
        if (remaining == 1 && strcmp(args[0], "--dry-run") != 0) {
            usage();
            return 2;
        }
        return blob_sweep(data_dir, remaining == 1);
    }
    usage();
    return 2;
}
