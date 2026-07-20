#define _POSIX_C_SOURCE 200809L

#include "metalbear/account_context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char *join_path(const char *directory, const char *name) {
    size_t dn = strlen(directory), nn = strlen(name);
    bool slash = dn > 0 && directory[dn - 1] == '/';
    char *path = malloc(dn + nn + (slash ? 1 : 2));
    if (!path) return NULL;
    snprintf(path, dn + nn + (slash ? 1 : 2), "%s%s%s", directory,
             slash ? "" : "/", name);
    return path;
}

static bool make_directory(const char *path) {
    if (mkdir(path, 0700) == 0) return true;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

wf_status metalbear_account_context_open(const char *service_did,
                                         const char *public_url,
                                         const char *did, const char *handle,
                                         const char *data_directory,
                                         const char *password,
                                         metalbear_account_context **out) {
    if (!service_did || !did || !handle || !data_directory || !out)
        return WF_ERR_INVALID_ARG;
    *out = NULL;
    if (!make_directory(data_directory))
        return WF_ERR_INTERNAL;

    metalbear_account_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return WF_ERR_ALLOC;
    ctx->did = strdup(did);
    ctx->handle = strdup(handle);
    ctx->data_directory = strdup(data_directory);
    if (!ctx->did || !ctx->handle || !ctx->data_directory) {
        metalbear_account_context_close(ctx);
        return WF_ERR_ALLOC;
    }

    char *repo_path = join_path(data_directory, "repo.sqlite3");
    char *blob_path = join_path(data_directory, "blobs");
    char *auth_path = join_path(data_directory, "auth.sqlite3");
    char *account_path = join_path(data_directory, "account.sqlite3");
    char *seq_path = join_path(data_directory, "sequencer.sqlite3");
    char *oauth_path = join_path(data_directory, "oauth.sqlite3");
    char *key_path = join_path(data_directory, "keys.sqlite3");
    wf_status status = WF_ERR_ALLOC;
    if (!repo_path || !blob_path || !auth_path || !account_path ||
        !seq_path || !oauth_path || !key_path ||
        !make_directory(blob_path))
        goto cleanup;

    if (metalbear_repo_store_open(repo_path, did, handle, &ctx->repo) != WF_OK)
        goto cleanup;
    ctx->blobs = wf_blob_store_new(blob_path);
    if (!ctx->blobs) goto cleanup;
    if (metalbear_auth_store_open(auth_path, service_did, did,
                                  &ctx->auth) != WF_OK)
        goto cleanup;
    if (metalbear_account_store_open(account_path, password ? password : "",
                                     &ctx->account) != WF_OK)
        goto cleanup;
    if (metalbear_sequencer_open(seq_path, did, handle,
                                 &ctx->sequencer) != WF_OK)
        goto cleanup;
    if (metalbear_oauth_store_open(oauth_path, public_url ? public_url : "",
                                   did, &ctx->oauth) != WF_OK)
        goto cleanup;
    if (metalbear_key_rotation_open(key_path, &ctx->key_rotation) != WF_OK)
        goto cleanup;

    ctx->active = metalbear_account_is_active(ctx->account);
    status = WF_OK;
    *out = ctx;

cleanup:
    free(repo_path); free(blob_path); free(auth_path); free(account_path);
    free(seq_path); free(oauth_path); free(key_path);
    if (status != WF_OK) metalbear_account_context_close(ctx);
    return status;
}

void metalbear_account_context_close(metalbear_account_context *ctx) {
    if (!ctx) return;
    if (ctx->repo) metalbear_repo_store_free(ctx->repo);
    if (ctx->blobs) wf_blob_store_free(ctx->blobs);
    if (ctx->auth) metalbear_auth_store_free(ctx->auth);
    if (ctx->account) metalbear_account_store_free(ctx->account);
    if (ctx->sequencer) metalbear_sequencer_free(ctx->sequencer);
    if (ctx->oauth) metalbear_oauth_store_free(ctx->oauth);
    if (ctx->key_rotation) metalbear_key_rotation_free(ctx->key_rotation);
    free(ctx->did);
    free(ctx->handle);
    free(ctx->data_directory);
    free(ctx);
}
