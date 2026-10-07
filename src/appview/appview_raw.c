/* Read-after-write for proxied AppView reads: splice the requester's own
 * records that the AppView has not indexed yet into its response. */

#include "appview_raw.h"

#include "metalbear/account/account.h"
#include "metalbear/account/account_context.h"
#include "metalbear/log.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* ------------------------------------------------------------------ */
/* Read-after-write                                                     */
/* ------------------------------------------------------------------ */
/*
 * An AppView reports how far it has indexed a repo with the `atproto-repo-rev`
 * response header. Anything the account has written past that rev exists here
 * but not there yet, so a user who has just posted would not see their own
 * post. The reference PDS patches the proxied response with those local
 * records before returning it (packages/pds/src/read-after-write); this is the
 * same idea against the same set of endpoints.
 *
 * Everything here degrades to "return the upstream response unchanged": if the
 * body is not the shape we expect, or the rev looks like it belongs to another
 * repo, a stale view is always preferable to a wrong one.
 */


/* Build the PostView the AppView would have produced for a local post.
 * Counts are zero because the post is, by construction, brand new. */
static cJSON *local_post_view(const char *uri, const char *cid,
                              const char *indexed_at, const cJSON *record,
                              const cJSON *author) {
    cJSON *post = cJSON_CreateObject();
    if (!post) return NULL;
    cJSON_AddStringToObject(post, "uri", uri ? uri : "");
    cJSON_AddStringToObject(post, "cid", cid ? cid : "");
    if (author) {
        cJSON *dup = cJSON_Duplicate(author, 1);
        if (dup) cJSON_AddItemToObject(post, "author", dup);
    }
    cJSON *rec = cJSON_Duplicate(record, 1);
    if (rec) cJSON_AddItemToObject(post, "record", rec);
    cJSON_AddNumberToObject(post, "replyCount", 0);
    cJSON_AddNumberToObject(post, "repostCount", 0);
    cJSON_AddNumberToObject(post, "likeCount", 0);
    cJSON_AddNumberToObject(post, "quoteCount", 0);
    cJSON_AddStringToObject(post, "indexedAt", indexed_at ? indexed_at : "");
    return post;
}

/* The author view to attach to local posts: reuse one the upstream already
 * returned for this DID so avatars and labels stay consistent, rather than
 * fabricating a half-populated one. */
static const cJSON *find_author_view(const cJSON *root, const char *did) {
    if (!cJSON_IsObject(root) && !cJSON_IsArray(root)) return NULL;
    const cJSON *self_did = cJSON_GetObjectItemCaseSensitive(root, "did");
    const cJSON *handle = cJSON_GetObjectItemCaseSensitive(root, "handle");
    if (cJSON_IsString(self_did) && cJSON_IsString(handle) &&
        strcmp(self_did->valuestring, did) == 0)
        return root;
    const cJSON *child = NULL;
    cJSON_ArrayForEach(child, root) {
        const cJSON *found = find_author_view(child, did);
        if (found) return found;
    }
    return NULL;
}

/* Insert local posts into a feed array, newest first, mirroring
 * LocalViewer.formatAndInsertPostsInFeed. */
static void insert_local_posts(cJSON *feed, const cJSON *local_records,
                               const char *did, const cJSON *author) {
    if (!cJSON_IsArray(feed)) return;

    /* The upstream page ends at some timestamp; anything older than that
     * belongs on a later page, not spliced into this one. */
    const char *last_time = NULL;
    int feed_len = cJSON_GetArraySize(feed);
    if (feed_len > 0) {
        const cJSON *last = cJSON_GetArrayItem(feed, feed_len - 1);
        const cJSON *post = cJSON_GetObjectItemCaseSensitive(last, "post");
        const cJSON *at = cJSON_GetObjectItemCaseSensitive(post, "indexedAt");
        if (cJSON_IsString(at)) last_time = at->valuestring;
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, local_records) {
        const cJSON *coll =
            cJSON_GetObjectItemCaseSensitive(entry, "collection");
        if (!cJSON_IsString(coll) ||
            strcmp(coll->valuestring, "app.bsky.feed.post") != 0)
            continue;
        const cJSON *uri = cJSON_GetObjectItemCaseSensitive(entry, "uri");
        const cJSON *cid = cJSON_GetObjectItemCaseSensitive(entry, "cid");
        const cJSON *at = cJSON_GetObjectItemCaseSensitive(entry, "indexedAt");
        const cJSON *value = cJSON_GetObjectItemCaseSensitive(entry, "value");
        if (!cJSON_IsString(uri) || !cJSON_IsString(at) || !value) continue;
        if (last_time && strcmp(at->valuestring, last_time) <= 0) continue;

        /* Skip anything the upstream already returned. */
        bool already = false;
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, feed) {
            const cJSON *p = cJSON_GetObjectItemCaseSensitive(item, "post");
            const cJSON *u = cJSON_GetObjectItemCaseSensitive(p, "uri");
            if (cJSON_IsString(u) &&
                strcmp(u->valuestring, uri->valuestring) == 0) {
                already = true;
                break;
            }
        }
        if (already) continue;

        cJSON *post = local_post_view(
            uri->valuestring, cJSON_IsString(cid) ? cid->valuestring : "",
            at->valuestring, value, author);
        if (!post) continue;
        cJSON *wrapper = cJSON_CreateObject();
        if (!wrapper) {
            cJSON_Delete(post);
            continue;
        }
        cJSON_AddItemToObject(wrapper, "post", post);

        /* Keep the feed ordered newest-first. */
        int idx = -1;
        for (int i = 0; i < cJSON_GetArraySize(feed); i++) {
            const cJSON *fi = cJSON_GetArrayItem(feed, i);
            const cJSON *p = cJSON_GetObjectItemCaseSensitive(fi, "post");
            const cJSON *pa = cJSON_GetObjectItemCaseSensitive(p, "indexedAt");
            if (cJSON_IsString(pa) &&
                strcmp(pa->valuestring, at->valuestring) < 0) {
                idx = i;
                break;
            }
        }
        if (idx >= 0)
            cJSON_InsertItemInArray(feed, idx, wrapper);
        else
            cJSON_AddItemToArray(feed, wrapper);
        (void)did;
    }
}

/* Overlay a locally-written profile record onto a profile view. */
static void overlay_local_profile(cJSON *view, const cJSON *record) {
    if (!cJSON_IsObject(view) || !cJSON_IsObject(record)) return;
    static const char *const fields[] = {"displayName", "description"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(record, fields[i]);
        cJSON_DeleteItemFromObjectCaseSensitive(view, fields[i]);
        if (cJSON_IsString(v))
            cJSON_AddStringToObject(view, fields[i], v->valuestring);
    }
}

/* Copy the fields an app.bsky.actor.profile record carries onto a locally
 * served profile view, preserving each one's structure exactly as the record
 * stores it. Per profile.json: avatar/banner are #blob objects
 * ({$type, ref:{$link}, mimeType, size}); labels is the record's selfLabels
 * union; joinedViaStarterPack/pinnedPost are strongRefs. The view's own
 * $type is deliberately not written — the AppView serves profile views
 * without one (Un$Typed), and copying the record's $type would be wrong. */
void append_profile_record_fields(cJSON *view, const cJSON *record) {
    if (!cJSON_IsObject(view) || !cJSON_IsObject(record)) return;
    static const char *const strings[] = {
        "displayName", "description", "pronouns", "website", "createdAt",
    };
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(record, strings[i]);
        if (!cJSON_IsString(v)) continue;
        cJSON_DeleteItemFromObjectCaseSensitive(view, strings[i]);
        cJSON_AddStringToObject(view, strings[i], v->valuestring);
    }
    static const char *const objects[] = {
        "avatar", "banner", "labels", "joinedViaStarterPack", "pinnedPost",
    };
    for (size_t i = 0; i < sizeof(objects) / sizeof(objects[0]); i++) {
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(record, objects[i]);
        if (!cJSON_IsObject(v)) continue;
        cJSON_DeleteItemFromObjectCaseSensitive(view, objects[i]);
        cJSON *copy = cJSON_Duplicate(v, 1);
        if (copy) cJSON_AddItemToObject(view, objects[i], copy);
    }
}

/*
 * Patch `body` with the requester's records newer than `repo_rev`. Returns a
 * heap-allocated replacement body, or NULL to send the upstream response
 * through untouched.
 */
char *read_after_write_munge(metalbear_server *server,
                                    const char *requester_did, const char *nsid,
                                    const char *repo_rev, const char *body,
                                    size_t body_len, wf_xrpc_response *resp) {
    static const char *const feed_methods[] = {
        "app.bsky.feed.getTimeline",
        "app.bsky.feed.getAuthorFeed",
        "app.bsky.feed.getActorLikes",
    };
    bool is_feed = false;
    for (size_t i = 0; i < sizeof(feed_methods) / sizeof(feed_methods[0]); i++)
        if (strcmp(nsid, feed_methods[i]) == 0) is_feed = true;
    bool is_profile = strcmp(nsid, "app.bsky.actor.getProfile") == 0;
    bool is_profiles = strcmp(nsid, "app.bsky.actor.getProfiles") == 0;
    if (!is_feed && !is_profile && !is_profiles) return NULL;

    metalbear_account_context *acct = context_for_did(server, requester_did);
    if (!acct || !acct->repo) return NULL;

    char *local_json = NULL;
    if (metalbear_repo_store_records_since_rev(acct->repo, repo_rev, 10,
                                               &local_json) != WF_OK ||
        !local_json)
        return NULL;
    cJSON *local = cJSON_Parse(local_json);
    free(local_json);
    if (!local) return NULL;
    cJSON *records = cJSON_GetObjectItemCaseSensitive(local, "records");
    if (!cJSON_IsArray(records) || cJSON_GetArraySize(records) == 0) {
        cJSON_Delete(local);
        return NULL; /* upstream is caught up; nothing to add */
    }

    cJSON *root = cJSON_ParseWithLength(body, body_len);
    if (!root) {
        cJSON_Delete(local);
        return NULL;
    }

    bool changed = false;
    if (is_feed) {
        cJSON *feed = cJSON_GetObjectItemCaseSensitive(root, "feed");
        if (cJSON_IsArray(feed)) {
            const cJSON *author = find_author_view(root, requester_did);
            int before = cJSON_GetArraySize(feed);
            insert_local_posts(feed, records, requester_did, author);
            changed = cJSON_GetArraySize(feed) != before;
        }
    } else {
        /* Profile record edits: overlay onto the requester's own view. */
        const cJSON *entry = NULL;
        const cJSON *profile_record = NULL;
        cJSON_ArrayForEach(entry, records) {
            const cJSON *coll =
                cJSON_GetObjectItemCaseSensitive(entry, "collection");
            if (cJSON_IsString(coll) &&
                strcmp(coll->valuestring, "app.bsky.actor.profile") == 0)
                profile_record =
                    cJSON_GetObjectItemCaseSensitive(entry, "value");
        }
        if (profile_record) {
            if (is_profile) {
                const cJSON *did =
                    cJSON_GetObjectItemCaseSensitive(root, "did");
                if (cJSON_IsString(did) &&
                    strcmp(did->valuestring, requester_did) == 0) {
                    overlay_local_profile(root, profile_record);
                    changed = true;
                }
            } else {
                cJSON *profiles =
                    cJSON_GetObjectItemCaseSensitive(root, "profiles");
                cJSON *p = NULL;
                cJSON_ArrayForEach(p, profiles) {
                    const cJSON *did =
                        cJSON_GetObjectItemCaseSensitive(p, "did");
                    if (cJSON_IsString(did) &&
                        strcmp(did->valuestring, requester_did) == 0) {
                        overlay_local_profile(p, profile_record);
                        changed = true;
                    }
                }
            }
        }
    }

    char *out = changed ? cJSON_PrintUnformatted(root) : NULL;
    if (changed) {
        /* Tell the client the view was completed locally, as the reference
         * does, so a debugging client can tell this apart from a fresh
         * upstream response. */
        wf_xrpc_response_add_header(resp, "Atproto-Upstream-Lag", "0");
    }
    cJSON_Delete(root);
    cJSON_Delete(local);
    return out;
}
