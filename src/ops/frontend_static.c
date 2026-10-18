#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "frontend_static.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "metalbear/log.h"

/* A frontend build is a few megabytes; a single file larger than this is a
 * wrong directory, not a page. */
#define FRONTEND_MAX_FILE_BYTES (16u * 1024u * 1024u)

/* Paths the server registers itself. Skipping them here keeps startup from
 * failing on a duplicate and leaves the server's own copy in place. */
static const char *const frontend_reserved[] = {"robots.txt", NULL};

static const struct {
    const char *ext;
    const char *type;
} frontend_types[] = {
    {".html", "text/html; charset=utf-8"},
    {".js", "text/javascript; charset=utf-8"},
    {".mjs", "text/javascript; charset=utf-8"},
    {".css", "text/css; charset=utf-8"},
    {".json", "application/json"},
    {".map", "application/json"},
    {".txt", "text/plain; charset=utf-8"},
    {".svg", "image/svg+xml"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".webp", "image/webp"},
    {".ico", "image/x-icon"},
    {".webmanifest", "application/manifest+json"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
};

static const char *content_type_for(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return "application/octet-stream";
    for (size_t i = 0; i < sizeof(frontend_types) / sizeof(frontend_types[0]);
         i++) {
        if (strcmp(dot, frontend_types[i].ext) == 0)
            return frontend_types[i].type;
    }
    return "application/octet-stream";
}

static int is_reserved(const char *rel) {
    for (size_t i = 0; frontend_reserved[i]; i++) {
        if (strcmp(rel, frontend_reserved[i]) == 0) return 1;
    }
    return 0;
}

/* Read a whole file. The caller frees *out. */
static wf_status read_file(const char *path, unsigned char **out, size_t *len) {
    *out = NULL;
    *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return WF_ERR_NOT_FOUND;
    unsigned char *buf = NULL;
    size_t used = 0, cap = 0;
    for (;;) {
        if (used == cap) {
            size_t next = cap ? cap * 2 : 65536;
            if (next > FRONTEND_MAX_FILE_BYTES + 1)
                next = FRONTEND_MAX_FILE_BYTES + 1;
            if (next <= cap) break;
            unsigned char *grown = realloc(buf, next);
            if (!grown) {
                free(buf);
                fclose(f);
                return WF_ERR_ALLOC;
            }
            buf = grown;
            cap = next;
        }
        size_t n = fread(buf + used, 1, cap - used, f);
        used += n;
        if (n == 0) break;
        if (used > FRONTEND_MAX_FILE_BYTES) {
            free(buf);
            fclose(f);
            return WF_ERR_INVALID_ARG;
        }
    }
    int failed = ferror(f);
    fclose(f);
    if (failed) {
        free(buf);
        return WF_ERR_INTERNAL;
    }
    *out = buf;
    *len = used;
    return WF_OK;
}

static wf_status register_file(wf_xrpc_server *xrpc, const char *fs_path,
                               const char *rel, size_t *count) {
    unsigned char *body = NULL;
    size_t len = 0;
    wf_status st = read_file(fs_path, &body, &len);
    if (st != WF_OK) {
        LOG_WARN("frontend: cannot read %s (%d); skipping", fs_path, (int)st);
        return WF_OK;
    }
    const char *type = content_type_for(rel);
    char route[PATH_MAX];

    if (strcmp(rel, "index.html") == 0) {
        snprintf(route, sizeof(route), "/");
    } else {
        snprintf(route, sizeof(route), "/%s", rel);
    }
    st = wf_xrpc_server_register_static_get(xrpc, route, type, body, len);
    if (st == WF_OK) (*count)++;

    /* SvelteKit links to /account, not /account.html, so an .html page also
     * answers on its bare path. */
    size_t rel_len = strlen(rel);
    if (st == WF_OK && rel_len > 5 && strcmp(rel + rel_len - 5, ".html") == 0 &&
        strcmp(rel, "index.html") != 0) {
        char bare[PATH_MAX];
        snprintf(bare, sizeof(bare), "/%.*s", (int)(rel_len - 5), rel);
        st = wf_xrpc_server_register_static_get(xrpc, bare, type, body, len);
        if (st == WF_OK) (*count)++;
    }
    free(body);
    if (st != WF_OK) {
        LOG_WARN("frontend: cannot register %s (%d); skipping", route, (int)st);
        return WF_OK;
    }
    return WF_OK;
}

static wf_status walk(wf_xrpc_server *xrpc, const char *root,
                      const char *prefix, size_t *count) {
    char dir_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), "%s%s%s", root, prefix[0] ? "/" : "",
             prefix);
    DIR *d = opendir(dir_path);
    if (!d) return WF_ERR_NOT_FOUND;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char fs_path[PATH_MAX];
        char rel[PATH_MAX];
        snprintf(fs_path, sizeof(fs_path), "%s/%s", dir_path, ent->d_name);
        snprintf(rel, sizeof(rel), "%s%s%s", prefix, prefix[0] ? "/" : "",
                 ent->d_name);
        struct stat sb;
        if (stat(fs_path, &sb) != 0) continue;
        if (S_ISDIR(sb.st_mode)) {
            wf_status st = walk(xrpc, root, rel, count);
            if (st != WF_OK) {
                closedir(d);
                return st;
            }
        } else if (S_ISREG(sb.st_mode)) {
            if (prefix[0] == '\0' && is_reserved(rel)) continue;
            wf_status st = register_file(xrpc, fs_path, rel, count);
            if (st != WF_OK) {
                closedir(d);
                return st;
            }
        }
    }
    closedir(d);
    return WF_OK;
}

wf_status metalbear_frontend_register(wf_xrpc_server *xrpc, const char *dir,
                                      size_t *out_routes) {
    if (!xrpc || !dir || !*dir || !out_routes) return WF_ERR_INVALID_ARG;
    *out_routes = 0;
    struct stat sb;
    if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        LOG_WARN("frontend: %s is not a directory", dir);
        return WF_ERR_NOT_FOUND;
    }
    wf_status st = walk(xrpc, dir, "", out_routes);
    if (st == WF_OK)
        LOG_INFO("frontend: serving %zu routes from %s", *out_routes, dir);
    return st;
}
