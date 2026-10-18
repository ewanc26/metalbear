/*
 * The frontend static handler against a live wf_xrpc_server. The fixture is a
 * small tree shaped like a SvelteKit build: index.html, a prerendered page with
 * a nested sibling, an _app asset, and a robots.txt that the handler must leave
 * to the server.
 */
#if defined(__APPLE__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ops/frontend_static.h"
#include "wolfram/xrpc_server.h"

static int failures = 0;

#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "FAIL: cannot write %s\n", path);
        failures++;
        return;
    }
    fputs(content, f);
    fclose(f);
}

/* Raw HTTP/1.1 GET. Returns the status code, or -1 on a transport error. The
 * content type and body are copied out, truncated to their buffers. */
static int http_get(unsigned short port, const char *path, char *ctype,
                    size_t ctype_len, char *body, size_t body_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
             path);
    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return -1;
    }
    size_t cap = 65536, used = 0;
    char *raw = malloc(cap);
    if (!raw) {
        close(fd);
        return -1;
    }
    for (;;) {
        if (used == cap) {
            char *grown = realloc(raw, cap * 2);
            if (!grown) break;
            raw = grown;
            cap *= 2;
        }
        ssize_t n = recv(fd, raw + used, cap - used, 0);
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    int status = -1;
    if (used >= 12 && strncmp(raw, "HTTP/1.", 7) == 0) status = atoi(raw + 9);

    if (ctype && ctype_len) ctype[0] = '\0';
    char *sep = NULL;
    for (size_t i = 0; i + 3 < used; i++) {
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' &&
            raw[i + 3] == '\n') {
            sep = raw + i;
            break;
        }
    }
    if (sep) {
        if (ctype && ctype_len) {
            char *line = strcasestr(raw, "\r\nContent-Type:");
            if (line && line < sep) {
                line += strlen("\r\nContent-Type:");
                while (*line == ' ') line++;
                size_t n = 0;
                while (line + n < sep && line[n] != '\r' && n + 1 < ctype_len) {
                    ctype[n] = line[n];
                    n++;
                }
                ctype[n] = '\0';
            }
        }
        if (body && body_len) {
            size_t n = (size_t)((raw + used) - (sep + 4));
            if (n >= body_len) n = body_len - 1;
            memcpy(body, sep + 4, n);
            body[n] = '\0';
        }
    }
    free(raw);
    return status;
}

static void build_fixture(const char *root) {
    char path[512];
    snprintf(path, sizeof(path), "%s/index.html", root);
    write_file(path, "<html>home page</html>");
    snprintf(path, sizeof(path), "%s/account.html", root);
    write_file(path, "<html>account page</html>");
    snprintf(path, sizeof(path), "%s/account", root);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/account/devices.html", root);
    write_file(path, "<html>devices page</html>");
    snprintf(path, sizeof(path), "%s/_app", root);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/_app/app.js", root);
    write_file(path, "console.log('app');");
    snprintf(path, sizeof(path), "%s/robots.txt", root);
    write_file(path, "frontend robots");
}

static void remove_fixture(const char *root) {
    const char *files[] = {"index.html", "account.html", "account/devices.html",
                           "_app/app.js", "robots.txt"};
    char path[512];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", root, files[i]);
        unlink(path);
    }
    snprintf(path, sizeof(path), "%s/account", root);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/_app", root);
    rmdir(path);
    rmdir(root);
}

int main(void) {
    char root[] = "/tmp/metalbear-frontend-XXXXXX";
    if (!mkdtemp(root)) {
        fprintf(stderr, "FAIL: mkdtemp\n");
        return 1;
    }
    build_fixture(root);

    /* A path that is not a directory must stop startup, not serve nothing. */
    wf_xrpc_server *probe = wf_xrpc_server_start("127.0.0.1", 0, 0);
    CHECK(probe != NULL);
    size_t routes = 99;
    CHECK(metalbear_frontend_register(probe, "/nonexistent/frontend",
                                      &routes) == WF_ERR_NOT_FOUND);
    CHECK(routes == 0);
    wf_xrpc_server_free(probe);

    wf_xrpc_server *server = wf_xrpc_server_start("127.0.0.1", 0, 0);
    CHECK(server != NULL);
    if (!server) {
        remove_fixture(root);
        return 1;
    }
    routes = 0;
    CHECK(metalbear_frontend_register(server, root, &routes) == WF_OK);
    /* index + account.html + its bare alias + devices + its alias + app.js.
     * robots.txt is skipped. */
    CHECK(routes == 6);
    unsigned short port = wf_xrpc_server_port(server);

    char ctype[128], body[256];

    CHECK(http_get(port, "/", ctype, sizeof(ctype), body, sizeof(body)) == 200);
    CHECK(strcmp(body, "<html>home page</html>") == 0);
    CHECK(strncmp(ctype, "text/html", 9) == 0);

    CHECK(http_get(port, "/account", ctype, sizeof(ctype), body,
                   sizeof(body)) == 200);
    CHECK(strcmp(body, "<html>account page</html>") == 0);

    CHECK(http_get(port, "/account.html", ctype, sizeof(ctype), body,
                   sizeof(body)) == 200);
    CHECK(strcmp(body, "<html>account page</html>") == 0);

    CHECK(http_get(port, "/account/devices", ctype, sizeof(ctype), body,
                   sizeof(body)) == 200);
    CHECK(strcmp(body, "<html>devices page</html>") == 0);

    CHECK(http_get(port, "/_app/app.js", ctype, sizeof(ctype), body,
                   sizeof(body)) == 200);
    CHECK(strncmp(ctype, "text/javascript", 15) == 0);
    CHECK(strcmp(body, "console.log('app');") == 0);

    /* Not in the build: the server's own fallback answers, not a frontend
     * page. That fallback is a 400 "URL must be /xrpc/<nsid>" today, so this
     * asserts only that the page is not served. */
    CHECK(http_get(port, "/no-such-page", ctype, sizeof(ctype), body,
                   sizeof(body)) != 200);
    CHECK(strstr(body, "home page") == NULL);

    wf_xrpc_server_free(server);
    remove_fixture(root);

    if (failures == 0) {
        printf("PASS: frontend static routes (%zu registered)\n", routes);
        return 0;
    }
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
