#define _POSIX_C_SOURCE 200809L

/*
 * test_config_file.c — the TOML subset reader.
 *
 * The parser is strict on purpose: a configuration file that is silently
 * half-read is worse than one that refuses to load, because the operator ends
 * up running settings they did not ask for. These tests hold it to that.
 */

#include "metalbear/config_file.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static char *write_temp(const char *body) {
    static char path[] = "/tmp/metalbear-cfg-XXXXXX";
    char *p = strdup(path);
    int fd = mkstemp(p);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fputs(body, f);
    fclose(f);
    return p;
}

static void test_reads_every_type(void) {
    char *path = write_temp(
        "# a comment\n"
        "[server]\n"
        "listen = \"0.0.0.0\"   # trailing comment\n"
        "port = 8080\n"
        "threads = 6\n"
        "service_did = \"did:web:example.com\"\n"
        "\n"
        "[accounts]\n"
        "invite_required = false\n"
        "\n"
        "[limits]\n"
        "rate_limit = 2500\n"
        "\n"
        "[firehose]\n"
        "crawlers = [\"https://a.example\", \"https://b.example\"]\n");

    metalbear_config cfg = {0};
    metalbear_config_file *owner = NULL;
    char err[256] = "";
    CHECK(metalbear_config_file_load(path, &cfg, &owner, err, sizeof(err)) ==
          WF_OK);
    CHECK(cfg.listen_address && strcmp(cfg.listen_address, "0.0.0.0") == 0);
    CHECK(cfg.port == 8080);
    CHECK(cfg.thread_count == 6);
    CHECK(cfg.service_did &&
          strcmp(cfg.service_did, "did:web:example.com") == 0);
    CHECK(cfg.invite_required == false);
    CHECK(cfg.rate_limit == 2500);
    /* An array becomes the comma-separated form used everywhere else, rather
     * than a second representation of one setting. */
    CHECK(cfg.crawlers &&
          strcmp(cfg.crawlers, "https://a.example,https://b.example") == 0);
    metalbear_config_file_free(owner);
    unlink(path);
    free(path);
}

static void test_absent_settings_are_left_alone(void) {
    char *path = write_temp("[server]\nport = 9000\n");
    metalbear_config cfg = {0};
    cfg.listen_address = "preset";
    cfg.rate_limit = 42;
    metalbear_config_file *owner = NULL;
    CHECK(metalbear_config_file_load(path, &cfg, &owner, NULL, 0) == WF_OK);
    CHECK(cfg.port == 9000);
    CHECK(strcmp(cfg.listen_address, "preset") == 0);
    CHECK(cfg.rate_limit == 42);
    metalbear_config_file_free(owner);
    unlink(path);
    free(path);
}

/* operator.email and operator.override_email are distinct fields
 * (account_email vs. operator_email) -- setting one must not touch the
 * other. */
static void test_operator_email_override_is_distinct(void) {
    char *path = write_temp("[operator]\n"
                            "email = \"contact@example.com\"\n"
                            "override_email = \"press@example.com\"\n");
    metalbear_config cfg = {0};
    metalbear_config_file *owner = NULL;
    char err[256] = "";
    CHECK(metalbear_config_file_load(path, &cfg, &owner, err, sizeof(err)) ==
          WF_OK);
    CHECK(cfg.account_email &&
          strcmp(cfg.account_email, "contact@example.com") == 0);
    CHECK(cfg.operator_email &&
          strcmp(cfg.operator_email, "press@example.com") == 0);
    metalbear_config_file_free(owner);
    unlink(path);
    free(path);
}

/* Each of these must fail loudly, naming the line. */
static void test_rejects_bad_input(void) {
    const char *cases[][2] = {
        {"unknown setting", "[server]\nnonsense = 1\n"},
        {"missing equals", "[server]\nport 8080\n"},
        {"unquoted string", "[server]\nlisten = 0.0.0.0\n"},
        {"non-integer port", "[server]\nport = \"eighty\"\n"},
        {"bad boolean", "[accounts]\ninvite_required = yes\n"},
        {"out-of-range port", "[server]\nport = 70000\n"},
        {"unterminated section", "[server\nport = 1\n"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char *path = write_temp(cases[i][1]);
        metalbear_config cfg = {0};
        metalbear_config_file *owner = NULL;
        char err[256] = "";
        wf_status st =
            metalbear_config_file_load(path, &cfg, &owner, err, sizeof(err));
        if (st == WF_OK) {
            fprintf(stderr, "FAIL: accepted bad input (%s)\n", cases[i][0]);
            failures++;
        }
        /* The message must locate the problem, or it is not actionable. */
        if (!strstr(err, ".toml") && !strstr(err, "metalbear-cfg")) {
            fprintf(stderr, "FAIL: error for '%s' names no file: %s\n",
                    cases[i][0], err);
            failures++;
        }
        CHECK(owner == NULL);
        metalbear_config_file_free(owner);
        unlink(path);
        free(path);
    }
}

static void test_missing_file_is_reported(void) {
    metalbear_config cfg = {0};
    metalbear_config_file *owner = NULL;
    char err[256] = "";
    CHECK(metalbear_config_file_load("/nonexistent/config.toml", &cfg, &owner,
                                     err, sizeof(err)) == WF_ERR_NOT_FOUND);
    CHECK(err[0] != '\0');
}

/* The shipped example must actually parse, or it is documentation that lies. */
static void test_example_config_parses(void) {
    const char *candidates[] = {"config.example.toml", "../config.example.toml",
                                "../../config.example.toml"};
    for (size_t i = 0; i < 3; i++) {
        if (access(candidates[i], R_OK) != 0) continue;
        metalbear_config cfg = {0};
        metalbear_config_file *owner = NULL;
        char err[512] = "";
        wf_status st = metalbear_config_file_load(candidates[i], &cfg, &owner,
                                                  err, sizeof(err));
        if (st != WF_OK) {
            fprintf(stderr, "FAIL: shipped example does not parse: %s\n", err);
            failures++;
        }
        CHECK(cfg.port == 2583);
        CHECK(cfg.rate_limit == 3000);
        metalbear_config_file_free(owner);
        return;
    }
    fprintf(stderr, "note: config.example.toml not found from the test cwd\n");
}

int main(void) {
    printf("MetalBear config file tests\n");
    test_reads_every_type();
    test_absent_settings_are_left_alone();
    test_operator_email_override_is_distinct();
    test_rejects_bad_input();
    test_missing_file_is_reported();
    test_example_config_parses();
    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    fprintf(stderr, "%d checks failed\n", failures);
    return 1;
}
