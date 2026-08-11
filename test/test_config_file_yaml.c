#define _POSIX_C_SOURCE 200809L

/*
 * test_config_file_yaml.c — the YAML subset reader.
 *
 * Mirrors test_config_file.c's coverage for the TOML dialect: same
 * strictness, same "reject loudly rather than misread" policy, dispatched by
 * the .yml/.yaml extension instead of a syntax difference the caller has to
 * know about.
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

/* metalbear_config_file_load dispatches on extension, so the temp path must
 * actually end in .yml -- unlike the TOML tests, which rely on the
 * extension-less default. */
static char *write_temp(const char *body) {
    static char tmpl[] = "/tmp/metalbear-cfg-XXXXXX";
    char *base = strdup(tmpl);
    int fd = mkstemp(base);
    assert(fd >= 0);
    close(fd);
    char *path = malloc(strlen(base) + 5);
    sprintf(path, "%s.yml", base);
    unlink(base);
    free(base);
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(body, f);
    fclose(f);
    return path;
}

static void test_reads_every_type(void) {
    char *path = write_temp(
        "# a comment\n"
        "server:\n"
        "  listen: \"0.0.0.0\"   # trailing comment\n"
        "  port: 8080\n"
        "  threads: 6\n"
        "  service_did: \"did:web:example.com\"\n"
        "\n"
        "accounts:\n"
        "  invite_required: false\n"
        "\n"
        "limits:\n"
        "  rate_limit: 2500\n"
        "\n"
        "firehose:\n"
        "  crawlers: [\"https://a.example\", \"https://b.example\"]\n");

    metalbear_config cfg = {0};
    metalbear_config_file *owner = NULL;
    char err[256] = "";
    wf_status st =
        metalbear_config_file_load(path, &cfg, &owner, err, sizeof(err));
    if (st != WF_OK) fprintf(stderr, "load failed: %s\n", err);
    CHECK(st == WF_OK);
    CHECK(cfg.listen_address && strcmp(cfg.listen_address, "0.0.0.0") == 0);
    CHECK(cfg.port == 8080);
    CHECK(cfg.thread_count == 6);
    CHECK(cfg.service_did &&
          strcmp(cfg.service_did, "did:web:example.com") == 0);
    CHECK(cfg.invite_required == false);
    CHECK(cfg.rate_limit == 2500);
    CHECK(cfg.crawlers &&
          strcmp(cfg.crawlers, "https://a.example,https://b.example") == 0);
    metalbear_config_file_free(owner);
    unlink(path);
    free(path);
}

/* Bare (unquoted) scalars are idiomatic YAML and must work too, not just
 * quoted strings -- this is the one place the two dialects deliberately
 * differ (TOML always requires quotes). */
static void test_bare_scalars(void) {
    char *path =
        write_temp("server:\n"
                   "  listen: 0.0.0.0\n"
                   "  service_did: did:web:example.com\n"
                   "operator:\n"
                   "  name: Your Name\n"
                   "firehose:\n"
                   "  crawlers: [https://a.example, https://b.example]\n");
    metalbear_config cfg = {0};
    metalbear_config_file *owner = NULL;
    char err[256] = "";
    CHECK(metalbear_config_file_load(path, &cfg, &owner, err, sizeof(err)) ==
          WF_OK);
    CHECK(cfg.listen_address && strcmp(cfg.listen_address, "0.0.0.0") == 0);
    CHECK(cfg.service_did &&
          strcmp(cfg.service_did, "did:web:example.com") == 0);
    CHECK(cfg.operator_name && strcmp(cfg.operator_name, "Your Name") == 0);
    CHECK(cfg.crawlers &&
          strcmp(cfg.crawlers, "https://a.example,https://b.example") == 0);
    metalbear_config_file_free(owner);
    unlink(path);
    free(path);
}

static void test_single_quoted_strings(void) {
    char *path = write_temp("operator:\n"
                            "  name: 'It''s Ewan'\n"
                            "  url: 'https://example.com'\n");
    metalbear_config cfg = {0};
    metalbear_config_file *owner = NULL;
    char err[256] = "";
    CHECK(metalbear_config_file_load(path, &cfg, &owner, err, sizeof(err)) ==
          WF_OK);
    CHECK(cfg.operator_name && strcmp(cfg.operator_name, "It's Ewan") == 0);
    CHECK(cfg.operator_url &&
          strcmp(cfg.operator_url, "https://example.com") == 0);
    metalbear_config_file_free(owner);
    unlink(path);
    free(path);
}

static void test_absent_settings_are_left_alone(void) {
    char *path = write_temp("server:\n  port: 9000\n");
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

/* Each of these must fail loudly, naming the line. */
static void test_rejects_bad_input(void) {
    const char *cases[][2] = {
        {"unknown setting", "server:\n  nonsense: 1\n"},
        {"missing colon", "server:\n  port 8080\n"},
        {"non-integer port", "server:\n  port: \"eighty\"\n"},
        {"bad boolean", "accounts:\n  invite_required: yes\n"},
        {"out-of-range port", "server:\n  port: 70000\n"},
        {"setting outside section", "  port: 8080\n"},
        {"4-space indent", "server:\n    port: 8080\n"},
        {"tab indent", "server:\n\tport: 8080\n"},
        {"section header with value", "server: oops\n  port: 8080\n"},
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
        if (!strstr(err, ".yml")) {
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
    CHECK(metalbear_config_file_load("/nonexistent/config.yml", &cfg, &owner,
                                     err, sizeof(err)) == WF_ERR_NOT_FOUND);
    CHECK(err[0] != '\0');
}

/* The shipped example must actually parse, or it is documentation that
 * lies. */
static void test_example_config_parses(void) {
    const char *candidates[] = {"config.example.yaml", "../config.example.yaml",
                                "../../config.example.yaml"};
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
        CHECK(cfg.crawlers &&
              strcmp(cfg.crawlers, "https://bsky.network") == 0);
        metalbear_config_file_free(owner);
        return;
    }
    fprintf(stderr, "note: config.example.yaml not found from the test cwd\n");
}

/* The TOML and YAML examples describe the same deployment and must produce
 * an identical config, or the two dialects have quietly drifted apart. */
static void test_toml_and_yaml_examples_agree(void) {
    const char *toml_candidates[] = {"config.example.toml",
                                     "../config.example.toml",
                                     "../../config.example.toml"};
    const char *yaml_candidates[] = {"config.example.yaml",
                                     "../config.example.yaml",
                                     "../../config.example.yaml"};
    for (size_t i = 0; i < 3; i++) {
        if (access(toml_candidates[i], R_OK) != 0 ||
            access(yaml_candidates[i], R_OK) != 0)
            continue;
        metalbear_config toml_cfg = {0};
        metalbear_config yaml_cfg = {0};
        metalbear_config_file *toml_owner = NULL;
        metalbear_config_file *yaml_owner = NULL;
        char err[512] = "";
        CHECK(metalbear_config_file_load(toml_candidates[i], &toml_cfg,
                                         &toml_owner, err,
                                         sizeof(err)) == WF_OK);
        CHECK(metalbear_config_file_load(yaml_candidates[i], &yaml_cfg,
                                         &yaml_owner, err,
                                         sizeof(err)) == WF_OK);
        CHECK(toml_cfg.port == yaml_cfg.port);
        CHECK(toml_cfg.rate_limit == yaml_cfg.rate_limit);
        CHECK(strcmp(toml_cfg.listen_address, yaml_cfg.listen_address) == 0);
        CHECK(strcmp(toml_cfg.crawlers, yaml_cfg.crawlers) == 0);
        CHECK(toml_cfg.invite_required == yaml_cfg.invite_required);
        CHECK(toml_cfg.did_cache_ttl_seconds == yaml_cfg.did_cache_ttl_seconds);
        metalbear_config_file_free(toml_owner);
        metalbear_config_file_free(yaml_owner);
        return;
    }
    fprintf(stderr, "note: example configs not found from the test cwd\n");
}

int main(void) {
    printf("MetalBear YAML config file tests\n");
    test_reads_every_type();
    test_bare_scalars();
    test_single_quoted_strings();
    test_absent_settings_are_left_alone();
    test_rejects_bad_input();
    test_missing_file_is_reported();
    test_example_config_parses();
    test_toml_and_yaml_examples_agree();
    if (failures == 0) {
        printf("All tests passed.\n");
        return 0;
    }
    fprintf(stderr, "%d checks failed\n", failures);
    return 1;
}
