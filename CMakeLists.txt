cmake_minimum_required(VERSION 3.20)
project(metalbear VERSION 0.31.1 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wno-gcc-compat)

# Build provenance surfaced on the landing page and /_debug/health. Captured at
# configure time -- accurate for the common case (a fresh cmake + build, which
# is what both the Docker image and CI do); re-run cmake to refresh the commit
# after reconfiguring an existing build tree from a new commit without a full
# reconfigure in between.
#
# The Docker build's context deliberately excludes .git (see the repo root's
# .dockerignore -- keeping the context small), so git-detection can never see a
# commit from inside that build. Accept an external override instead: the
# Dockerfile passes -DMETALBEAR_BUILD_COMMIT=... from a build arg computed on
# the host, where .git *is* available. A CACHE variable set via -D on the
# initial configure wins over the set() below, so the override is used as-is and
# git-detection is skipped entirely; without an override this falls back to
# "unknown" outside a git checkout too (e.g. a source tarball).
set(METALBEAR_BUILD_COMMIT
    "unknown"
    CACHE
      STRING
      "Short git commit this build was compiled from; auto-detected unless overridden with -D."
)
if(METALBEAR_BUILD_COMMIT STREQUAL "unknown")
  find_package(Git QUIET)
  if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      OUTPUT_VARIABLE METALBEAR_BUILD_COMMIT
      OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(NOT METALBEAR_BUILD_COMMIT)
      set(METALBEAR_BUILD_COMMIT "unknown")
    endif()
  endif()
endif()
string(TIMESTAMP METALBEAR_BUILD_TIME "%Y-%m-%dT%H:%M:%SZ" UTC)

# Single source of truth for where this build sits on the software release
# life cycle (https://en.wikipedia.org/wiki/Software_release_life_cycle),
# surfaced alongside the other build provenance so an operator or a client
# doesn't have to infer it from the 0.x version number alone. One of
# "pre-alpha", "alpha", "beta", "rc", or "stable" by convention -- nothing
# enforces the value beyond that; see README.md's "Release stage" section.
# Override with -DMETALBEAR_RELEASE_STAGE=... per deployment; the default
# here is the project's own current stage, updated as it matures.
set(METALBEAR_RELEASE_STAGE
    "beta"
    CACHE
      STRING
      "Where this build sits on the software release life cycle (pre-alpha/alpha/beta/rc/stable)."
)

option(METALBEAR_BUILD_TESTS "Build MetalBear tests" ON)
find_package(SQLite3 REQUIRED)
# Some CMake/FindSQLite3 combinations (e.g. Debian bookworm's 3.25) populate
# SQLite3_LIBRARIES but do not define the SQLite3::SQLite3 imported target that
# later target_link_libraries calls rely on. Create it when absent so the build
# is portable across toolchains.
if(NOT TARGET SQLite3::SQLite3)
  add_library(SQLite3::SQLite3 UNKNOWN IMPORTED)
  set_target_properties(
    SQLite3::SQLite3
    PROPERTIES IMPORTED_LOCATION "${SQLite3_LIBRARY}"
               INTERFACE_INCLUDE_DIRECTORIES "${SQLite3_INCLUDE_DIR}")
endif()
find_package(Threads REQUIRED)
# The C++ dev tools link OpenSSL. Wolfram's subdirectory runs its own
# find_package(OpenSSL REQUIRED), but that only populates targets in wolfram's
# scope, so MetalBear must resolve OpenSSL::Crypto here.
find_package(OpenSSL REQUIRED)

# PCRE2 (8-bit/UTF-8 build) for explicit-slur record-key detection
# (src/repo/explicit_slurs.c) -- the reference's own detection patterns are
# Unicode character classes POSIX regex.h cannot express correctly. No
# standard CMake config package ships on every platform, so this goes
# through pkg-config (libpcre2-8.pc), which every target this project builds
# for already provides.
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCRE2 REQUIRED IMPORTED_TARGET libpcre2-8)
set(WOLFRAM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../wolfram"
    CACHE PATH "Path to the Wolfram source tree")

if(NOT EXISTS "${WOLFRAM_SOURCE_DIR}/CMakeLists.txt")
  message(FATAL_ERROR "WOLFRAM_SOURCE_DIR does not point to a Wolfram checkout")
endif()

set(WOLFRAM_BUILD_SERVER ON CACHE BOOL "" FORCE)
set(WOLFRAM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(WOLFRAM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WOLFRAM_BUILD_CPP OFF CACHE BOOL "" FORCE)
add_subdirectory("${WOLFRAM_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/wolfram")
get_target_property(METALBEAR_CJSON_SOURCE_DIR cjson SOURCE_DIR)
target_compile_options(cjson PRIVATE -Wno-keyword-macro)

add_library(
  metalbear_core
  src/ops/metrics.c
  src/dns/handle_dns.c
  src/dns/handle_dns_rfc2136.c
  cpp/metalbear/account_registry.cpp
  src/account/account_context.c
  src/account/account_cache.c
  src/oauth/auth.c
  src/repo/backup.c
  src/repo/explicit_slurs.c
  src/repo/explicit_slurs_patterns.c
  src/email.cpp
  src/oauth/oauth.c
  src/oauth/oauth_routes.c
  src/oauth/oauth_account_routes.c
  src/oauth/oauth_scope.c
  src/oauth/oauth_credentials.c
  cpp/metalbear/key_rotation.cpp
  src/repo/repo_store.c
  src/repo/repo_routes.c
  src/repo/did_document.c
  src/sequencer.c
  src/server.c
  src/admin/admin_routes.c
  src/identity/identity_routes.c
  src/session/session_routes.c
  src/account/account_routes.c
  src/sync/sync_routes.c
  src/appview/appview_routes.c
  src/moderation/moderation_routes.c
  src/moderation/report.c
  src/video/video_routes.c
  src/repo/blob_store.c
  src/repo/blob_store_server.c
  src/ops/update_watcher.c
  src/ops/status.c
  cpp/metalbear/config_file.cpp
  cpp/metalbear/log.cpp
  cpp/metalbear/account.cpp)
target_include_directories(metalbear_core PUBLIC include
                           PUBLIC "${METALBEAR_CJSON_SOURCE_DIR}")
target_link_libraries(metalbear_core PUBLIC wolfram cjson
                      PRIVATE SQLite3::SQLite3 Threads::Threads PkgConfig::PCRE2)
# PUBLIC so consumers — and the test targets, which assert what the running
# server reports against what it was built as — see the version they link.
target_compile_definitions(
  metalbear_core
  PUBLIC METALBEAR_VERSION="${PROJECT_VERSION}"
  PUBLIC METALBEAR_BUILD_COMMIT="${METALBEAR_BUILD_COMMIT}"
  PUBLIC METALBEAR_BUILD_TIME="${METALBEAR_BUILD_TIME}"
  PUBLIC METALBEAR_RELEASE_STAGE="${METALBEAR_RELEASE_STAGE}")

# nftw() and its FTW_* flags are XSI extensions. Wolfram exports
# _POSIX_C_SOURCE/_DEFAULT_SOURCE, which is enough for strdup and friends but
# does not set __USE_XOPEN_EXTENDED, so glibc still hides FTW_DEPTH/FTW_PHYS.
# PUBLIC so the test targets, which recursively delete their fixture trees,
# inherit it too — the Docker image builds with tests off and so never caught
# this, while CI did.
if(UNIX)
  target_compile_definitions(metalbear_core PUBLIC _XOPEN_SOURCE=700)
  if(APPLE)
    target_compile_definitions(metalbear_core PUBLIC _DARWIN_C_SOURCE)
  endif()
endif()
target_compile_options(metalbear_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(metalbear src/main.c)
target_link_libraries(metalbear PRIVATE metalbear_core)
if(UNIX AND NOT APPLE)
  # metalbear_core links C++ translation units (account.cpp and friends), so
  # this binary depends on libstdc++/libgcc_s even though main.c is C. Both the
  # Alpine and Debian runtime images copy only this one file and never install
  # those packages — matching the Dockerfiles' documented "single self-contained
  # binary" design — so on a musl runtime the dynamic linker fails outright
  # (libstdc++.so.6: No such file or directory) and on glibc it depends on some
  # other package having pulled libstdc++ in as a side effect. Link both
  # statically so the binary never depends on either being present.
  target_link_options(metalbear PRIVATE -static-libgcc -static-libstdc++)
endif()

if(METALBEAR_BUILD_TESTS)
  enable_testing()
  add_executable(test_metalbear test/test_server.c)
  target_link_libraries(test_metalbear PRIVATE metalbear_core)
  target_include_directories(test_metalbear
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_server COMMAND test_metalbear)

  add_executable(test_metalbear_auth test/test_auth.c)
  target_link_libraries(test_metalbear_auth PRIVATE metalbear_core)
  add_test(NAME metalbear_auth COMMAND test_metalbear_auth)

  add_executable(test_metalbear_auth_unknown_subject
                 test/test_auth_unknown_subject.c)
  target_link_libraries(test_metalbear_auth_unknown_subject
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_auth_unknown_subject
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_auth_unknown_subject
           COMMAND test_metalbear_auth_unknown_subject)

  add_executable(test_metalbear_oauth test/test_oauth.c)
  target_link_libraries(test_metalbear_oauth PRIVATE metalbear_core)
  add_test(NAME metalbear_oauth COMMAND test_metalbear_oauth)

  add_executable(test_metalbear_oauth_metadata test/test_oauth_metadata.c)
  target_link_libraries(test_metalbear_oauth_metadata PRIVATE metalbear_core)
  target_include_directories(
    test_metalbear_oauth_metadata PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}"
                                          "${WOLFRAM_SOURCE_DIR}/test")
  add_test(NAME metalbear_oauth_metadata COMMAND test_metalbear_oauth_metadata)

  # private_key_jwt client auth at the token endpoint: serves the client's
  # metadata + jwks from a local MHD stub and drives /oauth/token over the wire,
  # covering the happy path and every client-auth failure.
  add_executable(test_metalbear_oauth_token_assertion
                 test/test_oauth_token_assertion.c)
  target_link_libraries(
    test_metalbear_oauth_token_assertion
    PRIVATE metalbear_core ${MICROHTTPD_LIBRARY} Threads::Threads
            OpenSSL::Crypto)
  target_include_directories(
    test_metalbear_oauth_token_assertion
    PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}" "${WOLFRAM_SOURCE_DIR}/test"
            ${MICROHTTPD_INCLUDE_DIR})
  add_test(NAME metalbear_oauth_token_assertion
           COMMAND test_metalbear_oauth_token_assertion)

  add_executable(test_metalbear_oauth_scope test/test_oauth_scope.c)
  target_link_libraries(test_metalbear_oauth_scope PRIVATE metalbear_core)
  target_include_directories(test_metalbear_oauth_scope
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_oauth_scope COMMAND test_metalbear_oauth_scope)

  add_executable(test_metalbear_routes test/test_routes.c)
  target_link_libraries(test_metalbear_routes PRIVATE metalbear_core)
  target_include_directories(test_metalbear_routes
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_routes COMMAND test_metalbear_routes)

  add_executable(test_metalbear_registry test/test_registry.c)
  target_link_libraries(test_metalbear_registry PRIVATE metalbear_core)
  add_test(NAME metalbear_registry COMMAND test_metalbear_registry)

  add_executable(test_metalbear_config_file test/test_config_file.c)
  target_link_libraries(test_metalbear_config_file PRIVATE metalbear_core)
  target_include_directories(test_metalbear_config_file
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  # Run from the source tree so the shipped config.example.toml is reachable.
  add_test(NAME metalbear_config_file COMMAND test_metalbear_config_file
           WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  add_executable(test_metalbear_config_file_yaml test/test_config_file_yaml.c)
  target_link_libraries(test_metalbear_config_file_yaml PRIVATE metalbear_core)
  target_include_directories(test_metalbear_config_file_yaml
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  # Run from the source tree so the shipped config.example.yaml is reachable.
  add_test(NAME metalbear_config_file_yaml
          COMMAND test_metalbear_config_file_yaml
          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  # Runs the publisher against a stand-in for the Cloudflare API, so the
  # requests it would send to a live zone can be asserted on directly.
  find_path(MICROHTTPD_INCLUDE_DIR NAMES microhttpd.h REQUIRED)
  find_library(MICROHTTPD_LIBRARY NAMES microhttpd REQUIRED)
  add_executable(test_metalbear_handle_dns test/test_handle_dns.c)
  target_link_libraries(
    test_metalbear_handle_dns PRIVATE metalbear_core ${MICROHTTPD_LIBRARY}
                                      Threads::Threads)
  target_include_directories(
    test_metalbear_handle_dns PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}"
                                      ${MICROHTTPD_INCLUDE_DIR})
  add_test(NAME metalbear_handle_dns COMMAND test_metalbear_handle_dns)

  add_executable(test_metalbear_handle_dns_rfc2136
                 test/test_handle_dns_rfc2136.c)
  target_link_libraries(test_metalbear_handle_dns_rfc2136
                        PRIVATE metalbear_core Threads::Threads)
  target_include_directories(test_metalbear_handle_dns_rfc2136
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_handle_dns_rfc2136
           COMMAND test_metalbear_handle_dns_rfc2136)

  add_executable(test_metalbear_backup test/test_backup.c)
  target_link_libraries(test_metalbear_backup PRIVATE metalbear_core
                                                      SQLite3::SQLite3)
  target_include_directories(test_metalbear_backup
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_backup COMMAND test_metalbear_backup)

  add_executable(test_metalbear_multi_account test/test_multi_account.c)
  target_link_libraries(test_metalbear_multi_account PRIVATE metalbear_core
                                                             SQLite3::SQLite3)
  target_include_directories(test_metalbear_multi_account
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_multi_account COMMAND test_metalbear_multi_account)

  add_executable(test_metalbear_takedown test/test_takedown.c)
  target_link_libraries(test_metalbear_takedown PRIVATE metalbear_core
                                                        SQLite3::SQLite3)
  target_include_directories(test_metalbear_takedown
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_takedown COMMAND test_metalbear_takedown)

  # Parity-audit fixes: createReport union $type + params lifetime, createAccount
  # validation, sync/session/repo write semantics, and local getProfile.
  add_executable(test_metalbear_audit_moderation test/test_audit_moderation.c)
  target_link_libraries(test_metalbear_audit_moderation
                        PRIVATE metalbear_core SQLite3::SQLite3)
  target_include_directories(test_metalbear_audit_moderation
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_audit_moderation
           COMMAND test_metalbear_audit_moderation)

  add_executable(test_metalbear_audit_account test/test_audit_account.c)
  target_link_libraries(test_metalbear_audit_account
                        PRIVATE metalbear_core SQLite3::SQLite3)
  target_include_directories(test_metalbear_audit_account
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_audit_account COMMAND test_metalbear_audit_account)

  add_executable(test_metalbear_audit_sync test/test_audit_sync.c)
  target_link_libraries(test_metalbear_audit_sync
                        PRIVATE metalbear_core SQLite3::SQLite3)
  target_include_directories(test_metalbear_audit_sync
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_audit_sync COMMAND test_metalbear_audit_sync)

  add_executable(test_metalbear_audit_identity test/test_audit_identity.c)
  target_link_libraries(test_metalbear_audit_identity
                        PRIVATE metalbear_core SQLite3::SQLite3)
  target_include_directories(test_metalbear_audit_identity
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_audit_identity COMMAND test_metalbear_audit_identity)

  add_executable(test_metalbear_rate_limits test/test_rate_limits.c)
  target_link_libraries(test_metalbear_rate_limits PRIVATE metalbear_core
                                                           SQLite3::SQLite3)
  target_include_directories(test_metalbear_rate_limits
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_rate_limits COMMAND test_metalbear_rate_limits)

  add_executable(test_metalbear_account_email_tokens
                 test/test_account_email_tokens.c)
  target_link_libraries(test_metalbear_account_email_tokens
                        PRIVATE metalbear_core SQLite3::SQLite3)
  target_include_directories(test_metalbear_account_email_tokens
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_account_email_tokens
          COMMAND test_metalbear_account_email_tokens)

  add_executable(test_metalbear_email_internal test/test_email_internal.c)
  target_link_libraries(test_metalbear_email_internal PRIVATE metalbear_core)
  add_test(NAME metalbear_email_internal COMMAND test_metalbear_email_internal)

  add_executable(test_metalbear_account_email_send_failure
                 test/test_account_email_send_failure.c)
  target_link_libraries(test_metalbear_account_email_send_failure
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_account_email_send_failure
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_account_email_send_failure
          COMMAND test_metalbear_account_email_send_failure)

  add_executable(test_metalbear_proxy test/test_proxy.c)
  target_link_libraries(test_metalbear_proxy PRIVATE metalbear_core
                                                     Threads::Threads)
  target_include_directories(test_metalbear_proxy
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_proxy COMMAND test_metalbear_proxy)

  add_executable(test_metalbear_oauth_device_session
                 test/test_oauth_device_session.c)
  target_link_libraries(test_metalbear_oauth_device_session
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_oauth_device_session
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_oauth_device_session
           COMMAND test_metalbear_oauth_device_session)

  add_executable(test_metalbear_oauth_multi_device_session
                 test/test_oauth_multi_device_session.c)
  target_link_libraries(test_metalbear_oauth_multi_device_session
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_oauth_multi_device_session
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_oauth_multi_device_session
           COMMAND test_metalbear_oauth_multi_device_session)

  add_executable(test_metalbear_oauth_account_routes
                 test/test_oauth_account_routes.c)
  target_link_libraries(test_metalbear_oauth_account_routes
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_oauth_account_routes
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_oauth_account_routes
           COMMAND test_metalbear_oauth_account_routes)

  add_executable(test_metalbear_oauth_authorize_info
                 test/test_oauth_authorize_info.c)
  target_link_libraries(test_metalbear_oauth_authorize_info
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_oauth_authorize_info
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_oauth_authorize_info
           COMMAND test_metalbear_oauth_authorize_info)

  add_executable(test_metalbear_repo_store test/test_repo_store.c)
  target_link_libraries(test_metalbear_repo_store PRIVATE metalbear_core)
  target_include_directories(
    test_metalbear_repo_store PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}"
                                      "${WOLFRAM_SOURCE_DIR}/test")
  target_compile_definitions(
    test_metalbear_repo_store
    PRIVATE METALBEAR_TEST_LEXICON_DIR="${WOLFRAM_SOURCE_DIR}/lexicons")
  add_test(NAME metalbear_repo_store COMMAND test_metalbear_repo_store)

  add_executable(test_metalbear_repo_store_resolver
                 test/test_repo_store_resolver.c)
  target_link_libraries(test_metalbear_repo_store_resolver
                        PRIVATE metalbear_core)
  target_include_directories(
    test_metalbear_repo_store_resolver PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}"
                                               "${WOLFRAM_SOURCE_DIR}/test")
  add_test(NAME metalbear_repo_store_resolver
           COMMAND test_metalbear_repo_store_resolver)

  add_executable(test_metalbear_blob_store test/test_blob_store.c)
  target_link_libraries(test_metalbear_blob_store PRIVATE metalbear_core)
  target_include_directories(test_metalbear_blob_store
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_blob_store COMMAND test_metalbear_blob_store)

  add_executable(test_metalbear_blob_gc test/test_blob_gc.c)
  target_link_libraries(test_metalbear_blob_gc PRIVATE metalbear_core)
  target_include_directories(
    test_metalbear_blob_gc PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}"
                                   "${WOLFRAM_SOURCE_DIR}/test")
  add_test(NAME metalbear_blob_gc COMMAND test_metalbear_blob_gc)

  add_executable(test_metalbear_import_repo test/test_import_repo.c)
  target_link_libraries(test_metalbear_import_repo PRIVATE metalbear_core)
  target_include_directories(test_metalbear_import_repo
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_import_repo COMMAND test_metalbear_import_repo)

  add_executable(test_metalbear_identity_plc_operation
                 test/test_identity_plc_operation.c)
  target_link_libraries(test_metalbear_identity_plc_operation
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_identity_plc_operation
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_identity_plc_operation
          COMMAND test_metalbear_identity_plc_operation)

  add_executable(test_metalbear_handle_plc_update
                 test/test_handle_plc_update.c)
  target_link_libraries(test_metalbear_handle_plc_update
                        PRIVATE metalbear_core)
  target_include_directories(test_metalbear_handle_plc_update
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_handle_plc_update
          COMMAND test_metalbear_handle_plc_update)

  add_executable(test_metalbear_explicit_slurs test/test_explicit_slurs.c)
  target_link_libraries(test_metalbear_explicit_slurs PRIVATE metalbear_core)
  target_include_directories(test_metalbear_explicit_slurs
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_explicit_slurs
          COMMAND test_metalbear_explicit_slurs)

  add_executable(test_metalbear_metrics test/test_metrics.c)
  target_link_libraries(test_metalbear_metrics PRIVATE metalbear_core)
  target_include_directories(test_metalbear_metrics
                             PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_metrics COMMAND test_metalbear_metrics)

  add_executable(test_metalbear_repo_parallel test/test_repo_parallel.c)
  target_link_libraries(test_metalbear_repo_parallel
                        PRIVATE metalbear_core Threads::Threads)
  target_include_directories(test_metalbear_repo_parallel
                            PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
  add_test(NAME metalbear_repo_parallel
           COMMAND test_metalbear_repo_parallel)
endif()

# C++ dev tools (replacements for the Python tools of the same name). Guarded so
# the build still works while the sources are mid-migration and may be
# incomplete.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/firehose_probe.cpp")
  add_executable(firehose_probe tools/firehose_probe.cpp)
  target_link_libraries(firehose_probe PRIVATE OpenSSL::Crypto OpenSSL::SSL)
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_repo_car.cpp")
  find_package(CURL REQUIRED)
  add_executable(verify_repo_car tools/verify_repo_car.cpp)
  target_link_libraries(verify_repo_car PRIVATE OpenSSL::Crypto CURL::libcurl)
endif()
