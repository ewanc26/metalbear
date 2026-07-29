cmake_minimum_required(VERSION 3.20)
project(metalbear VERSION 0.7.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(METALBEAR_BUILD_TESTS "Build MetalBear tests" ON)
find_package(SQLite3 REQUIRED)
# Some CMake/FindSQLite3 combinations (e.g. Debian bookworm's 3.25) populate
# SQLite3_LIBRARIES but do not define the SQLite3::SQLite3 imported target that
# later target_link_libraries calls rely on. Create it when absent so the build
# is portable across toolchains.
if(NOT TARGET SQLite3::SQLite3)
    add_library(SQLite3::SQLite3 UNKNOWN IMPORTED)
    set_target_properties(SQLite3::SQLite3 PROPERTIES
        IMPORTED_LOCATION "${SQLite3_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SQLite3_INCLUDE_DIR}")
endif()
find_package(Threads REQUIRED)
set(WOLFRAM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../wolfram" CACHE PATH
    "Path to the Wolfram source tree")

if(NOT EXISTS "${WOLFRAM_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "WOLFRAM_SOURCE_DIR does not point to a Wolfram checkout")
endif()

set(WOLFRAM_BUILD_SERVER ON CACHE BOOL "" FORCE)
set(WOLFRAM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(WOLFRAM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WOLFRAM_BUILD_CPP OFF CACHE BOOL "" FORCE)
add_subdirectory("${WOLFRAM_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/wolfram")
get_target_property(METALBEAR_CJSON_SOURCE_DIR cjson SOURCE_DIR)

add_library(metalbear_core src/config_file.c src/log.c src/metrics.c src/handle_dns.c src/handle_dns_rfc2136.c src/account.c src/account_registry.c src/account_context.c src/account_cache.c src/auth.c src/backup.c src/email.c src/oauth.c src/oauth_routes.c src/key_rotation.c src/repo_store.c src/sequencer.c src/server.c src/report.c src/blob_store.c src/blob_store_server.c)
target_include_directories(metalbear_core PUBLIC include
    PUBLIC "${METALBEAR_CJSON_SOURCE_DIR}")
target_link_libraries(metalbear_core PUBLIC wolfram cjson PRIVATE SQLite3::SQLite3 Threads::Threads)
target_compile_definitions(metalbear_core PRIVATE
    METALBEAR_VERSION="${PROJECT_VERSION}")

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
# metalbear_core keeps the define PRIVATE, so the executable needs its own copy
# for `--version`.
target_compile_definitions(metalbear PRIVATE
    METALBEAR_VERSION="${PROJECT_VERSION}")

if(METALBEAR_BUILD_TESTS)
    enable_testing()
    add_executable(test_metalbear test/test_server.c)
    target_link_libraries(test_metalbear PRIVATE metalbear_core)
    target_include_directories(test_metalbear PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_server COMMAND test_metalbear)

    add_executable(test_metalbear_auth test/test_auth.c)
    target_link_libraries(test_metalbear_auth PRIVATE metalbear_core)
    add_test(NAME metalbear_auth COMMAND test_metalbear_auth)

    add_executable(test_metalbear_oauth test/test_oauth.c)
    target_link_libraries(test_metalbear_oauth PRIVATE metalbear_core)
    add_test(NAME metalbear_oauth COMMAND test_metalbear_oauth)

    add_executable(test_metalbear_routes test/test_routes.c)
    target_link_libraries(test_metalbear_routes PRIVATE metalbear_core)
    target_include_directories(test_metalbear_routes PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_routes COMMAND test_metalbear_routes)

    add_executable(test_metalbear_registry test/test_registry.c)
    target_link_libraries(test_metalbear_registry PRIVATE metalbear_core)
    add_test(NAME metalbear_registry COMMAND test_metalbear_registry)

    add_executable(test_metalbear_config_file test/test_config_file.c)
    target_link_libraries(test_metalbear_config_file PRIVATE metalbear_core)
    target_include_directories(test_metalbear_config_file PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    # Run from the source tree so the shipped config.example.toml is reachable.
    add_test(NAME metalbear_config_file COMMAND test_metalbear_config_file
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    # Runs the publisher against a stand-in for the Cloudflare API, so the
    # requests it would send to a live zone can be asserted on directly.
    find_path(MICROHTTPD_INCLUDE_DIR NAMES microhttpd.h REQUIRED)
    find_library(MICROHTTPD_LIBRARY NAMES microhttpd REQUIRED)
    add_executable(test_metalbear_handle_dns test/test_handle_dns.c)
    target_link_libraries(test_metalbear_handle_dns PRIVATE metalbear_core
        ${MICROHTTPD_LIBRARY} Threads::Threads)
    target_include_directories(test_metalbear_handle_dns PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}" ${MICROHTTPD_INCLUDE_DIR})
    add_test(NAME metalbear_handle_dns COMMAND test_metalbear_handle_dns)

    add_executable(test_metalbear_handle_dns_rfc2136
        test/test_handle_dns_rfc2136.c)
    target_link_libraries(test_metalbear_handle_dns_rfc2136 PRIVATE
        metalbear_core Threads::Threads)
    target_include_directories(test_metalbear_handle_dns_rfc2136 PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_handle_dns_rfc2136
        COMMAND test_metalbear_handle_dns_rfc2136)

    add_executable(test_metalbear_backup test/test_backup.c)
    target_link_libraries(test_metalbear_backup PRIVATE metalbear_core SQLite3::SQLite3)
    target_include_directories(test_metalbear_backup PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_backup COMMAND test_metalbear_backup)

    add_executable(test_metalbear_multi_account test/test_multi_account.c)
    target_link_libraries(test_metalbear_multi_account PRIVATE metalbear_core
        SQLite3::SQLite3)
    target_include_directories(test_metalbear_multi_account PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_multi_account COMMAND test_metalbear_multi_account)

    add_executable(test_metalbear_takedown test/test_takedown.c)
    target_link_libraries(test_metalbear_takedown PRIVATE metalbear_core
        SQLite3::SQLite3)
    target_include_directories(test_metalbear_takedown PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_takedown COMMAND test_metalbear_takedown)

    add_executable(test_metalbear_repo_store test/test_repo_store.c)
    target_link_libraries(test_metalbear_repo_store PRIVATE metalbear_core)
    target_include_directories(test_metalbear_repo_store PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}" "${WOLFRAM_SOURCE_DIR}/test")
    target_compile_definitions(test_metalbear_repo_store PRIVATE
        METALBEAR_TEST_LEXICON_DIR="${WOLFRAM_SOURCE_DIR}/lexicons")
    add_test(NAME metalbear_repo_store COMMAND test_metalbear_repo_store)

    add_executable(test_metalbear_repo_store_resolver
        test/test_repo_store_resolver.c)
    target_link_libraries(test_metalbear_repo_store_resolver PRIVATE
        metalbear_core)
    target_include_directories(test_metalbear_repo_store_resolver PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}" "${WOLFRAM_SOURCE_DIR}/test")
    add_test(NAME metalbear_repo_store_resolver
        COMMAND test_metalbear_repo_store_resolver)

    add_executable(test_metalbear_metrics test/test_metrics.c)
    target_link_libraries(test_metalbear_metrics PRIVATE metalbear_core)
    add_test(NAME metalbear_metrics COMMAND test_metalbear_metrics)

    add_executable(test_metalbear_blob_store test/test_blob_store.c)
    target_link_libraries(test_metalbear_blob_store PRIVATE metalbear_core)
    target_include_directories(test_metalbear_blob_store PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_blob_store COMMAND test_metalbear_blob_store)
endif()
