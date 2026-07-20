cmake_minimum_required(VERSION 3.20)
project(metalbear VERSION 0.1.0 LANGUAGES C)

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

add_library(metalbear_core src/account.c src/account_registry.c src/account_context.c src/auth.c src/backup.c src/email.c src/oauth.c src/oauth_routes.c src/key_rotation.c src/sequencer.c src/server.c)
target_include_directories(metalbear_core PUBLIC include
    PRIVATE "${METALBEAR_CJSON_SOURCE_DIR}")
target_link_libraries(metalbear_core PUBLIC wolfram cjson PRIVATE SQLite3::SQLite3 Threads::Threads)
target_compile_definitions(metalbear_core PRIVATE
    METALBEAR_VERSION="${PROJECT_VERSION}")
target_compile_options(metalbear_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(metalbear src/main.c)
target_link_libraries(metalbear PRIVATE metalbear_core)

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

    add_executable(test_metalbear_backup test/test_backup.c)
    target_link_libraries(test_metalbear_backup PRIVATE metalbear_core SQLite3::SQLite3)
    target_include_directories(test_metalbear_backup PRIVATE
        "${METALBEAR_CJSON_SOURCE_DIR}")
    add_test(NAME metalbear_backup COMMAND test_metalbear_backup)
endif()
