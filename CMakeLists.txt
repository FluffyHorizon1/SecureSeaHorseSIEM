cmake_minimum_required(VERSION 3.15)

# =============================================================================
# SecureSeaHorse SIEM -- root superbuild
# -----------------------------------------------------------------------------
# Convenience entry point that configures BOTH programs at once:
#
#     cmake -S . -B build && cmake --build build -j
#
# The server and client remain fully independent projects -- you can still
# build either on its own exactly as the README describes:
#
#     cmake -S server -B server/build && cmake --build server/build
#     cmake -S client -B client/build && cmake --build client/build
#
# This root file only exists so a fresh clone builds in one command and so CI
# has a single configure step. It adds no compile logic of its own.
# =============================================================================
project(SecureSeaHorseSIEM LANGUAGES CXX)

option(BUILD_SERVER "Build the SeaHorse analysis server" ON)
option(BUILD_CLIENT "Build the SeaHorse endpoint agent" ON)
option(BUILD_TESTS  "Build the test suite (Phase 29)" ON)
# Flip on once the remaining -Wall -Wextra warnings are cleared (see docs/ROADMAP_v5.1.md).
# CI passes -DENABLE_WERROR=ON; the default build stays lenient so contributors are not blocked.
option(ENABLE_WERROR "Treat warnings as errors" OFF)

if(ENABLE_WERROR AND NOT MSVC)
    add_compile_options(-Werror)
endif()

if(BUILD_SERVER)
    add_subdirectory(server)
endif()

if(BUILD_CLIENT)
    add_subdirectory(client)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

message(STATUS "SecureSeaHorse superbuild: server=${BUILD_SERVER} client=${BUILD_CLIENT} tests=${BUILD_TESTS} werror=${ENABLE_WERROR}")
