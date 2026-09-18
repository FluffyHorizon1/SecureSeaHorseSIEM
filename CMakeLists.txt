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

if(BUILD_SERVER)
    add_subdirectory(server)
endif()

if(BUILD_CLIENT)
    add_subdirectory(client)
endif()

message(STATUS "SecureSeaHorse superbuild: server=${BUILD_SERVER} client=${BUILD_CLIENT}")
