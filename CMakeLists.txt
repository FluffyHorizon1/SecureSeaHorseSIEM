cmake_minimum_required(VERSION 3.15)
project(SecureSeaHorseSIEM VERSION 1.6.0 LANGUAGES CXX)

# ==============================================================================
# 1. Project Settings
# ==============================================================================
# Require C++17 (Needed for <filesystem>, <shared_mutex>, <regex>)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define source and config directories
set(SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/config")

# ==============================================================================
# 2. Find Dependencies
# ==============================================================================

# --- OpenSSL (Required for both Client and Server) ---
find_package(OpenSSL REQUIRED)

# --- PostgreSQL / LibPQ (Required for Server) ---
# Try finding the vcpkg config first (libpq::libpq), otherwise fall back to standard PostgreSQL
find_package(libpq CONFIG QUIET)
if(libpq_FOUND)
    message(STATUS "Found libpq via vcpkg config")
    set(PG_LIBS libpq::libpq)
else()
    message(STATUS "Searching for system PostgreSQL...")
    find_package(PostgreSQL REQUIRED)
    set(PG_LIBS ${PostgreSQL_LIBRARIES})
    set(PG_INCLUDES ${PostgreSQL_INCLUDE_DIRS})
endif()

# ==============================================================================
# 3. Global Compiler Flags
# ==============================================================================
if(MSVC)
    # Fix for "min/max" macro collisions and unsafe function warnings on Windows
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
    # Standard MSVC warning levels
    add_compile_options(/W3)
else()
    # Standard GCC/Clang warning levels
    add_compile_options(-Wall -Wextra)
endif()

# ==============================================================================
# 4. Target: SeaHorseServer
# ==============================================================================
add_executable(SeaHorseServer
    ${SOURCE_DIR}/server.cpp
    # --- Shared ---
    ${SOURCE_DIR}/crypto_utils.h
    # --- Phase 1: Core Protocol ---
    ${SOURCE_DIR}/server_protocol.h
    # --- Phase 2: Analysis & Persistence ---
    ${SOURCE_DIR}/regex_engine.h
    ${SOURCE_DIR}/alert_engine.h
    ${SOURCE_DIR}/db_layer.h
    # --- Phase 4: Traffic Classification ---
    ${SOURCE_DIR}/traffic_classifier.h
    ${SOURCE_DIR}/baseline_tracker.h
    ${SOURCE_DIR}/mitre_map.h
    # --- Phase 5: Threat Intelligence ---
    ${SOURCE_DIR}/threat_intel.h
    # --- Phase 6: File Integrity Monitoring ---
    ${SOURCE_DIR}/fim_common.h
    ${SOURCE_DIR}/fim_monitor.h
)

# Includes
target_include_directories(SeaHorseServer PRIVATE 
    ${SOURCE_DIR} 
    ${PG_INCLUDES} # Only needed if using standard FindPostgreSQL
)

# Libraries
target_link_libraries(SeaHorseServer PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    ${PG_LIBS}
)

# Windows-specific system libraries for Server
if(WIN32)
    target_link_libraries(SeaHorseServer PRIVATE ws2_32 wsock32)
endif()

# ==============================================================================
# 5. Target: SeaHorseClient
# ==============================================================================
add_executable(SeaHorseClient
    ${SOURCE_DIR}/client.cpp
    # --- Shared ---
    ${SOURCE_DIR}/crypto_utils.h
    # --- Phase 1: Core Protocol ---
    ${SOURCE_DIR}/client_protocol.h
    # --- Phase 6: File Integrity Monitoring ---
    ${SOURCE_DIR}/fim_common.h
    ${SOURCE_DIR}/fim_scanner.h
)

# Includes
target_include_directories(SeaHorseClient PRIVATE ${SOURCE_DIR})

# Libraries
target_link_libraries(SeaHorseClient PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Windows-specific system libraries for Client
# (Requires ws2_32 for sockets, iphlpapi for network info, wevtapi for event logs)
if(WIN32)
    target_link_libraries(SeaHorseClient PRIVATE ws2_32 iphlpapi wevtapi)
endif()

# ==============================================================================
# 6. Post-Build: Copy Config & Data Files
# ==============================================================================
# Config files
file(COPY "${CONFIG_DIR}/server.conf" DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/client.conf" DESTINATION "${CMAKE_BINARY_DIR}")
file(COPY "${CONFIG_DIR}/rules.conf"  DESTINATION "${CMAKE_BINARY_DIR}")

# Phase 5: Threat intelligence feed files
if(EXISTS "${CONFIG_DIR}/feeds")
    file(COPY "${CONFIG_DIR}/feeds" DESTINATION "${CMAKE_BINARY_DIR}")
    message(STATUS "Copied threat intel feeds directory")
endif()

message(STATUS "Build configuration complete. Version ${PROJECT_VERSION}")
