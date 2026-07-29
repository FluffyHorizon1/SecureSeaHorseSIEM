cmake_minimum_required(VERSION 3.15)
project(SeaHorseClient VERSION 5.0.0 LANGUAGES CXX)

# ==============================================================================
# SecureSeaHorse SIEM -- CLIENT AGENT (standalone build)
# Build:  mkdir build && cd build && cmake .. && cmake --build . --config Release
# No PostgreSQL dependency -- the agent only needs OpenSSL.
# ==============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/config")

find_package(OpenSSL REQUIRED)

if(MSVC)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
    add_compile_options(/W3)
else()
    add_compile_options(-Wall -Wextra)
endif()

file(GLOB CLIENT_HEADERS "${SRC}/*.h")
add_executable(SeaHorseClient
    ${SRC}/client.cpp
    ${CLIENT_HEADERS}
)

target_include_directories(SeaHorseClient PRIVATE ${SRC})
target_link_libraries(SeaHorseClient PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(SeaHorseClient PRIVATE ws2_32 iphlpapi wevtapi wtsapi32 psapi)
endif()

file(COPY "${CONFIG_DIR}/client.conf" DESTINATION "${CMAKE_BINARY_DIR}")

message(STATUS "SeaHorseClient configuration complete. Version ${PROJECT_VERSION}")
