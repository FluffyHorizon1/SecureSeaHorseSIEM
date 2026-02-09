cmake_minimum_required(VERSION 3.10)
project(SecureSeaHorse)

set(CMAKE_CXX_STANDARD 17)

# Find OpenSSL (Required)
find_package(OpenSSL REQUIRED)

# --- Server Executable ---
add_executable(server src/server/server.cpp src/server/server_protocol.h)
target_include_directories(server PRIVATE src/server)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)

# Link Windows-specific libraries for Server
if(WIN32)
    target_link_libraries(server ws2_32)
endif()

# --- Client Executable ---
add_executable(client src/client/client.cpp src/client/client_protocol.h)
target_include_directories(client PRIVATE src/client)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)

# Link OS-specific libraries for Client
if(WIN32)
    # ws2_32: Winsock, iphlpapi: Adapters, wevtapi: Event Logs
    target_link_libraries(client ws2_32 iphlpapi wevtapi)
else()
    # pthread is often needed on Linux
    target_link_libraries(client pthread)
endif()
