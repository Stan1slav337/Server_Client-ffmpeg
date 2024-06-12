cmake_minimum_required(VERSION 3.0)
project(App1)

add_compile_options(-Wall -Wextra)

# Attempt to find libmicrohttpd
find_library(LIBMHD NAMES microhttpd)
if(NOT LIBMHD)
    message(FATAL_ERROR "libmicrohttpd not found")
endif()
# Add your executable

add_executable(client client.c)
add_executable(server server.c)
add_executable(client_admin client_admin.c)

find_package(Threads REQUIRED)
target_link_libraries(server PRIVATE Threads::Threads)

# Include directories for targets that need it
include_directories(/usr/include/p11-kit-1) 

# Link the executable to libmicrohttpd
target_link_libraries(server PRIVATE ${LIBMHD})