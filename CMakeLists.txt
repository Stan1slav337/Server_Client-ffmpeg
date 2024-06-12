cmake_minimum_required(VERSION 3.0)
project(App1)

add_compile_options(-Wall -Wextra)

# Add your executable

add_executable(client client.c)
add_executable(server server.c)

find_package(Threads REQUIRED)
target_link_libraries(server PRIVATE Threads::Threads)
