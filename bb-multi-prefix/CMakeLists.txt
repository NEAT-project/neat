#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(neat_multi_prefix_example)

set(CMAKE_C_FLAGS "-O1 -Wall -std=gnu99")

set(SOURCE
    neat_example.c
    neat_core.c
    neat_addr.c)
set(LIBS uv)

if (TARGET_LINUX)
    add_definitions("-DLINUX")
    set(SOURCE ${SOURCE} 
        neat_linux.c)
    set(LIBS ${LIBS} mnl)
else()
    message(FATAL_ERROR "No target OS specified")
endif()

add_executable(neat_multi_prefix_example ${SOURCE})
target_link_libraries(neat_multi_prefix_example ${LIBS})

install(TARGETS neat_multi_prefix_example RUNTIME DESTINATION /usr/bin)
