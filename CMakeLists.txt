#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(neat)

set(CMAKE_C_FLAGS "-O1 -Wall -std=gnu99 -g")

set(HEADERS neat.h neat_queue.h)

set(SOURCE
    neat_core.c
    neat_addr.c
    neat_resolver.c)
set(LIBS uv ldns)

if (TARGET_LINUX)
    set(SOURCE ${SOURCE} 
        neat_linux.c)
    set(LIBS ${LIBS} mnl)
    set(HEADERS ${HEADERS} neat_linux.h)
    set(LIB_DIR "/usr/local/lib")
    set(HDR_DIR "/usr/local/include/neat")
else()
    message(FATAL_ERROR "No target OS specified")
endif()

add_library(neat SHARED ${SOURCE})
target_link_libraries(neat ${LIBS})

install(TARGETS neat LIBRARY DESTINATION ${LIB_DIR})
install(FILES ${HEADERS} DESTINATION ${HDR_DIR})
