#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(neat)


# OS DEPENDENT
#################################################
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(SOURCE ${SOURCE}
    neat_linux.c)
    set(LIBS ${LIBS} mnl)
    set(HEADERS ${HEADERS} neat_linux.h)
    set(LIB_DIR "/usr/local/lib")
    set(HDR_DIR "/usr/local/include/neat")
else()
    message(FATAL_ERROR ${CMAKE_SYSTEM_NAME} " not supported")
endif()


# COMPILER FLAGS
#################################################
set(CMAKE_C_FLAGS "-O1 -Wall -std=gnu99 -g")


# SOURCES, HEADERS, LIBS
#################################################
LIST(APPEND neat_HEADERS
    neat.h
    neat_queue.h
    )

LIST(APPEND neat_SOURCES
    neat_core.c
    neat_addr.c
    neat_he.c
    neat_resolver.c
    )

LIST(APPEND neat_LIBS
    uv
    ldns
    )


# LIBRARIES
#################################################
add_library(neat SHARED ${neat_SOURCES})
target_link_libraries(neat ${neat_LIBS})

add_library(neat-static STATIC ${neat_SOURCES})

install(TARGETS neat LIBRARY DESTINATION ${LIB_DIR})
install(FILES ${neat_HEADERS} DESTINATION ${HDR_DIR})
