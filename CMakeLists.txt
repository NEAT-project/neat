#Standard stuff
cmake_minimum_required(VERSION 2.6)
project(neat)
include(CheckIncludeFile)



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


# OS DEPENDENT
#################################################
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    message(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_HEADERS neat_linux.h)
    LIST(APPEND neat_SOURCES neat_linux.c)
    LIST(APPEND neat_LIBS mnl)
    set(LIB_DIR "/usr/local/lib")
    set(HDR_DIR "/usr/local/include/neat")
    
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    message(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    set(LIB_DIR "/usr/local/lib")
    set(HDR_DIR "/usr/local/include/neat")
    set(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include")
    include_directories("/usr/local/include")

else()
    message(FATAL_ERROR ${CMAKE_SYSTEM_NAME} " not supported (yet?)")

endif()

# REQUIREMENTS
#################################################
check_include_file(uv.h HAVE_SYS_UV_H)
if(NOT HAVE_SYS_UV_H)
	message(FATAL_ERROR "uv.h not not found - libuv installed?")
endif()

check_include_file(ldns/ldns.h HAVE_SYS_LDNS_H)
if(NOT HAVE_SYS_LDNS_H)
	message(FATAL_ERROR "ldns/ldns.h not found - libdns installed?")
endif()

check_include_file(libmnl/libmnl.h HAVE_SYS_LIBMNL_H)
if(NOT HAVE_SYS_LIBMNL_H AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	message(FATAL_ERROR "libmnl/libmnl.h not found - libmnl installed?")
endif()


# COMPILER FLAGS
#################################################
set(CMAKE_C_FLAGS "-O1 -Wall -std=gnu99 -g")


# LIBRARIES
#################################################
add_library(neat SHARED ${neat_SOURCES})
target_link_libraries(neat ${neat_LIBS})

add_library(neat-static STATIC ${neat_SOURCES})

install(TARGETS neat LIBRARY DESTINATION ${LIB_DIR})
install(FILES ${neat_HEADERS} DESTINATION ${HDR_DIR})


# SAMPLES FOLDER
#################################################
add_subdirectory(samples)
