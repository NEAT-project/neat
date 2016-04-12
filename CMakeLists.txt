#Standard stuff
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(neat)
INCLUDE(CheckIncludeFile)
set(CMAKE_MACOSX_RPATH 1)

# SOURCES + HEADERS
#################################################
list(APPEND neat_HEADERS
    neat.h
    neat_queue.h
    )

LIST(APPEND neat_SOURCES
    neat_core.c
    neat_addr.c
    neat_he.c
    neat_resolver.c
    neat_property_helpers.c
    neat_log.c
    )

# OS DEPENDENT
#################################################
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_HEADERS neat_linux.h)
    LIST(APPEND neat_SOURCES neat_linux.c)
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")

ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_HEADERS neat_bsd.h)
    LIST(APPEND neat_SOURCES neat_bsd.c)
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include")
    SET(CMAKE_LIBRARY_PATH /usr/local/lib)
    INCLUDE_DIRECTORIES("/usr/local/include")

ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_HEADERS neat_bsd.h)
    LIST(APPEND neat_SOURCES neat_bsd.c)
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include" "/usr/local/opt/openssl/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/local/include" "/usr/local/opt/openssl/include")

ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_HEADERS neat_bsd.h)
    LIST(APPEND neat_SOURCES neat_bsd.c)
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")
    SET(CMAKE_LIBRARY_PATH /usr/local/lib)
    SET(CMAKE_REQUIRED_INCLUDES "/usr/pkg/include" "/usr/include")
    INCLUDE_DIRECTORIES("/usr/pkg/include")

ELSE()
    MESSAGE(FATAL_ERROR ${CMAKE_SYSTEM_NAME} " not supported (yet?)")

ENDIF()

# REQUIREMENTS
#################################################
CHECK_INCLUDE_FILE(uv.h HAVE_SYS_UV_H)
FIND_LIBRARY(UV_LIB uv)
MESSAGE(STATUS "UV found: " ${UV_LIB})
IF(NOT HAVE_SYS_UV_H OR NOT UV_LIB)
    message(FATAL_ERROR "uv.h not not found - libuv installed?")
endif()


CHECK_INCLUDE_FILE(ldns/ldns.h HAVE_SYS_LDNS_H)
FIND_LIBRARY(LDNS_LIB ldns)
MESSAGE(STATUS "LDNS found: " ${LDNS_LIB})
IF(NOT HAVE_SYS_LDNS_H OR NOT LDNS_LIB)
    MESSAGE(FATAL_ERROR "ldns/ldns.h not found - libdns installed?")
ENDIF()


IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    FIND_LIBRARY(MNL_LIB mnl)
    CHECK_INCLUDE_FILE(libmnl/libmnl.h HAVE_SYS_LIBMNL_H)
    IF(NOT HAVE_SYS_LIBMNL_H OR NOT MNL_LIB)
        MESSAGE(FATAL_ERROR "libmnl/libmnl.h not found - libmnl installed?")
    ENDIF()
ENDIF()

CHECK_INCLUDE_FILE(netinet/sctp.h HAVE_NETINET_SCTP_H)
IF(HAVE_NETINET_SCTP_H)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_NETINET_SCTP_H")
ENDIF()


# COMPILER FLAGS
#################################################
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1 -Wall -std=gnu99 -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wno-unused-function")


# LIBRARIES
#################################################
LIST(APPEND neat_LIBS
    ${UV_LIB}
    ${LDNS_LIB}
    )

IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    LIST(APPEND neat_LIBS ${MNL_LIB})
ENDIF()

ADD_LIBRARY(neat SHARED ${neat_SOURCES})
ADD_LIBRARY(neat-static STATIC ${neat_SOURCES})

TARGET_LINK_LIBRARIES (neat ${neat_LIBS})

INSTALL(TARGETS neat LIBRARY DESTINATION ${LIB_DIR})
INSTALL(FILES ${neat_HEADERS} DESTINATION ${HDR_DIR})


# SAMPLES FOLDER
#################################################
ADD_SUBDIRECTORY(samples)
