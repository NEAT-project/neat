CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(neat)

set(BUILD_MAJOR "0")
set(BUILD_MINOR "0")
set(BUILD_VERSION "1")
set(BUILD_VERSION ${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_VERSION})

INCLUDE(CheckIncludeFile)
INCLUDE(CheckStructHasMember)
SET(CMAKE_MACOSX_RPATH 1)

# SOURCES + HEADERS
#################################################
LIST(APPEND neat_headers
    neat.h
    neat_queue.h
)

LIST(APPEND neat_sources
    neat_addr.c
    neat_core.c
    neat_he.c
    neat_log.c
    neat_qos.c
    neat_stat.c
    neat_property_helpers.c
    neat_json_helpers.c
    neat_pvd.c
    neat_resolver.c
    neat_resolver_conf.c
    neat_resolver_helpers.c
    neat_security.c
    neat_pm_socket.c
    neat_unix_json_socket.c
    tls-trust.c
)

# OS DEPENDENT
#################################################
IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    ADD_DEFINITIONS("-D_DEFAULT_SOURCE")
    LIST(APPEND neat_headers neat_linux.h)
    LIST(APPEND neat_sources neat_linux.c)

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_headers neat_bsd.h)
    LIST(APPEND neat_sources neat_bsd.c)
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/local/include")

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_headers neat_bsd.h)
    LIST(APPEND neat_sources neat_bsd.c)
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include" "/usr/local/opt/openssl/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/local/include" "/usr/local/opt/openssl/include")

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_headers neat_bsd.h)
    LIST(APPEND neat_sources neat_bsd.c)
    SET(CMAKE_REQUIRED_INCLUDES "/usr/pkg/include" "/usr/include" "/usr/local/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/pkg/include" "/usr/local/include")

ELSE()
    MESSAGE(FATAL_ERROR ${CMAKE_SYSTEM_NAME} " not supported (yet?)")

ENDIF()

#################################################
# CHECK STRUCT MEMBERS
#################################################
CHECK_STRUCT_HAS_MEMBER("struct sockaddr" "sa_len" "sys/types.h;sys/socket.h" HAVE_SA_LEN)
IF (HAVE_SA_LEN)
    MESSAGE(STATUS "HAVE_SA_LEN")
    ADD_DEFINITIONS(-DHAVE_SA_LEN)
ENDIF()

CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in" "sin_len" "sys/types.h;netinet/in.h" HAVE_SIN_LEN)
IF (HAVE_SIN_LEN)
    MESSAGE(STATUS "HAVE_SIN_LEN")
    ADD_DEFINITIONS(-DHAVE_SIN_LEN)
ENDIF()

CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in6" "sin6_len" "sys/types.h;netinet/in.h" HAVE_SIN6_LEN)
IF (HAVE_SIN6_LEN)
    MESSAGE(STATUS "HAVE_SIN6_LEN")
    ADD_DEFINITIONS(-DHAVE_SIN6_LEN)
ENDIF()

CHECK_STRUCT_HAS_MEMBER("struct sockaddr_storage" "ss_len" "sys/types.h;sys/socket.h" HAVE_SS_LEN)
IF (HAVE_SS_LEN)
    MESSAGE(STATUS "HAVE_SS_LEN")
    ADD_DEFINITIONS(-DHAVE_SS_LEN)
ENDIF()

#################################################
# CHECK OPTIONS
#################################################
# Debug build type as default
IF (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, using DEBUG")
    set(CMAKE_BUILD_TYPE "DEBUG")
endif()

OPTION(USRSCTP_SUPPORT "Include usrsctp support" 0)
IF (USRSCTP_SUPPORT)
    ADD_DEFINITIONS(-DUSRSCTP_SUPPORT)
    ADD_DEFINITIONS(-DINET)
    ADD_DEFINITIONS(-DINET6)
    ADD_DEFINITIONS(-DSCTP_DEBUG)
    LIST(APPEND neat_headers neat_usrsctp.h)
    LIST(APPEND neat_sources neat_usrsctp.c)

    FIND_LIBRARY(USRSCTP_LIB usrsctp)
    LIST(APPEND neat_libs ${USRSCTP_LIB})
    MESSAGE(STATUS "USRSCTP found: " ${USRSCTP_LIB})
ENDIF()

OPTION(NEAT_LOG "enable NEAT log module" 1)
IF (NEAT_LOG)
    ADD_DEFINITIONS(-DNEAT_LOG)
ENDIF()

OPTION(FLOW_GROUPS "Include support for flow grouping" 0)
IF (FLOW_GROUPS)
    ADD_DEFINITIONS(-DFLOW_GROUPS)
ENDIF()

# REQUIREMENTS
#################################################
CHECK_INCLUDE_FILE(uv.h HAVE_SYS_UV_H)
FIND_LIBRARY(UV_LIB uv)
MESSAGE(STATUS "UV found: " ${UV_LIB})
IF (NOT HAVE_SYS_UV_H OR NOT UV_LIB)
    MESSAGE(FATAL_ERROR "uv.h not found - libuv installed?")
ENDIF()

CHECK_INCLUDE_FILE(ldns/ldns.h HAVE_SYS_LDNS_H)
FIND_LIBRARY(LDNS_LIB ldns)
MESSAGE(STATUS "LDNS found: " ${LDNS_LIB})
IF (NOT HAVE_SYS_LDNS_H OR NOT LDNS_LIB)
    MESSAGE(FATAL_ERROR "ldns/ldns.h not found - libdns installed?")
ENDIF()

FIND_PACKAGE(OpenSSL)
IF (NOT OPENSSL_FOUND)
    MESSAGE(STATUS "openssl >= 1.0.2 required for TLS - none found")
ELSE()
    MESSAGE(STATUS "OPENSSL version found: " ${OPENSSL_VERSION})
    IF (OPENSSL_VERSION VERSION_LESS "1.0.2")
        MESSAGE(STATUS "openssl >= 1.0.2 required for TLS")
    ELSE()
        CHECK_INCLUDE_FILE(openssl/ssl.h HAVE_SYS_OPENSSL_H)
        FIND_LIBRARY(OPENSSL_LIB ssl)
        FIND_LIBRARY(OPENSSL_CRYPTO_LIB crypto)
        MESSAGE(STATUS "OPENSSL found: " ${OPENSSL_LIB})
        MESSAGE(STATUS "OPENSSL Crypto found: " ${OPENSSL_CRYPTO_LIB})
        ADD_DEFINITIONS(-DNEAT_USETLS)
    ENDIF()
ENDIF()

IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    FIND_LIBRARY(MNL_LIB mnl)
    CHECK_INCLUDE_FILE(libmnl/libmnl.h HAVE_SYS_LIBMNL_H)
    IF(NOT HAVE_SYS_LIBMNL_H OR NOT MNL_LIB)
        MESSAGE(FATAL_ERROR "libmnl/libmnl.h not found - libmnl installed?")
    ENDIF()
ENDIF()

CHECK_INCLUDE_FILE(jansson.h HAVE_JANSSON_H)
FIND_LIBRARY(JANSSON_LIB jansson)
MESSAGE(STATUS "jansson found: " ${JANSSON_LIB})
IF (NOT HAVE_JANSSON_H OR NOT JANSSON_LIB)
    MESSAGE(FATAL_ERROR "jansson.h not found - jansson installed?")
ENDIF()

CHECK_INCLUDE_FILE(netinet/sctp.h HAVE_NETINET_SCTP_H)
IF (HAVE_NETINET_SCTP_H)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_NETINET_SCTP_H")
    SET(SCTP_INCLUDE "netinet/sctp.h")
ENDIF()

IF (USRSCTP_SUPPORT)
    CHECK_INCLUDE_FILE(usrsctp.h HAVE_USRSCTP_H)
    IF (NOT HAVE_USRSCTP_H)
      MESSAGE(FATAL_ERROR "usrsctp.h not found - usrsctp installed?")
    ENDIF()

    SET(SCTP_INCLUDE "usrsctp.h")

ENDIF()

IF (SCTP_INCLUDE)
    CHECK_STRUCT_HAS_MEMBER("struct sctp_event_subscribe" sctp_association_event ${SCTP_INCLUDE} HAVE_SCTP_EVENT_SUBSCRIBE)
    CHECK_STRUCT_HAS_MEMBER("struct sctp_send_failed_event" ssfe_error ${SCTP_INCLUDE} HAVE_SCTP_SEND_FAILED_EVENT)
ENDIF()

IF (HAVE_SCTP_SEND_FAILED_EVENT)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_SCTP_SEND_FAILED_EVENT")
ENDIF()

IF (USRSCTP_SUPPORT)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_SCTP_SEND_FAILED_EVENT")
ENDIF()

IF (HAVE_SCTP_EVENT_SUBSCRIBE)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_SCTP_EVENT_SUBSCRIBE")
ENDIF()

# COMPILER FLAGS
#################################################
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -Wno-overlength-strings")

IF (CMAKE_BUILD_TYPE MATCHES DEBUG)
    MESSAGE(STATUS "Building in DEBUG mode")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
ENDIF()

# LIBRARIES
#################################################
LIST(APPEND neat_libs
    ${UV_LIB}
    ${LDNS_LIB}
    ${JANSSON_LIB}
    ${OPENSSL_LIB}
    ${OPENSSL_CRYPTO_LIB}
    )

IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    LIST(APPEND neat_libs ${MNL_LIB})
ENDIF()

ADD_LIBRARY(neat SHARED ${neat_sources})

set_target_properties(neat PROPERTIES
    VERSION ${BUILD_VERSION}
    SOVERSION ${BUILD_MAJOR}
    )

ADD_LIBRARY(neat-static STATIC ${neat_sources})

TARGET_LINK_LIBRARIES (neat ${neat_libs})

# INSTALL
#################################################
MESSAGE(STATUS "Install directory: ${CMAKE_INSTALL_PREFIX}")

INSTALL(TARGETS neat LIBRARY DESTINATION lib)
INSTALL(FILES ${neat_headers} DESTINATION include/neat)


# INCLUDE EXAMPLES AND TESTS FOLDER
#################################################
ADD_SUBDIRECTORY(examples)
ADD_SUBDIRECTORY(tests)
