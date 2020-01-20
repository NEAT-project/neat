CMAKE_MINIMUM_REQUIRED(VERSION 3.0.2)
PROJECT(libneat)

SET(BUILD_MAJOR "1")
SET(BUILD_MINOR "0")
SET(BUILD_PATCH "1")
SET(BUILD_VERSION ${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_PATCH})

include(FindPythonLibs)


#############################################################################
# INSTALLATION_DIRECTORIES
#############################################################################

# See: https://cmake.org/cmake/help/v3.0/module/GNUInstallDirs.html
INCLUDE(GNUInstallDirs)


#############################################################################
# PACKAGING
#############################################################################

SET(CPACK_SOURCE_GENERATOR "TGZ")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME
   "${CMAKE_PROJECT_NAME}-${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_PATCH}")
SET(CPACK_SOURCE_IGNORE_FILES
   "${PROJECT_SOURCE_DIR}/${CMAKE_PROJECT_NAME}-*;${PROJECT_SOURCE_DIR}/${CMAKE_PROJECT_NAME}_*;/build/;/.git/;/CMakeFiles/;CMakeCache.txt$;.cmake$;.tar.gz$;/_CPack_Packages;/Makefile$;~$;/build-deb;/clean-deb;/filter-empty-entries;/make-symbols;/make-ppa;/make-deb;/debian.conf;/make-rpm;/rpm.conf;${CPACK_SOURCE_IGNORE_FILES}")
INCLUDE(CPack)

ADD_CUSTOM_TARGET(dist COMMAND ${CMAKE_MAKE_PROGRAM} clean package_source)

INCLUDE(CheckIncludeFile)
INCLUDE(CheckStructHasMember)
INCLUDE(CheckTypeSize)
INCLUDE(CheckCCompilerFlag)
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


#############################################################################
# OS DEPENDENT
#############################################################################

IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    MESSAGE(${CMAKE_SYSTEM_NAME} " supported")
    ADD_DEFINITIONS("-D_DEFAULT_SOURCE")
    LIST(APPEND neat_headers neat_linux.h)
    LIST(APPEND neat_sources neat_linux.c)

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    MESSAGE(${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_headers neat_bsd.h)
    LIST(APPEND neat_sources neat_bsd.c)
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/local/include")

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    MESSAGE(${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_headers neat_bsd.h)
    LIST(APPEND neat_sources neat_bsd.c)
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include" "/usr/local/opt/openssl/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/local/include" "/usr/local/opt/openssl/include")

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
    MESSAGE(${CMAKE_SYSTEM_NAME} " supported")
    LIST(APPEND neat_headers neat_bsd.h)
    LIST(APPEND neat_sources neat_bsd.c)
    SET(CMAKE_REQUIRED_INCLUDES "/usr/pkg/include" "/usr/include" "/usr/local/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/pkg/include" "/usr/local/include")

ELSE()
    MESSAGE(FATAL_ERROR ${CMAKE_SYSTEM_NAME} " not supported (yet?)")

ENDIF()

FIND_PACKAGE(Threads REQUIRED)


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
    MESSAGE("No build type selected, using DEBUG")
    SET(CMAKE_BUILD_TYPE "DEBUG")
ENDIF()

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
    MESSAGE("USRSCTP found: " ${USRSCTP_LIB})
ENDIF()

OPTION(MPTCP_SUPPORT "Include MPTCP support" 0)
IF (MPTCP_SUPPORT)
    MESSAGE(STATUS "Included MPTCP support")
    ADD_DEFINITIONS(-DMPTCP_SUPPORT)
ENDIF()

OPTION(NEAT_LOG "enable NEAT log module" 1)
IF (NEAT_LOG)
    ADD_DEFINITIONS(-DNEAT_LOG)
ENDIF()

OPTION(STATIC_LOG "Enable logging with nt_log without neat context" 0)
IF (STATIC_LOG)
    ADD_DEFINITIONS(-DSTATIC_LOG)
ENDIF()

OPTION(FLOW_GROUPS "Include support for flow grouping" 0)
IF (FLOW_GROUPS)
    ADD_DEFINITIONS(-DFLOW_GROUPS)
ENDIF()

OPTION(SCTP_MULTISTREAMING "Include support for SCTP multistreaming" 1)
IF (SCTP_MULTISTREAMING)
    ADD_DEFINITIONS(-DSCTP_MULTISTREAMING)
ENDIF()

OPTION(OPENSSL_SUPPORT "Include support for OpenSSL" 1)

OPTION(SOCKET_API "Include the socket API" 1)

OPTION(SWIG_PYTHON "Include SWIG Python bindings" 0)
IF (SWIG_PYTHON)
    FIND_PACKAGE(SWIG REQUIRED)
    INCLUDE(${SWIG_USE_FILE})
    FIND_PACKAGE(PythonLibs 3.7 REQUIRED)
    INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_DIRS})
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

    SET(CMAKE_SWIG_FLAGS "")
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}  -Wno-error=shadow -Wno-error=pedantic")

    SET_SOURCE_FILES_PROPERTIES(neat_swig.i PROPERTIES SWIG_FLAGS "-includeall")
ENDIF()

OPTION(WEBRTC_SUPPORT "Include WebRTC support" 1)

OPTION(SANITIZER_ADDRESS "Compile with address sanitizer" 0)

OPTION(SANITIZER_MEMORY "Compile with memory sanitizer" 0)

IF (SANITIZER_ADDRESS AND SANITIZER_MEMORY)
    MESSAGE(FATAL_ERROR "Can not compile with both sanitizer options")
ENDIF()


# REQUIREMENTS
#################################################
CHECK_INCLUDE_FILE(uv.h HAVE_UV_H)
FIND_LIBRARY(UV_LIB uv)

IF (NOT HAVE_UV_H OR NOT UV_LIB)
    MESSAGE(FATAL_ERROR "uv.h or libuv not found - libuv installed?")
ELSE()
    MESSAGE("UV found: " ${UV_LIB})
ENDIF()

CHECK_INCLUDE_FILE(ldns/ldns.h HAVE_LDNS_H)
FIND_LIBRARY(LDNS_LIB NAMES ldns libldns)
IF (NOT HAVE_LDNS_H OR NOT LDNS_LIB)
    MESSAGE(FATAL_ERROR "ldns/ldns.h or libuv not found - libldns installed?")
ELSE()
    MESSAGE("LDNS found: " ${LDNS_LIB})
ENDIF()

IF (OPENSSL_SUPPORT)
    FIND_PACKAGE(OpenSSL)
    IF (NOT OPENSSL_FOUND)
        MESSAGE(WARNING "openssl >= 1.0.2 required for TLS - none found")
    ELSE()
        MESSAGE("OPENSSL version found: " ${OPENSSL_VERSION})
        IF (OPENSSL_VERSION VERSION_LESS "1.0.2")
            MESSAGE(WARNING "openssl >= 1.0.2 required for TLS")
        ELSE()
            CHECK_INCLUDE_FILE(openssl/ssl.h HAVE_SYS_OPENSSL_H)
            MESSAGE(STATUS "OPENSSL Crypto found: " ${OPENSSL_LIBRARIES})
            ADD_DEFINITIONS(-DNEAT_USETLS)
            SET(CMAKE_EXTRA_INCLUDE_FILES "openssl/ssl.h")

            IF ((OPENSSL_VERSION VERSION_EQUAL "1.1.0") OR (OPENSSL_VERSION VERSION_GREATER "1.1.0"))
                CHECK_TYPE_SIZE("struct bio_dgram_sctp_sndinfo" OPENSSL_DTLS)
                IF (HAVE_OPENSSL_DTLS)
                    MESSAGE("DTLS for SCTP supported")
                    ADD_DEFINITIONS(-DNEAT_SCTP_DTLS)
                ENDIF()
            ENDIF()
            if (OPENSSL_ROOT_DIR)
                # if a custom dir was set, specify the include path too
                SET(CMAKE_C_FLAGS "-I${OPENSSL_ROOT_DIR}/include")
            ENDIF()
        ENDIF()
    ENDIF()
ENDIF()

IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    FIND_LIBRARY(MNL_LIB mnl)
    CHECK_INCLUDE_FILE(libmnl/libmnl.h HAVE_SYS_LIBMNL_H)
    IF(NOT HAVE_SYS_LIBMNL_H OR NOT MNL_LIB)
        MESSAGE(FATAL_ERROR "libmnl/libmnl.h not found - libmnl installed?")
    ELSE()
        MESSAGE("LIBMNL found: " ${MNL_LIB})
    ENDIF()
    FIND_LIBRARY(SCTP_LIB sctp)
    IF (NOT MPTCP_SUPPORT)
        IF(EXISTS "/proc/sys/net/mptcp/mptcp_enabled")
            MESSAGE(STATUS "MPTCP found")
            ADD_DEFINITIONS(-DMPTCP_SUPPORT)
        ENDIF()
    ENDIF()
ENDIF()

CHECK_INCLUDE_FILE(jansson.h HAVE_JANSSON_H)
FIND_LIBRARY(JANSSON_LIB jansson)
IF (NOT HAVE_JANSSON_H OR NOT JANSSON_LIB)
    MESSAGE(FATAL_ERROR "jansson.h not found - jansson installed?")
ELSE()
    MESSAGE(STATUS "jansson found: " ${JANSSON_LIB})
ENDIF()

IF (WEBRTC_SUPPORT)
    SET(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${RAWRTC_PREFIX}/include)
    SET(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ${RAWRTC_PREFIX}/lib)
    INCLUDE_DIRECTORIES(${INCLUDE_DIRECTORIES} ${RAWRTC_PREFIX}/include)

    CHECK_INCLUDE_FILE(rawrtc.h HAVE_RAWRTC_H)
    FIND_LIBRARY(RAWRTC_LIB rawrtc)

    IF (NOT HAVE_RAWRTC_H OR NOT RAWRTC_LIB)
        MESSAGE(WARNING "rawrtc.h not found - rawrtc installed?")
        SET(WEBRTC_SUPPORT 0)
    ELSE()
        MESSAGE(STATUS "rawrtc found: " ${RAWRTC_LIB})
        ADD_DEFINITIONS(-DWEBRTC_SUPPORT)
        LIST(APPEND neat_sources neat_webrtc.c neat_webrtc_tools.c)
    ENDIF()
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

CHECK_INCLUDE_FILE(sys/epoll.h HAVE_SYS_EPOLL_H)
IF (HAVE_SYS_EPOLL_H)
    ADD_DEFINITIONS(-DHAVE_SYS_EPOLL_H)
ENDIF()

CHECK_INCLUDE_FILE_CXX(RTIMULib.h HAVE_RTIMULIB_H)
IF (HAVE_RTIMULIB_H)
    ADD_DEFINITIONS(-DHAVE_RTIMULIB_H)
ENDIF()

# COMPILER FLAGS
#################################################
# -Wno-array-bounds is unfortunate, but caused by https://bugs.llvm.org/show_bug.cgi?id=20144
SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -g -std=c11   -pedantic -Wall -Wextra -Werror -Wfloat-equal -Wshadow -Wpointer-arith -Wunreachable-code -Winit-self -Wno-unused-function -Wno-unused-parameter -Wno-overlength-strings -Wno-unreachable-code -Wno-array-bounds")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++11 -pedantic -Wall -Wextra -Werror -Wfloat-equal -Wshadow -Wpointer-arith -Wunreachable-code -Winit-self -Wno-unused-function -Wno-unused-parameter -Wno-overlength-strings -Wno-unreachable-code")

CHECK_C_COMPILER_FLAG(-Wfloat-equal HAS_WFLOAT_EQUAL)
IF (HAS_WFLOAT_EQUAL)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wfloat-equal")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wfloat-equal")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wshadow HAS_WSHADOW)
IF (HAS_WSHADOW)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wshadow")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wshadow")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wpointer-arith HAS_WPOINTER_ARITIH)
IF (HAS_WPOINTER_ARITIH)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wpointer-arith")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wpointer-arith")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wunreachable-code HAS_WUNREACHABLE_CODE)
IF (HAS_WUNREACHABLE_CODE)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wunreachable-code")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunreachable-code")
ENDIF()

CHECK_C_COMPILER_FLAG(-Winit-self HAS_WINIT_SELF)
IF (HAS_WINIT_SELF)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Winit-self")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Winit-self")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wno-unused-function HAS_WNO_UNUSED_FUNCTION)
IF (HAS_WNO_UNUSED_FUNCTION)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wno-unused-function")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-function")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wno-unused-parameter HAS_WNO_UNUSED_PARAMETER)
IF (HAS_WNO_UNUSED_PARAMETER)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wno-unused-parameter")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wno-overlength-strings HAS_WNO_OVERLENGTH_STRINGS)
IF (HAS_WNO_OVERLENGTH_STRINGS)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wno-overlength-strings")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-overlength-strings")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wno-unused-command-line-argument HAS_WNO_UNUSED_COMMAND_LINE_ARGUMENT)
IF (HAS_WNO_UNUSED_COMMAND_LINE_ARGUMENT)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wno-unused-command-line-argument")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wno-unreachable-code HAS_WNO_UNREACHABLE_CODE)
IF (HAS_WNO_UNREACHABLE_CODE)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wno-unreachable-code")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unreachable-code")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wno-parentheses-equality HAS_WNO_PARANTHESES_EQUALITY)
IF (HAS_WNO_PARANTHESES_EQUALITY)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wno-parentheses-equality")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-parentheses-equality")
ENDIF()

CHECK_C_COMPILER_FLAG(-Wno-array-bounds HAS_WNO_ARRAY_BOUNDS)
IF (HAS_WNO_ARRAY_BOUNDS)
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wno-array-bounds")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-array-bounds")
ENDIF()

IF (SANITIZER_ADDRESS)
    #SET(CMAKE_BUILD_TYPE "RelWithDebInfo")
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -fsanitize=address -fno-omit-frame-pointer")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
ENDIF()

IF (SANITIZER_MEMORY)
    # maybe add "-fPIE -pie" here
    SET(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -fsanitize=memory -fno-omit-frame-pointer -fsanitize-memory-track-origins")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=memory -fno-omit-frame-pointer -fsanitize-memory-track-origins")
ENDIF()

IF (CMAKE_BUILD_TYPE MATCHES DEBUG)
    MESSAGE(STATUS "Building in DEBUG mode")
    # _FORTIFY_SOURCE requires compiling with optimization
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O")
ENDIF()

# LIBRARIES
#################################################
INCLUDE_DIRECTORIES(.)

LIST(APPEND neat_libs
    ${UV_LIB}
    ${LDNS_LIB}
    ${JANSSON_LIB}
    )

IF (OPENSSL_SUPPORT)
    LIST(APPEND neat_libs
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        )
ENDIF()

IF (WEBRTC_SUPPORT)
    LIST(APPEND neat_libs
        ${RAWRTC_LIB}
    )
ENDIF()

IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    LIST(APPEND neat_libs ${MNL_LIB})
    LIST(APPEND neat_libs ${SCTP_LIB})
ENDIF()

ADD_LIBRARY(neat SHARED ${neat_sources})

SET_TARGET_PROPERTIES(neat PROPERTIES
    VERSION ${BUILD_VERSION}
    SOVERSION ${BUILD_MAJOR}
    )

ADD_LIBRARY(neat-static STATIC ${neat_sources})

TARGET_LINK_LIBRARIES (neat ${neat_libs})

IF (SWIG_PYTHON)
    SWIG_ADD_MODULE(neat python neat_swig.i ${neat_sources})
    SWIG_LINK_LIBRARIES(neat ${neat_libs} ${PYTHON_LIBRARIES})
ENDIF()

# INSTALL
#################################################
MESSAGE("Install directory: ${CMAKE_INSTALL_PREFIX}")

INSTALL(TARGETS neat neat-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL(FILES "neat.h" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


# INCLUDE EXAMPLES AND TESTS FOLDER
#################################################
IF (SOCKET_API)
    ADD_SUBDIRECTORY(socketapi)
ENDIF()
ADD_SUBDIRECTORY(examples)
ADD_SUBDIRECTORY(tests)
