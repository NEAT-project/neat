
INCLUDE_DIRECTORIES(..)

# SOURCES, HEADERS, LIBS
#################################################
LIST(APPEND neat_PROGRAMS
    neat_basic.c
    neat_basic_sctp.c
    neat_http_get.c
    neat_resolver_example.c
    neat_server.c
    client.c
    )

LIST(APPEND neat_PROGRAMS_LIBS
    neat
    ${UV_LIB}
    ${LDNS_LIB}
    )

IF (USRSCTP_SUPPORT)
    add_definitions(-DUSRSCTP_SUPPORT)
    LIST(APPEND neat_PROGRAMS neat_basic_usrsctp.c)
    LIST(APPEND neat_PROGRAMS neat_usrsctp_server.c)
    LIST(APPEND neat_PROGRAMS_LIBS ${USRSCTP_LIB})
ELSE()
    LIST(APPEND neat_PROGRAMS
        server_daytime.c
        server_chargen.c
        server_discard.c
        server_echo.c
        tneat.c
    )
ENDIF()

# OS DEPENDENT
#################################################
IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    LIST(APPEND neat_PROGRAMS_LIBS ${LDNS_LIB})
ENDIF()

# BUILD EACH SAMPLE
#################################################
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -g -Wall -Werror -Wextra -pedantic -Wno-unused-function  -Wno-unused-parameter")


FOREACH (source_file ${neat_PROGRAMS})
    GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES (${source_file_we} ${neat_PROGRAMS_LIBS})
ENDFOREACH ()
