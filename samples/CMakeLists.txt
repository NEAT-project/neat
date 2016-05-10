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
    server_daytime.c
    server_chargen.c
    server_discard.c
    server_echo.c
    tneat.c
    selftest.c
    )

LIST(APPEND neat_PROGRAMS_LIBS
    neat
    )

IF (USRSCTP_SUPPORT)
    ADD_DEFINITIONS(-DUSRSCTP_SUPPORT)
    LIST(APPEND neat_PROGRAMS_LIBS ${USRSCTP_LIB})
ENDIF()

# BUILD EACH SAMPLE
#################################################
FOREACH (source_file ${neat_PROGRAMS})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES(${source_file_we} ${neat_PROGRAMS_LIBS})
ENDFOREACH ()
