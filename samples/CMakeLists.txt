
include_directories(..)

# SOURCES, HEADERS, LIBS
#################################################
LIST(APPEND neat_PROGRAMS
    neat_basic.c
    neat_basic_sctp.c
    neat_resolver_example.c
    neat_server.c
    client.c
    server_chargen.c
    server_daytime.c
    server_discard_echo.c
    tneat.c
    )

LIST(APPEND neat_PROGRAMS_LIBS
    neat
    ${UV_LIB}
    ${LDNS_LIB}
    )


# OS DEPENDENT
#################################################
IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    LIST(APPEND neat_PROGRAMS_LIBS ${LDNS_LIB})
ENDIF()


# BUILD EACH SAMPLE
#################################################
FOREACH (source_file ${neat_PROGRAMS})
	GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
	ADD_EXECUTABLE (
		${source_file_we}
		${source_file}
	)

	TARGET_LINK_LIBRARIES (${source_file_we} ${neat_PROGRAMS_LIBS})
	#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1 -Wall -std=gnu99 -g")
ENDFOREACH ()
