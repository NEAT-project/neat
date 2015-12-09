
include_directories(..)

# SOURCES, HEADERS, LIBS
#################################################
LIST(APPEND neat_PROGRAMS
    neat_basic.c
    neat_resolver_example.c
    neat_server.c
    )

LIST(APPEND neat_PROGRAMS_LIBS
    neat-static
    uv
    ldns
    mnl
    )


# BUILD EACH SAMPLE
#################################################
FOREACH (source_file ${neat_PROGRAMS})
	GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
	ADD_EXECUTABLE (
		${source_file_we}
		${source_file}
	)

	TARGET_LINK_LIBRARIES (${source_file_we}
		${neat_PROGRAMS_LIBS}
	)

	ADD_TEST (${source_file_we} ${source_file_we})

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O1 -Wall -std=gnu99 -g")
ENDFOREACH ()
