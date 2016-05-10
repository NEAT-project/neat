# SAMPLES LIST
#################################################
LIST(APPEND neat_programs
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


# BUILD EACH SAMPLE
#################################################
FOREACH (source_file ${neat_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES(${source_file_we} neat)
ENDFOREACH ()
