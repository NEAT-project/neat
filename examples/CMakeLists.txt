# PROGRAMS LIST
#################################################
LIST(APPEND neat_programs
    client.c
    client_multi.c
    client_http_get.c
    client_https_get.c
    server_chargen.c
    server_daytime.c
    server_discard.c
    server_echo.c
    server_echo_multi.c
    tneat.c
)


# BUILD EACH PROGRAM
#################################################
FOREACH (source_file ${neat_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES(${source_file_we} neat)
ENDFOREACH ()
