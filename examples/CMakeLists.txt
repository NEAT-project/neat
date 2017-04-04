# PROGRAMS LIST
#################################################
LIST(APPEND neat_programs
    client.c
    client_data.c
    client_http_get.c
    client_http_run_once.c
    client_https_get.c
    server_chargen.c
    server_daytime.c
    server_discard.c
    server_echo.c
    server_http.c
    tneat.c
    peer.c
    msbench.c
)

LIST(APPEND neat_property_examples
    prop_all.json
    prop_datagram.json
    prop_default.json
    prop_sctp.json
    prop_sctp_multihomed.json
    prop_tcp.json
    neat.supp
)

# BUILD EACH PROGRAM
#################################################
FOREACH (source_file ${neat_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
        util.c
    )
    TARGET_LINK_LIBRARIES(${source_file_we} neat)
ENDFOREACH ()

# COPY EXAMPLE PROPERTY FILES
#################################################
FOREACH (property_example ${neat_property_examples})
    MESSAGE(STATUS "copy file ${property_example}")
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${property_example} ${CMAKE_CURRENT_BINARY_DIR}/${property_example} COPYONLY)
ENDFOREACH()
