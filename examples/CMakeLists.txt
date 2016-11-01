# PROGRAMS LIST
#################################################
LIST(APPEND neat_programs
    client.c
    client_http_get.c
    client_https_get.c
    server_chargen.c
    server_daytime.c
    server_discard.c
    server_echo.c
    tneat.c
    peer.c
)

LIST(APPEND neat_property_examples
    all.json
    datagrams.json
    default.json
    tcp.json
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
