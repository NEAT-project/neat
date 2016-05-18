# TESTS LIST
#################################################
LIST(APPEND neat_programs
    neat_resolver_example.c
    neat_property_api_test.c
)


# BUILD EACH TEST
#################################################
FOREACH (source_file ${neat_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES(${source_file_we} neat)
ENDFOREACH ()
