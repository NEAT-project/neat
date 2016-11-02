# TESTS LIST
#################################################
LIST(APPEND neat_test_programs
    neat_resolver_example.c
    test_echo.c
    test_close.c
)

LIST(APPEND neat_test_scripts
    run.sh
    test_echo.sh
)

# BUILD EACH TEST
#################################################
FOREACH (source_file ${neat_test_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (${source_file_we} ${source_file})
    TARGET_LINK_LIBRARIES(${source_file_we} neat)
ENDFOREACH()

# COPY TEST SCRIPTS
#################################################
FOREACH (neat_test ${neat_test_scripts})
    MESSAGE(STATUS "copy script ${neat_test}")
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${neat_test} ${CMAKE_CURRENT_BINARY_DIR}/${neat_test} COPYONLY)
ENDFOREACH()
