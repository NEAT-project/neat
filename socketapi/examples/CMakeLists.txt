# PROGRAMS LIST
#################################################
LIST(APPEND neat_socketapi_example_programs
   httpget.cc
   httpserver1.cc
   httpserver2-select.cc
   httpserver2-threads.cc
)


# BUILD EACH PROGRAM
#################################################
FOREACH (source_file ${neat_socketapi_example_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
        safeprint.cc thread.cc mutex.cc
    )
    TARGET_LINK_LIBRARIES(${source_file_we} neat-socketapi neat "${CMAKE_THREAD_LIBS_INIT}")
    INSTALL(TARGETS             ${source_file_we}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            BUNDLE DESTINATION  ${CMAKE_INSTALL_BINDIR})
ENDFOREACH ()
