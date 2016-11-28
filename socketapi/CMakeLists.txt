# SOURCES + HEADERS
#################################################
LIST(APPEND neat_socketapi_headers
   neat-socketapi.h
)

LIST(APPEND neat_socketapi_sources
   neat-socketapi.c
)


# PROGRAMS LIST
#################################################
LIST(APPEND neat_socketapi_programs
   t1.cc
)


# LIBRARIES
#################################################
ADD_LIBRARY(neat-socketapi SHARED ${neat_socketapi_sources})

set_target_properties(neat-socketapi PROPERTIES
   VERSION ${BUILD_VERSION}
   SOVERSION ${BUILD_MAJOR}
)

ADD_LIBRARY(neat-socketapi-static STATIC ${neat_socketapi_sources})

TARGET_LINK_LIBRARIES (neat-socketapi ${neat_socketapi_libs})


# INSTALL
#################################################
MESSAGE(STATUS "Install directory: ${CMAKE_INSTALL_PREFIX}")

INSTALL(TARGETS neat-socketapi LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL(FILES ${neat_socketapi_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/neat)


# BUILD EACH PROGRAM
#################################################
FOREACH (source_file ${neat_socketapi_programs})
   GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
   ADD_EXECUTABLE (
      ${source_file_we}
      ${source_file}
   )
   TARGET_LINK_LIBRARIES(${source_file_we} neat-socketapi)
   INSTALL(TARGETS             ${source_file_we}
           RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
           BUNDLE DESTINATION  ${CMAKE_INSTALL_BINDIR})
ENDFOREACH ()
