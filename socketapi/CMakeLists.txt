# SOURCES + HEADERS
#################################################
LIST(APPEND neat_socket_headers
   neat-socket.h
)

LIST(APPEND neat_socket_sources
   neat-socket.c
)

# PROGRAMS LIST
#################################################
LIST(APPEND neat_socket_programs
   t1.cc
)

# LIBRARIES
#################################################
ADD_LIBRARY(neat-socket SHARED ${neat_socket_sources})

set_target_properties(neat-socket PROPERTIES
   VERSION ${BUILD_VERSION}
   SOVERSION ${BUILD_MAJOR}
)

ADD_LIBRARY(neat-socket-static STATIC ${neat_socket_sources})

TARGET_LINK_LIBRARIES (neat-socket ${neat_socket_libs})

# BUILD EACH PROGRAM
#################################################
FOREACH (source_file ${neat_socket_programs})
   GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
   ADD_EXECUTABLE (
      ${source_file_we}
      ${source_file}
   )
   TARGET_LINK_LIBRARIES(${source_file_we} neat-socket)
   INSTALL(TARGETS             ${source_file_we}
           RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
           BUNDLE DESTINATION  ${CMAKE_INSTALL_BINDIR})
ENDFOREACH ()
