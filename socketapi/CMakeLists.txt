# SOURCES + HEADERS
#################################################
LIST(APPEND neat_socketapi_headers
   neat-socketapi.h
)

LIST(APPEND neat_socketapi_sources
   neat-socketapi.c
   neat-socketapi-file.c
   neat-socketapi-internals.c
   neat-socketapi-io.c
   neat-socketapi-poll.c
   identifierbitmap.c
   notificationqueue.c
   eventsignal.c
   redblacktree.c
)

# Define *64() functions
ADD_DEFINITIONS(-D_LARGEFILE64_SOURCE)


# PROGRAMS LIST
#################################################
#LIST(APPEND neat_socketapi_programs
#   t1.cc t2.cc
#)


# LIBRARIES
#################################################
include_directories(.)

ADD_LIBRARY(neat-socketapi SHARED ${neat_socketapi_sources})

set_target_properties(neat-socketapi PROPERTIES
   VERSION ${BUILD_VERSION}
   SOVERSION ${BUILD_MAJOR}
)

ADD_LIBRARY(neat-socketapi-static STATIC ${neat_socketapi_sources})

if(THREADS_HAVE_PTHREAD_ARG)
   TARGET_COMPILE_OPTIONS(PUBLIC neat-socketapi "-pthread")
endif()
TARGET_LINK_LIBRARIES (neat-socketapi neat ${neat_socketapi_libs} "${CMAKE_THREAD_LIBS_INIT}")


# INSTALL
#################################################
MESSAGE(STATUS "Install directory: ${CMAKE_INSTALL_PREFIX}")

INSTALL(TARGETS neat-socketapi neat-socketapi-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL(FILES ${neat_socketapi_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


# BUILD EACH PROGRAM
#################################################
FOREACH (source_file ${neat_socketapi_programs})
   GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
   ADD_EXECUTABLE (
      ${source_file_we}
      ${source_file}
   )
   if(THREADS_HAVE_PTHREAD_ARG)
      TARGET_COMPILE_OPTIONS(PUBLIC ${source_file_we} "-pthread")
   endif()
   TARGET_LINK_LIBRARIES(${source_file_we} neat-socketapi "${CMAKE_THREAD_LIBS_INIT}")
   # INSTALL(TARGETS             ${source_file_we}
   #         RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
   #         BUNDLE DESTINATION  ${CMAKE_INSTALL_BINDIR})
ENDFOREACH ()


# INCLUDE EXAMPLES AND TESTS FOLDER
#################################################
ADD_SUBDIRECTORY(examples)
