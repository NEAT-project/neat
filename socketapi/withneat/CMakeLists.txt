# SOURCES + HEADERS
#################################################
LIST(APPEND withneat_headers
)

LIST(APPEND withneat_sources
   libwithneat.c
)


# LIBRARIES
#################################################
include_directories(.)

ADD_LIBRARY(withneat SHARED ${withneat_sources})

set_target_properties(withneat PROPERTIES
   VERSION ${BUILD_VERSION}
   SOVERSION ${BUILD_MAJOR}
)

if(THREADS_HAVE_PTHREAD_ARG)
   TARGET_COMPILE_OPTIONS(PUBLIC withneat "-pthread")
endif()
TARGET_LINK_LIBRARIES (withneat neat-socketapi ${withneat_libs} "${CMAKE_THREAD_LIBS_INIT}")


# PROGRAMS
#################################################

SET_SOURCE_FILES_PROPERTIES(run-with-neat PROPERTIES GENERATED 1)

ADD_CUSTOM_TARGET(run-with-neat
  COMMAND sed -e "s:@libdir@:${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}:g" -e "s:@libversion@:${BUILD_VERSION}:g" < ${CMAKE_CURRENT_SOURCE_DIR}/run-with-neat.in > ${CMAKE_CURRENT_SOURCE_DIR}/run-with-neat
  COMMAND chmod +x ${CMAKE_CURRENT_SOURCE_DIR}/run-with-neat
  # DEPENDS run-with-neat.in
  COMMENT "Generating run-with-neat program"
)
ADD_DEPENDENCIES(withneat run-with-neat)

INSTALL(FILES run-with-neat
        DESTINATION ${CMAKE_INSTALL_BINDIR})

# ====== Test only ==============================
ADD_EXECUTABLE(t1 t1.cc)
TARGET_LINK_LIBRARIES(t1)
# ===============================================


# INSTALL
#################################################
MESSAGE(STATUS "Install directory: ${CMAKE_INSTALL_PREFIX}")

INSTALL(TARGETS withneat DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL(FILES ${withneat_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
