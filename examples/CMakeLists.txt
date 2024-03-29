# PROGRAMS LIST
#############################################################################
LIST(APPEND neat_programs
    client_dtls_echo.c
    server_dtls_echo.c
    client.c
    client_data.c
    client_http_get.c
    client_http_run_once.c
    server_chargen.c
    server_daytime.c
    server_discard.c
    server_echo.c
    server_http.c
    tneat.c
    peer.c
    msbench.c
    minimal_client.c
    minimal_server.c
    minimal_server2.c

)

LIST(APPEND neat_property_examples
    prop_all.json
    prop_datagram.json
    prop_default.json
    prop_sctp.json
    prop_sctp_delayed.json
    prop_sctp_dtls.json
    prop_sctp_multihomed.json
    prop_tcp.json
    prop_tcp_delayed.json
    prop_tcp_security.json
    prop_streaming_mode.json
    prop_message_mode.json
    webrtcDCExample.sh
)

IF (WEBRTC_SUPPORT)
    LIST(APPEND neat_programs
        peer_webrtc.c
        peer_webrtc_signaling.c
        signaling.c
        webrtcPi.c
        sensehat_test.c
    )
ENDIF()

#### BUILD EACH PROGRAM                                                  ####
#############################################################################
FOREACH (source_file ${neat_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
        util.c
        picohttpparser.c
        webrtc_signaling.c
        gyropi.cpp
    )
    TARGET_LINK_LIBRARIES(${source_file_we} neat)
    IF (HAVE_RTIMULIB_H)
        TARGET_LINK_LIBRARIES(${source_file_we} RTIMULib)
    ENDIF()
    INSTALL(TARGETS             ${source_file_we}
            RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/libneat
            BUNDLE DESTINATION  ${CMAKE_INSTALL_LIBDIR}/libneat)
ENDFOREACH ()


# COPY EXAMPLE PROPERTY FILES
#############################################################################
FOREACH (property_example ${neat_property_examples})
    MESSAGE(STATUS "copy file ${property_example}")
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${property_example} ${CMAKE_CURRENT_BINARY_DIR}/${property_example} COPYONLY)
ENDFOREACH()
