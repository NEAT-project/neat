#ifndef NEAT_USRSCTP_H
#define NEAT_USRSCTP_H


#define MAXLEN_MBUF_CHAIN 32
// Usrsctp internal information related to SCTP and UDP sockets
#define NEAT_INTERNAL_USRSCTP \
    uv_timer_t usrsctp_timer_handle; \
    int sctp4_fd; \
    int udpsctp4_fd; \
    int sctp6_fd; \
    int udpsctp6_fd; \
    uv_poll_t uv_sctp4_handle; \
    uv_poll_t uv_udpsctp4_handle; \
    uv_poll_t uv_sctp6_handle; \
    uv_poll_t uv_udpsctp6_handle; \
    struct neat_flow *flow;
#endif
