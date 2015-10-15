#ifndef NEAT_MULTI_PREFIX_LINUX_H
#define NEAT_MULTI_PREFIX_LINUX_H

struct mnl_socket;

//Linux internal options, all related to netfilter
#define NEAT_INTERNAL_OS \
    struct mnl_socket *mnl_sock; \
    uv_udp_t uv_nl_handle; \
    char *mnl_rcv_buf

#endif
