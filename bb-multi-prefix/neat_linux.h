#ifndef NEAT_MULTI_PREFIX_LINUX_H
#define NEAT_MULTI_PREFIX_LINUX_H

#include <uv.h>

struct mnl_socket;

#define NEAT_INTERNAL_OS \
    struct mnl_socket *mnl_sock; \
    uv_udp_t uv_nl_handle; \
    char mnl_rcv_buf[8192]

#endif
