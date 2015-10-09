#ifndef NEAT_MULTI_PREFIX_LINUX_H
#define NEAT_MULTI_PREFIX_LINUX_H

#include <uv.h>

#include "neat_core.h"

//lo interface has fixed index 1
#define LO_DEV_IDX 1

struct mnl_socket;
struct neat_ctx;
struct nlattr;

struct nlattr_storage {
    const struct nlattr **tb;
    uint32_t limit;
};

struct neat_ctx_linux {
    NEAT_CTX;
    struct mnl_socket *mnl_sock;
    uv_udp_t uv_nl_handle;
    //Can't use header constant, as it is a calculation based on page size.
    //Kernel ensures we don't get partial messages in buffer
    //Assum 8192 byte page size for now
    char mnl_rcv_buf[8192];
};

struct neat_ctx_linux *neat_alloc_ctx_linux();

#endif
