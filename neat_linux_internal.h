#ifndef NEAT_LINUX_INTERNAL
#define NEAT_LINUX_INTERNAL

#include "neat_stat.h"

//lo interface has fixed index 1
#define LO_DEV_IDX 1

#if defined(MPTCP_SUPPORT) && !defined(MPTCP_ENABLED)
#define MPTCP_ENABLED 42
#endif

struct nlattr;
struct neat_ctx;

struct nlattr_storage {
    const struct nlattr **tb;
    uint32_t limit;
};

struct neat_ctx *nt_linux_init_ctx(struct neat_ctx *nic);

/* Get statistics from Linux TCP_INFO */
int linux_get_tcp_info(struct neat_flow * , struct neat_tcp_info *);

#endif
