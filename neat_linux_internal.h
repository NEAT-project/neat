#ifndef NEAT_LINUX_INTERNAL
#define NEAT_LINUX_INTERNAL

#include "neat_stat.h"

//lo interface has fixed index 1
#define LO_DEV_IDX 1

struct nlattr;
struct neat_ctx;

struct nlattr_storage {
    const struct nlattr **tb;
    uint32_t limit;
};

//TODO: Do not export this to user 
struct neat_ctx *neat_linux_init_ctx(struct neat_ctx *nic);

/* Get statistics from Linux TCP_INFO */
void linux_get_tcp_info(struct neat_flow * , struct neat_tcp_info *);

#endif
