#ifndef NEAT_MULTI_PREFIX_H
#define NEAT_MULTI_PREFIX_H

#include <uv.h>
#include "include/queue.h"

#include "neat_addr.h"

#define RETVAL_SUCCESS 0
#define RETVAL_FAILURE 1

//So far, only trust public DNS servers
//TODO: Some firewalls like to block these, implement a platform-independent way of reading from resolv.conf etc.
static char* const INET_DNS_SERVERS [] = {"8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220"};
static char* const INET6_DNS_SERVERS [] = {"2001:4860:4860::8888", "2001:4860:4860::8844", "2620:0:ccc::2", "2620:0:ccd::2"};

#define NEAT_CTX \
    uint8_t (*init)(struct neat_ctx *nc); \
    void (*cleanup)(struct neat_ctx *nc); \
    uv_loop_t *loop; \
    struct neat_src_addrs src_addrs

struct neat_ctx {
    NEAT_CTX;
};

struct neat_ctx *neat_alloc_ctx();
void neat_start_event_loop(struct neat_ctx *nc);
void neat_free_ctx(struct neat_ctx *nc);
#endif
