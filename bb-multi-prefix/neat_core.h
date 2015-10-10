#ifndef NEAT_MULTI_PREFIX_H
#define NEAT_MULTI_PREFIX_H

#include "include/queue.h"

#include "neat.h"
#include "neat_addr.h"

#define RETVAL_SUCCESS 0
#define RETVAL_FAILURE 1

enum {
    NEAT_NEWADDR = 0,
    NEAT_UPDATEADDR,
    NEAT_DELADDR,
    __NEAT_MAX_EVENT
};

#define NEAT_MAX_EVENT (__NEAT_MAX_EVENT - 1)

//TODO: Consider better naming for list
//TODO: One drawkback with using LIST from queue.h, is that a callback can only
//be member of one list. Decide if this is critical and improve if needed
LIST_HEAD(neat_event_cbs, neat_event_cb);

//So far, only trust public DNS servers
//TODO: Some firewalls like to block these, implement a platform-independent way of reading from resolv.conf etc.
//TODO: Move to resolve header file when that work starts
static char* const INET_DNS_SERVERS [] = {"8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220"};
static char* const INET6_DNS_SERVERS [] = {"2001:4860:4860::8888", "2001:4860:4860::8844", "2620:0:ccc::2", "2620:0:ccd::2"};

struct neat_resolver;

#define NEAT_INTERNAL_CTX \
    uint8_t (*init)(struct neat_internal_ctx *nc); \
    void (*cleanup)(struct neat_internal_ctx *nc); \
    struct neat_resolver *resolver; \
    struct neat_src_addrs src_addrs; \
    struct neat_event_cbs* event_cbs;

struct neat_internal_ctx {
    NEAT_CTX;
    NEAT_INTERNAL_CTX;
};

//List event
struct neat_event_cb {
    //So far we only support one type of callback. Second argument is decided by
    //callback type
    //TODO: Return something else than void? Do we ever want to for example stop
    //processing?
    void (*event_cb)(struct neat_internal_ctx *nic, void*);
    LIST_ENTRY(neat_event_cb) next_cb;
};

//Register/remove a callback from the internal callback API
uint8_t neat_add_event_cb(struct neat_internal_ctx *nic, uint8_t event_type,
        struct neat_event_cb *cb);
uint8_t neat_remove_event_cb(struct neat_internal_ctx *nic, uint8_t event_type,
        struct neat_event_cb *cb);

//Pass data to all subscribers of event type
void neat_run_event_cb(struct neat_internal_ctx *nic, uint8_t event_type,
        void *data);
#endif
