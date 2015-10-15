#ifndef NEAT_H
#define NEAT_H

#include <stdint.h>
#include <uv.h>

#ifdef LINUX
    #include "neat_linux.h"
#endif

#include "include/queue.h"

#define MAX_DOMAIN_LENGTH   254

//data is supposed to be used to store any private data pointer
#define NEAT_CTX \
    uv_loop_t *loop; \
    void *data

#define NEAT_INTERNAL_CTX \
    void (*cleanup)(struct neat_ctx *nc); \
    struct neat_src_addrs src_addrs; \
    struct neat_event_cbs* event_cbs; \
    uint8_t src_addr_cnt

//TODO: One drawkback with using LIST from queue.h, is that a callback can only
//be member of one list. Decide if this is critical and improve if needed
LIST_HEAD(neat_event_cbs, neat_event_cb);
LIST_HEAD(neat_src_addrs, neat_addr);

struct neat_resolver;

struct neat_ctx {
    NEAT_CTX;
    //Look, but don't touch. I.e., read-only
    NEAT_INTERNAL_CTX;
    NEAT_INTERNAL_OS;
};

//Set up context
uint8_t neat_init_ctx(struct neat_ctx *nc);

//Start the event loop, currently uses libuv. User wants to start some action
//(like resolve) before this is called
void neat_start_event_loop(struct neat_ctx *nc);

//Free memory used by context
void neat_free_ctx(struct neat_ctx *nc);

LIST_HEAD(neat_resolver_pairs, neat_resolver_src_dst_addr);

//This data structure must be filled out and added using neat_add_event_cb in
//order for an application to register for a callback
//TODO: Fix forward declaration error, so that this can be placed with the rest
//of the callback stuff
struct neat_event_cb {
    //So far we only support one type of callback. p_ptr is data in this
    //cb-struct, data is decided by callback type
    //TODO: Return something else than void? Do we ever want to for example stop
    //processing?
    void (*event_cb)(struct neat_ctx *nc, void *p_ptr, void *data);
    void *data;
    LIST_ENTRY(neat_event_cb) next_cb;
};

//NEAT resolver public data structures/functions
LIST_HEAD(neat_resolver_results, neat_resolver_res);
typedef void (*neat_resolver_handle_t)(struct neat_resolver*, struct neat_resolver_results *, uint8_t);
typedef void (*neat_resolver_cleanup_t)(struct neat_resolver *resolver);

enum neat_resolver_code {
    //Everything is good
    NEAT_RESOLVER_OK = 0,
    //Resolving timed out without result
    NEAT_RESOLVER_TIMEOUT,
    //Signal internal error
    NEAT_RESOLVER_ERROR,
};

//Struct passed to resolver callback, mirrors what we get back from getaddrinfo
struct neat_resolver_res {
    int32_t ai_family;
    int32_t ai_socktype;
    int32_t ai_protocol;
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    struct sockaddr_storage dst_addr;
    socklen_t dst_addr_len;
    LIST_ENTRY(neat_resolver_res) next_res;
};

struct neat_resolver {
    //The resolver will wrap the context, so that we can easily have many
    //resolvers
    struct neat_ctx *nc;

    //Domain name and family to look up
    uint8_t family;
    //Will be set to 1 if we are going to free resolver in idle
    //TODO: Will most likely be changed to a state variable
    uint8_t free_resolver;
    //Flag used to signal if we have resolved name and timeout has switched from
    //total DNS timeout
    uint8_t name_resolved_timeout;
    uint8_t __pad;
    char domain_name[MAX_DOMAIN_LENGTH];

    //The reason we need two of these is that as of now, a neat_event_cb
    //struct can only be part of one list. This is a future optimization, if we
    //decide that it is a problem
    struct neat_event_cb newaddr_cb;
    struct neat_event_cb deladdr_cb;

    //List of all active resolver pairs
    struct neat_resolver_pairs resolver_pairs;
    //Need to defer free until libuv has clean up memory
    struct neat_resolver_pairs resolver_pairs_del;
    uv_idle_t idle_handle;
    uv_timer_t timeout_handle;

    //Result is the resolved addresses, code is one of the neat_resolver_codes.
    //Ownsership of results is transfered to application, so it is the
    //applications responsibility to free memory
    //void (*handle_resolve)(struct neat_resolver*, struct neat_resolver_results *, uint8_t);
    neat_resolver_handle_t handle_resolve;

    //Users must be notified when it is safe to free or reset resolver memory.
    //It has to be done ansync due to libuv cleanup order
    neat_resolver_cleanup_t cleanup;
};


//Intilize resolver. Sets up internal callbacks etc.
//Resolve is required, cleanup is not
uint8_t neat_resolver_init(struct neat_ctx *nc, struct neat_resolver *resolver,
        neat_resolver_handle_t handle_resolve, neat_resolver_cleanup_t cleanup);

//Free resources used by resolver, resolver is invalid after this function is
//called
void neat_resolver_cleanup(struct neat_resolver *resolver);

//Free the list of results
void neat_resolver_free_results(struct neat_resolver_results *results);
//Start to resolve a domain name
//TODO: Add missing parameters compared to normal getaddrinfo
uint8_t neat_getaddrinfo(struct neat_resolver *resolver, uint8_t family,
        const char *service);

//NEAT public callback API
//The different event types that NEAT generate
enum neat_events{
    //A new address has been added to an interface
    NEAT_NEWADDR = 0,
    //An address has been updated (typically ifa_pref or ifa_valid)
    NEAT_UPDATEADDR,
    //An address has been deleted from an interface
    NEAT_DELADDR,
    __NEAT_MAX_EVENT
};
#define NEAT_MAX_EVENT (__NEAT_MAX_EVENT - 1)

//Register/remove a callback from the NEAT callback API
uint8_t neat_add_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb);
uint8_t neat_remove_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb);
#endif
