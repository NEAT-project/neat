#ifndef NEAT_H
#define NEAT_H

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef __linux__
    #include "neat_linux.h"
#endif

#include "neat_queue.h"

// this is the public API.. todo organize and explain

struct neat_ctx;

//Set up and allocate context
struct neat_ctx *neat_init_ctx();

//Start the event loop, currently uses libuv. User wants to start some action
//(like resolve) before this is called
void neat_start_event_loop(struct neat_ctx *nc);

//Free memory used by context
void neat_free_ctx(struct neat_ctx *nc);

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
struct neat_resolver;
struct neat_resolver_res;

LIST_HEAD(neat_resolver_results, neat_resolver_res);

// todo - probably not a good api to give the callback function a result set it needs to free
// that tends to create leaks (especially on error paths)
// better to free it for them after the callback returns and provide a clone (or addref) function
// if they want to take ownership explicitly
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
#ifdef __linux__
    uint32_t if_idx;
#endif
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    struct sockaddr_storage dst_addr;
    socklen_t dst_addr_len;
    uint8_t internal;
    LIST_ENTRY(neat_resolver_res) next_res;
};


//Intilize resolver. Sets up internal callbacks etc.
//Resolve is required, cleanup is not
struct neat_resolver *neat_resolver_init(struct neat_ctx *nc,
                                         neat_resolver_handle_t handle_resolve,
                                         neat_resolver_cleanup_t cleanup);

//Reset resolver, it is ready for use right after this is called
void neat_resolver_reset(struct neat_resolver *resolver);
//Free resolver, resolver can't be used again
void neat_resolver_free(struct neat_resolver *resolver);

//Free the list of results
void neat_resolver_free_results(struct neat_resolver_results *results);
//Start to resolve a domain name. Only supports domain names as node and ports
//as service
uint8_t neat_getaddrinfo(struct neat_resolver *resolver, uint8_t family,
        const char *node, const char *service, int ai_socktype, int ai_protocol);

//Update timeouts (in ms) for DNS resolving. T1 is total timeout, T2 is how long
//to wait after first reply from DNS server. Initial values are 30s and 1s.
void neat_resolver_update_timeouts(struct neat_resolver *resolver, uint16_t t1,
        uint16_t t2);

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
