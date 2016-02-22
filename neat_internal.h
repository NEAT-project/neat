#ifndef NEAT_INTERNAL_H
#define NEAT_INTERNAL_H

#include <stdint.h>
#include <uv.h>

#include "neat_queue.h"
#ifdef __linux__
    #include "neat_linux.h"
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    #include "neat_bsd.h"
#endif

#define NEAT_INTERNAL_CTX \
    void (*cleanup)(struct neat_ctx *nc); \
    struct neat_src_addrs src_addrs; \
    struct neat_event_cbs* event_cbs; \
    uint8_t src_addr_cnt

#define NEAT_MAX_NUM_PROTO 4

struct neat_event_cb;
struct neat_addr;

//TODO: One drawkback with using LIST from queue.h, is that a callback can only
//be member of one list. Decide if this is critical and improve if needed
LIST_HEAD(neat_event_cbs, neat_event_cb);
LIST_HEAD(neat_src_addrs, neat_addr);

struct neat_pib
{ // todo
};

struct neat_cib
{ // todo
};

struct neat_ctx {
    uv_loop_t *loop;
    struct neat_resolver *resolver;
    struct neat_pib pib;
    struct neat_cib cib;
    uv_timer_t addr_lifetime_handle;

    // resolver
    NEAT_INTERNAL_CTX;
    NEAT_INTERNAL_OS;
};

typedef struct neat_ctx neat_ctx ;
typedef neat_error_code (*neat_read_impl)(struct neat_ctx *ctx, struct neat_flow *flow,
                                          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt);
typedef neat_error_code (*neat_write_impl)(struct neat_ctx *ctx, struct neat_flow *flow,
                                           const unsigned char *buffer, uint32_t amt);
typedef int (*neat_accept_impl)(struct neat_ctx *ctx, struct neat_flow *flow, int fd);
typedef int (*neat_connect_impl)(struct neat_ctx *ctx, struct neat_flow *flow);
typedef int (*neat_listen_impl)(struct neat_ctx *ctx, struct neat_flow *flow);
typedef int (*neat_close_impl)(struct neat_ctx *ctx, struct neat_flow *flow);
typedef int (*neat_shutdown_impl)(struct neat_ctx *ctx, struct neat_flow *flow);

struct neat_buffered_message {
    unsigned char *buffered; // memory for write buffers
    size_t bufferedOffset;  // offset of data still to be written
    size_t bufferedSize;    // amount of unwritten data
    size_t bufferedAllocation; // size of buffered allocation
    TAILQ_ENTRY(neat_buffered_message) message_next;
};

TAILQ_HEAD(neat_message_queue_head, neat_buffered_message);

struct neat_flow
{
    int fd;
    struct neat_flow_operations *operations; // see ownedByCore flag
    const char *name;
    const char *port;
    uint64_t propertyMask;
    uint64_t propertyAttempt;
    uint64_t propertyUsed;
    uint8_t family;
    int sockType;
    int sockProtocol;
    struct neat_resolver_results *resolver_results;
    const struct sockaddr *sockAddr; // raw unowned pointer into resolver_results
    struct neat_ctx *ctx; // raw convenience pointer
    uv_poll_t handle;

    size_t writeLimit;  // maximum to write if the socket supports partial writes
    size_t writeSize;   // send buffer size
    // The memory buffer for writing.
    struct neat_message_queue_head bufferedMessages;

    size_t readSize;   // receive buffer size
    // The memory buffer for reading. Used of SCTP reassembly.
    unsigned char *readBuffer;    // memory for read buffer
    size_t readBufferSize;        // amount of received data
    size_t readBufferAllocation;  // size of buffered allocation
    int readBufferMsgComplete;    // it contains a complete user message

    neat_read_impl readfx;
    neat_write_impl writefx;
    neat_accept_impl acceptfx;
    neat_connect_impl connectfx;
    neat_close_impl closefx;
    neat_listen_impl listenfx;
    neat_shutdown_impl shutdownfx;

    int firstWritePending : 1;
    int acceptPending : 1;
    int isPolling : 1;
    int ownedByCore : 1;
    int everConnected : 1;
    int isDraining : 1;
    int isSCTPExplicitEOR : 1;
};

typedef struct neat_flow neat_flow;

//NEAT resolver public data structures/functions
struct neat_resolver;
struct neat_resolver_res;

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
    uint32_t if_idx;
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    struct sockaddr_storage dst_addr;
    socklen_t dst_addr_len;
    uint8_t internal;
    LIST_ENTRY(neat_resolver_res) next_res;
};

// Argument to connect thread during HE.
struct he_thread_arg {
    struct neat_resolver_res *candidate;
    struct neat_flow *flow;
    uv_mutex_t *mutex_first;
    uv_cond_t *cond_first;
    uv_mutex_t *mutex_start;
    uv_cond_t *cond_start;
    int32_t test_val; /* TODO: Remove. */
};


//Intilize resolver. Sets up internal callbacks etc.
//Resolve is required, cleanup is not
struct neat_resolver *neat_resolver_init(struct neat_ctx *nc,
                                         neat_resolver_handle_t handle_resolve,
                                         neat_resolver_cleanup_t cleanup);

//Reset resolver, it is ready for use right after this is called
void neat_resolver_reset(struct neat_resolver *resolver);
//Release all memory occupied by a resolver. Resolver can't be used again
void neat_resolver_release(struct neat_resolver *resolver);

//Free the list of results
void neat_resolver_free_results(struct neat_resolver_results *results);

//Start to resolve a domain name (or literal). Accepts a list of protocols, will
//set socktype based on protocol
uint8_t neat_getaddrinfo(struct neat_resolver *resolver, uint8_t family,
        const char *node, const char *service, int ai_protocol[],
        uint8_t proto_count);

//Update timeouts (in ms) for DNS resolving. T1 is total timeout, T2 is how long
//to wait after first reply from DNS server. Initial values are 30s and 1s.
void neat_resolver_update_timeouts(struct neat_resolver *resolver, uint16_t t1,
        uint16_t t2);

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

struct neat_resolver_src_dst_addr;
LIST_HEAD(neat_resolver_pairs, neat_resolver_src_dst_addr);
#define MAX_DOMAIN_LENGTH   254

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

struct neat_resolver {
    //The resolver will wrap the context, so that we can easily have many
    //resolvers
    struct neat_ctx *nc;
    void *userData1;
    void *userData2;

    //These values are just passed on to neat_resolver_res
    //TODO: Remove this, will be set on result
    int ai_protocol[NEAT_MAX_NUM_PROTO];
    //DNS timeout before any domain has been resolved
    uint16_t dns_t1;
    //DNS timeout after at least one domain has been resolved
    uint16_t dns_t2;
    uint16_t dst_port;
    uint16_t __pad;

    //Domain name and family to look up
    uint8_t family;
    //Will be set to 1 if we are going to free resolver in idle
    //TODO: Will most likely be changed to a state variable
    uint8_t free_resolver;
    //Flag used to signal if we have resolved name and timeout has switched from
    //total DNS timeout
    uint8_t name_resolved_timeout;
    uint8_t __pad2;
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

// for happy eyeballs framework
typedef void (*neat_he_callback_fx)(neat_ctx *ctx,
                                    neat_flow *flow,
                                    neat_error_code code,
                                    uint8_t family, int sockType, int sockProtocol,
                                    int fd); // can be -1

neat_error_code neat_he_lookup(neat_ctx *ctx, neat_flow *flow, neat_he_callback_fx callback_fx);

#endif
