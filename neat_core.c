#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uv.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"
#include "neat_queue.h"
#include "neat_addr.h"
#include "neat_queue.h"

#ifdef __linux__
    #include "neat_linux_internal.h"
#endif
#ifdef __FreeBSD__
    #include "neat_freebsd_internal.h"
#endif

//Intiailize the OS-independent part of the context, and call the OS-dependent
//init function
struct neat_ctx *neat_init_ctx()
{
    struct neat_ctx *nc = calloc(sizeof(struct neat_ctx), 1);
    if (!nc) {
        return NULL;
    }
    nc->loop = malloc(sizeof(uv_loop_t));

    if (nc->loop == NULL) {
        free(nc);
        return NULL;
    }

    uv_loop_init(nc->loop);
    LIST_INIT(&(nc->src_addrs));

    uv_timer_init(nc->loop, &(nc->addr_lifetime_handle));
    nc->addr_lifetime_handle.data = nc;
    uv_timer_start(&(nc->addr_lifetime_handle),
                   neat_addr_lifetime_timeout_cb,
                   1000 * NEAT_ADDRESS_LIFETIME_TIMEOUT,
                   1000 * NEAT_ADDRESS_LIFETIME_TIMEOUT);

#if defined(__linux__)
    return neat_linux_init_ctx(nc);
#elif defined(__FreeBSD__)
    return neat_freebsd_init_ctx(nc);
#else
    uv_loop_close(nc->loop);
    free(nc->loop);
    free(nc);
    return NULL;
#endif
}

//Start the internal NEAT event loop
//TODO: Add support for embedding libuv loops in other event loops
void neat_start_event_loop(struct neat_ctx *nc, neat_run_mode run_mode)
{
    uv_run(nc->loop, (uv_run_mode) run_mode);
    uv_loop_close(nc->loop);
}

void neat_stop_event_loop(struct neat_ctx *nc)
{
    uv_stop(nc->loop);
}

int neat_get_backend_fd(struct neat_ctx *nc)
{
    return uv_backend_fd(nc->loop);
}

static void neat_walk_cb(uv_handle_t *handle, void *arg)
{
    if (!uv_is_closing(handle))
        uv_close(handle, NULL);
}

static void neat_close_loop(struct neat_ctx *nc)
{
    uv_walk(nc->loop, neat_walk_cb, nc);
    //Let all close handles run
    uv_run(nc->loop, UV_RUN_DEFAULT);
    uv_loop_close(nc->loop);
}

static void neat_core_cleanup(struct neat_ctx *nc)
{
    //We need to gracefully clean-up loop resources
    neat_close_loop(nc);
    neat_addr_free_src_list(nc);

    if (nc->cleanup)
        nc->cleanup(nc);
}

//Free any resource used by the context. Loop must be stopped before this is
//called
//TODO: Consider adding callback, like for resolver
void neat_free_ctx(struct neat_ctx *nc)
{
    neat_core_cleanup(nc);

    if (nc->resolver) {
        neat_resolver_release(nc->resolver);
        free(nc->resolver);
    }

    if(nc->event_cbs)
        free(nc->event_cbs);

    free(nc->loop);
    free(nc);
}

//The three functions that deal with the NEAT callback API. Nothing very
//interesting, register a callback, run all callbacks and remove callbacks
uint8_t neat_add_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    uint8_t i = 0;
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr;

    if (event_type > NEAT_MAX_EVENT)
        return RETVAL_FAILURE;

    //Do not initialize callback array before we have to, in case no-one will
    //use the callback API
    if (!nc->event_cbs) {
        nc->event_cbs = calloc(NEAT_MAX_EVENT + 1,
                sizeof(struct neat_event_cbs));

        //TODO: Decide what to do here
        assert(nc->event_cbs != NULL);

        for (i = 0; i < NEAT_MAX_EVENT; i++)
            LIST_INIT(&(nc->event_cbs[i]));
    }

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next) {
  
        if (cb_itr == cb) {
            //TODO: Debug level
            fprintf(stderr, "Callback for %u has already been added\n",
                    event_type); 
            return RETVAL_FAILURE;
        }
    }

    //TODO: Debug level
    fprintf(stderr, "Added new callback for event type %u\n", event_type); 
    LIST_INSERT_HEAD(cb_list_head, cb, next_cb);
    return RETVAL_SUCCESS;
}

uint8_t neat_remove_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr = NULL;

    if (event_type > NEAT_MAX_EVENT ||
        !nc->event_cbs)
        return RETVAL_FAILURE;

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next) {
        if (cb_itr == cb)
            break;
    }

    if (cb_itr) {
        //TODO: Debug level print
        fprintf(stderr, "Removed callback for type %u\n", event_type);
        LIST_REMOVE(cb_itr, next_cb);
    }

    return RETVAL_SUCCESS;
}

void neat_run_event_cb(struct neat_ctx *nc, uint8_t event_type,
        void *data)
{
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr = NULL;

    if (event_type > NEAT_MAX_EVENT ||
        !nc->event_cbs)
        return;

    cb_list_head = &(nc->event_cbs[event_type]);
    
    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next)
        cb_itr->event_cb(nc, cb_itr->data, data);
}

static void free_cb(uv_handle_t *handle)
{
    neat_flow *flow = handle->data;
    flow->closefx(flow->ctx, flow);
    free((char *)flow->name);
    free((char *)flow->port);
    if (flow->resolver_results) {
        neat_resolver_free_results(flow->resolver_results);
    }
    if (flow->ownedByCore) {
        free(flow->operations);
    }
    free(flow);
}

void neat_free_flow(neat_flow *flow)
{
    if (flow->isPolling) {
        uv_poll_stop(&flow->handle);
    }
    uv_close((uv_handle_t *)(&flow->handle), free_cb);
    return;
}

neat_error_code neat_get_property(neat_ctx *mgr, struct neat_flow *flow,
                                  uint64_t *outMask)
{
    *outMask = flow->propertyUsed;
    return NEAT_OK;
}

neat_error_code neat_set_property(neat_ctx *mgr, neat_flow *flow,
                                  uint64_t inMask)
{
    flow->propertyMask = inMask;
    return NEAT_OK;
}

neat_error_code neat_set_operations(neat_ctx *mgr, neat_flow *flow,
                                    struct neat_flow_operations *ops)
{
    flow->operations = ops;
    return NEAT_OK;
}

#define READYCALLBACKSTRUCT \
    flow->operations->status = code;\
    flow->operations->ctx = ctx;\
    flow->operations->flow = flow;

static void io_error(neat_ctx *ctx, neat_flow *flow,
                     neat_error_code code)
{
    if (!flow->operations || !flow->operations->on_error) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_error(flow->operations);
}

static void io_connected(neat_ctx *ctx, neat_flow *flow,
                         neat_error_code code)
{
    if (!flow->operations || !flow->operations->on_connected) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_connected(flow->operations);
}

static void io_writable(neat_ctx *ctx, neat_flow *flow,
                        neat_error_code code)
{
    if (!flow->operations || !flow->operations->on_writable) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_writable(flow->operations);
}

static void io_readable(neat_ctx *ctx, neat_flow *flow,
                        neat_error_code code)
{
    if (!flow->operations || !flow->operations->on_readable) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_readable(flow->operations);
}

static void do_accept(neat_ctx *ctx, neat_flow *flow);
static void uvpollable_cb(uv_poll_t *handle, int status, int events);

static void updatePollHandle(neat_ctx *ctx, neat_flow *flow, uv_poll_t *handle)
{
    if (uv_is_closing((uv_handle_t *)&flow->handle)) {
        return;
    }

    int newEvents = 0;
    if (flow->operations && flow->operations->on_readable) {
        newEvents |= UV_READABLE;
    }
    if (flow->operations && flow->operations->on_writable) {
        newEvents |= UV_WRITABLE;
    }
    if (newEvents) {
        flow->isPolling = 1;
        uv_poll_start(handle, newEvents, uvpollable_cb);
    } else {
        flow->isPolling = 0;
        uv_poll_stop(handle);
    }
}

static void uvpollable_cb(uv_poll_t *handle, int status, int events)
{
    neat_flow *flow = handle->data;
    neat_ctx *ctx = flow->ctx;

    if ((events & UV_READABLE) && flow->acceptPending) {
        do_accept(ctx, flow);
        return;
    }

    // todo check error in status
    if ((events & UV_WRITABLE) && flow->firstWritePending) {
        flow->firstWritePending = 0;
        io_connected(ctx, flow, NEAT_OK);
    }
    if (events & UV_WRITABLE) {
        io_writable(ctx, flow, NEAT_OK);
    }
    if (events & UV_READABLE) {
        io_readable(ctx, flow, NEAT_OK);
    }
    updatePollHandle(ctx, flow, &flow->handle);
}

static void do_accept(neat_ctx *ctx, neat_flow *flow)
{
    neat_flow *newFlow = neat_new_flow(ctx);
    newFlow->name = strdup (flow->name);
    newFlow->port = strdup (flow->port);
    newFlow->propertyMask = flow->propertyMask;
    newFlow->propertyAttempt = flow->propertyAttempt;
    newFlow->propertyUsed = flow->propertyUsed;
    newFlow->everConnected = 1;
    newFlow->family = flow->family;
    newFlow->sockType = flow->sockType;
    newFlow->sockProtocol = flow->sockProtocol;
    newFlow->ctx = ctx;

    newFlow->ownedByCore = 1;
    newFlow->operations = calloc (sizeof(struct neat_flow_operations), 1);
    newFlow->operations->on_connected = flow->operations->on_connected;
    newFlow->operations->on_readable = flow->operations->on_readable;
    newFlow->operations->on_writable = flow->operations->on_writable;
    newFlow->operations->ctx = ctx;
    newFlow->operations->flow = flow;

    newFlow->fd = newFlow->acceptfx(ctx, newFlow, flow->fd);
    if (newFlow->fd == -1) {
        neat_free_flow(newFlow);
    } else {
        uv_poll_init(ctx->loop, &newFlow->handle, newFlow->fd); // makes fd nb as side effect
        newFlow->handle.data = newFlow;
        io_connected(ctx, newFlow, NEAT_OK);
        uvpollable_cb(&newFlow->handle, NEAT_OK, 0);
    }
}

static void
open_he_callback(neat_ctx *ctx, neat_flow *flow,
                 neat_error_code code,
                 uint8_t family, int sockType, int sockProtocol,
                 int fd)
{
    if (code != NEAT_OK) {
        io_error(ctx, flow, code);
        goto cleanup;
    }

    flow->family = family;
    flow->sockType = sockType;
    flow->sockProtocol = sockProtocol;

    if (fd != -1) {
        uv_poll_init(ctx->loop, &flow->handle, fd); // makes fd nb as side effect
        flow->everConnected = 1;
        flow->fd = fd;
    } else {
        // todo when we have sctp
        if (flow->propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) {
            io_error(ctx, flow, NEAT_ERROR_UNABLE);
            goto cleanup;
        }

        if (flow->connectfx(ctx, flow) == -1) {
            io_error(ctx, flow, NEAT_ERROR_IO);
            goto cleanup;
        }
    }

    // todo he needs to consider these properties to do the right thing
    if ((flow->propertyMask & NEAT_PROPERTY_IPV6_BANNED) &&
        (flow->family == AF_INET6)) {
        io_error(ctx, flow, NEAT_ERROR_UNABLE);
        goto cleanup;
    }

    if ((flow->propertyMask & NEAT_PROPERTY_IPV6_REQUIRED) &&
        (flow->family != AF_INET6)) {
        io_error(ctx, flow, NEAT_ERROR_UNABLE);
        goto cleanup;
    }

    // io callbacks take over now
    flow->ctx = ctx;
    flow->handle.data = flow;
    flow->firstWritePending = 1;
    flow->isPolling = 1;
    uv_poll_start(&flow->handle, UV_WRITABLE, uvpollable_cb);

    // security layer todo

cleanup:
    if (flow->resolver_results) {
        neat_resolver_free_results(flow->resolver_results);
        flow->resolver_results = NULL;
    }
    return;
}

neat_error_code
neat_open(neat_ctx *mgr, neat_flow *flow, const char *name, const char *port)
{
    if (flow->name) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    flow->name = strdup(name);
    flow->port = strdup(port);
    flow->propertyAttempt = flow->propertyMask;
    neat_he_lookup(mgr, flow, open_he_callback);

    return NEAT_OK;
}

static void
accept_resolve_cb(struct neat_resolver *resolver, struct neat_resolver_results *results, uint8_t code)
{
    neat_flow *flow = (neat_flow *)resolver->userData1;
    struct neat_ctx *ctx = flow->ctx;

    if (code != NEAT_RESOLVER_OK) {
        io_error(ctx, flow, code);
        return;
    }
    assert (results->lh_first);
    flow->family = results->lh_first->ai_family;
    flow->sockType = results->lh_first->ai_socktype;
    flow->sockProtocol = results->lh_first->ai_protocol;
    flow->resolver_results = results;
    flow->sockAddr = (struct sockaddr *) &(results->lh_first->dst_addr);

    if (flow->listenfx(ctx, flow) == -1) {
        io_error(ctx, flow, NEAT_ERROR_IO);
        return;
    }

    flow->handle.data = flow;
    uv_poll_init(ctx->loop, &flow->handle, flow->fd);

    if (!(flow->propertyMask & NEAT_PROPERTY_MESSAGE)) {
        flow->isPolling = 1;
        flow->acceptPending = 1;
        uv_poll_start(&flow->handle, UV_READABLE, uvpollable_cb);
    } else {
        // do normal i/o events without accept() for non connected protocols
        updatePollHandle(ctx, flow, &flow->handle);
    }
}

neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                            const char *name, const char *port)
{
    if (flow->name) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    if (!strcmp(name, "*")) {
        name = "0.0.0.0";
    }
    flow->name = strdup(name);
    flow->port = strdup(port);
    flow->propertyAttempt = flow->propertyMask;
    flow->ctx = ctx;

    if (!ctx->resolver) {
        ctx->resolver = neat_resolver_init(ctx, accept_resolve_cb, NULL);
    }
    ctx->resolver->userData1 = (void *)flow;
    neat_getaddrinfo(ctx->resolver, AF_INET, flow->name, flow->port,
                     (flow->propertyMask & NEAT_PROPERTY_MESSAGE) ? SOCK_DGRAM : SOCK_STREAM, 0);
    return NEAT_OK;
}

static neat_error_code
neat_write_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow,
                      const unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    *actualAmt = 0;
    ssize_t rv = send(flow->fd, buffer, amt, 0);
    if (rv == -1 && errno == EWOULDBLOCK){
        return NEAT_ERROR_WOULD_BLOCK;
    }

    if (rv >= 0) {
        *actualAmt = rv;
        return NEAT_OK;
    }
    return NEAT_ERROR_IO;
}

static neat_error_code
neat_read_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow,
                     unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    ssize_t rv = recv(flow->fd, buffer, amt, 0);
    if (rv == -1 && errno == EWOULDBLOCK){
        return NEAT_ERROR_WOULD_BLOCK;
    }
    if (rv == -1) {
        return NEAT_ERROR_IO;
    }
    *actualAmt = rv;
    return NEAT_OK;
}

static int
neat_accept_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow, int fd)
{
    return accept(fd, NULL, NULL);
}

static int
neat_connect_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    socklen_t slen =
        (flow->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    flow->fd = socket(flow->family, flow->sockType, flow->sockProtocol);
    uv_poll_init(ctx->loop, &flow->handle, flow->fd); // makes fd nb as side effect
    if ((flow->fd == -1) ||
        (connect(flow->fd, flow->sockAddr, slen) && (errno != EINPROGRESS))) {
        return -1;
    }
    return 0;
}

static int
neat_close_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    if (flow->fd != -1) {
        // we might want a fx callback here to split between
        // kernel and userspace.. same for connect read and write
        close(flow->fd);
    }
    return 0;
}

static int
neat_listen_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    int enable = 1;
    socklen_t slen =
        (flow->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    flow->fd = socket(flow->family, flow->sockType, flow->sockProtocol);
    setsockopt(flow->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));
    setsockopt(flow->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if ((flow->fd == -1) ||
        (bind(flow->fd, flow->sockAddr, slen) == -1) ||
        (listen(flow->fd, 100) == -1)) {
        return -1;
    }
    return 0;
}

neat_error_code
neat_write(struct neat_ctx *ctx, struct neat_flow *flow,
           const unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    return flow->writefx(ctx, flow, buffer, amt, actualAmt);
}

neat_error_code
neat_read(struct neat_ctx *ctx, struct neat_flow *flow,
          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    return flow->readfx(ctx, flow, buffer, amt, actualAmt);
}

neat_flow *neat_new_flow(neat_ctx *mgr)
{
    neat_flow *rv = (neat_flow *)calloc (1, sizeof (neat_flow));

    if (!rv)
        return NULL;

    rv->fd = -1;
    // defaults
    rv->writefx = neat_write_via_kernel;
    rv->readfx = neat_read_via_kernel;
    rv->acceptfx = neat_accept_via_kernel;
    rv->connectfx = neat_connect_via_kernel;
    rv->closefx = neat_close_via_kernel;
    rv->listenfx = neat_listen_via_kernel;
    return rv;
}
