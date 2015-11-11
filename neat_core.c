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

#ifdef __linux__
    #include "neat_linux_internal.h"
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
        return NULL;
    }

    uv_loop_init(nc->loop);
    LIST_INIT(&(nc->src_addrs));

#ifdef __linux__
    return neat_linux_init_ctx(nc);
#else
    return NULL;
#endif
}

//Start the internal NEAT event loop
//TODO: Add support for embedding libuv loops in other event loops
void neat_start_event_loop(struct neat_ctx *nc)
{
    uv_run(nc->loop, UV_RUN_DEFAULT);
    uv_loop_close(nc->loop);
}

void neat_stop_event_loop(struct neat_ctx *nc)
{
    uv_stop(nc->loop);
}

//Free any resource used by the context
//TODO: Consider adding callback, like for resolver
void neat_free_ctx(struct neat_ctx *nc)
{
    if (nc->cleanup)
        nc->cleanup(nc);

    if (nc->resolver) {
        neat_resolver_free(nc->resolver);
    }
    if(nc->event_cbs) {
        free (nc->event_cbs);
    }
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
    neat_socket *sock = handle->data;
    sock->closefx(sock->ctx, sock);
    free((char *)sock->name);
    free((char *)sock->port);
    if (sock->resolver_results) {
        neat_resolver_free_results(sock->resolver_results);
    }
    if (sock->ownedByCore) {
        free(sock->operations);
    }
    free(sock);
}

void neat_free_socket(neat_socket *sock)
{
    if (sock->isPolling) {
        uv_poll_stop(&sock->handle);
    }
    uv_close((uv_handle_t *)(&sock->handle), free_cb);
    return;
}

neat_error_code neat_get_property(neat_ctx *mgr, struct neat_socket *socket,
                                  uint64_t *outMask)
{
    *outMask = socket->propertyUsed;
    return NEAT_OK;
}

neat_error_code neat_set_property(neat_ctx *mgr, neat_socket *socket,
                                  uint64_t inMask)
{
    socket->propertyMask = inMask;
    return NEAT_OK;
}

neat_error_code neat_set_operations(neat_ctx *mgr, neat_socket *socket,
                                    struct neat_socket_operations *ops)
{
    socket->operations = ops;
    return NEAT_OK;
}

#define READYCALLBACKSTRUCT \
    sock->operations->status = code;\
    sock->operations->ctx = ctx;\
    sock->operations->sock = sock;

static void io_error(neat_ctx *ctx, neat_socket *sock,
                     neat_error_code code)
{
    if (!sock->operations || !sock->operations->on_error) {
        return;
    }
    READYCALLBACKSTRUCT;
    sock->operations->on_error(sock->operations);
}

static void io_connected(neat_ctx *ctx, neat_socket *sock,
                         neat_error_code code)
{
    if (!sock->operations || !sock->operations->on_connected) {
        return;
    }
    READYCALLBACKSTRUCT;
    sock->operations->on_connected(sock->operations);
}

static void io_writable(neat_ctx *ctx, neat_socket *sock,
                        neat_error_code code)
{
    if (!sock->operations || !sock->operations->on_writable) {
        return;
    }
    READYCALLBACKSTRUCT;
    sock->operations->on_writable(sock->operations);
}

static void io_readable(neat_ctx *ctx, neat_socket *sock,
                        neat_error_code code)
{
    if (!sock->operations || !sock->operations->on_readable) {
        return;
    }
    READYCALLBACKSTRUCT;
    sock->operations->on_readable(sock->operations);
}

static void do_accept(neat_ctx *ctx, neat_socket *sock);
static void uvpollable_cb(uv_poll_t *handle, int status, int events);

static void updatePollHandle(neat_ctx *ctx, neat_socket *sock, uv_poll_t *handle)
{
    if (uv_is_closing((uv_handle_t *)&sock->handle)) {
        return;
    }

    int newEvents = 0;
    if (sock->operations && sock->operations->on_readable) {
        newEvents |= UV_READABLE;
    }
    if (sock->operations && sock->operations->on_writable) {
        newEvents |= UV_WRITABLE;
    }
    if (newEvents) {
        sock->isPolling = 1;
        uv_poll_start(handle, newEvents, uvpollable_cb);
    } else {
        sock->isPolling = 0;
        uv_poll_stop(handle);
    }
}

static void uvpollable_cb(uv_poll_t *handle, int status, int events)
{
    neat_socket *sock = handle->data;
    neat_ctx *ctx = sock->ctx;

    if ((events & UV_READABLE) && sock->acceptPending) {
        do_accept(ctx, sock);
        return;
    }

    // todo check error in status
    if ((events & UV_WRITABLE) && sock->firstWritePending) {
        sock->firstWritePending = 0;
        io_connected(ctx, sock, NEAT_OK);
    }
    if (events & UV_WRITABLE) {
        io_writable(ctx, sock, NEAT_OK);
    }
    if (events & UV_READABLE) {
        io_readable(ctx, sock, NEAT_OK);
    }
    updatePollHandle(ctx, sock, &sock->handle);
}

static void do_accept(neat_ctx *ctx, neat_socket *sock)
{
    neat_socket *newSock = neat_new_socket(ctx);
    newSock->name = strdup (sock->name);
    newSock->port = strdup (sock->port);
    newSock->propertyMask = sock->propertyMask;
    newSock->propertyAttempt = sock->propertyAttempt;
    newSock->propertyUsed = sock->propertyUsed;
    newSock->everConnected = 1;
    newSock->family = sock->family;
    newSock->sockType = sock->sockType;
    newSock->sockProtocol = sock->sockProtocol;
    newSock->ctx = ctx;

    newSock->ownedByCore = 1;
    newSock->operations = calloc (sizeof(struct neat_socket_operations), 1);
    newSock->operations->on_connected = sock->operations->on_connected;
    newSock->operations->on_readable = sock->operations->on_readable;
    newSock->operations->on_writable = sock->operations->on_writable;
    newSock->operations->ctx = ctx;
    newSock->operations->sock = sock;

    newSock->fd = newSock->acceptfx(ctx, newSock, sock->fd);
    if (newSock->fd == -1) {
        neat_free_socket(newSock);
    } else {
        uv_poll_init(ctx->loop, &newSock->handle, newSock->fd); // makes fd nb as side effect
        newSock->handle.data = newSock;
        io_connected(ctx, newSock, NEAT_OK);
        uvpollable_cb(&newSock->handle, NEAT_OK, 0);
    }
}

static void
open_he_callback(neat_ctx *ctx, neat_socket *sock,
                 neat_error_code code,
                 uint8_t family, int sockType, int sockProtocol,
                 int fd)
{
    if (code != NEAT_OK) {
        io_error(ctx, sock, code);
        goto cleanup;
    }

    sock->family = family;
    sock->sockType = sockType;
    sock->sockProtocol = sockProtocol;

    if (fd != -1) {
        uv_poll_init(ctx->loop, &sock->handle, fd); // makes fd nb as side effect
        sock->everConnected = 1;
        sock->fd = fd;
    } else {
        // todo when we have sctp
        if (sock->propertyMask & NEAT_PROPERTY_SCTP_REQUIRED) {
            io_error(ctx, sock, NEAT_ERROR_UNABLE);
            goto cleanup;
        }

        if (sock->connectfx(ctx, sock) == -1) {
            io_error(ctx, sock, NEAT_ERROR_IO);
            goto cleanup;
        }
    }

    // todo he needs to consider these properties to do the right thing
    if ((sock->propertyMask & NEAT_PROPERTY_IPV6_BANNED) &&
        (sock->family == AF_INET6)) {
        io_error(ctx, sock, NEAT_ERROR_UNABLE);
        goto cleanup;
    }

    if ((sock->propertyMask & NEAT_PROPERTY_IPV6_REQUIRED) &&
        (sock->family != AF_INET6)) {
        io_error(ctx, sock, NEAT_ERROR_UNABLE);
        goto cleanup;
    }

    // io callbacks take over now
    sock->ctx = ctx;
    sock->handle.data = sock;
    sock->firstWritePending = 1;
    sock->isPolling = 1;
    uv_poll_start(&sock->handle, UV_WRITABLE, uvpollable_cb);

    // security layer todo

cleanup:
    if (sock->resolver_results) {
        neat_resolver_free_results(sock->resolver_results);
        sock->resolver_results = NULL;
    }
    return;
}

neat_error_code
neat_open(neat_ctx *mgr, neat_socket *sock, const char *name, const char *port)
{
    if (sock->name) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    sock->name = strdup(name);
    sock->port = strdup(port);
    sock->propertyAttempt = sock->propertyMask;
    neat_he_lookup(mgr, sock, open_he_callback);

    return NEAT_OK;
}

static void
accept_resolve_cb(struct neat_resolver *resolver, struct neat_resolver_results *results, uint8_t code)
{
    neat_socket *sock = (neat_socket *)resolver->userData1;
    struct neat_ctx *ctx = sock->ctx;

    if (code != NEAT_RESOLVER_OK) {
        io_error(ctx, sock, code);
        return;
    }
    assert (results->lh_first);
    sock->family = results->lh_first->ai_family;
    sock->sockType = results->lh_first->ai_socktype;
    sock->sockProtocol = results->lh_first->ai_protocol;
    sock->resolver_results = results;
    sock->sockAddr = (struct sockaddr *) &(results->lh_first->dst_addr);

    if (sock->listenfx(ctx, sock) == -1) {
        io_error(ctx, sock, NEAT_ERROR_IO);
        return;
    }

    sock->handle.data = sock;
    uv_poll_init(ctx->loop, &sock->handle, sock->fd);

    if (!(sock->propertyMask & NEAT_PROPERTY_MESSAGE)) {
        sock->isPolling = 1;
        sock->acceptPending = 1;
        uv_poll_start(&sock->handle, UV_READABLE, uvpollable_cb);
    } else {
        // do normal i/o events without accept() for non connected protocols
        updatePollHandle(ctx, sock, &sock->handle);
    }
}

neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_socket *sock,
                            const char *name, const char *port)
{
    if (sock->name) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    if (!strcmp(name, "*")) {
        name = "0.0.0.0";
    }
    sock->name = strdup(name);
    sock->port = strdup(port);
    sock->propertyAttempt = sock->propertyMask;
    sock->ctx = ctx;

    if (!ctx->resolver) {
        ctx->resolver = neat_resolver_init(ctx, accept_resolve_cb, NULL);
    }
    ctx->resolver->userData1 = (void *)sock;
    neat_getaddrinfo(ctx->resolver, AF_INET, sock->name, sock->port,
                     (sock->propertyMask & NEAT_PROPERTY_MESSAGE) ? SOCK_DGRAM : SOCK_STREAM, 0);
    return NEAT_OK;
}

static neat_error_code
neat_write_via_kernel(struct neat_ctx *ctx, struct neat_socket *sock,
                      const unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    *actualAmt = 0;
    ssize_t rv = send(sock->fd, buffer, amt, 0);
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
neat_read_via_kernel(struct neat_ctx *ctx, struct neat_socket *sock,
                     unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    ssize_t rv = recv(sock->fd, buffer, amt, 0);
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
neat_accept_via_kernel(struct neat_ctx *ctx, struct neat_socket *sock, int fd)
{
    return accept(fd, NULL, NULL);
}

static int
neat_connect_via_kernel(struct neat_ctx *ctx, struct neat_socket *sock)
{
    socklen_t slen =
        (sock->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    sock->fd = socket(sock->family, sock->sockType, sock->sockProtocol);
    uv_poll_init(ctx->loop, &sock->handle, sock->fd); // makes fd nb as side effect
    if ((sock->fd == -1) ||
        (connect(sock->fd, sock->sockAddr, slen) && (errno != EINPROGRESS))) {
        return -1;
    }
    return 0;
}

static int
neat_close_via_kernel(struct neat_ctx *ctx, struct neat_socket *sock)
{
    if (sock->fd != -1) {
        // we might want a fx callback here to split between
        // kernel and userspace.. same for connect read and write
        close(sock->fd);
    }
    return 0;
}

static int
neat_listen_via_kernel(struct neat_ctx *ctx, struct neat_socket *sock)
{
    int enable = 1;
    socklen_t slen =
        (sock->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    sock->fd = socket(sock->family, sock->sockType, sock->sockProtocol);
    setsockopt(sock->fd, SOL_TCP, TCP_NODELAY, &enable, sizeof(int));
    setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if ((sock->fd == -1) ||
        (bind(sock->fd, sock->sockAddr, slen) == -1) ||
        (listen(sock->fd, 100) == -1)) {
        return -1;
    }
    return 0;
}

neat_error_code
neat_write(struct neat_ctx *ctx, struct neat_socket *sock,
           const unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    return sock->writefx(ctx, sock, buffer, amt, actualAmt);
}

neat_error_code
neat_read(struct neat_ctx *ctx, struct neat_socket *sock,
          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    return sock->readfx(ctx, sock, buffer, amt, actualAmt);
}

neat_socket *neat_new_socket(neat_ctx *mgr)
{
    neat_socket *rv = (neat_socket *)calloc (1, sizeof (neat_socket));
    if (rv) {
        rv->fd = -1;
    }
    // defaults
    rv->writefx = neat_write_via_kernel;
    rv->readfx = neat_read_via_kernel;
    rv->acceptfx = neat_accept_via_kernel;
    rv->connectfx = neat_connect_via_kernel;
    rv->closefx = neat_close_via_kernel;
    rv->listenfx = neat_listen_via_kernel;
    return rv;
}
