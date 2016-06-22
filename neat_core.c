#include <sys/types.h>
#include <netinet/in.h>
#if defined(HAVE_NETINET_SCTP_H) && !defined(USRSCTP_SUPPORT)
#include <netinet/sctp.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uv.h>
#include <errno.h>

#ifdef __linux__
    #include <net/if.h>
#ifndef USRSCTP_SUPPORT
    #include <sys/socket.h>
#endif // USRSCTP_SUPPORT
#endif // __linux__

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"
#include "neat_queue.h"
#include "neat_addr.h"
#include "neat_queue.h"
#include "neat_property_helpers.h"
#include "neat_stat.h"

#if defined(USRSCTP_SUPPORT)
    #include "neat_usrsctp_internal.h"
    #include <usrsctp.h>
#endif
#ifdef __linux__
    #include "neat_linux_internal.h"
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    #include "neat_bsd_internal.h"
#endif

static void updatePollHandle(neat_ctx *ctx, neat_flow *flow, uv_poll_t *handle);
static void free_send_buffers(neat_ctx *ctx, neat_flow *flow);
static neat_error_code neat_write_flush(struct neat_ctx *ctx, struct neat_flow *flow, int stream_id);
static int neat_listen_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow);
static int neat_close_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow);
static int neat_close_via_kernel_2(int fd);
#if defined(USRSCTP_SUPPORT)
static int neat_connect_via_usrsctp(struct he_cb_ctx *he_ctx);
static int neat_listen_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow);
static int neat_close_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow);
static int neat_shutdown_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow);
static void handle_upcall(struct socket *s, void *arg, int flags);
static void neat_sctp_init_events(struct socket *sock);
#else
static void neat_sctp_init_events(int sock);
#endif

//Intiailize the OS-independent part of the context, and call the OS-dependent
//init function
struct neat_ctx *neat_init_ctx()
{
    struct neat_ctx *nc;
    neat_log_init();
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    nc = calloc(sizeof(struct neat_ctx), 1);

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

#if defined(USRSCTP_SUPPORT)
    neat_usrsctp_init_ctx(nc);
#endif
#if defined(__linux__)
    return neat_linux_init_ctx(nc);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    return neat_bsd_init_ctx(nc);
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
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    uv_run(nc->loop, (uv_run_mode) run_mode);
    uv_loop_close(nc->loop);
}

void neat_stop_event_loop(struct neat_ctx *nc)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    uv_stop(nc->loop);
}

int neat_get_backend_fd(struct neat_ctx *nc)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    return uv_backend_fd(nc->loop);
}

static void neat_walk_cb(uv_handle_t *handle, void *arg)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!uv_is_closing(handle))
        uv_close(handle, NULL);
}

static void neat_close_loop(struct neat_ctx *nc)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    uv_walk(nc->loop, neat_walk_cb, nc);
    //Let all close handles run
    uv_run(nc->loop, UV_RUN_DEFAULT);
    uv_loop_close(nc->loop);
}

static void neat_core_cleanup(struct neat_ctx *nc)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

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
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_core_cleanup(nc);

    if (nc->resolver) {
        neat_resolver_release(nc->resolver);
        free(nc->resolver);
    }

    if(nc->event_cbs)
        free(nc->event_cbs);

    free(nc->loop);
    free(nc);
    neat_log_close();
}

//The three functions that deal with the NEAT callback API. Nothing very
//interesting, register a callback, run all callbacks and remove callbacks
uint8_t neat_add_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    uint8_t i = 0;
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

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
            neat_log(NEAT_LOG_INFO, "%s - Callback for %u has already been added", __func__, event_type);
            return RETVAL_FAILURE;
        }
    }

    //TODO: Debug level
    neat_log(NEAT_LOG_INFO, "%s - Added new callback for event type %u", __func__, event_type);
    LIST_INSERT_HEAD(cb_list_head, cb, next_cb);
    return RETVAL_SUCCESS;
}

uint8_t neat_remove_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    struct neat_event_cbs *cb_list_head = NULL;
    struct neat_event_cb *cb_itr = NULL;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

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
        neat_log(NEAT_LOG_INFO, "%s - Removed callback for type %u", __func__, event_type);
        LIST_REMOVE(cb_itr, next_cb);
    }

    return RETVAL_SUCCESS;
}

void neat_run_event_cb(struct neat_ctx *nc, uint8_t event_type,
        void *data)
{
    struct neat_event_cbs *cb_list_head = NULL;
    struct neat_event_cb *cb_itr = NULL;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (event_type > NEAT_MAX_EVENT ||
        !nc->event_cbs)
        return;

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next)
        cb_itr->event_cb(nc, cb_itr->data, data);
}

static void free_he_handle_cb(uv_handle_t *handle);

static void free_cb(uv_handle_t *handle)
{
    neat_flow *flow = handle->data;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    flow->closefx(flow->ctx, flow);
    free((char *)flow->name);
    if (flow->resolver_results) {
        neat_resolver_free_results(flow->resolver_results);
    }
    if (flow->ownedByCore) {
        free(flow->operations);
    }

    free_send_buffers(flow->ctx, flow);

    // Make sure any still active HE connection attempts are
    // properly terminated and pertaining memory released
    int count = 0;
    while(!LIST_EMPTY(&(flow->he_cb_ctx_list))) {
        count++;
        struct he_cb_ctx *e = LIST_FIRST(&(flow->he_cb_ctx_list));
        LIST_REMOVE(e, next_he_ctx);
        free(e->handle);
        free(e);
    }

    free(flow->readBuffer);
    free(flow->handle);
    free(flow);
}

#if defined(USRSCTP_SUPPORT)
void usrsctp_free(neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    flow->closefx(flow->ctx, flow);
    free((char *)flow->name);
    if (flow->resolver_results) {
        neat_resolver_free_results(flow->resolver_results);
    }
    if (flow->ownedByCore) {
        free(flow->operations);
    }
    free_send_buffers(flow->ctx, flow);
    free(flow->handle);
    free(flow);
}
#endif

static int neat_close_socket(struct neat_ctx *ctx, struct neat_flow *flow)
{
#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
        neat_close_via_usrsctp(flow->ctx, flow);
        return 0;
    }
#endif
    neat_close_via_kernel(flow->ctx, flow);
    return 0;
}

static int neat_close_socket_2(int fd)
{
    /* TODO: Needs fix to work with usrsctp? */
    neat_close_via_kernel_2(fd);
    return 0;
}

void neat_free_flow(neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
       usrsctp_free(flow);
        return;
    }
#endif
    if (flow->isPolling)
        uv_poll_stop(flow->handle);

    if ((flow->handle != NULL) &&
        (flow->handle->type != UV_UNKNOWN_HANDLE))
        uv_close((uv_handle_t *)(flow->handle), free_cb);
}

neat_error_code neat_get_property(neat_ctx *mgr, struct neat_flow *flow,
                                  uint64_t *outMask)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    *outMask = flow->propertyUsed;
    return NEAT_OK;
}

neat_error_code neat_set_property(neat_ctx *mgr, neat_flow *flow,
                                  uint64_t inMask)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    flow->propertyMask = inMask;
    return NEAT_OK;
}

int neat_get_stack(neat_ctx* mgr, neat_flow* flow)
{
    return flow->sockStack;
}

neat_error_code neat_set_operations(neat_ctx *mgr, neat_flow *flow,
                                    struct neat_flow_operations *ops)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    flow->operations = ops;
#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP)
        return NEAT_OK;
#endif
    updatePollHandle(mgr, flow, flow->handle);
    return NEAT_OK;
}

/* Return statistics about the flow in JSON format
   NB - the memory allocated for the return string must be freed
   by the caller */
neat_error_code neat_get_stats(neat_flow *flow, char **json_stats)
{
      neat_log(NEAT_LOG_DEBUG, "%s", __func__);

      neat_stats_build_json(flow, json_stats);

      return NEAT_OK;
}

#define READYCALLBACKSTRUCT \
    flow->operations->status = code;\
    flow->operations->stream_id = stream_id;\
    flow->operations->ctx = ctx;\
    flow->operations->flow = flow;

void io_error(neat_ctx *ctx, neat_flow *flow, int stream_id,
                     neat_error_code code)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_error) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_error(flow->operations);
}

static void io_connected(neat_ctx *ctx, neat_flow *flow,
                         neat_error_code code)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    const int stream_id = NEAT_INVALID_STREAM;

#ifdef NEAT_LOG
    char proto[16];

    switch (flow->sockStack) {
        case NEAT_STACK_UDP:
            snprintf(proto, 16, "UDP");
            break;
        case NEAT_STACK_TCP:
            snprintf(proto, 16, "TCP");
            break;
        case NEAT_STACK_SCTP:
            snprintf(proto, 16, "SCTP");
            break;
        case NEAT_STACK_UDPLITE:
            snprintf(proto, 16, "UDPLite");
            break;
        default:
            snprintf(proto, 16, "stack%d", flow->sockStack);
            break;
    }

    neat_log(NEAT_LOG_INFO, "Connected: %s/%s", proto, (flow->family == AF_INET ? "IPv4" : "IPv6" ));
#endif // NEAT_LOG


    if (!flow->operations || !flow->operations->on_connected) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_connected(flow->operations);
}

static void io_writable(neat_ctx *ctx, neat_flow *flow, int stream_id,
                        neat_error_code code)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->isDraining[stream_id]) {
        neat_write_flush(ctx, flow, stream_id);
    }
    if (!flow->operations || !flow->operations->on_writable || flow->isDraining[stream_id]) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_writable(flow->operations);
}

// Translate SCTP cause codes (RFC4960 sect.3.3.10)
// into NEAT error codes
static neat_error_code sctp_to_neat_code(uint16_t sctp_code)
{
    neat_error_code outcode;

    // TODO: this translation table is not very good,
    // should probably improve on it, add more NEAT codes
    switch (sctp_code) {
    case NEAT_SCTP_CAUSE_INVALID_STREAM:
    case NEAT_SCTP_CAUSE_UNRESOLVABLE_ADDR:
    case NEAT_SCTP_CAUSE_UNRECOG_CHUNK:
    case NEAT_SCTP_CAUSE_INVALID_PARAM:
    case NEAT_SCTP_CAUSE_UNRECOG_PARAM:
    case NEAT_SCTP_CAUSE_NO_USER_DATA:
    case NEAT_SCTP_CAUSE_MISSING_PARAM:
    case NEAT_SCTP_CAUSE_STALE_COOKIE:
	outcode = NEAT_ERROR_BAD_ARGUMENT;
	break;
    case NEAT_SCTP_CAUSE_OUT_OF_RESC:
	outcode = NEAT_ERROR_IO;
	break;
    case NEAT_SCTP_CAUSE_COOKIE_IN_SHUTDOWN:
    case NEAT_SCTP_CAUSE_PROTOCOL_VIOLATION:
    case NEAT_SCTP_CAUSE_RESTART_W_NEWADDR:
	outcode = NEAT_ERROR_INTERNAL;
	break;
    case NEAT_SCTP_CAUSE_USER_INITIATED_ABT:
	outcode = NEAT_ERROR_REMOTE;
	break;
    default:
	outcode = NEAT_ERROR_INTERNAL;
    }

    return outcode;
}

#if defined(HAVE_NETINET_SCTP_H) || defined(USRSCTP_SUPPORT)

// Handle SCTP association change events
// includes shutdown complete, etc.
static void handle_sctp_assoc_change(neat_flow *flow, struct sctp_assoc_change *sac)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    switch (sac->sac_state) {
    case SCTP_SHUTDOWN_COMP:
	neat_notify_close(flow);
	break;
    case SCTP_COMM_LOST:
	// Draft specifies to return cause code, D1.2 doesn't - we
	// follow D1.2
	neat_notify_aborted(flow);
	// Fallthrough:
    case SCTP_COMM_UP: // Fallthrough:
    case SCTP_RESTART:
	// TODO: might want to "translate" the state codes to a NEAT code.
	neat_notify_network_status_changed(flow, sac->sac_state);
	break;
    }
}

// Handle SCTP send failed event
// One is generated per failed message
// Only FreeBSD and USRSCTP support the new RFC6458 API so far,
// hence the ifdefs
#ifdef HAVE_SCTP_SEND_FAILED_EVENT
static void handle_sctp_send_failed(neat_flow *flow, struct sctp_send_failed_event *ssfe)
#else
static void handle_sctp_send_failed(neat_flow *flow, struct sctp_send_failed *ssf)
#endif
{
    uint32_t error, context;
    uint8_t *unsent_msg;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#ifdef HAVE_SCTP_SEND_FAILED_EVENT
    error = ssfe->ssfe_error;
    unsent_msg = ssfe->ssfe_data;
    context = ssfe->ssfe_info.snd_context;
#else
    error = ssf->ssf_error;
    unsent_msg = ssf->ssf_data;
    context = ssf->ssf_info.sinfo_context;
#endif

    // TODO: context no. needs to be implemneted in the write functions!

    neat_notify_send_failure(flow, sctp_to_neat_code(error), context, unsent_msg);
}

// Handle notifications about SCTP events
static void handle_sctp_event(neat_flow *flow, union sctp_notification *notfn)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    switch (notfn->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE:
	handle_sctp_assoc_change(flow, &notfn->sn_assoc_change);
	break;
#ifdef HAVE_SCTP_SEND_FAILED_EVENT
    // RFC6458 API is not defined on all platforms
    case SCTP_SEND_FAILED_EVENT:
	handle_sctp_send_failed(flow, &notfn->sn_send_failed_event);
	break;
#else
    case SCTP_SEND_FAILED:
	handle_sctp_send_failed(flow, &notfn->sn_send_failed);
	break;
#endif // else HAVE_SCTP_SEND_FAILED_EVENT
    case SCTP_PEER_ADDR_CHANGE:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP peer address change event\n");
	break;
    case SCTP_REMOTE_ERROR:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP remote error event\n");
	break;
    case SCTP_SHUTDOWN_EVENT:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP shutdown event\n");
	break;
    case SCTP_ADAPTATION_INDICATION:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP adaption indication event\n");
	break;
    case SCTP_PARTIAL_DELIVERY_EVENT:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP partial delivery event\n");
	break;
    default:
	neat_log(NEAT_LOG_WARNING, "Got unhandled SCTP event type %d",
		 notfn->sn_header.sn_type);
    }
}
#endif // defined(HAVE_NETINET_SCTP_H) || defined(USRSCTP_SUPPORT)


#define READ_OK 0
#define READ_WITH_ERROR 1
#define READ_WITH_ZERO 2

static int io_readable(neat_ctx *ctx, neat_flow *flow,
                        neat_error_code code)
{
    int stream_id = NEAT_INVALID_STREAM;
    ssize_t n, spaceFree;
    ssize_t spaceNeeded, spaceThreshold;
    //Not used when notifications aren't available:
    int flags __attribute__((unused));
#if !defined(USRSCTP_SUPPORT)
    struct msghdr msghdr;
    struct iovec iov;
#else
    struct sockaddr_in addr;
    socklen_t len;
    unsigned int infotype;
    struct sctp_recvv_rn rn;
    socklen_t infolen = sizeof(struct sctp_recvv_rn);
#endif // else !defined(USRSCTP_SUPPORT)

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_readable) {
        return READ_WITH_ERROR;
    }
    if ((neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) &&
        (!flow->readBufferMsgComplete)) {
        spaceFree = flow->readBufferAllocation - flow->readBufferSize;
        if (flow->readSize > 0) {
            spaceThreshold = (flow->readSize / 4 + 8191) & ~8191;
        } else {
            spaceThreshold = 8192;
        }
        if (spaceFree < spaceThreshold) {
            if (flow->readBufferAllocation == 0) {
                spaceNeeded = spaceThreshold;
            } else {
                spaceNeeded = 2 * flow->readBufferAllocation;
            }
            flow->readBuffer = realloc(flow->readBuffer, spaceNeeded);
            if (flow->readBuffer == NULL) {
                flow->readBufferAllocation = 0;
                return READ_WITH_ERROR;
            }
            flow->readBufferAllocation = spaceNeeded;
        }
#if !defined(USRSCTP_SUPPORT)
        iov.iov_base = flow->readBuffer + flow->readBufferSize;
        iov.iov_len = flow->readBufferAllocation - flow->readBufferSize;
        msghdr.msg_name = NULL;
        msghdr.msg_namelen = 0;
        msghdr.msg_iov = &iov;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = NULL;
        msghdr.msg_controllen = 0;
        msghdr.msg_flags = 0;
        if ((n = recvmsg(flow->fd, &msghdr, 0)) < 0) {
            return READ_WITH_ERROR;
        }

	flags = msghdr.msg_flags; // For notification handling
#else // !defined(USRSCTP_SUPPORT)
        len = sizeof(struct sockaddr);
        memset((void *)&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	addr.sin_family = AF_INET;

        n = usrsctp_recvv(flow->sock, flow->readBuffer + flow->readBufferSize,
                               flow->readBufferAllocation - flow->readBufferSize,
                               (struct sockaddr *) &addr, &len, (void *)&rn,
                                &infolen, &infotype, &flags);
        if (n < 0) {
            return READ_WITH_ERROR;
        }
#endif // else !defined(USRSCTP_SUPPORT)
        // Same handling for both kernel and userspace SCTP
#if defined(MSG_NOTIFICATION)
	if (flags & MSG_NOTIFICATION) {
	    // Event notification
	    neat_log(NEAT_LOG_INFO, "SCTP event notification");

	    if (!(flags & MSG_EOR)) {
		neat_log(NEAT_LOG_WARNING, "buffer overrun reading SCTP notification");
		// TODO: handle this properly
		return READ_WITH_ERROR;
	    }
	    handle_sctp_event(flow, (union sctp_notification*)(flow->readBuffer
								  + flow->readBufferSize));


	    //We don't update readBufferSize, so buffer is implicitly "freed"
	    return READ_OK;
	}
#endif //defined(MSG_NOTIFICATION)

// TODO KAH: the code below seems to do the same thing in both cases!
// Should refactor it into one code path.
#if !defined(USRSCTP_SUPPORT)
        flow->readBufferSize += n;
        if ((msghdr.msg_flags & MSG_EOR) || (n == 0)) {
            flow->readBufferMsgComplete = 1;
        }
        if (!flow->readBufferMsgComplete) {
            return READ_WITH_ERROR;
        }
#else // !defined(USRSCTP_SUPPORT)
        neat_log(NEAT_LOG_INFO, " %zd bytes received\n", n);
        flow->readBufferSize += n;
        if ((flags & MSG_EOR) || (n == 0)) {
            flow->readBufferMsgComplete = 1;
        }
        if (!flow->readBufferMsgComplete) {
            neat_log(NEAT_LOG_DEBUG, "Message not complete, yet");
            return READ_WITH_ERROR;
        }
        READYCALLBACKSTRUCT;
        flow->operations->on_readable(flow->operations);
        if (n == 0) {
            return READ_WITH_ZERO;
        }
#endif // else !defined(USRSCTP_SUPPORT)
    }
    READYCALLBACKSTRUCT;
    flow->operations->on_readable(flow->operations);
    return READ_OK;
}

static void io_all_written(neat_ctx *ctx, neat_flow *flow, int stream_id)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_all_written) {
        return;
    }
    neat_error_code code = NEAT_OK;
    READYCALLBACKSTRUCT;
    flow->operations->on_all_written(flow->operations);
}

static void io_timeout(neat_ctx *ctx, neat_flow *flow) {
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    const int stream_id = NEAT_INVALID_STREAM;

    if (!flow->operations || !flow->operations->on_timeout) {
        return;
    }
    neat_error_code code = NEAT_OK;
    READYCALLBACKSTRUCT;
    flow->operations->on_timeout(flow->operations);
}

static void do_accept(neat_ctx *ctx, neat_flow *flow);
static void uvpollable_cb(uv_poll_t *handle, int status, int events);
static neat_error_code
neat_write_flush(struct neat_ctx *ctx, struct neat_flow *flow, int stream_id);

static void updatePollHandle(neat_ctx *ctx, neat_flow *flow, uv_poll_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->handle != NULL) {
        if (handle->loop == NULL || uv_is_closing((uv_handle_t *)flow->handle)) {
            return;
        }
    }

    int newEvents = 0;
    if (flow->operations && flow->operations->on_readable) {
        newEvents |= UV_READABLE;
    }
    if (flow->operations && flow->operations->on_writable) {
        newEvents |= UV_WRITABLE;
    }

    for (size_t i = 0; i < flow->buffer_count; ++i) {
        if (flow->isDraining[i]) {
            newEvents |= UV_WRITABLE;
            break;
        }
    }

    if (newEvents) {
        flow->isPolling = 1;
        if (flow->handle != NULL) {
            uv_poll_start(handle, newEvents, uvpollable_cb);
        }
    } else {
        flow->isPolling = 0;
        if (flow->handle != NULL) {
            uv_poll_stop(handle);
        }
    }
}

static void free_he_handle_cb(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    free(handle);
}

neat_error_code
allocate_send_buffers(neat_flow* flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    assert(flow->stream_count > 0);

    flow->buffer_count = flow->stream_count;

    flow->bufferedMessages = malloc(sizeof(*flow->bufferedMessages) *
                                    flow->buffer_count);

    if (!flow->bufferedMessages)
        return NEAT_ERROR_INTERNAL;

    flow->isDraining = calloc(flow->buffer_count, sizeof(unsigned int));

    if (!flow->isDraining)
        return NEAT_ERROR_INTERNAL;

    for (size_t buffer = 0; buffer < flow->buffer_count; ++buffer) {
        TAILQ_INIT(&(flow->bufferedMessages[buffer]));
    }

    neat_log(NEAT_LOG_DEBUG, "Allocated %d send buffers", flow->buffer_count);

    return NEAT_OK;
}

static void
free_send_buffers(neat_ctx* ctx, neat_flow* flow)
{
    for (size_t i = 0; i < flow->buffer_count; ++i) {
        struct neat_buffered_message *msg, *next_msg;
        TAILQ_FOREACH_SAFE(msg, &flow->bufferedMessages[i], message_next, next_msg) {
            TAILQ_REMOVE(&flow->bufferedMessages[i], msg, message_next);
            free(msg->buffered);
            free(msg);
        }
    }

    if (flow->isDraining)
        free(flow->isDraining);

    if (flow->bufferedMessages)
        free(flow->bufferedMessages);
}

static void
he_connected_cb(uv_poll_t *handle, int status, int events)
{
    struct he_cb_ctx *he_ctx = (struct he_cb_ctx *) handle->data;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_flow *flow = he_ctx->flow;

    //TODO: Final place to filter based on policy
    //TODO: This one uses the first result, so is wrong
    if (flow->hefirstConnect && (status == 0)) {

        neat_log(NEAT_LOG_DEBUG, "%s: First successful connect. Socket fd %d", __func__, he_ctx->fd);
        flow->hefirstConnect = 0;
        flow->family = he_ctx->candidate->ai_family;
        flow->sockType = he_ctx->candidate->ai_socktype;
        flow->sockStack = he_ctx->candidate->ai_stack;
        flow->everConnected = 1;
#if defined(USRSCTP_SUPPORT)
        flow->sock = he_ctx->sock;
#endif
        flow->fd = he_ctx->fd;
        flow->ctx = he_ctx->nc;
        flow->handle = handle;
        flow->handle->data = (void *) flow;
        flow->writeSize = he_ctx->writeSize;
        flow->writeLimit = he_ctx->writeLimit;
        flow->readSize = he_ctx->readSize;
        flow->isSCTPExplicitEOR = he_ctx->isSCTPExplicitEOR;
        flow->firstWritePending = 1;
        flow->isPolling = 1;

        if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
            flow->stream_count = 1;
        } else {
            flow->stream_count = 1;
        }

        LIST_REMOVE(he_ctx, next_he_ctx);
        free(he_ctx);

        if (allocate_send_buffers(flow) != NEAT_OK) {
            io_error(he_ctx->nc, flow, NEAT_INVALID_STREAM, NEAT_ERROR_IO );
            return;
        }

        // TODO: Security layer.
        uvpollable_cb(handle, NEAT_OK, UV_WRITABLE);
    } else {

        neat_log(NEAT_LOG_DEBUG, "%s: NOT first connect. Socket fd %d", __func__, he_ctx->fd);
        flow->close2fx(he_ctx->fd);
        uv_poll_stop(handle);
        uv_close((uv_handle_t*)handle, free_he_handle_cb);

        LIST_REMOVE(he_ctx, next_he_ctx);
        free(he_ctx);

        if (status < 0) {
            flow->heConnectAttemptCount--;
            if (flow->heConnectAttemptCount == 0) {
		io_error(flow->ctx, flow, NEAT_INVALID_STREAM, NEAT_ERROR_IO);
            }
        }
    }
}

static void uvpollable_cb(uv_poll_t *handle, int status, int events)
{
    neat_flow *flow = handle->data;
    neat_ctx *ctx = flow->ctx;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if ((events & UV_READABLE) && flow->acceptPending) {
        do_accept(ctx, flow);
        return;
    }

    // TODO: Are there cases when we should keep polling?
    if (status < 0) {
        neat_log(NEAT_LOG_DEBUG, "status: %d - events: %d", status, events);
        neat_log(NEAT_LOG_DEBUG, "ERROR: %s", uv_strerror(status));

#if !defined(USRSCTP_SUPPORT)
        if (neat_base_stack(flow->sockStack) == NEAT_STACK_TCP ||
            neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
#else
        if (neat_base_stack(flow->sockStack) == NEAT_STACK_TCP) {
#endif
            int so_error = 0;
            unsigned int len = sizeof(so_error);
            if (getsockopt(flow->fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                neat_log(NEAT_LOG_DEBUG, "Call to getsockopt failed: %s", strerror(errno));
                io_error(ctx, flow, NEAT_INVALID_STREAM, NEAT_ERROR_INTERNAL);
                return;
            }

            neat_log(NEAT_LOG_DEBUG, "Socket layer errno: %d (%s)", so_error, strerror(so_error));

            if (so_error == ETIMEDOUT) {
                io_timeout(ctx, flow);
                return;
            } else if (so_error == ECONNRESET) {
		neat_notify_aborted(flow);
	    }
        }

        neat_log(NEAT_LOG_ERROR, "Unspecified internal error when polling socket");
        io_error(ctx, flow, NEAT_INVALID_STREAM, NEAT_ERROR_INTERNAL);

        return;
    }

    // TODO: Check error in status
    if ((events & UV_WRITABLE) && flow->firstWritePending) {
        flow->firstWritePending = 0;
        io_connected(ctx, flow, NEAT_OK);
    }

    for (unsigned int stream = 0; stream < flow->stream_count; ++stream) {
        neat_log(NEAT_LOG_DEBUG, "Stream %d", stream);

        if (events & UV_WRITABLE && flow->isDraining[stream]) {
            neat_error_code code = neat_write_flush(ctx, flow, stream);
            if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
                io_error(ctx, flow, stream, code);
                return;
            }
            if (!flow->isDraining[stream]) {
                io_all_written(ctx, flow, stream);
            }
        }

        if (events & UV_WRITABLE) {
            io_writable(ctx, flow, stream, NEAT_OK);
        }
    }

    if (events & UV_READABLE) {
        io_readable(ctx, flow, NEAT_OK);
    }

    updatePollHandle(ctx, flow, flow->handle);
}


static void do_accept(neat_ctx *ctx, neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_flow *newFlow = neat_new_flow(ctx);
    newFlow->name = strdup (flow->name);
    newFlow->port = flow->port;
    newFlow->propertyMask = flow->propertyMask;
    newFlow->propertyAttempt = flow->propertyAttempt;
    newFlow->propertyUsed = flow->propertyUsed;
    newFlow->everConnected = 1;
    newFlow->family = flow->family;
    newFlow->sockType = flow->sockType;
    newFlow->sockStack = flow->sockStack;
    newFlow->ctx = ctx;
    newFlow->writeLimit = flow->writeLimit;
    newFlow->writeSize = flow->writeSize;
    newFlow->readSize = flow->readSize;

    newFlow->ownedByCore = 1;
    newFlow->isSCTPExplicitEOR = flow->isSCTPExplicitEOR;
    newFlow->operations = calloc (sizeof(struct neat_flow_operations), 1);
    newFlow->operations->on_connected = flow->operations->on_connected;
    newFlow->operations->on_readable = flow->operations->on_readable;
    newFlow->operations->on_writable = flow->operations->on_writable;
    newFlow->operations->ctx = ctx;
    newFlow->operations->flow = flow;

    newFlow->handle = (uv_poll_t *) malloc(sizeof(uv_poll_t));
    assert(newFlow->handle != NULL);

    newFlow->stream_count = 1;
    if (allocate_send_buffers(newFlow) != NEAT_OK) {
        io_error(ctx, newFlow, NEAT_INVALID_STREAM, NEAT_ERROR_IO);
        return;
    }

    switch (newFlow->sockStack) {
    case NEAT_STACK_SCTP:
#if defined(USRSCTP_SUPPORT)
        newFlow->sock = newFlow->acceptusrsctpfx(ctx, newFlow, flow->sock);
        if (!newFlow->sock) {
            neat_free_flow(newFlow);
        } else {
            io_connected(ctx, newFlow, NEAT_OK);
            newFlow->acceptPending = 0;
        }
#else
        newFlow->fd = newFlow->acceptfx(ctx, newFlow, flow->fd);
        if (newFlow->fd == -1) {
            neat_free_flow(newFlow);
        } else {
            uv_poll_init(ctx->loop, newFlow->handle, newFlow->fd); // makes fd nb as side effect
            newFlow->handle->data = newFlow;
            io_connected(ctx, newFlow, NEAT_OK);
            uvpollable_cb(newFlow->handle, NEAT_OK, 0);
        }
#endif
        break;
    default:
        newFlow->fd = newFlow->acceptfx(ctx, newFlow, flow->fd);
        if (newFlow->fd == -1) {
            neat_free_flow(newFlow);
        } else {
            uv_poll_init(ctx->loop, newFlow->handle, newFlow->fd); // makes fd nb as side effect
            newFlow->handle->data = newFlow;
            io_connected(ctx, newFlow, NEAT_OK);
            uvpollable_cb(newFlow->handle, NEAT_OK, 0);
        }
    }
}

neat_error_code
neat_open(neat_ctx *mgr, neat_flow *flow, const char *name, uint16_t port)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->name) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    flow->name = strdup(name);
    flow->port = port;
    flow->propertyAttempt = flow->propertyMask;

    return neat_he_lookup(mgr, flow, he_connected_cb);
}

neat_error_code
neat_change_timeout(neat_ctx *mgr, neat_flow *flow, int seconds)
{
#if defined(TCP_USER_TIMEOUT)
    unsigned int timeout_msec;
    int rc;
#endif

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (seconds < 0) {
            neat_log(NEAT_LOG_WARNING,
                    "Unable to change timeout: "
                    "Negative timeout specified");

            return NEAT_ERROR_BAD_ARGUMENT;
    }

    // TCP User Timeout isn't supported on all platforms
#if defined(TCP_USER_TIMEOUT)
    timeout_msec = ((unsigned int)seconds) * 1000;

    if (neat_base_stack(flow->sockStack) == NEAT_STACK_TCP) {
        if (flow->fd == -1) {
            neat_log(NEAT_LOG_WARNING,
                    "Unable to change timeout for TCP socket: "
                    "Invalid socket value");
            return NEAT_ERROR_BAD_ARGUMENT;
        }

        rc = setsockopt(flow->fd,
                        IPPROTO_TCP,
                        TCP_USER_TIMEOUT,
                        &timeout_msec,
                        sizeof(timeout_msec));

        if (rc < 0) {
            neat_log(NEAT_LOG_ERROR,
                    "Unable to change timeout for TCP socket: "
                    "Call to setsockopt failed with errno=%d", errno);
            return NEAT_ERROR_IO;
        }

        return NEAT_ERROR_OK;
    }
#endif // defined(TCP_USER_TIMEOUT)
    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
#if 0 // Disabled due to discussion with MT in PR #85
        struct sctp_paddrparams params;
        unsigned int optsize = sizeof(params);
        int rc = getsockopt(flow->fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &params, &optsize);
        if (rc < 0) {
            neat_log(NEAT_LOG_ERROR,
                    "Unable to change timeout for SCTP socket: "
                    "Call to getsockopt failed with errno=%d", errno);
            return NEAT_ERROR_IO;
        }

        params.spp_hbinterval = (unsigned int)seconds * 1000 / 4;
        params.spp_flags |= SPP_HB_ENABLE;
        params.spp_pathmaxrxt = 4;

        rc = setsockopt(flow->fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &params, sizeof(params));
        if (rc < 0) {
            neat_log(NEAT_LOG_ERROR,
                    "Unable to change timeout for SCTP socket: "
                    "Call to setsockopt failed with errno=%d", errno);
            return NEAT_ERROR_IO;
        }
#endif // if 0
        return NEAT_ERROR_UNABLE;
    }

    return NEAT_ERROR_UNABLE;
}

static void
set_primary_dest_resolve_cb(struct neat_resolver *resolver, struct neat_resolver_results *results, uint8_t code)
{
    int rc;
    neat_flow *flow = (neat_flow *)resolver->userData1;
    struct neat_ctx *ctx = flow->ctx;
    char dest_addr[NI_MAXHOST];

#ifdef USRSCTP_SUPPORT
    struct sctp_setprim addr;
#elif defined(HAVE_NETINET_SCTP_H) && defined(__linux__)
    struct sctp_prim addr;
    struct sctp_assocparams assocparams;
    unsigned int optlen = sizeof(assocparams);
#endif

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        io_error(ctx, flow, NEAT_INVALID_STREAM, code);
        return;
    }

    assert(results->lh_first);

#ifdef USRSCTP_SUPPORT
    addr.ssp_addr = results->lh_first->dst_addr;

    if (usrsctp_setsockopt(flow->sock, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, &addr, sizeof(addr)) < 0) {
        neat_log(NEAT_LOG_DEBUG, "Call to usrsctp_setsockopt failed");
        return;
    }
#elif defined(HAVE_NETINET_SCTP_H) && defined(__linux__)
    rc = getsockopt(flow->fd, IPPROTO_SCTP, SCTP_ASSOCINFO, &assocparams, &optlen);
    if (rc < 0) {
        neat_log(NEAT_LOG_DEBUG, "Call to getsockopt failed");
        return;
    }

    neat_log(NEAT_LOG_DEBUG, "assoc: %d", assocparams.sasoc_assoc_id);

    addr.ssp_assoc_id = assocparams.sasoc_assoc_id;
    addr.ssp_addr = results->lh_first->dst_addr;

    rc = setsockopt(flow->fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, &addr, sizeof(addr));
    if (rc < 0) {
        neat_log(NEAT_LOG_DEBUG, "Call to setsockopt failed");
        return;
    }
#endif
    rc = getnameinfo((struct sockaddr *)&results->lh_first->dst_addr,
                     results->lh_first->dst_addr_len,
                     dest_addr, sizeof(dest_addr), NULL, 0, 0);

    if (rc < 0) {
        neat_log(NEAT_LOG_DEBUG, "getnameinfo failed for primary destination address");
    } else {
        neat_log(NEAT_LOG_DEBUG, "Updated primary destination address to: %s", dest_addr);
    }
}

neat_error_code
neat_set_primary_dest(struct neat_ctx *ctx, struct neat_flow *flow, const char *name)
{
    int8_t literal;
    uint8_t family = AF_UNSPEC;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
        neat_protocol_stack_type stacks[] = {NEAT_STACK_SCTP};

	literal = neat_resolver_check_for_literal(&family, name);

	if (literal != 1) {
	    neat_log(NEAT_LOG_ERROR, "%s: provided name '%s' is not an address literal.\n",
		     __func__, name);
	    return NEAT_ERROR_BAD_ARGUMENT;
	}

        ctx->resolver->handle_resolve = set_primary_dest_resolve_cb;
        neat_getaddrinfo(ctx->resolver, AF_UNSPEC, name, flow->port,
                stacks, sizeof(*stacks)/sizeof(stacks[0]));

        return NEAT_ERROR_OK;
    }

    return NEAT_ERROR_UNABLE;
}

neat_error_code
neat_request_capacity(struct neat_ctx *ctx, struct neat_flow *flow, int rate, int seconds)
{
    return NEAT_ERROR_UNABLE;
}

static void
accept_resolve_cb(struct neat_resolver *resolver, struct neat_resolver_results *results, uint8_t code)
{
    neat_flow *flow = (neat_flow *)resolver->userData1;
    struct neat_ctx *ctx = flow->ctx;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        io_error(ctx, flow, NEAT_INVALID_STREAM, code);
        return;
    }
    assert (results->lh_first);
    flow->family = results->lh_first->ai_family;
    flow->sockType = results->lh_first->ai_socktype;
    flow->sockStack = results->lh_first->ai_stack;
    flow->resolver_results = results;
    flow->sockAddr = (struct sockaddr *) &(results->lh_first->dst_addr);

    if (flow->listenfx(ctx, flow) == -1) {
        io_error(ctx, flow, NEAT_INVALID_STREAM, NEAT_ERROR_IO);
        return;
    }

    flow->handle->data = flow;
    if (flow->fd != -1) {
        uv_poll_init(ctx->loop, flow->handle, flow->fd);

        if ((neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) ||
            (neat_base_stack(flow->sockStack) == NEAT_STACK_TCP)) {
            flow->isPolling = 1;
            flow->acceptPending = 1;
            uv_poll_start(flow->handle, UV_READABLE, uvpollable_cb);
        } else {
            // do normal i/o events without accept() for non connected protocols
            updatePollHandle(ctx, flow, flow->handle);
        }
    } else {
        flow->acceptPending = 1;
    }
}

neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                            const char *name, uint16_t port)
{
    neat_protocol_stack_type stacks[NEAT_STACK_MAX_NUM]; /* We only support SCTP, TCP, UDP, and UDPLite */
    uint8_t nr_of_stacks;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    nr_of_stacks = neat_property_translate_protocols(flow->propertyMask, stacks);

    if (nr_of_stacks == 0)
        return NEAT_ERROR_UNABLE;

    if (flow->name)
        return NEAT_ERROR_BAD_ARGUMENT;

    if (!strcmp(name, "*"))
        name = "0.0.0.0";

    flow->name = strdup(name);
    flow->port = port;
    flow->propertyAttempt = flow->propertyMask;
    flow->ctx = ctx;
    flow->handle = (uv_poll_t *) malloc(sizeof(uv_poll_t));
    assert(flow->handle != NULL);

    if (!ctx->resolver)
        ctx->resolver = neat_resolver_init(ctx, "/etc/resolv.conf",
                                           accept_resolve_cb, NULL);
    else if (ctx->resolver->handle_resolve != accept_resolve_cb)
        // TODO: Race condition if this is updated before the callback for
        // set_primary_addr is called
        ctx->resolver->handle_resolve = accept_resolve_cb;

    ctx->resolver->userData1 = (void *)flow;

    neat_getaddrinfo(ctx->resolver, AF_INET, flow->name, flow->port,
                     stacks, nr_of_stacks);
    return NEAT_OK;
}

static neat_error_code
neat_write_flush(struct neat_ctx *ctx, struct neat_flow *flow, int stream_id)
{
    struct neat_buffered_message *msg, *next_msg;
    ssize_t rv = 0;
    size_t len;
#if defined(SCTP_SNDINFO) || defined (SCTP_SNDRCV)
    struct cmsghdr *cmsg;
#endif
    struct msghdr msghdr;
    struct iovec iov;
#if defined(SCTP_SNDINFO)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
    struct sctp_sndinfo *sndinfo;
#elif defined (SCTP_SNDRCV)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct sctp_sndrcvinfo *sndrcvinfo;
#endif
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_log(NEAT_LOG_DEBUG, "stream_id: %d - isDraining: %d", stream_id, flow->isDraining[stream_id]);
    if (TAILQ_EMPTY(&flow->bufferedMessages[stream_id])) {
        return NEAT_OK;
    }
    TAILQ_FOREACH_SAFE(msg, &flow->bufferedMessages[stream_id], message_next, next_msg) {
        do {
            iov.iov_base = msg->buffered + msg->bufferedOffset;
            if ((neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) &&
                (flow->isSCTPExplicitEOR) &&
                (flow->writeLimit > 0) &&
                (msg->bufferedSize > flow->writeLimit)) {
                len = flow->writeLimit;
            } else {
                len = msg->bufferedSize;
            }
            iov.iov_len = len;
            msghdr.msg_name = NULL;
            msghdr.msg_namelen = 0;
            msghdr.msg_iov = &iov;
            msghdr.msg_iovlen = 1;

            if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
#if defined(SCTP_SNDINFO)
                msghdr.msg_control = cmsgbuf;
                msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndinfo));
                cmsg = (struct cmsghdr *)cmsgbuf;
                cmsg->cmsg_level = IPPROTO_SCTP;
                cmsg->cmsg_type = SCTP_SNDINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
                sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
                memset(sndinfo, 0, sizeof(struct sctp_sndinfo));
#if defined(SCTP_EOR)
                if ((flow->isSCTPExplicitEOR) && (len == msg->bufferedSize)) {
                    sndinfo->snd_flags |= SCTP_EOR;
                }
#endif
#elif defined (SCTP_SNDRCV)
                msghdr.msg_control = cmsgbuf;
                msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
                cmsg = (struct cmsghdr *)cmsgbuf;
                cmsg->cmsg_level = IPPROTO_SCTP;
                cmsg->cmsg_type = SCTP_SNDRCV;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
                sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
                memset(sndrcvinfo, 0, sizeof(struct sctp_sndrcvinfo));
#if defined(SCTP_EOR)
                if ((flow->isSCTPExplicitEOR) && (len == msg->bufferedSize)) {
                    sndrcvinfo->sinfo_flags |= SCTP_EOR;
                }
#endif
#else
                msghdr.msg_control = NULL;
                msghdr.msg_controllen = 0;
#endif
            } else {
                msghdr.msg_control = NULL;
                msghdr.msg_controllen = 0;
            }

            msghdr.msg_flags = 0;
            if (flow->fd != -1) {
                rv = sendmsg(flow->fd, (const struct msghdr *)&msghdr, 0);
            }
            else {
#if defined(USRSCTP_SUPPORT)
                rv = usrsctp_sendv(flow->sock, msg->buffered + msg->bufferedOffset, msg->bufferedSize,
                               (struct sockaddr *) (flow->sockAddr), 1, (void *)sndinfo,
                               (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
                               0);
#endif
            }
            if (rv < 0) {
                if (errno == EWOULDBLOCK) {
                    return NEAT_ERROR_WOULD_BLOCK;
                } else {
                    return NEAT_ERROR_IO;
                }
            }
            msg->bufferedOffset += rv;
            msg->bufferedSize -= rv;
        } while (msg->bufferedSize > 0);
        TAILQ_REMOVE(&flow->bufferedMessages[stream_id], msg, message_next);
        free(msg->buffered);
        free(msg);
    }
    if (TAILQ_EMPTY(&flow->bufferedMessages[stream_id])) {
        flow->isDraining[stream_id] = 0;
    }
    return NEAT_OK;
}

static neat_error_code
neat_write_fillbuffer(struct neat_ctx *ctx, struct neat_flow *flow,
                                 const unsigned char *buffer, uint32_t amt, int stream_id)
{
    struct neat_buffered_message *msg;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    // TODO: A better implementation here is a linked list of buffers
    // but this gets us started
    if (amt == 0) {
        return NEAT_OK;
    }

    if ((flow->sockStack != NEAT_STACK_TCP) || TAILQ_EMPTY(&flow->bufferedMessages[stream_id])) {
        msg = malloc(sizeof(struct neat_buffered_message));
        if (msg == NULL) {
            return NEAT_ERROR_INTERNAL;
        }
        msg->buffered = NULL;
        msg->bufferedOffset = 0;
        msg->bufferedSize = 0;
        msg->bufferedAllocation= 0;
        TAILQ_INSERT_TAIL(&flow->bufferedMessages[stream_id], msg, message_next);
    } else {
        msg = TAILQ_LAST(&flow->bufferedMessages[stream_id], neat_message_queue_head);
    }
    // check if there is room to buffer without extending allocation
    if ((msg->bufferedOffset + msg->bufferedSize + amt) <= msg->bufferedAllocation) {
        memcpy(msg->buffered + msg->bufferedOffset + msg->bufferedSize,
                buffer, amt);
        msg->bufferedSize += amt;
        return NEAT_OK;
    }

    // round up to ~8K
    size_t needed = ((amt + msg->bufferedSize) + 8191) & ~8191;
    if (msg->bufferedOffset == 0) {
        msg->buffered = realloc(msg->buffered, needed);
        if (msg->buffered == NULL) {
            return NEAT_ERROR_INTERNAL;
        }
        msg->bufferedAllocation = needed;
    } else {
        void *newptr = malloc(needed);
        if (newptr == NULL) {
            return NEAT_ERROR_INTERNAL;
        }
        memcpy(newptr, msg->buffered + msg->bufferedOffset, msg->bufferedSize);
        free(msg->buffered);
        msg->buffered = newptr;
        msg->bufferedAllocation = needed;
        msg->bufferedOffset = 0;
    }
    memcpy(msg->buffered + msg->bufferedSize, buffer, amt);
    msg->bufferedSize += amt;
    return NEAT_OK;
}

static neat_error_code
neat_write_to_lower_layer(struct neat_ctx *ctx, struct neat_flow *flow,
                      const unsigned char *buffer, uint32_t amt, int stream_id)
{
    ssize_t rv = 0;
    size_t len;
    int atomic;
#if defined(SCTP_SNDINFO) || defined (SCTP_SNDRCV)
    struct cmsghdr *cmsg;
#endif
    struct msghdr msghdr;
    struct iovec iov;
#if defined(SCTP_SNDINFO)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
    struct sctp_sndinfo *sndinfo = NULL;
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
#elif defined (SCTP_SNDRCV)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct sctp_sndrcvinfo *sndrcvinfo;
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
#endif
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);



    switch (flow->sockStack) {
    case NEAT_STACK_TCP:
        atomic = 0;
        break;
    case NEAT_STACK_SCTP:
        if (flow->isSCTPExplicitEOR) {
            atomic = 0;
        } else {
            atomic = 1;
        }
        break;
    case NEAT_STACK_UDP:
    case NEAT_STACK_UDPLITE:
        atomic = 1;
        break;
    default:
        atomic = 1;
        break;
    }
    if (atomic && flow->writeSize > 0 && amt > flow->writeSize) {
        return NEAT_ERROR_MESSAGE_TOO_BIG;
    }
    neat_error_code code = neat_write_flush(ctx, flow, stream_id);
    if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
        return code;
    }
    if (TAILQ_EMPTY(&flow->bufferedMessages[stream_id]) && code == NEAT_OK && amt > 0) {
        iov.iov_base = (void *)buffer;
        if ((neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) &&
            (flow->isSCTPExplicitEOR) &&
            (flow->writeLimit > 0) &&
            (amt > flow->writeLimit)) {
            len = flow->writeLimit;
        } else {
            len = amt;
        }
        iov.iov_len = len;
        msghdr.msg_name = NULL;
        msghdr.msg_namelen = 0;
        msghdr.msg_iov = &iov;
        msghdr.msg_iovlen = 1;

        if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
#if defined(SCTP_SNDINFO)
            msghdr.msg_control = cmsgbuf;
            msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndinfo));
            cmsg = (struct cmsghdr *)cmsgbuf;
            cmsg->cmsg_level = IPPROTO_SCTP;
            cmsg->cmsg_type = SCTP_SNDINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
            sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
            memset(sndinfo, 0, sizeof(struct sctp_sndinfo));
#if defined(SCTP_EOR)
            if ((flow->isSCTPExplicitEOR) && (len == amt)) {
                sndinfo->snd_flags |= SCTP_EOR;
            }
#endif
#elif defined (SCTP_SNDRCV)
            msghdr.msg_control = cmsgbuf;
            msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
            cmsg = (struct cmsghdr *)cmsgbuf;
            cmsg->cmsg_level = IPPROTO_SCTP;
            cmsg->cmsg_type = SCTP_SNDRCV;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
            sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
            memset(sndrcvinfo, 0, sizeof(struct sctp_sndrcvinfo));
#if defined(SCTP_EOR)
            if ((flow->isSCTPExplicitEOR) && (len == amt)) {
                sndrcvinfo->sinfo_flags |= SCTP_EOR;
            }
#endif
#else
            msghdr.msg_control = NULL;
            msghdr.msg_controllen = 0;
#endif
        } else {
            msghdr.msg_control = NULL;
            msghdr.msg_controllen = 0;
        }

        msghdr.msg_flags = 0;
        if (flow->fd != -1) {
            rv = sendmsg(flow->fd, (const struct msghdr *)&msghdr, 0);
        } else {
#if defined(USRSCTP_SUPPORT)
            rv = usrsctp_sendv(flow->sock, buffer, len, NULL, 0,
                  (void *)sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
                  0);
#endif
        }
        neat_log(NEAT_LOG_DEBUG, "%zd bytes sent", rv);
        if (rv < 0 ) {
            if (errno != EWOULDBLOCK) {
                return NEAT_ERROR_IO;
            }
        }
        if (rv != -1) {
            amt -= rv;
            buffer += rv;
        }
    }
    code = neat_write_fillbuffer(ctx, flow, buffer, amt, stream_id);
    if (code != NEAT_OK) {
        return code;
    }
    if (TAILQ_EMPTY(&flow->bufferedMessages[stream_id])) {
        flow->isDraining[stream_id] = 0;
        io_all_written(ctx, flow, stream_id);
    } else {
        flow->isDraining[stream_id] = 1;
    }
#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP)
        return NEAT_OK;
#endif
    updatePollHandle(ctx, flow, flow->handle);
    return NEAT_OK;
}

static neat_error_code
neat_read_from_lower_layer(struct neat_ctx *ctx, struct neat_flow *flow,
                     unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    ssize_t rv;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
        if (!flow->readBufferMsgComplete) {
            return NEAT_ERROR_WOULD_BLOCK;
        }
        if (flow->readBufferSize > amt) {
            neat_log(NEAT_LOG_DEBUG, "%s: Message too big", __func__);
            return NEAT_ERROR_MESSAGE_TOO_BIG;
        }
        memcpy(buffer, flow->readBuffer, flow->readBufferSize);
        *actualAmt = flow->readBufferSize;
        flow->readBufferSize = 0;
        flow->readBufferMsgComplete = 0;
        return NEAT_OK;
    }

    rv = recv(flow->fd, buffer, amt, 0);
    if (rv == -1 && errno == EWOULDBLOCK){
        return NEAT_ERROR_WOULD_BLOCK;
    }
    if (rv == -1) {
	if (errno == ECONNRESET) {
	    neat_log(NEAT_LOG_DEBUG, "%s: ECONNRESET", __func__);
	    neat_notify_aborted(flow);
	} else {
	    neat_log(NEAT_LOG_DEBUG, "%s: err %d (%s)", __func__,
		     errno, strerror(errno));
	}
        return NEAT_ERROR_IO;
    }
    *actualAmt = rv;
    return NEAT_OK;
}

static int
neat_accept_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow, int fd)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    return accept(fd, NULL, NULL);
}

int neat_stack_to_protocol(neat_protocol_stack_type stack)
{
    switch (stack) {
        case NEAT_STACK_UDP:
            return IPPROTO_UDP;
#ifdef IPPROTO_UDPLITE
        case NEAT_STACK_UDPLITE:
            return IPPROTO_UDPLITE;
#endif
        case NEAT_STACK_TCP:
            return IPPROTO_TCP;
#ifdef IPPROTO_SCTP
        case NEAT_STACK_SCTP:
            return IPPROTO_SCTP;
#endif
        default:
            return 0;
    }
}

int neat_base_stack(neat_protocol_stack_type stack)
{
    switch (stack) {
        case NEAT_STACK_UDP:
        case NEAT_STACK_UDPLITE:
        case NEAT_STACK_TCP:
        case NEAT_STACK_SCTP:
            return stack;
        default:
            return 0;
    }
}

static int
neat_connect(struct he_cb_ctx *he_ctx, uv_poll_cb callback_fx)
{
    int enable = 1;
    socklen_t len = 0;
    int size = 0, protocol;
#ifdef __linux__
    char if_name[IF_NAMESIZE];
#endif

    socklen_t slen =
            (he_ctx->candidate->ai_family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    char addrsrcbuf[INET6_ADDRSTRLEN];
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(he_ctx->candidate->ai_stack) == NEAT_STACK_SCTP) {
        neat_connect_via_usrsctp(he_ctx);
    } else {
#endif
    protocol = neat_stack_to_protocol(neat_base_stack(he_ctx->candidate->ai_stack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", he_ctx->candidate->ai_stack);
        return -1;
    }
    if ((he_ctx->fd = socket(he_ctx->candidate->ai_family, he_ctx->candidate->ai_socktype, protocol)) < 0) {
        neat_log(NEAT_LOG_ERROR, "Failed to create he socket");
        return -1;
    }

    if (he_ctx->candidate->ai_family == AF_INET) {
        inet_ntop(AF_INET, &(((struct sockaddr_in *) &(he_ctx->candidate->src_addr))->sin_addr), addrsrcbuf, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &(he_ctx->candidate->src_addr))->sin6_addr), addrsrcbuf, INET6_ADDRSTRLEN);
    }
    neat_log(NEAT_LOG_INFO, "%s: Bind fd %d to %s", __func__, he_ctx->fd, addrsrcbuf);

    /* Bind to address + interface (if Linux) */
    if (bind(he_ctx->fd, (struct sockaddr*) &(he_ctx->candidate->src_addr),
            he_ctx->candidate->src_addr_len)) {
        neat_log(NEAT_LOG_ERROR, "Failed to bind fd %d socket to IP. Error: %s", he_ctx->fd, strerror(errno));
        return -1;
    }

#ifdef __linux__
    if (if_indextoname(he_ctx->candidate->if_idx, if_name)) {
        if (setsockopt(he_ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, if_name,
                strlen(if_name)) < 0) {
            //Not a critical error
            neat_log(NEAT_LOG_WARNING, "Could not bind fd %d socket to interface %s", he_ctx->fd, if_name);
        }
    }
#endif

    len = (socklen_t)sizeof(int);
    if (getsockopt(he_ctx->fd, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        he_ctx->writeSize = size;
    } else {
        he_ctx->writeSize = 0;
    }
    len = (socklen_t)sizeof(int);
    if (getsockopt(he_ctx->fd, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        he_ctx->readSize = size;
    } else {
        he_ctx->readSize = 0;
    }
    switch (he_ctx->candidate->ai_stack) {
        case NEAT_STACK_TCP:
            setsockopt(he_ctx->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));
            break;
        case NEAT_STACK_SCTP:
            he_ctx->writeLimit =  he_ctx->writeSize / 4;
#ifdef SCTP_NODELAY
            setsockopt(he_ctx->fd, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
        if (setsockopt(he_ctx->fd, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            he_ctx->isSCTPExplicitEOR = 1;
#endif
#ifndef USRSCTP_SUPPORT
        // Subscribe to events needed for callbacks
        neat_sctp_init_events(he_ctx->fd);
#endif
            break;
        default:
            break;
    }
    uv_poll_init(he_ctx->nc->loop, he_ctx->handle, he_ctx->fd); // makes fd nb as side effect
    if ((he_ctx->fd == -1) ||
        (connect(he_ctx->fd, (struct sockaddr *) &(he_ctx->candidate->dst_addr), slen) && (errno != EINPROGRESS))) {
        neat_log(NEAT_LOG_DEBUG, "%s: Connect failed for fd %d", __func__, he_ctx->fd);
        return -2;
    }
    uv_poll_start(he_ctx->handle, UV_WRITABLE, callback_fx);
#if defined(USRSCTP_SUPPORT)
    }
#endif
    return 0;
}

static int
neat_close_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    if (flow->fd != -1) {
        neat_log(NEAT_LOG_DEBUG, "%s: Close fd %d", __func__, flow->fd);
        // we might want a fx callback here to split between
        // kernel and userspace.. same for connect read and write
        close(flow->fd);

	// KAH: AFAIK the socket API provides no way of knowing any
	// further status of the close op for TCP.
	// taps-transports-usage does not specify CLOSE-EVENT.TCP,
	// maybe it should be dropped from the implementation?
	neat_notify_close(flow);
    }
    return 0;
}

static int
neat_close_via_kernel_2(int fd)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    if (fd != -1) {
        neat_log(NEAT_LOG_DEBUG, "%s: Close fd %d", __func__, fd);
        close(fd);
    }
    return 0;
}

static int
neat_listen(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP) {
        neat_listen_via_usrsctp(ctx, flow);
        return 0;
    }
#endif
    neat_listen_via_kernel(ctx, flow);
    return 0;
}

static int
neat_listen_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    int enable = 1;
    socklen_t len;
    int size, protocol;
    socklen_t slen =
        (flow->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    protocol = neat_stack_to_protocol(neat_base_stack(flow->sockStack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", flow->sockStack);
        return -1;
    }
    if ((flow->fd = socket(flow->family, flow->sockType, protocol)) < 0) {
        neat_log(NEAT_LOG_ERROR, "%s: opening listening socket failed - %s", __func__, strerror(errno));
        return -1;
    }
    len = (socklen_t)sizeof(int);
    if (getsockopt(flow->fd, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        flow->writeSize = size;
    } else {
        flow->writeSize = 0;
    }
    len = (socklen_t)sizeof(int);
    if (getsockopt(flow->fd, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        flow->readSize = size;
    } else {
        flow->readSize = 0;
    }
    switch (flow->sockStack) {
    case NEAT_STACK_TCP:
        setsockopt(flow->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));
        break;
    case NEAT_STACK_SCTP:
        flow->writeLimit = flow->writeSize / 4;
#ifdef SCTP_NODELAY
        setsockopt(flow->fd, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
        if (setsockopt(flow->fd, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            flow->isSCTPExplicitEOR = 1;
#endif
        break;
    default:
        break;
    }
    setsockopt(flow->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if ((flow->fd == -1) ||
        (bind(flow->fd, flow->sockAddr, slen) == -1) ||
        (listen(flow->fd, 100) == -1)) {
        return -1;
    }
    return 0;
}

static int
neat_shutdown_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (shutdown(flow->fd, SHUT_WR) == 0) {
        return NEAT_OK;
    } else {
        return NEAT_ERROR_IO;
    }
}

#if defined(USRSCTP_SUPPORT)
static void neat_sctp_init_events(struct socket *sock)
#else
static void neat_sctp_init_events(int sock)
#endif
{
#if defined(IPPROTO_SCTP)
#if defined(SCTP_EVENT)
    // Set up SCTP event subscriptions using RFC6458 API
    // (does not work with current Linux kernel SCTP)
    struct sctp_event event;
    unsigned int i;
    uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
			      SCTP_PEER_ADDR_CHANGE,
			      SCTP_REMOTE_ERROR,
			      SCTP_SHUTDOWN_EVENT,
			      SCTP_ADAPTATION_INDICATION,
			      SCTP_PARTIAL_DELIVERY_EVENT,
			      SCTP_SEND_FAILED_EVENT};

    memset(&event, 0, sizeof(event));
    event.se_assoc_id = SCTP_FUTURE_ASSOC;
    event.se_on = 1;

    for (i = 0; i < (unsigned int)(sizeof(event_types)/sizeof(uint16_t)); i++) {
	    event.se_type = event_types[i];
#if defined(USRSCTP_SUPPORT)
	    if (usrsctp_setsockopt(
#else
	    if (setsockopt(
#endif
			sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(struct sctp_event)) < 0) {
		    neat_log(NEAT_LOG_ERROR, "%s: failed to subscribe to event type %u - %s",
			     __func__, event_types[i], strerror(errno));
		}
    }
#else // defined(SCTP_EVENT)

#if defined(HAVE_SCTP_EVENT_SUBSCRIBE)
// Set up SCTP event subscriptions using deprecated API
// (for compatibility with Linux kernel SCTP)
    struct sctp_event_subscribe event;

    memset(&event, 0, sizeof(event));
    event.sctp_association_event = 1;
    event.sctp_address_event = 1;
    event.sctp_send_failure_event = 1;
    event.sctp_peer_error_event = 1;
    event.sctp_shutdown_event = 1;
    event.sctp_partial_delivery_event = 1;
    event.sctp_adaptation_layer_event = 1;

    if (setsockopt(sock, IPPROTO_SCTP, SCTP_EVENTS, &event,
		   sizeof(struct sctp_event_subscribe)) < 0) {
	neat_log(NEAT_LOG_ERROR, "%s: failed to subscribe to SCTP events - %s",
		 __func__, strerror(errno));
    }
#endif // else HAVE_SCTP_EVENT_SUBSCRIBE
#endif //else defined(SCTP_EVENT)
#endif
}

#ifdef USRSCTP_SUPPORT
static struct socket *
neat_accept_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow, struct socket *sock)
{
    struct sockaddr_in remote_addr;
    struct socket *newsock;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in));
    if (((newsock = usrsctp_accept(sock, (struct sockaddr *) &remote_addr, &addr_len)) == NULL) && (errno != EINPROGRESS)) {
        neat_log(NEAT_LOG_ERROR, "%s: usrsctp_accept failed - %s", __func__, strerror(errno));
        return NULL;
    }
    usrsctp_set_upcall(newsock, handle_upcall, (void *)flow);
    return newsock;
}

static int
neat_connect_via_usrsctp(struct he_cb_ctx *he_ctx)
{
    int enable = 1;
    socklen_t len;
    int size, protocol;
    socklen_t slen =
            (he_ctx->candidate->ai_family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    char addrsrcbuf[slen], addrdstbuf[slen];

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    protocol = neat_stack_to_protocol(neat_base_stack(he_ctx->candidate->ai_stack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", he_ctx->candidate->ai_stack);
        return -1;
    }

    he_ctx->sock = usrsctp_socket(he_ctx->candidate->ai_family, he_ctx->candidate->ai_socktype, protocol, NULL, NULL, 0, NULL);
    if (he_ctx->sock) {
        usrsctp_set_non_blocking(he_ctx->sock, 1);
        len = (socklen_t)sizeof(int);
        if (usrsctp_getsockopt(he_ctx->sock, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
            he_ctx->writeSize = size;
        } else {
            he_ctx->writeSize = 0;
        }
        len = (socklen_t)sizeof(int);
        if (usrsctp_getsockopt(he_ctx->sock, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
            he_ctx->readSize = size;
        } else {
            he_ctx->readSize = 0;
        }
        he_ctx->writeLimit =  he_ctx->writeSize / 4;

#ifdef SCTP_NODELAY
        usrsctp_setsockopt(he_ctx->sock, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
        if (usrsctp_setsockopt(he_ctx->sock, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            he_ctx->isSCTPExplicitEOR = 1;
#endif

        // Subscribe to SCTP events
        neat_sctp_init_events(he_ctx->sock);

        neat_log(NEAT_LOG_INFO, "%s: Connect from %s to %s", __func__,
           inet_ntop(AF_INET, &(((struct sockaddr_in *) &(he_ctx->candidate->src_addr))->sin_addr), addrsrcbuf, slen),
           inet_ntop(AF_INET, &(((struct sockaddr_in *) &(he_ctx->candidate->dst_addr))->sin_addr), addrdstbuf, slen));

        if (!(he_ctx->sock) || (usrsctp_connect(he_ctx->sock, (struct sockaddr *) &(he_ctx->candidate->dst_addr), slen) && (errno != EINPROGRESS))) {
            neat_log(NEAT_LOG_ERROR, "%s: usrsctp_connect failed - %s", __func__, strerror(errno));
            return -1;
        } else {
            neat_log(NEAT_LOG_INFO, "%s: usrsctp_socket connected", __func__);
        }


        neat_flow *flow = he_ctx->flow;
        if (flow->hefirstConnect) {
            flow->hefirstConnect = 0;
            flow->family = he_ctx->candidate->ai_family;
            flow->sockType = he_ctx->candidate->ai_socktype;
            flow->sockStack = he_ctx->candidate->ai_stack;
            flow->everConnected = 1;
            flow->sock = he_ctx->sock;
            flow->fd = -1;
            flow->ctx = he_ctx->nc;
            flow->handle = he_ctx->handle;
            flow->handle->data = (void *) flow;
            flow->writeSize = he_ctx->writeSize;
            flow->writeLimit = he_ctx->writeLimit;
            flow->readSize = he_ctx->readSize;
            flow->isSCTPExplicitEOR = he_ctx->isSCTPExplicitEOR;
            flow->firstWritePending = 1;
            flow->isPolling = 0;
            usrsctp_set_upcall(he_ctx->sock, handle_upcall, (void *)flow);
            free(he_ctx);
        } else {
            flow->closefx(he_ctx->nc, flow);
            free(he_ctx);
        }
    } else {
        return -1;
    }
    return 0;
}

static int
neat_close_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->sock) {
        usrsctp_close(flow->sock);
    }
    return 0;
}

static int
neat_shutdown_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (usrsctp_shutdown(flow->sock, SHUT_WR) == 0) {
        return NEAT_OK;
    } else {
        return NEAT_ERROR_IO;
    }
}

#define SCTP_EVENT_READ    0x0001
#define SCTP_EVENT_WRITE   0x0002
#define SCTP_EVENT_ERROR   0x0004


static void handle_upcall(struct socket *sock, void *arg, int flags)
{
    neat_flow *flow = (neat_flow *)arg;
    if (flow) {
        neat_ctx *ctx = flow->ctx;
        neat_log(NEAT_LOG_DEBUG, "%s", __func__);

        int events = usrsctp_get_events(sock);

        if ((events & SCTP_EVENT_READ) && flow->acceptPending) {
            do_accept(ctx, flow);
            return;
        }

        if ((events & SCTP_EVENT_WRITE) && flow->firstWritePending) {
            flow->firstWritePending = 0;
            io_connected(ctx, flow, NEAT_OK);
        }

        for (unsigned int stream = 0; stream < flow->stream_count; ++stream) {
            if (events & SCTP_EVENT_WRITE && flow->isDraining[stream]) {
                neat_error_code code = neat_write_flush(ctx, flow, stream);
                if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
                    io_error(ctx, flow, stream, code);
                    return;
                }
                if (!flow->isDraining[stream]) {
                    io_all_written(ctx, flow, stream);
                }
            }
            if (events & SCTP_EVENT_WRITE) {
                io_writable(ctx, flow, stream, NEAT_OK);
            }
        }

        if (events & SCTP_EVENT_READ) {
            neat_error_code code;

            do {
                code = io_readable(ctx, flow, NEAT_OK);
            } while (code == READ_OK);
        }
    }
}

static int
neat_listen_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow)
{
    int enable = 1;
    socklen_t len;
    int size, protocol;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    socklen_t slen =
        (flow->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);

    protocol = neat_stack_to_protocol(neat_base_stack(flow->sockStack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", flow->sockStack);
        return -1;
    }

    if (!(flow->sock = usrsctp_socket(flow->family, flow->sockType, protocol, NULL, NULL, 0, NULL))) {
        neat_log(NEAT_LOG_ERROR, "%s: user_socket failed - %s", __func__, strerror(errno));
        return -1;
    }
    usrsctp_set_non_blocking(flow->sock, 1);
    usrsctp_set_upcall(flow->sock, handle_upcall, (void *)flow);
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(flow->sock, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        flow->writeSize = size;
    } else {
        flow->writeSize = 0;
    }
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(flow->sock, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        flow->readSize = size;
    } else {
        flow->readSize = 0;
    }
    flow->writeLimit = flow->writeSize / 4;

#ifdef SCTP_NODELAY
    usrsctp_setsockopt(flow->sock, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
        if (usrsctp_setsockopt(flow->sock, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            flow->isSCTPExplicitEOR = 1;
#endif
    usrsctp_setsockopt(flow->sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    char addrbuf[slen];
    neat_log(NEAT_LOG_INFO, "%s: Bind to %s", __func__,
        inet_ntop(AF_INET, &(((struct sockaddr_in *)flow->sockAddr)->sin_addr), addrbuf, slen));
    if (usrsctp_bind(flow->sock, (struct sockaddr *)(flow->sockAddr), slen) == -1) {
        neat_log(NEAT_LOG_ERROR, "%s: Error binding usrsctp socket - %s", __func__, strerror(errno));
        return -1;
    }
    if (usrsctp_listen(flow->sock, 1) == -1) {
        neat_log(NEAT_LOG_ERROR, "%s: Error listening on usrsctp socket - %s", __func__, strerror(errno));
        return -1;
    }
    return 0;
}


#endif


// this function needs to accept all the data (buffering if necessary)
neat_error_code
neat_write(struct neat_ctx *ctx, struct neat_flow *flow,
           const unsigned char *buffer, uint32_t amt)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    return flow->writefx(ctx, flow, buffer, amt, 0);
}

neat_error_code
neat_write_ex(struct neat_ctx *ctx, struct neat_flow *flow,
              const unsigned char *buffer, uint32_t amt, int stream_id)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    return flow->writefx(ctx, flow, buffer, amt, stream_id);
}

neat_error_code
neat_read(struct neat_ctx *ctx, struct neat_flow *flow,
          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    return flow->readfx(ctx, flow, buffer, amt, actualAmt);
}

neat_error_code
neat_shutdown(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->sockStack) == NEAT_STACK_SCTP)
        return neat_shutdown_via_usrsctp(ctx, flow);
#endif
    return flow->shutdownfx(ctx, flow);
}

neat_flow *neat_new_flow(neat_ctx *mgr)
{
    neat_flow *rv;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    rv = (neat_flow *)calloc (1, sizeof (neat_flow));

    if (!rv)
        return NULL;

    rv->handle = NULL;
    rv->writefx = neat_write_to_lower_layer;
    rv->readfx = neat_read_from_lower_layer;
    LIST_INIT(&(rv->he_cb_ctx_list));
    rv->fd = -1;
    rv->acceptfx = neat_accept_via_kernel;
    rv->connectfx = neat_connect;
    rv->closefx = neat_close_socket;
    rv->close2fx = neat_close_socket_2;
    rv->listenfx = neat_listen;
    rv->shutdownfx = neat_shutdown_via_kernel;
    rv->bufferedMessages = NULL;
    rv->buffer_count = 0;
#if defined(USRSCTP_SUPPORT)
    rv->sock = NULL;
    rv->acceptusrsctpfx = neat_accept_via_usrsctp;
#endif
    return rv;
}

neat_error_code
neat_flow_init(struct neat_ctx *ctx, struct neat_flow* flow,
                               uint64_t flags, int capacity_profile,
                               struct neat_flow_security *sec)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    return NEAT_ERROR_UNABLE;
}

// Notify application about congestion via callback
// Set ecn to true if ECN signalled congestion.
// Set rate to non-zero if wanting to signal a new *maximum* bitrate
void neat_notify_cc_congestion(neat_flow *flow, int ecn, uint32_t rate)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations ||!flow->operations->on_slowdown) {
	return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_slowdown(flow->operations, ecn, rate);
}

// Notify application about new max. bitrate
// Set rate to the new advised maximum bitrate
void neat_notify_cc_hint(neat_flow *flow, int ecn, uint32_t rate)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_rate_hint) {
	return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_rate_hint(flow->operations, rate);
}

// Notify application about a failed send.
// Set errorcode in cause, context to msg.-context-id from WRITE,
// unsent_buffer points at the failed message. Context is optional,
// set to -1 if not specified.
void neat_notify_send_failure(neat_flow *flow, neat_error_code code,
			      int context, const unsigned char *unsent_buffer)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_ctx *ctx = flow->ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_send_failure) {
	return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_send_failure(flow->operations, context, unsent_buffer);
}

// Notify application about timeout
void neat_notify_timeout(neat_flow *flow)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_timeout) {
	return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_timeout(flow->operations);
}

// Notify application about an aborted connection
// TODO: this should perhaps return a status code?
void neat_notify_aborted(neat_flow *flow)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_aborted) {
	return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_aborted(flow->operations);
}

// Notify application a connection has closed
void neat_notify_close(neat_flow *flow)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_close) {
	return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_close(flow->operations);
}

// Notify application about network changes.
// Code should identify what happened.
void neat_notify_network_status_changed(neat_flow *flow, neat_error_code code)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_ctx *ctx = flow->ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations || !flow->operations->on_network_status_changed) {
	return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_network_status_changed(flow->operations);
}

// CLOSE, D1.2 sect. 3.2.4
neat_error_code neat_close(struct neat_ctx *ctx, struct neat_flow *flow)
{
    // KAH: free_cb actually does the closefx() call

    // This code is copied from neat_free_flow
    // TODO consider a refactor...
    if (flow->isPolling)
        uv_poll_stop(flow->handle);

    if ((flow->handle != NULL) &&
        (flow->handle->type != UV_UNKNOWN_HANDLE))
        uv_close((uv_handle_t *)(flow->handle), free_cb);

    return NEAT_OK;
}

// ABORT, D1.2 sect. 3.2.4
neat_error_code neat_abort(struct neat_ctx *ctx, struct neat_flow *flow)
{
    struct linger ling;

    ling.l_onoff = 1;
    ling.l_linger = 0;

#if !defined(USRSCTP_SUPPORT)
    setsockopt(flow->fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));
#else
    usrsctp_setsockopt(flow->sock, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));
#endif

    neat_close(ctx, flow);

    return NEAT_OK;
}
