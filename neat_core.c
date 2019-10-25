#include <sys/types.h>
#include <netinet/in.h>
#if defined(USRSCTP_SUPPORT)
#include <usrsctp.h>
#else
#if defined(HAVE_NETINET_SCTP_H) && !defined(USRSCTP_SUPPORT)
#ifdef __linux__
#include <netinet/sctp.h>
#else // __linux__
#include <netinet/sctp.h>
#include <netinet/udplite.h>
#endif // __linux__
#endif // defined(HAVE_NETINET_SCTP_H) && !defined(USRSCTP_SUPPORT)
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <uv.h>
#include <errno.h>
#include <ifaddrs.h>

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
#include "neat_stat.h"
#include "neat_resolver_helpers.h"
#include "neat_json_helpers.h"
#include "neat_unix_json_socket.h"
#include "neat_pm_socket.h"

#if defined(USRSCTP_SUPPORT)
#include "neat_usrsctp_internal.h"
#include <usrsctp.h>
#endif // defined(USRSCTP_SUPPORT)

#ifdef __linux__
#include "neat_linux_internal.h"
#endif // __linux__

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include "neat_bsd_internal.h"
#endif

static void intHandler();
static void nt_update_poll_handle(neat_ctx *ctx, neat_flow *flow, uv_poll_t *handle);
static neat_error_code nt_write_flush(struct neat_ctx *ctx, struct neat_flow *flow);
static int nt_listen_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow,
                                  struct neat_pollable_socket *listen_socket);
#if defined(USRSCTP_SUPPORT)
static int nt_connect_via_usrsctp(struct neat_he_candidate *candidate);
static int nt_listen_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow,
                                   struct neat_pollable_socket *listen_socket);
static int nt_close_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow);
static int nt_shutdown_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow);
static void handle_upcall(struct socket *s, void *arg, int flags);
static void handle_connect(struct socket *s, void *arg, int flags);
static void nt_sctp_init_events(struct socket *sock);
#else // defined(USRSCTP_SUPPORT)
static void nt_sctp_init_events(int sock);
#endif // defined(USRSCTP_SUPPORT)

#ifdef SCTP_MULTISTREAMING
static neat_flow *nt_sctp_get_flow_by_sid(struct neat_pollable_socket *socket, uint16_t sid);
static void nt_sctp_reset_stream(struct neat_pollable_socket *socket, uint16_t sid);
static void nt_hook_mulitstream_flows(neat_flow *flow);
#ifdef SCTP_RESET_STREAMS
static void nt_sctp_handle_reset_stream(struct neat_pollable_socket *socket, struct sctp_stream_reset_event *notfn);
#endif // SCTP_RESET_STREAMS
#endif // SCTP_MULTISTREAMING

static void nt_free_flow(struct neat_flow *flow);
static int nt_prepare_sctp_socket(struct neat_ctx* ctx, struct neat_pollable_socket* pollable_socket);

static neat_flow * do_accept(neat_ctx *ctx, neat_flow *flow, struct neat_pollable_socket *socket);
neat_flow * nt_find_flow(neat_ctx *, struct sockaddr_storage *, struct sockaddr_storage *);

static void io_all_written(neat_ctx *ctx, neat_flow *flow, uint16_t stream_id);

#define TAG_STRING(tag) [tag] = #tag
const char *neat_tag_name[NEAT_TAG_LAST] = {
    TAG_STRING(NEAT_TAG_STREAM_ID),
    TAG_STRING(NEAT_TAG_STREAM_COUNT),
    TAG_STRING(NEAT_TAG_LOCAL_NAME),
    TAG_STRING(NEAT_TAG_LOCAL_ADDRESS),
    TAG_STRING(NEAT_TAG_SERVICE_NAME),
    TAG_STRING(NEAT_TAG_CONTEXT),
    TAG_STRING(NEAT_TAG_PARTIAL_RELIABILITY_METHOD),
    TAG_STRING(NEAT_TAG_PARTIAL_RELIABILITY_VALUE),
    TAG_STRING(NEAT_TAG_PARTIAL_MESSAGE_RECEIVED),
    TAG_STRING(NEAT_TAG_PARTIAL_SEQNUM),
    TAG_STRING(NEAT_TAG_UNORDERED),
    TAG_STRING(NEAT_TAG_UNORDERED_SEQNUM),
    TAG_STRING(NEAT_TAG_DESTINATION_IP_ADDRESS),
    TAG_STRING(NEAT_TAG_PRIORITY),
    TAG_STRING(NEAT_TAG_FLOW_GROUP),
    TAG_STRING(NEAT_TAG_CC_ALGORITHM),
    TAG_STRING(NEAT_TAG_TRANSPORT_STACK),
    TAG_STRING(NEAT_TAG_CHANNEL_NAME)
};

#define MIN(a,b) (((a)<(b))?(a):(b))

static void intHandler() {
    exit(0);
}

//Intiailize the OS-independent part of the context, and call the OS-dependent
//init function
struct neat_ctx *
neat_init_ctx()
{
    struct neat_ctx *nc;
    struct neat_ctx *ctx = NULL;

    nc = calloc(1, sizeof(struct neat_ctx));

    if (!nc) {
        return NULL;
    }
    nc->loop = calloc(1, sizeof(uv_loop_t));
    nc->pvd = NULL;

    if (nc->loop == NULL) {
        free(nc);
        return NULL;
    }

    nc->error = NEAT_OK;
    nc->log_level = NEAT_LOG_DEBUG;

    nt_log_init(nc);
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    // TODO: Disable these checks for non-debug builds
    if (sizeof(neat_tag_name) / sizeof(neat_tag_name[0]) != NEAT_TAG_LAST) {
        nt_log(nc, NEAT_LOG_DEBUG,
                 "Warning: Expected %d tag names, but found %d tag names",
                 NEAT_TAG_LAST,
                 sizeof(neat_tag_name) / sizeof(*neat_tag_name));
    }

    for (int i = 0; i < NEAT_TAG_LAST; ++i) {
        if (neat_tag_name[i] == NULL) {
            nt_log(nc, NEAT_LOG_DEBUG, "Warning: Missing one or more tag names (index %d)", i);
            break;
        }
    }

    uv_loop_init(nc->loop);
    LIST_INIT(&(nc->src_addrs));
    LIST_INIT(&(nc->flows));

    uv_timer_init(nc->loop, &(nc->addr_lifetime_handle));
    nc->addr_lifetime_handle.data = nc;
    uv_timer_start(&(nc->addr_lifetime_handle),
                   nt_addr_lifetime_timeout_cb,
                   1000 * NEAT_ADDRESS_LIFETIME_TIMEOUT,
                   1000 * NEAT_ADDRESS_LIFETIME_TIMEOUT);
    nt_security_init(nc);
#if defined(USRSCTP_SUPPORT)
    if (usr_intern.num_ctx == 0) {
        nt_usrsctp_init(nc);
    }
    nt_usrsctp_init_ctx(nc);
#endif
#if defined(__linux__)
    ctx = nt_linux_init_ctx(nc);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    ctx = nt_bsd_init_ctx(nc);
#else
    uv_loop_close(nc->loop);
#endif
    if (!ctx) {
        free(nc->loop);
        free(nc);
    }
#if defined(USRSCTP_SUPPORT)
    usr_intern.num_ctx++;
#endif
    return ctx;
}

//Start the internal NEAT event loop
//TODO: Add support for embedding libuv loops in other event loops
neat_error_code
neat_start_event_loop(struct neat_ctx *nc, neat_run_mode run_mode)
{
    signal(SIGINT, intHandler);
    if (run_mode == NEAT_RUN_DEFAULT)
        nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    uv_run(nc->loop, (uv_run_mode) run_mode);
    uv_loop_close(nc->loop);
    return nc->error;
}

void
neat_stop_event_loop(struct neat_ctx *nc)
{
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);
    if (nc && nc->loop) {
        uv_stop(nc->loop);
    }
}

int
neat_get_backend_fd(struct neat_ctx *nc)
{
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    return uv_backend_fd(nc->loop);
}

uv_loop_t
*neat_get_event_loop(struct neat_ctx *ctx)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    assert(ctx);

    return ctx->loop;
}

/*
 * Terminate a NEAT context upon error.
 * Errors are reported back to the user through neat_start_event_loop.
 */
void
nt_ctx_fail_on_error(struct neat_ctx *nc, neat_error_code error)
{
    if (error == NEAT_OK)
        return;

    nc->error = error;
    neat_stop_event_loop(nc);
}

int
neat_get_backend_timeout(struct neat_ctx *nc)
{
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    return uv_backend_timeout(nc->loop);
}

static void
nt_walk_cb(uv_handle_t *handle, void *ctx)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    // Bug fix (karlgrin, 170323).
    if ((handle == NULL) || (handle->data == NULL))
        return;

    //HACK: Can't stop the IDLE handle used by resolver. Should probably do
    //something more advanced in case we use other idle handles
    if (handle->type == UV_IDLE) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - handle->type == UV_IDLE - skipping", __func__);
        return;
    }

    if (!uv_is_closing(handle)) {
        // If this assert triggers, then some handle is not being closed
        // correctly. A handle with a data pointer should already be closed
        // before this point since the next uv_close operation will not free
        // any handles. In other words, you have a memory leak.
        assert(handle->data);

        nt_log(ctx, NEAT_LOG_DEBUG, "%s - closing handle", __func__);
        uv_close(handle, NULL);
    }
}

//Free any resource used by the context. Loop must be stopped before this is
//called
//TODO: Consider adding callback, like for resolver
void
neat_free_ctx(struct neat_ctx *nc)
{
    struct neat_flow *flow, *prev_flow = NULL;
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    if (!nc) {
        return;
    }

    if (nc->resolver) {
        nt_resolver_release(nc->resolver);
    }

    while (!LIST_EMPTY(&nc->flows)) {
        flow = LIST_FIRST(&nc->flows);

        /*
         * If this assert triggers, it means that a call to neat_free_flow did
         * not remove the flow pointed to by f from the list of flows. The
         * assert is present because clang-analyzer somehow doesn't see the fact
         * that the list is changed in nt_free_flow().
         */
        assert(flow != prev_flow);
        if (flow == prev_flow) {
            nt_log(nc, NEAT_LOG_ERROR, "%s - nt_free_flow() failed", __func__);
        }
        /* NEAT is shutting down. Make sure that close callback is called here,
         * since there is no main loop any more. */
        if (!flow->socket->multistream
#ifdef SCTP_MULTISTREAMING
            || flow->socket->sctp_streams_used == 0
#endif
        ) {
            flow->closefx(flow->ctx, flow);
        }

        if (flow->operations.on_close) {
            //READYCALLBACKSTRUCT;
            flow->operations.on_close(&flow->operations);
        }

        nt_free_flow(flow);
        prev_flow = flow;
    }

    //uv_run(nc->loop, UV_RUN_NOWAIT);

    uv_walk(nc->loop, nt_walk_cb, nc);

    //Let all close handles run
    uv_run(nc->loop, UV_RUN_DEFAULT);
    uv_loop_close(nc->loop);

    nt_addr_free_src_list(nc);

    if (nc->cleanup) {
        nc->cleanup(nc);
    }

    if (nc->event_cbs) {
        free(nc->event_cbs);
    }

    if (nc->pvd) {
        neat_pvd_release(nc->pvd);
        free(nc->pvd);
    }

    free(nc->loop);

    nt_security_close(nc);
    nt_log_close(nc);
    free(nc);
#if defined(USRSCTP_SUPPORT)
    usr_intern.num_ctx--;
#endif
}

//The three functions that deal with the NEAT callback API. Nothing very
//interesting, register a callback, run all callbacks and remove callbacks
uint8_t nt_add_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    uint8_t i = 0;
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr;
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    if (event_type > NEAT_MAX_EVENT)
        return RETVAL_FAILURE;

    //Do not initialize callback array before we have to, in case no-one will
    //use the callback API
    if (!nc->event_cbs) {
        nc->event_cbs = calloc(NEAT_MAX_EVENT + 1,
                               sizeof(struct neat_event_cbs));

        if (!nc->event_cbs)
            return RETVAL_FAILURE;

        for (i = 0; i < NEAT_MAX_EVENT; i++)
            LIST_INIT(&(nc->event_cbs[i]));
    }

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next) {

        if (cb_itr == cb) {
            //TODO: Debug level
            nt_log(nc, NEAT_LOG_INFO, "%s - Callback for %u has already been added", __func__, event_type);
            return RETVAL_FAILURE;
        }
    }

    //TODO: Debug level
    nt_log(nc, NEAT_LOG_INFO, "%s - Added new callback for event type %u", __func__, event_type);
    LIST_INSERT_HEAD(cb_list_head, cb, next_cb);
    return RETVAL_SUCCESS;
}

uint8_t nt_remove_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    struct neat_event_cbs *cb_list_head = NULL;
    struct neat_event_cb *cb_itr = NULL;
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    if (event_type > NEAT_MAX_EVENT || !nc->event_cbs)
        return RETVAL_FAILURE;

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next) {
        if (cb_itr == cb)
            break;
    }

    if (cb_itr) {
        //TODO: Debug level print
        nt_log(nc, NEAT_LOG_INFO, "%s - Removed callback for type %u", __func__, event_type);
        LIST_REMOVE(cb_itr, next_cb);
    }

    return RETVAL_SUCCESS;
}

void
nt_run_event_cb(struct neat_ctx *nc, uint8_t event_type, void *data)
{
    struct neat_event_cbs *cb_list_head = NULL;
    struct neat_event_cb *cb_itr = NULL;
    nt_log(nc, NEAT_LOG_DEBUG, "%s", __func__);

    if (event_type > NEAT_MAX_EVENT ||
        !nc->event_cbs)
        return;

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next)
        cb_itr->event_cb(nc, cb_itr->data, data);
}

struct neat_iofilter *
insert_neat_iofilter(neat_ctx *ctx, neat_flow *flow)
{
    struct neat_iofilter *filter = calloc(1, sizeof (struct neat_iofilter));
    if (filter) {
        filter->next = flow->iofilters;
        flow->iofilters = filter;
    }
    return filter;
}

static void free_iofilters(struct neat_iofilter *filter)
{
    if (!filter) {
        return;
    }
    free_iofilters(filter->next);
    if (filter->dtor) {
        filter->dtor(filter);
    }
    free (filter);
}

static void free_dtlsdata(struct neat_dtls_data *dtls)
{
    if (!dtls) {
        return;
    }
    if (dtls->dtor) {
        dtls->dtor(dtls);
    }
    free (dtls);
    dtls = NULL;
}

static void
on_handle_closed(uv_handle_t *handle)
{
    //nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    free(handle);
}

static void
on_handle_closed_candidate(uv_handle_t *handle)
{
    struct neat_he_candidate *candidate = (struct neat_he_candidate *)handle->data;

    close(candidate->pollable_socket->fd);

    if (candidate->pollable_socket->dtls_data) {
        free_dtlsdata(candidate->pollable_socket->dtls_data);
    }

    free(candidate->pollable_socket);
    free(candidate->if_name);
    json_decref(candidate->properties);
    free(candidate);
    free(handle);
}

void
nt_free_candidate(struct neat_ctx *ctx, struct neat_he_candidate *candidate)
{
    struct neat_he_sockopt *sockopt;
    struct neat_he_sockopt *tmp;
    struct linger so_linger;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (candidate == NULL) {
        return;
    }

    // Enable SO_LINGER so that the following close will abort the connection.
    // It is desired to abort any unused connections.
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;

    if (candidate->prio_timer != NULL) {
        uv_timer_stop(candidate->prio_timer);
        uv_close((uv_handle_t *) candidate->prio_timer, on_handle_closed);
    }

    free(candidate->pollable_socket->dst_address);
    free(candidate->pollable_socket->src_address);

    if (!TAILQ_EMPTY(&(candidate->sock_opts))) {
        TAILQ_FOREACH_SAFE(sockopt, (&candidate->sock_opts), next, tmp) {
            if (sockopt->type == NEAT_SOCKOPT_STRING) {
                free(sockopt->value.s_val);
            }
            TAILQ_REMOVE((&candidate->sock_opts), sockopt, next);
        }
    }

    // We should close the handle of this candidate asynchronously, but only if
    // this handle is not being used by the flow.
    if (candidate->pollable_socket->handle != NULL) {
        if (candidate->pollable_socket->handle == candidate->pollable_socket->flow->socket->handle) {
            nt_log(ctx, NEAT_LOG_DEBUG,"%s: Handle used by flow, flow should release it", __func__);
        } else {
            if (candidate->pollable_socket->fd == -1) {
                nt_log(ctx, NEAT_LOG_DEBUG,"%s: Candidate does not use a socket", __func__);
#if defined(USRSCTP_SUPPORT)
                if (candidate->pollable_socket->usrsctp_socket != NULL) {
                    if (usrsctp_setsockopt(candidate->pollable_socket->usrsctp_socket, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) < 0) {
                        nt_log(ctx, NEAT_LOG_DEBUG, "%s - usrsctp_setsockopt(SO_LINGER) failed", __func__);
                    }

                    usrsctp_close(candidate->pollable_socket->usrsctp_socket);
                }
#endif
                free(candidate->pollable_socket->handle);
            } else if (!uv_is_closing((uv_handle_t*)candidate->pollable_socket->handle)) {
                nt_log(ctx, NEAT_LOG_DEBUG,"%s: Release candidate after closing (%d)", __func__,
                       candidate->pollable_socket->fd);
                if (setsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(struct linger)) < 0) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - setsockopt(SO_LINGER) failed", __func__);
                }
                candidate->pollable_socket->handle->data = candidate;
                uv_close((uv_handle_t*)candidate->pollable_socket->handle, on_handle_closed_candidate);
                return;
            } else {
                nt_log(ctx, NEAT_LOG_DEBUG,"%s: Candidate handle is already closing", __func__);
            }
        }
    }

    if (candidate->pollable_socket->dtls_data) {
        free (candidate->pollable_socket->dtls_data->userData);
        candidate->pollable_socket->dtls_data->userData = NULL;
        free (candidate->pollable_socket->dtls_data);
        candidate->pollable_socket->dtls_data = NULL;
    }
    free(candidate->pollable_socket);
    free(candidate->if_name);
    json_decref(candidate->properties);
    free(candidate);
}

void
nt_free_candidates(struct neat_ctx *ctx, struct neat_he_candidates *candidates)
{
    struct neat_he_candidate *candidate;
    struct neat_he_candidate *tmp;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (candidates == NULL) {
        return;
    }

    TAILQ_FOREACH_SAFE(candidate, candidates, next, tmp) {
        nt_free_candidate(ctx, candidate);
    }

    free(candidates);
}

static void
synchronous_free(neat_flow *flow)
{
    nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    assert(flow);
    assert(flow->socket);

    free((char *)flow->name);
    free((char *)flow->server_pem);
    free((char *)flow->cert_pem);
    free((char *)flow->key_pem);

    if (flow->cc_algorithm) {
        free((char*)flow->cc_algorithm);
    }
    if (flow->resolver_results) {
        nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s - neat_resolver_free_results", __func__);
        nt_resolver_free_results(flow->resolver_results);
    } else {
        nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s - NOT neat_resolver_free_results", __func__);
    }

    json_decref(flow->properties);

    free_iofilters(flow->iofilters);
    free_dtlsdata(flow->socket->dtls_data);
    free(flow->readBuffer);

    if (!flow->socket->multistream
#ifdef SCTP_MULTISTREAMING
        || flow->socket->sctp_streams_used == 0
#endif
    ) {
        free(flow->socket->handle);
#if defined(USRSCTP_SUPPORT)
        if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
            if (flow->socket->usrsctp_socket) {
                usrsctp_close(flow->socket->usrsctp_socket);
            }
        }
#endif
        free(flow->socket);
    }

    free(flow);
}

static void
socket_handle_free_cb(uv_handle_t *handle)
{
    struct neat_pollable_socket *pollable_socket = handle->data;
#ifdef SCTP_MULTISTREAMING
    struct neat_flow *flow = NULL;
    struct neat_flow *next_flow = NULL;
#endif

    assert(pollable_socket);

    if (pollable_socket->multistream) {
#ifdef SCTP_MULTISTREAMING

#if 0
        while (!LIST_EMPTY(&pollable_socket->sctp_multistream_flows)) {
            flow = LIST_FIRST(&pollable_socket->sctp_multistream_flows);
            assert(flow);
            LIST_REMOVE(flow, multistream_next_flow);
            synchronous_free(flow);
        }
#else
        LIST_FOREACH_SAFE(flow, &(pollable_socket->sctp_multistream_flows), multistream_next_flow, next_flow) {
            LIST_REMOVE(flow, multistream_next_flow);
            synchronous_free(flow);
        }
#endif
        //assert(pollable_socket->sctp_streams_used == 0);

        //free(pollable_socket->handle);
        //free(pollable_socket);
#else
        assert(false);
#endif

    } else {
        synchronous_free(pollable_socket->flow);
    }
}

static void
listen_socket_handle_free_cb(uv_handle_t *handle)
{
    struct neat_pollable_socket *pollable_socket = handle->data;
    //struct neat_ctx *ctx = pollable_socket->flow->ctx;
    //nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    free(pollable_socket);
    free(handle);
}

static int
nt_close_socket(struct neat_ctx *ctx, struct neat_flow *flow)
{
    struct neat_pollable_socket *listening_socket;
    struct neat_pollable_socket *listening_socket_temp;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#if defined(USRSCTP_SUPPORT)
    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        nt_close_via_usrsctp(flow->ctx, flow);
        return 0;
    }
#endif

    // close all listening sockets
    TAILQ_FOREACH_SAFE(listening_socket, &(flow->listen_sockets), next, listening_socket_temp) {
        assert(listening_socket->fd > 0);
        close(listening_socket->fd);
    }

    // close active socket
    close(flow->socket->fd);
    return 0;
}

void
nt_free_flow(neat_flow *flow)
{
    struct neat_ctx *ctx = flow->ctx;
    struct neat_pollable_socket *listen_socket;
    struct neat_pollable_socket *listen_socket_temp;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    nt_log(ctx, NEAT_LOG_INFO, "%s - removing %p", __func__, flow);
    LIST_REMOVE(flow, next_flow);



#if defined(USRSCTP_SUPPORT)
    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
       synchronous_free(flow);
       return;
    }
#endif

    nt_free_candidates(ctx, flow->candidate_list);
    flow->candidate_list = NULL;

    // close all listening sockets
    TAILQ_FOREACH_SAFE(listen_socket, &(flow->listen_sockets), next, listen_socket_temp) {
        if (!uv_is_closing((uv_handle_t *)listen_socket->handle)) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - closing listening handle and waiting for listen_socket_handle_free_cb", __func__);
            uv_close((uv_handle_t *)(listen_socket->handle), listen_socket_handle_free_cb);
        } else {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - listen handle is already closing", __func__);
        }
    }

#ifdef SCTP_MULTISTREAMING
    if (flow->socket->multistream) {
        LIST_REMOVE(flow, multistream_next_flow);
    }
#endif

    // close handles for active flow
    if (flow->socket->handle != NULL && flow->socket->handle->type != UV_UNKNOWN_HANDLE
#ifdef SCTP_MULTISTREAMING
        && (!flow->socket->multistream || flow->socket->sctp_streams_used == 0)
#endif
    ) {
        if (!uv_is_closing((uv_handle_t *)flow->socket->handle)) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - closing handle and waiting for socket_handle_free_cb", __func__);
            uv_close((uv_handle_t *)(flow->socket->handle), socket_handle_free_cb);
        } else {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - handle is already closing", __func__);
        }
    } else {
        synchronous_free(flow);
    }
}

neat_error_code
neat_set_property(neat_ctx *ctx, neat_flow *flow, const char *properties)
{
    json_t *prop, *props;
    json_t *val;
    json_error_t error;
    const char *key;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    nt_log(ctx, NEAT_LOG_DEBUG, "%s - %s", __func__, properties);

    if (strlen(properties) != 0) {
        props = json_loads(properties, 0, &error);
        if (props == NULL) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Error in property string, line %d col %d",
            error.line, error.position);
            nt_log(ctx, NEAT_LOG_DEBUG, "%s", error.text);

            return NEAT_ERROR_BAD_ARGUMENT;
        }

        json_object_foreach(props, key, prop) {
            if (strcmp(key, "transport") == 0) {
                val = json_object_get(prop, "value");
                assert(val);
                if (json_typeof(val) == JSON_STRING) {
                    if (strcmp(json_string_value(val), "WEBRTC") == 0) {
                        flow->webrtcEnabled = true;
                    }
                }
            }

            // This step is not strictly required, but informs of overwritten keys
            if (json_object_del(flow->properties, key) == 0) {
                nt_log(ctx, NEAT_LOG_DEBUG, "Existing property %s was overwritten!", key);
            }

            json_object_set(flow->properties, key, prop);
        }

        json_decref(props);
    } else {
        nt_log(ctx, NEAT_LOG_DEBUG, "User did not specify any properties!");
    }

#if 0
    char *buffer = json_dumps(flow->properties, JSON_INDENT(2));
    nt_log(ctx, NEAT_LOG_DEBUG, "Flow properties are now:\n%s\n", buffer);
    free(buffer);
#endif

    return NEAT_OK;
}

neat_error_code
neat_get_property(neat_ctx *ctx, neat_flow *flow, const char* name, void *ptr, size_t *size)
{
    json_t *prop;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->properties == NULL) {
        nt_log(ctx, NEAT_LOG_DEBUG, "Flow has no properties (properties == NULL)");
        return NEAT_ERROR_UNABLE;
    }

    prop = json_object_get(flow->properties, name);

    if (prop == NULL) {
        nt_log(ctx, NEAT_LOG_DEBUG, "Flow has no property named %s");
        return NEAT_ERROR_UNABLE;
    }

    prop = json_object_get(prop, "value");
    if (prop == NULL) {
        nt_log(ctx, NEAT_LOG_DEBUG, "Flow has property %s, but it contains no \"value\" key!");
        return NEAT_ERROR_UNABLE;
    }

    switch (json_typeof(prop)) {
    case JSON_STRING:
        {
            size_t str_len = json_string_length(prop);
            if (str_len + 1 > *size) {
                *size = str_len + 1;
                return NEAT_ERROR_MESSAGE_TOO_BIG;
            }

            strncpy(ptr, json_string_value(prop), *size);
            *size = str_len;

            break;

        }
    case JSON_INTEGER:
        {
            if (sizeof(json_int_t) > *size) {
                *size = sizeof(json_int_t);
                return NEAT_ERROR_MESSAGE_TOO_BIG;
            }

            *((json_int_t*)ptr) = json_integer_value(prop);
            *size = sizeof(json_int_t);

            break;
        }
    case JSON_TRUE:
    case JSON_FALSE:
        {
            if (sizeof(json_int_t) > *size) {
                *size = sizeof(json_int_t);
                return NEAT_ERROR_MESSAGE_TOO_BIG;
            }

            *((json_int_t*)ptr) = json_is_true(prop);
            *size = sizeof(json_int_t);

            break;
        }
    default:
        return NEAT_ERROR_UNABLE;
    }

    return NEAT_OK;
}


int
nt_get_stack(neat_ctx* mgr, neat_flow* flow)
{
    return flow->socket->stack;
}

neat_error_code
neat_set_operations(neat_ctx *ctx, neat_flow *flow, struct neat_flow_operations *ops)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (&flow->operations != ops) {
        int transport_protocol = flow->operations.transport_protocol;

        // only copy when not trying to set the same ops again
        flow->operations = *ops;
        flow->operations.transport_protocol = transport_protocol;
    }

    if (flow->socket == NULL) {
        return NEAT_OK;
    }

#if defined(USRSCTP_SUPPORT)
    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
     //   handle_upcall(flow->socket->usrsctp_socket, flow->socket, 0);
        return NEAT_OK;
    }
#endif

    nt_update_poll_handle(ctx, flow, flow->socket->handle);
    return NEAT_OK;
}

/* Return statistics about the flow in JSON format
   NB - the memory allocated for the return string must be freed
   by the caller */
neat_error_code
neat_get_stats(neat_ctx *ctx, char **json_stats)
{
      nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

      nt_stats_build_json(ctx, json_stats);

      return NEAT_OK;
}

#define READYCALLBACKSTRUCT \
    flow->operations.status = code;\
    flow->operations.stream_id = stream_id;\
    flow->operations.ctx = ctx;\
    flow->operations.flow = flow;

void
nt_io_error(neat_ctx *ctx, neat_flow *flow, neat_error_code code)
{
    const int stream_id = NEAT_INVALID_STREAM;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow) {
        nt_log(ctx, NEAT_LOG_ERROR, "Called nt_io_error() with invalid flow");
        return;
    }

    if (!flow->operations.on_error) {
        return;
    }
    READYCALLBACKSTRUCT;
    flow->operations.on_error(&flow->operations);
}

static void
io_connected(neat_ctx *ctx, neat_flow *flow, neat_error_code code)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    const int stream_id = NEAT_INVALID_STREAM;
#if defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)
    unsigned int statuslen;
    int rc;
    struct sctp_status status;
#endif // defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)
#if defined(IPPROTO_SCTP) && defined(SCTP_INTERLEAVING_SUPPORTED) && !defined(USRSCTP_SUPPORT)
    unsigned int valuelen;
    struct sctp_assoc_value value;
#endif // #if defined(IPPROTO_SCTP) && defined(SCTP_INTERLEAVING_SUPPORTED) && !defined(USRSCTP_SUPPORT)
    char proto[16];

    switch (flow->socket->stack) {
        case NEAT_STACK_UDP:
            snprintf(proto, 16, "UDP");
            break;
        case NEAT_STACK_TCP:
            snprintf(proto, 16, "TCP");
            break;
        case NEAT_STACK_MPTCP:
            snprintf(proto, 16, "MPTCP");
            break;
        case NEAT_STACK_SCTP:
            snprintf(proto, 16, "SCTP");
#if defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)
            statuslen = sizeof(status);
            rc = getsockopt(flow->socket->fd, IPPROTO_SCTP, SCTP_STATUS, &status, &statuslen);
            if (rc < 0) {
                nt_log(ctx, NEAT_LOG_DEBUG, "Call to getsockopt(SCTP_STATUS) failed");
                flow->socket->sctp_streams_available = 1;
            } else {
                flow->socket->sctp_streams_available = MIN(status.sstat_outstrms, status.sstat_outstrms);
            }
            // number of outbound streams == number of inbound streams
            nt_log(ctx, NEAT_LOG_INFO, "%s - SCTP - number of streams: %d", __func__, flow->socket->sctp_streams_available);
#endif // defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)

#if defined(IPPROTO_SCTP) && defined(SCTP_INTERLEAVING_SUPPORTED) && !defined(USRSCTP_SUPPORT)
            valuelen = sizeof(value);
            rc = getsockopt(flow->socket->fd, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &value, &valuelen);
            if (rc < 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "Call to getsockopt(SCTP_INTERLEAVING_SUPPORTED) failed");
            } else {
                nt_log(ctx, NEAT_LOG_INFO, "SCTP - I-DATA support: %s", value.assoc_value == 0 ? "disabled" : "enabled");
            }
#endif // defined(IPPROTO_SCTP) && defined(SCTP_INTERLEAVING_SUPPORTED) && !defined(USRSCTP_SUPPORT)
            break;
        case NEAT_STACK_UDPLITE:
            snprintf(proto, 16, "UDPLite");
            break;
        case NEAT_STACK_SCTP_UDP:
            snprintf(proto, 16, "SCTP/UDP");
            break;
        case NEAT_STACK_WEBRTC:
            snprintf(proto, 16, "WebRTC");
            break;
        default:
            snprintf(proto, 16, "stack%d", flow->socket->stack);
            break;
    }

    nt_log(ctx, NEAT_LOG_INFO, "Connected: %s/%s", proto, (flow->socket->family == AF_INET ? "IPv4" : "IPv6"));

    flow->operations.transport_protocol = flow->socket->stack;
    flow->state = NEAT_FLOW_OPEN;

    if (flow->operations.on_connected) {
        READYCALLBACKSTRUCT;
        flow->operations.on_connected(&flow->operations);
    }

#ifdef NEAT_SCTP_DTLS
    if (flow->security_needed && nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        nt_dtls_connect(ctx, flow);
    }
#endif
}

static void
io_writable(neat_ctx *ctx, neat_flow *flow, neat_error_code code)
{
    const uint16_t stream_id = NEAT_INVALID_STREAM;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    // we have buffered data, send to socket
    if (flow->isDraining) {
        code = nt_write_flush(ctx, flow);
        if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
            nt_log(ctx, NEAT_LOG_ERROR, "error : %d", code);
            nt_notify_aborted(flow);
            nt_io_error(ctx, flow, code);
            return;
        }
    // no buffered datat, notifiy application about writable flow
    } else if (flow->operations.on_writable) {
        READYCALLBACKSTRUCT;
        flow->operations.on_writable(&flow->operations);
    }

    // flow is not draining (anymore)
    if (!flow->isDraining) {
        if (flow->isClosing) {
            // neat_shutdown has been called while flow was draining, run shutdown procedure
            neat_shutdown(ctx, flow);
        } else {
            // outgoing flow buffer is empty
            io_all_written(ctx, flow, 0);
        }
    }
}

// Translate SCTP cause codes (RFC4960 sect.3.3.10)
// into NEAT error codes
static neat_error_code
sctp_to_neat_code(uint16_t sctp_code)
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

#define READ_OK 0
#define READ_WITH_ERROR 1
#define READ_WITH_ZERO 2

#if defined(HAVE_NETINET_SCTP_H) || defined(USRSCTP_SUPPORT)

// Handle SCTP association change events
// includes shutdown complete, etc.
static void
handle_sctp_assoc_change(neat_flow *flow, struct sctp_assoc_change *sac)
{
    unsigned int i, n;
    struct neat_ctx *ctx = flow->ctx;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    switch (sac->sac_state) {
        case SCTP_SHUTDOWN_COMP:
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - state : SCTP_SHUTDOWN_COMP", __func__);
            //nt_notify_close(flow);
            break;

        case SCTP_COMM_LOST:
            // Draft specifies to return cause code, D1.2 doesn't - we
            // follow D1.2
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - state : SCTP_COMM_LOST", __func__);
            //nt_notify_aborted(flow);
            break;

            // Fallthrough:
        case SCTP_COMM_UP: // Fallthrough:
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - state : SCTP_COMM_UP", __func__);
            // TODO: Allocate send buffers here instead?
            break;

        case SCTP_RESTART:
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - state : SCTP_RESTART", __func__);
            // TODO: might want to "translate" the state codes to a NEAT code.
            nt_notify_network_status_changed(flow, sac->sac_state);
            break;
    }

    n = sac->sac_length - sizeof(struct sctp_assoc_change);
    if (((sac->sac_state == SCTP_COMM_UP) ||
        (sac->sac_state == SCTP_RESTART)) && (n > 0)) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - supported features", __func__);
        for (i = 0; i < n; i++) {
            switch (sac->sac_info[i]) {
#ifdef SCTP_ASSOC_SUPPORTS_PR
                case SCTP_ASSOC_SUPPORTS_PR:
                    nt_log(ctx, NEAT_LOG_DEBUG, "\t- PR");
                    flow->socket->sctp_partial_reliability = 1;
                    break;
#endif // SCTP_ASSOC_SUPPORTS_PR

#ifdef SCTP_ASSOC_SUPPORTS_AUTH
                case SCTP_ASSOC_SUPPORTS_AUTH:
                    nt_log(ctx, NEAT_LOG_DEBUG, "\t- AUTH");
                    break;
#endif // SCTP_ASSOC_SUPPORTS_AUTH

#ifdef SCTP_ASSOC_SUPPORTS_ASCONF
                case SCTP_ASSOC_SUPPORTS_ASCONF:
                    nt_log(ctx, NEAT_LOG_DEBUG, "\t- ASCONF");
                    break;
#endif // SCTP_ASSOC_SUPPORTS_ASCONF

#ifdef SCTP_ASSOC_SUPPORTS_MULTIBUF
                case SCTP_ASSOC_SUPPORTS_MULTIBUF:
                    nt_log(ctx, NEAT_LOG_DEBUG, "\t- MULTIBUF");
                    break;
#endif

#ifdef SCTP_ASSOC_SUPPORTS_RE_CONFIG
                case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
                    nt_log(ctx, NEAT_LOG_DEBUG, "\t- RE-CONFIG");
#ifdef SCTP_MULTISTREAMING
                    flow->socket->sctp_stream_reset = 1;
                    if (flow->socket->sctp_neat_peer) {
                        flow->socket->multistream = 1;
                        flow->socket->flow = NULL;
                        flow->socket->sctp_streams_used = 1;
                        flow->multistream_id = 0;

                        assert(LIST_EMPTY(&flow->socket->sctp_multistream_flows));
                        LIST_INSERT_HEAD(&flow->socket->sctp_multistream_flows, flow, multistream_next_flow);
                        nt_log(ctx, NEAT_LOG_INFO, "Multistreaming enabled");
                    }
#endif
                    break;
#endif // SCTP_ASSOC_SUPPORTS_RE_CONFIG
                default:
                    nt_log(ctx, NEAT_LOG_DEBUG, "\t- UNKNOWN(0x%02x)", sac->sac_info[i]);
                    break;
            }
        }
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
    nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s", __func__);

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

    nt_notify_send_failure(flow, sctp_to_neat_code(error), context, unsent_msg);
}


// Handle notifications about SCTP events
static int
handle_sctp_event(neat_flow *flow, union sctp_notification *notfn)
{
    struct neat_ctx *ctx = flow->ctx;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#ifdef SCTP_MULTISTREAMING
    flow->socket->sctp_notification_recvd = 1;
#endif

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
            nt_log(ctx, NEAT_LOG_DEBUG, "Got SCTP peer address change event");
            break;
        case SCTP_REMOTE_ERROR:
            nt_log(ctx, NEAT_LOG_DEBUG, "Got SCTP remote error event");
            break;
        case SCTP_SHUTDOWN_EVENT:
            nt_log(ctx, NEAT_LOG_DEBUG, "Got SCTP shutdown event");
            flow->eofSeen               = 1;
            flow->readBufferMsgComplete = 1;
            return READ_WITH_ZERO;
            break;
        case SCTP_ADAPTATION_INDICATION:
            nt_log(ctx, NEAT_LOG_DEBUG, "Got SCTP adaptation indication event");
            struct sctp_adaptation_event *adaptation = (struct sctp_adaptation_event *) notfn;
            if (adaptation->sai_adaptation_ind == SCTP_ADAPTATION_NEAT) {
                nt_log(ctx, NEAT_LOG_INFO, "Peer is NEAT enabled");
#ifdef SCTP_MULTISTREAMING
                flow->socket->sctp_neat_peer = 1;
                if (flow->socket->sctp_stream_reset) {
                    flow->socket->multistream = 1;
                    flow->socket->flow = NULL;
                    flow->socket->sctp_streams_used = 1;
                    flow->multistream_id = 0;

                    assert(LIST_EMPTY(&flow->socket->sctp_multistream_flows));
                    LIST_INSERT_HEAD(&flow->socket->sctp_multistream_flows, flow, multistream_next_flow);
                    nt_log(ctx, NEAT_LOG_INFO, "Multistreaming enabled");
                }

                //nt_hook_mulitstream_flows(flow);
#endif // SCTP_MULTISTREAMING

            }
            break;
        case SCTP_PARTIAL_DELIVERY_EVENT:
            nt_log(ctx, NEAT_LOG_DEBUG, "Got SCTP partial delivery event");
            break;
#ifdef SCTP_RESET_STREAMS
        case SCTP_STREAM_RESET_EVENT:
            nt_log(ctx, NEAT_LOG_DEBUG, "Got SCTP Stream Reset");
#ifdef SCTP_MULTISTREAMING
            nt_sctp_handle_reset_stream(flow->socket, (struct sctp_stream_reset_event *) notfn);
#endif // SCTP_MULTISTREAMING
#endif // SCTP_RESET_STREAMS
            break;
        default:
            nt_log(ctx, NEAT_LOG_WARNING, "Got unhandled SCTP event type %d", notfn->sn_header.sn_type);
    }
    return READ_OK;
}
#endif // defined(HAVE_NETINET_SCTP_H) || defined(USRSCTP_SUPPORT)

static int
resize_read_buffer(neat_flow *flow)
{
    ssize_t spaceFree;
    ssize_t spaceNeeded, spaceThreshold;

    assert(flow);
    assert(flow->socket);

    spaceFree = flow->readBufferAllocation - flow->readBufferSize;
    if (flow->socket->read_size > 0) {
        spaceThreshold = (flow->socket->read_size / 4 + 8191) & ~8191;
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
    return READ_OK;
}

static int
io_readable(neat_ctx *ctx, neat_flow *flow, struct neat_pollable_socket *socket, neat_error_code code)
{
    struct sockaddr_storage peerAddr;
    socklen_t peerAddrLen = sizeof(struct sockaddr_storage);
    int stream_id   = -1;
    ssize_t n       = 0;
    char buffer[1];
    struct msghdr msghdr;
    //Not used when notifications aren't available:
#ifdef MSG_NOTIFICATION
    int sctp_event_ret = 0;
#endif //MSG_NOTIFICATION

#ifdef SCTP_MULTISTREAMING
    unsigned char *multistream_buffer = NULL;
    struct neat_flow *multistream_flow = NULL;
    struct neat_read_queue_message *multistream_message = NULL;
#endif // SCTP_MULTISTREAMING

#if !defined(USRSCTP_SUPPORT)

#if defined(SCTP_RCVINFO)
    struct sctp_rcvinfo *rcvinfo;
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
#elif defined (SCTP_SNDRCV)
    struct sctp_sndrcvinfo *sndrcvinfo;
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
#endif // defined(SCTP_RCVINFO)

#if (defined(SCTP_RCVINFO) || defined (SCTP_SNDRCV))
    struct cmsghdr *cmsg;
#endif
    struct iovec iov;

#else // !defined(USRSCTP_SUPPORT)
    struct sockaddr_in addr;
    socklen_t len;
    unsigned int infotype;
    struct sctp_recvv_rn rn;
    socklen_t infolen = sizeof(struct sctp_recvv_rn);
#endif // !defined(USRSCTP_SUPPORT)

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#ifdef NEAT_SCTP_DTLS
    if (flow->security_needed && nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
#if !defined(USRSCTP_SUPPORT)
        socklen_t len;
#endif // !defined(USRSCTP_SUPPORT)
        int ret = 0;
        struct security_data *private = (struct security_data *) flow->socket->dtls_data->userData;

        if (resize_read_buffer(flow) != READ_OK) {
            nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 7", __func__);
            return READ_WITH_ERROR;
        }

        len = SSL_read(private->ssl, flow->readBuffer + flow->readBufferSize,
                       flow->readBufferAllocation - flow->readBufferSize);
        switch (SSL_get_error(private->ssl, len)) {
            case SSL_ERROR_NONE:
                nt_log(ctx, NEAT_LOG_DEBUG, "%s: DTLS read %d bytes", __func__, len);
                flow->readBufferSize += len;
                flow->readBufferMsgComplete = 1;
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                /* Just try again */
                break;
            case SSL_ERROR_ZERO_RETURN:
                nt_log(ctx, NEAT_LOG_DEBUG, "%s: EOF received",  __func__);
                ret = READ_WITH_ZERO;
                flow->readBufferMsgComplete = 1;
                break;
            case SSL_ERROR_SYSCALL:
                nt_log(ctx, NEAT_LOG_DEBUG, "SSL_ERROR_SYSCALL: %s (%d)\n", ERR_error_string(ERR_get_error(), (char *)flow->readBuffer + flow->readBufferSize), SSL_get_error(private->ssl, len));
                neat_abort(ctx, flow);
                return READ_WITH_ERROR;
            case SSL_ERROR_SSL:
                nt_log(ctx, NEAT_LOG_DEBUG, "SSL_ERROR_SSL: %s (%d)\n", ERR_error_string(ERR_get_error(), (char *)flow->readBuffer + flow->readBufferSize), SSL_get_error(private->ssl, len));
                neat_abort(ctx, flow);
                return READ_WITH_ERROR;
            default:
                nt_log(ctx, NEAT_LOG_ERROR, "%s - Unexpected error while reading down!", __func__);
                break;
        }
        if (flow->operations.on_readable) {
            READYCALLBACKSTRUCT;
            flow->operations.on_readable(&flow->operations);
        }
        return ret;
    }
#endif

    /*
     * The UDP Accept flow isn't going to have on_readable set,
     * anything else will.
     */
    if (!flow->operations.on_readable && flow->acceptPending) {
        if (socket->stack != NEAT_STACK_UDP && socket->stack != NEAT_STACK_UDPLITE) {
            nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 1", __func__);
            return READ_WITH_ERROR;
        }
    }

    if ((socket->stack == NEAT_STACK_UDP || socket->stack == NEAT_STACK_UDPLITE) && (!flow->readBufferMsgComplete)) {
        if (resize_read_buffer(flow) != READ_OK) {
            nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 2", __func__);
            return READ_WITH_ERROR;
        }

        if (socket->stack == NEAT_STACK_UDP || socket->stack == NEAT_STACK_UDPLITE) {
            if (!flow->acceptPending && !flow->operations.on_readable) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 3", __func__);
                return READ_WITH_ERROR;
            }

            if ((n = recvfrom(socket->fd, flow->readBuffer, flow->readBufferAllocation, 0, (struct sockaddr *)&peerAddr, &peerAddrLen)) < 0)  {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 4", __func__);
                return READ_WITH_ERROR;
            }

            flow->readBufferSize = n;
            flow->readBufferMsgComplete = 1;

            if (n == 0) {
                flow->readBufferMsgComplete = 0;
                nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 5", __func__);
                return READ_WITH_ZERO;
            }

            if (flow->acceptPending) {
                flow->readBufferMsgComplete = 0;

                neat_flow *newFlow = nt_find_flow(ctx, &socket->src_sockaddr, &peerAddr);

                if (!newFlow) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - Creating new UDP flow", __func__);

                    memcpy(&socket->dst_sockaddr, &peerAddr, sizeof(struct sockaddr_storage));
                    newFlow = do_accept(ctx, flow, socket);
                }

                assert(newFlow);

                if (resize_read_buffer(newFlow) != READ_OK) {
                    nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 6", __func__);
                    return READ_WITH_ERROR;
                }
                newFlow->readBufferSize = n;
                newFlow->readBufferMsgComplete = 1;

                memcpy(newFlow->readBuffer, flow->readBuffer, newFlow->readBufferSize);

                newFlow->acceptPending = 0;
                io_readable(ctx, newFlow, newFlow->socket, NEAT_OK);

                return READ_WITH_ZERO;
            }
        }
    }

    if ((nt_base_stack(socket->stack) == NEAT_STACK_SCTP) && ((!flow->readBufferMsgComplete) || socket->multistream)) {

        if (resize_read_buffer(flow) != READ_OK) {
            nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 7", __func__);
            return READ_WITH_ERROR;
        }

#if !defined(USRSCTP_SUPPORT)
        if (socket->multistream) {
#ifdef SCTP_MULTISTREAMING

            nt_log(ctx, NEAT_LOG_INFO, "%s - allocating %d bytes", __func__, socket->read_size);
            if ((multistream_buffer = malloc(socket->read_size)) == NULL) {
                nt_log(ctx, NEAT_LOG_ERROR, "%s - allocating multistream buffer failed", __func__);
                return READ_WITH_ERROR;
            }

            iov.iov_base = multistream_buffer;
            iov.iov_len = socket->read_size;
#else // SCTP_MULTISTREAMING
            assert(false);
#endif // SCTP_MULTISTREAMING

        } else {
            if (resize_read_buffer(flow) != READ_OK) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 8", __func__);
                return READ_WITH_ERROR;
            }

            iov.iov_base = flow->readBuffer + flow->readBufferSize;
            iov.iov_len = flow->readBufferAllocation - flow->readBufferSize;
        }


        msghdr.msg_name = NULL;
        msghdr.msg_namelen = 0;
        msghdr.msg_iov = &iov;
        msghdr.msg_iovlen = 1;

#if defined(SCTP_RCVINFO) || defined(SCTP_SNDRCV)
        msghdr.msg_control = cmsgbuf;
        msghdr.msg_controllen = sizeof(cmsgbuf);
#else // defined(SCTP_RCVINFO) || defined(SCTP_SNDRCV)
        msghdr.msg_control = NULL;
        msghdr.msg_controllen = 0;
#endif // defined(SCTP_RCVINFO) || defined(SCTP_SNDRCV)

        msghdr.msg_flags = 0;

        if ((n = recvmsg(socket->fd, &msghdr, 0)) < 0) {
#ifdef SCTP_MULTISTREAMING
            if (multistream_buffer) {
                free(multistream_buffer);
            }
#endif
            nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 9 - %s", __func__, strerror(errno));
            return READ_WITH_ERROR;
        }

        // felix XXX polish me!
        if (n == 0) {
            flow->eofSeen = 1;
        }


#if (defined(SCTP_RCVINFO) || defined (SCTP_SNDRCV))
        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
            if (cmsg->cmsg_len == 0) {
                nt_log(ctx, NEAT_LOG_DEBUG, "%s - Error in ancilliary data from recvmsg", __func__);
                break;
            }
#ifdef IPPROTO_SCTP
            if (cmsg->cmsg_level == IPPROTO_SCTP) {
#if defined (SCTP_RCVINFO)
                if (cmsg->cmsg_type == SCTP_RCVINFO) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - got SCTP_RCVINFO", __func__);
                    rcvinfo     = (struct sctp_rcvinfo *)CMSG_DATA(cmsg);
                    stream_id   = rcvinfo->rcv_sid;

                }
#elif defined (SCTP_SNDRCV)
                if (cmsg->cmsg_type == SCTP_SNDRCV) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - got SCTP_SNDRCV", __func__);
                    sndrcvinfo  = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
                    stream_id   = sndrcvinfo->sinfo_stream;
                }
#endif // defined (SCTP_SNDRCV)
#if defined (SCTP_NXTINFO)
                if (cmsg->cmsg_type == SCTP_NXTINFO) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - got SCTP_NXTINFO", __func__);
                    //sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
                    //stream_id = sndrcvinfo->sinfo_stream;
                }
#endif // defined (SCTP_NXTINFO)
                if (stream_id >= 0) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - Received %d bytes on SCTP stream %d", __func__, n, stream_id);
                }
            }
#endif // defined(IPPROTP_SCTP)
        }
#endif // (defined(SCTP_RCVINFO) || defined (SCTP_SNDRCV))

        //flags = msghdr.msg_flags; // For notification handling
#else // !defined(USRSCTP_SUPPORT)
        len = sizeof(struct sockaddr);
        memset((void *)&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
        addr.sin_len = sizeof(struct sockaddr_in);
#endif
        addr.sin_family = AF_INET;
        msghdr.msg_flags = 0;
        n = usrsctp_recvv(socket->usrsctp_socket,
                            flow->readBuffer + flow->readBufferSize,
                            flow->readBufferAllocation - flow->readBufferSize,
                            (struct sockaddr *) &addr,
                            &len,
                            (void *)&rn,
                            &infolen,
                            &infotype,
                            &(msghdr.msg_flags));
        if (n < 0) {
            if (errno == EAGAIN) {
                //return READ_OK;
                nt_log(ctx, NEAT_LOG_WARNING, "%s - usrsctp_recvv error EAGAIN", __func__);
            }
            nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 10 - usrsctp_recvv error", __func__);
            return READ_WITH_ERROR;
        }
#endif // else !defined(USRSCTP_SUPPORT)
        // Same handling for both kernel and userspace SCTP
#if defined(MSG_NOTIFICATION)
        if (msghdr.msg_flags & MSG_NOTIFICATION) {
            // Event notification
            nt_log(ctx, NEAT_LOG_INFO, "SCTP event notification");

            if (!(msghdr.msg_flags & MSG_EOR)) {
                nt_log(ctx, NEAT_LOG_WARNING, "buffer overrun reading SCTP notification");
                // TODO: handle this properly
                nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 11", __func__);
                return READ_WITH_ERROR;
            }

#ifdef SCTP_MULTISTREAMING
            if (socket->multistream) {
                sctp_event_ret = handle_sctp_event(flow, (union sctp_notification*)(multistream_buffer));
                free(multistream_buffer);
            } else {
                sctp_event_ret = handle_sctp_event(flow, (union sctp_notification*)(flow->readBuffer + flow->readBufferSize));
            }
#else // SCTP_MULTISTREAM
            sctp_event_ret = handle_sctp_event(flow, (union sctp_notification*)(flow->readBuffer + flow->readBufferSize));
#endif // SCTP_MULTISTREAM

            return sctp_event_ret;

        }
#endif //defined(MSG_NOTIFICATION)

#ifdef SCTP_MULTISTREAMING
        if (socket->sctp_notification_wait) {
            socket->sctp_notification_wait = 0;
            nt_log(ctx, NEAT_LOG_ERROR, "%s - got all SCTP notifications", __func__);
        }

        if (stream_id > 0 && socket->sctp_neat_peer) {
            // felix todo: ppid check
            if ((multistream_flow = nt_sctp_get_flow_by_sid(socket, stream_id)) == NULL) {
                nt_log(ctx, NEAT_LOG_INFO, "%s - new incoming multistream flow - stream_id %d", __func__, stream_id);

                neat_flow *listen_flow  = flow->socket->listen_socket->flow;
                multistream_flow        = neat_new_flow(ctx);

                if (!multistream_flow) {
                    nt_log(ctx, NEAT_LOG_WARNING, "unable to create new flow");
                    return READ_WITH_ERROR;
                }

                multistream_flow->name                      = strdup(listen_flow->name);
                if (!multistream_flow->name) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Out of memory");
                    return READ_WITH_ERROR;
                }
                multistream_flow->port                      = listen_flow->port;
                multistream_flow->everConnected             = 1;
                multistream_flow->socket                    = socket;
                multistream_flow->ctx                       = ctx;
                multistream_flow->isServer                  = 1;
                multistream_flow->operations.on_connected   = listen_flow->operations.on_connected;
                multistream_flow->operations.on_readable    = listen_flow->operations.on_readable;
                multistream_flow->operations.on_writable    = listen_flow->operations.on_writable;
                multistream_flow->operations.on_close       = listen_flow->operations.on_close;
                multistream_flow->operations.on_error       = listen_flow->operations.on_error;
                multistream_flow->operations.ctx            = ctx;
                multistream_flow->operations.flow           = multistream_flow;
                multistream_flow->operations.userData       = listen_flow->operations.userData;
                multistream_flow->multistream_id            = stream_id;
                multistream_flow->state                     = NEAT_FLOW_OPEN;

                LIST_INSERT_HEAD(&flow->socket->sctp_multistream_flows, multistream_flow, multistream_next_flow);

                socket->sctp_streams_used++;
                free(multistream_buffer);

                multistream_flow->operations.on_connected(&multistream_flow->operations);

                return READ_OK;
            }
        }
#endif // SCTP_MULTISTREAMING

        if (socket->multistream && n > 0) {
#ifdef SCTP_MULTISTREAMING
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - got data for multistream flow %d", __func__, stream_id);

            multistream_flow = nt_sctp_get_flow_by_sid(socket, stream_id);
            assert(multistream_flow);

            // felix : SCTP EXPLICIT_EOR!
            if ((multistream_message = calloc(1, sizeof(struct neat_read_queue_message))) == NULL) {
                nt_log(ctx, NEAT_LOG_ERROR, "%s - allocating multistream queue element failed", __func__);
                return NEAT_ERROR_UNABLE;
            }

            if (n > 0) {
                multistream_message->buffer = realloc(multistream_buffer, n);
            }
            multistream_message->buffer_size = n;

            TAILQ_INSERT_TAIL(&multistream_flow->multistream_read_queue, multistream_message, message_next);

            if (multistream_flow->operations.on_readable) {
                READYCALLBACKSTRUCT;
                multistream_flow->operations.on_readable(&multistream_flow->operations);
            }
            return READ_OK;

#else // SCTP_MULTISTREAMING
            nt_log(ctx, NEAT_LOG_ERROR, "%s - multistream set but not supported", __func__);
            assert(false);
#endif // SCTP_MULTISTREAMING
        } else {

            flow->readBufferSize += n;

            nt_log(ctx, NEAT_LOG_INFO, " %zd bytes received", n);

            if ((msghdr.msg_flags & MSG_EOR) || (n == 0)) {
                flow->readBufferMsgComplete = 1;
            }

            if (!flow->readBufferMsgComplete && flow->preserveMessageBoundaries) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - READ_WITH_ERROR 12", __func__);
                return READ_WITH_ERROR;
            }
#if defined(USRSCTP_SUPPORT)
            if (n == 0) {
                return READ_WITH_ZERO;
            }
#endif //!defined(USRSCTP_SUPPORT)
        }
    }

    if (socket->stack == NEAT_STACK_TCP) {
        n = recv(flow->socket->fd, buffer, 1, MSG_PEEK);
        if (n <= 0) {
            nt_log(ctx, NEAT_LOG_INFO, "%s - TCP connection peek: %d - connection closed", __func__, n);
            socket->is_closed = 1;
            return READ_WITH_ZERO;
        }
    }

    if (socket->stack == NEAT_STACK_SCTP && n == 0 && flow->readBufferSize == 0) {
        //nt_log(ctx, NEAT_LOG_WARNING, "%s - SCTP connection closed and no outstanding messages buffered", __func__);
        socket->is_closed = 1;
        return READ_WITH_ZERO;
    }

    if (flow->operations.on_readable) {
        READYCALLBACKSTRUCT;
        flow->operations.on_readable(&flow->operations);
    }

    return READ_OK;
}

static void
io_all_written(neat_ctx *ctx, neat_flow *flow, uint16_t stream_id)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    stream_id = NEAT_INVALID_STREAM;

    if (!flow->operations.on_all_written || !flow->notifyDrainPending) {
        return;
    }

    flow->notifyDrainPending = 0;

    neat_error_code code = NEAT_OK;
    READYCALLBACKSTRUCT;
    flow->operations.on_all_written(&flow->operations);
}

static void
io_timeout(neat_ctx *ctx, neat_flow *flow)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    const int stream_id = NEAT_INVALID_STREAM;

    if (!flow->operations.on_timeout) {
        return;
    }
    neat_error_code code = NEAT_OK;
    READYCALLBACKSTRUCT;
    flow->operations.on_timeout(&flow->operations);
}

static neat_error_code
nt_write_flush(struct neat_ctx *ctx, struct neat_flow *flow);

static void
nt_update_poll_handle(neat_ctx *ctx, neat_flow *flow, uv_poll_t *handle)
{
    struct neat_pollable_socket *pollable_socket;
    int registered_events = 0;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    assert(handle);
    pollable_socket = handle->data;

#ifdef SCTP_MULTISTREAMING
    if (pollable_socket != NULL && pollable_socket->multistream) {
        flow = LIST_FIRST(&pollable_socket->sctp_multistream_flows);
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - multistreaming - taking first flow from ctx : %p", __func__, flow);

        if (!flow) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - multistreaming - no flow left", __func__);
            return;
        }
    }
#endif

    assert(flow);
    assert(flow->socket);
    assert(flow->socket->handle);

    if (handle->loop == NULL || uv_is_closing((uv_handle_t *)handle)) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - loop is NULL or handle is closing - skipping", __func__);
        return;
    }

    do {
        //nt_log(ctx, NEAT_LOG_DEBUG, "%s - iterating flows ...", __func__);
        assert(flow);

        flow->isPolling = 0;

#if !defined(MSG_NOTIFICATION)
        if (flow->operations.on_readable)
#else
        // If a flow has on_readable set, poll for reading.
        // If a flow is using SCTP for transport, also poll for reading if we're
        // interested in various SCTP events that is reported via SCTP_EVENT etc.
        if (flow->operations.on_readable ||
            (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP &&
            (flow->operations.on_close ||
            flow->operations.on_network_status_changed ||
            flow->operations.on_send_failure)))
#endif
        {
            registered_events |= UV_READABLE;
            flow->isPolling = 1;
        }

        if (flow->operations.on_writable || (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP && flow->firstWritePending)) {
            registered_events |= UV_WRITABLE;
            flow->isPolling = 1;
        }

        if (flow->isDraining) {
            registered_events |= UV_WRITABLE;
            flow->isPolling = 1;
        }

#ifdef SCTP_MULTISTREAMING
        if (flow->socket->sctp_notification_wait) {
            registered_events |= UV_READABLE;
            registered_events |= UV_READABLE;
            flow->isPolling = 1;
        }
#endif

#ifdef SCTP_MULTISTREAMING
        if (pollable_socket && pollable_socket->multistream == 1) {
            flow = LIST_NEXT(flow, multistream_next_flow);
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - next multistream flow : %p", __func__, flow);
        }
#endif

    // iterate over all flows
    } while (pollable_socket != NULL && pollable_socket->multistream == 1 && flow != NULL);

    if (registered_events) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - events - starting poll - %d : %s %s", __func__, registered_events, (registered_events & UV_READABLE) ? "UV_READABLE" : "", (registered_events & UV_WRITABLE) ? "UV_WRITABLE" : "");
        uv_poll_start(handle, registered_events, uvpollable_cb);
    } else {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - no events - stopping poll", __func__);
        uv_poll_stop(handle);
    }
}

static void
free_he_handle_cb(uv_handle_t *handle)
{
    free(handle);
}

/*
 * Installs security if requested by the flow.
 * Returns non-zero if security was requested.
 * If that is the case, the security subsystem takes care of the flow from this point.
 */
static int
install_security(struct neat_he_candidate *candidate)
{
    struct neat_flow *flow = candidate->pollable_socket->flow;
    json_t *security = NULL, *val = NULL;
    json_t *noVerify = NULL, *noVerifyVal = NULL;
    struct neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if ((security = json_object_get(candidate->properties, "security")) != NULL &&
        (val = json_object_get(security, "value")) != NULL &&
        json_typeof(val) == JSON_TRUE)
    {
        assert(!flow->skipCertVerification);
        if (!flow->isServer &&
            (noVerify = json_object_get(candidate->properties, "verification")) != NULL &&
            (noVerifyVal = json_object_get(noVerify, "value")) != NULL &&
            json_typeof(noVerifyVal) == JSON_FALSE) {
            nt_log(ctx, NEAT_LOG_INFO, "Flow disables cert verification");
            flow->skipCertVerification = 1;
        }

        nt_log(ctx, NEAT_LOG_DEBUG, "Flow required security");

        if (neat_security_install(flow->ctx, flow) != NEAT_OK) {
            nt_log(ctx, NEAT_LOG_ERROR, "neat_security_install failed");
            nt_io_error(flow->ctx, flow, NEAT_ERROR_SECURITY);
        }

        return 1;
    } else {
        nt_log(ctx, NEAT_LOG_DEBUG, "Flow did not require security");
        return 0;
    }
}

static void on_pm_he_error(struct neat_ctx *ctx, struct neat_flow *flow, int error);

static void
send_result_connection_attempt_to_pm(neat_ctx *ctx, neat_flow *flow, struct cib_he_res *he_res, _Bool result)
{
    int rc;
    const char *home_dir;
    const char *socket_path;
    char socket_path_buf[128];
    json_t *prop_obj = NULL;
    json_t *result_obj = NULL;
    json_t *result_array = NULL;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    assert(he_res);

    socket_path = getenv("NEAT_CIB_SOCKET");
    if (!socket_path) {
        if ((home_dir = getenv("HOME")) == NULL) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to locate the $HOME directory");
            goto end;
        }

        rc = snprintf(socket_path_buf, 128, "%s/.neat/neat_cib_socket", home_dir);
        if (rc < 0 || rc >= 128) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to construct default path to PM CIB socket");
            goto end;
        }

        socket_path = socket_path_buf;
    }

    prop_obj = json_pack("{s:{s:s},s:{s:s},s:{s:i},s:{s:b,s:i},s:{s:b}}",
        "transport", "value", stack_to_string(he_res->transport ),
        "remote_ip", "value", he_res->remote_ip,
        "port", "value", he_res->remote_port,
        "__he_candidate_success", "value", result, "score", result?5:-5,
        "__cached", "value", 1);
    if (prop_obj == NULL) {
        goto end;
    }

    if (json_object_update_missing(prop_obj, flow->properties) == -1) {
        goto end;
    }

    json_object_del(prop_obj, "interface");

    result_obj = json_pack("{s:[{s:{ss}}],s:b}",
    "match", "interface", "value", he_res->interface, "link", true);
    if (result_obj == NULL) {
        goto end;
    }

    if (json_object_set(result_obj, "properties", prop_obj) == -1) {
        goto end;
    }

    result_array = json_array();
    if (result_array == NULL) {
        goto end;
    }

    if (json_array_append(result_array, result_obj) == -1) {
        goto end;
    }

    nt_log(ctx, NEAT_LOG_INFO, "Sending HE result to PM for caching");
    nt_json_send_once_no_reply(ctx, flow, socket_path, result_array, NULL, on_pm_he_error);

end:
    free(he_res->interface);
    free(he_res->remote_ip);
    free(he_res);

    if (prop_obj) {
        json_decref(prop_obj);
    }

    if (result_obj) {
        json_decref(result_obj);
    }

    if (result_array) {
        json_decref(result_array);
    }
}

static void
he_connected_cb(uv_poll_t *handle, int status, int events)
{
    static unsigned int c = 0;
    const char *proto;
    const char *family;
    struct neat_he_candidate *candidate = handle->data;
    struct neat_flow *flow = candidate->pollable_socket->flow;
    struct neat_he_candidates *candidate_list = flow->candidate_list;
    struct cib_he_res *he_res = NULL;
    struct neat_ctx *ctx = flow->ctx;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    c++;
    nt_log(ctx, NEAT_LOG_DEBUG, "Invocation count: %d - flow: %p", c, flow);

    assert(candidate);
    assert(candidate->pollable_socket);
    assert(flow);

    switch (candidate->pollable_socket->stack) {
    case NEAT_STACK_UDP:
        proto = "UDP";
        break;
    case NEAT_STACK_TCP:
        proto = "TCP";
        break;
    case NEAT_STACK_MPTCP:
        proto = "MPTCP";
        break;
    case NEAT_STACK_SCTP:
        proto = "SCTP";
        break;
    case NEAT_STACK_SCTP_UDP:
        proto = "SCTP/UDP";
        break;
    case NEAT_STACK_UDPLITE:
        proto = "UDPLite";
        break;
    default:
        proto = "?";
        break;
    };

    switch (candidate->pollable_socket->family) {
    case AF_INET:
        family = "IPv4";
        break;
    case AF_INET6:
        family = "IPv6";
        break;
    default:
        family = "?";
        break;
    };

    nt_log(ctx, NEAT_LOG_DEBUG,
             "HE Candidate connected: %8s [%2d] %8s/%s <saddr %s> <dstaddr %s> port %5d priority %d",
             candidate->if_name,
             candidate->if_idx,
             proto,
             family,
             candidate->pollable_socket->src_address,
             candidate->pollable_socket->dst_address,
             candidate->pollable_socket->port,
             candidate->priority);

    int so_error = 0;
    unsigned int len = sizeof(so_error);
    if (getsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {

        nt_log(ctx, NEAT_LOG_DEBUG, "Call to getsockopt for fd %d failed: %s", candidate->pollable_socket->fd, strerror(errno));

        uv_poll_stop(handle);
        uv_close((uv_handle_t*)handle, free_he_handle_cb);

        nt_io_error(candidate->ctx, flow, NEAT_ERROR_INTERNAL);
        return;
    }
    status = so_error;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s - Connection status: %d - %s", __func__, status, strerror(status));

    he_res = calloc(1, sizeof(struct cib_he_res));
    if (!he_res)
        return;

    he_res->interface   = strdup(candidate->if_name);
    if (!he_res->interface) {
        free(he_res);
        return;
    }
    he_res->remote_ip   = strdup(candidate->pollable_socket->dst_address);
    if (!he_res->remote_ip) {
        free(he_res->interface);
        free(he_res);
        return;
    }
    he_res->remote_port = candidate->pollable_socket->port;
    he_res->transport   = candidate->pollable_socket->stack;

    // TODO: In which circumstances do we end up in the three different cases?
    if (flow->firstWritePending) {
        // assert(0);
        nt_log(ctx, NEAT_LOG_DEBUG, "First successful connect (flow->firstWritePending)");

        assert(flow->socket);

        send_result_connection_attempt_to_pm(flow->ctx, flow, he_res, true);

        // Transfer this handle to the "main" polling callback
        // TODO: Consider doing this in some other way that directly calling
        // this callback
        uvpollable_cb(flow->socket->handle, NEAT_OK, events);
    } else if (flow->hefirstConnect && (status == 0)) {
        /* if MPTCP was chosen, don't accept fallback to TCP */
#ifdef MPTCP_SUPPORT
        if (candidate->pollable_socket->stack == NEAT_STACK_MPTCP &&
            candidate->ctx->sys_mptcp_enabled == MPTCP_SYS_DISABLED) {
                uv_poll_stop(handle);
                uv_close((uv_handle_t*)handle, free_he_handle_cb);

                TAILQ_REMOVE(candidate_list, candidate, next);
                free(candidate->pollable_socket->dst_address);
                free(candidate->pollable_socket->src_address);
                free(candidate->pollable_socket);
                free(candidate->if_name);
                json_decref(candidate->properties);
                free(candidate);

                free(he_res->interface);
                free(he_res->remote_ip);
                free(he_res);

                if (!(--flow->heConnectAttemptCount)) {
                    nt_io_error(flow->ctx, flow, NEAT_ERROR_UNABLE);
                }

                return;
        }
#endif // MPTCP_SUPPORT

        flow->hefirstConnect = 0;
        nt_log(ctx, NEAT_LOG_DEBUG, "First successful connect (flow->hefirstConnect)");

        assert(flow->socket);

        // TODO: Security code should be wired back in

        flow->socket->fd = candidate->pollable_socket->fd;
        flow->socket->flow = flow;
        // TODO: Ensure initialization (when using PM)
        assert(flow->socket->handle->loop == NULL);
        free(flow->socket->handle);
        flow->socket->handle                = handle;
        flow->socket->handle->data          = flow->socket;
        flow->socket->family                = candidate->pollable_socket->family;
        flow->socket->type                  = candidate->pollable_socket->type;
        flow->socket->stack                 = candidate->pollable_socket->stack;
        flow->socket->write_size            = candidate->pollable_socket->write_size;
        flow->socket->write_limit           = candidate->pollable_socket->write_limit;
        flow->socket->read_size             = candidate->pollable_socket->read_size;
        flow->socket->sctp_explicit_eor     = candidate->pollable_socket->sctp_explicit_eor;
#ifdef NEAT_SCTP_DTLS
        if (flow->security_needed && flow->socket->stack == NEAT_STACK_SCTP) {
            copy_dtls_data(flow->socket, candidate->pollable_socket);
            free(candidate->pollable_socket->dtls_data->userData);
            candidate->pollable_socket->dtls_data->userData = NULL;
            free(candidate->pollable_socket->dtls_data);
            candidate->pollable_socket->dtls_data = NULL;
        }
#endif

#ifdef SCTP_MULTISTREAMING
        flow->socket->sctp_notification_wait= candidate->pollable_socket->sctp_notification_wait;
#endif

        if (candidate->properties != flow->properties) {
            json_incref(candidate->properties);
            json_decref(flow->properties);
            flow->properties = candidate->properties;
        }

        flow->everConnected = 1;

#if defined(USRSCTP_SUPPORT)
        // TODO:
        // flow->socket->usrsctp_socket = he_ctx->sock;
#endif
        // TODO:
        // flow->ctx = he_ctx->nc;

        flow->isPolling = 1;

        send_result_connection_attempt_to_pm(flow->ctx, flow, he_res, true);

        if (flow->security_needed) {
            if (flow->socket->stack == NEAT_STACK_TCP || flow->socket->stack == NEAT_STACK_UDP) {
                if (!install_security(candidate)) {
                    // Transfer this handle to the "main" polling callback
                    // TODO: Consider doing this in some other way that directly calling
                    // this callback
                    flow->firstWritePending = 1;
                    uvpollable_cb(flow->socket->handle, NEAT_OK, events);
                }
            } else {
                flow->firstWritePending = 1;
                uvpollable_cb(flow->socket->handle, NEAT_OK, events);
            }
        } else {
            flow->firstWritePending = 1;
            uvpollable_cb(flow->socket->handle, NEAT_OK, events);
        }
    } else {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - NOT first connect", __func__);

        if (status == 0) {
            send_result_connection_attempt_to_pm(flow->ctx, flow, he_res, true);
        } else {
            send_result_connection_attempt_to_pm(flow->ctx, flow, he_res, false);
        }

        close(candidate->pollable_socket->fd);
        uv_poll_stop(handle);
        uv_close((uv_handle_t*)handle, free_he_handle_cb);

        nt_log(ctx, NEAT_LOG_DEBUG, "%s:Release candidate", __func__);
        TAILQ_REMOVE(candidate_list, candidate, next);
        free(candidate->pollable_socket->dst_address);
        free(candidate->pollable_socket->src_address);
        if (candidate->pollable_socket->dtls_data) {
            free(candidate->pollable_socket->dtls_data->userData);
            candidate->pollable_socket->dtls_data->userData = NULL;
            free(candidate->pollable_socket->dtls_data);
            candidate->pollable_socket->dtls_data = NULL;
        }
        free(candidate->pollable_socket);
        free(candidate->if_name);
        json_decref(candidate->properties);
        free(candidate);

        if (!(--flow->heConnectAttemptCount)) {
            nt_io_error(flow->ctx, flow, NEAT_ERROR_UNABLE);
            return;
        }
    }
}

void uvpollable_cb(uv_poll_t *handle, int status, int events)
{
    struct neat_pollable_socket *pollable_socket = handle->data;
    neat_flow   *flow       = NULL;
#ifdef SCTP_MULTISTREAMING
    neat_flow   *next_flow  = NULL;
#endif
    neat_ctx    *ctx        = NULL;
    int         result      = NEAT_OK;

    if (pollable_socket->multistream) {
#ifdef SCTP_MULTISTREAMING
        ctx  = LIST_FIRST(&pollable_socket->sctp_multistream_flows)->ctx;
#else
        assert(false);
#endif
    } else {
        flow = pollable_socket->flow;
        ctx  = flow->ctx;
    }

    nt_log(ctx, NEAT_LOG_DEBUG, "%s - status: %d - events: %d", __func__, status, events);

    if ((events & UV_READABLE) && flow && flow->acceptPending) {
        if (pollable_socket->stack == NEAT_STACK_UDP || pollable_socket->stack == NEAT_STACK_UDPLITE) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - UDP or UDPLite accept flow", __func__);
            io_readable(ctx, flow, pollable_socket, NEAT_OK);
        } else {
            do_accept(ctx, flow, pollable_socket);
        }
        return;
    }

    // TODO: Are there cases when we should keep polling?
    if (status < 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "ERROR: %s", uv_strerror(status));

        if (!flow) {
            return;
        }

#if !defined(USRSCTP_SUPPORT)
        if (nt_base_stack(pollable_socket->stack) == NEAT_STACK_TCP ||
            nt_base_stack(pollable_socket->stack) == NEAT_STACK_SCTP)
#else
        if (nt_base_stack(pollable_socket->stack) == NEAT_STACK_TCP)
#endif
        { // special bracing beacuse of ifdef
            int so_error = 0;
            unsigned int len = sizeof(so_error);
            if (getsockopt(flow->socket->fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                nt_log(ctx, NEAT_LOG_DEBUG, "Call to getsockopt failed for FD : %d - %s", flow->socket->fd, strerror(errno));
                nt_io_error(ctx, flow, NEAT_ERROR_INTERNAL);
                return;
            }

            nt_log(ctx, NEAT_LOG_DEBUG, "Socket layer errno: %d (%s)", so_error, strerror(so_error));

            if (so_error == ETIMEDOUT) {
                io_timeout(ctx, flow);
                return;
            } else if (so_error == ECONNRESET) {
                nt_notify_aborted(flow);
            } else if (so_error == EPIPE) {
                nt_notify_aborted(flow);
            }
        }

        nt_log(ctx, NEAT_LOG_ERROR, "Unspecified internal error when polling socket");
        nt_io_error(ctx, flow, NEAT_ERROR_INTERNAL);

        return;
    }

    if (pollable_socket->multistream) {
#ifdef SCTP_MULTISTREAMING
        flow = LIST_FIRST(&pollable_socket->sctp_multistream_flows);
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - multistreaming - taking first flow from ctx", __func__);
        assert(flow);
#else // SCTP_MULTISTREAMING
        assert(false);
#endif
    }

    nt_log(ctx, NEAT_LOG_DEBUG, "%s - %s %s", __func__, (events & UV_READABLE) ? "UV_READABLE" : "", (events & UV_WRITABLE) ? "UV_WRITABLE" : "");

    do {
        assert(flow);

#ifdef SCTP_MULTISTREAMING
        if (flow->socket->sctp_notification_wait) {
            if ((events & UV_READABLE)) {
                nt_log(ctx, NEAT_LOG_DEBUG, "%s - awaiting notifications", __func__);
                io_readable(ctx, flow, pollable_socket, NEAT_OK);
            } else if (flow->socket->sctp_notification_recvd) {
                nt_log(ctx, NEAT_LOG_DEBUG, "%s - got notifications but socket is not readable anymore ...", __func__);
                flow->socket->sctp_notification_wait = 0;
            } else {
                nt_log(ctx, NEAT_LOG_DEBUG, "%s - awaiting notifications, socket not readable yet, skipping...", __func__);
            }
            break;
        }

        next_flow = LIST_NEXT(flow, multistream_next_flow);
#endif

        // newly created flow
        if ((events & UV_WRITABLE) && flow->firstWritePending) {
            flow->firstWritePending = 0;
            io_connected(ctx, flow, NEAT_OK);
        }

        // socket is writable
        if (events & UV_WRITABLE) {
            io_writable(ctx, flow, NEAT_OK);
        }

        // socket is readable
        if (events & UV_READABLE) {
            result = io_readable(ctx, flow, pollable_socket, NEAT_OK);

            if (result == READ_WITH_ZERO || result == READ_WITH_ERROR) {
                break;
            }
        }

#ifdef SCTP_MULTISTREAMING
        // next flow
        flow = next_flow;
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - next flow : %p", __func__, flow);
#endif

        // iterate through all flows
    } while (pollable_socket->multistream && flow);



    if (pollable_socket->is_closed) {
        //nt_log(ctx, NEAT_LOG_WARNING, "%s - OUT", __func__);
        if (!uv_is_closing((uv_handle_t *)handle)) {
            uv_poll_stop(handle);
        }
        if (pollable_socket->multistream) {
#ifdef SCTP_MULTISTREAMING
            while(!LIST_EMPTY(&pollable_socket->sctp_multistream_flows)) {
                flow = LIST_FIRST(&pollable_socket->sctp_multistream_flows);
                LIST_REMOVE(flow, multistream_next_flow);
                nt_notify_close(flow);
            }
#else // SCTP_MULTISTREAMING
            assert(false);
#endif
        } else {
            flow->closefx(flow->ctx, flow);
            nt_notify_close(flow);
        }
    } else {
        flow = pollable_socket->flow;
        nt_update_poll_handle(ctx, flow, handle);
    }
    nt_log(ctx, NEAT_LOG_DEBUG, "%s - finished", __func__);
}

int
neat_getlpaddrs(struct neat_ctx*  ctx,
                struct neat_flow* flow,
                struct sockaddr** addrs,
                const int         local)
{
    struct sockaddr_storage name;
    socklen_t namelen = sizeof(name);

    if ((flow->socket->stack == NEAT_STACK_SCTP) ||
        (flow->socket->stack == NEAT_STACK_SCTP_UDP)) {
#if defined(USRSCTP_SUPPORT)
        if (local) {
            return usrsctp_getladdrs(flow->socket->usrsctp_socket, 0, addrs);
        } else {
            return usrsctp_getpaddrs(flow->socket->usrsctp_socket, 0, addrs);
        }
#elif defined(HAVE_NETINET_SCTP_H)
        if (local) {
            return sctp_getladdrs(flow->socket->fd, 0, addrs);
        } else {
            return sctp_getpaddrs(flow->socket->fd, 0, addrs);
        }
#endif
    } else {
        const int result = (local) ? getsockname(flow->socket->fd, (struct sockaddr*)&name, &namelen) :
                                     getpeername(flow->socket->fd, (struct sockaddr*)&name, &namelen);
        if (result == 0) {
           *addrs = (struct sockaddr*)malloc(namelen);
           if (*addrs) {
              memcpy(*addrs, &name, namelen);
              return 1;
           }
           return -1; // out of memory
        }
    }

    *addrs = NULL;
    return -1;
}

void
neat_freelpaddrs(struct sockaddr* addrs)
{
    free(addrs);
}

static neat_flow *
do_accept(neat_ctx *ctx, neat_flow *flow, struct neat_pollable_socket *listen_socket)
{
    const char *proto = NULL;
    int rc;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    int optval;
#ifdef SCTP_STATUS
    unsigned int optlen;
    struct sctp_status status;
#endif

    neat_flow *newFlow = neat_new_flow(ctx);
    if (newFlow == NULL) {
        nt_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
        return NULL;
    }

    newFlow->name = strdup(flow->name);
    if (newFlow->name == NULL) {
        nt_io_error(ctx, newFlow, NEAT_ERROR_OUT_OF_MEMORY);
        return NULL;
    }

    if (flow->server_pem) {
        newFlow->server_pem = strdup(flow->server_pem);
        if (newFlow->server_pem == NULL) {
            nt_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
            return NULL;
        }
    }

    if (flow->cert_pem) {
        newFlow->cert_pem = strdup(flow->cert_pem);
        if (newFlow->cert_pem == NULL) {
            nt_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
            return NULL;
        }
    }

    if (flow->key_pem) {
        newFlow->key_pem = strdup(flow->key_pem);
        if (newFlow->key_pem == NULL) {
            nt_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
            return NULL;
        }
    }

    newFlow->port               = flow->port;
    newFlow->everConnected      = 1;

    switch (listen_socket->stack) {
        case NEAT_STACK_UDP:
            proto = "UDP";
            break;
        case NEAT_STACK_TCP:
            proto = "TCP";
            break;
        case NEAT_STACK_MPTCP:
            proto = "MPTCP";
            break;
        case NEAT_STACK_SCTP:
            proto = "SCTP";
            break;
        case NEAT_STACK_SCTP_UDP:
            proto = "SCTP/UDP";
            break;
        case NEAT_STACK_UDPLITE:
            proto = "UDPLite";
            break;
        default:
            proto = "?";
            break;
    };

    json_decref(newFlow->properties);
    newFlow->properties = json_pack("{"\
                 /* "transport" */  "s{ss}"\
                 /* "port"      */  "s{si}"\
                 /* "interface" */  "s{ss}"\
                                    "}",
                                    "transport", "value", proto,
                                    "port", "value", flow->port,
                                    "interface", "value", "(unknown)");

    newFlow->socket->listen_socket      = listen_socket;
    newFlow->socket->stack              = listen_socket->stack;
    newFlow->socket->src_sockaddr       = listen_socket->src_sockaddr;
    newFlow->socket->dst_sockaddr       = listen_socket->dst_sockaddr;
    newFlow->socket->type               = listen_socket->type;
    newFlow->socket->family             = listen_socket->family;
    newFlow->socket->write_limit        = listen_socket->write_limit;
    newFlow->socket->write_size         = listen_socket->write_size;
    newFlow->socket->read_size          = listen_socket->read_size;
    newFlow->socket->sctp_explicit_eor  = listen_socket->sctp_explicit_eor;

    nt_log(ctx, NEAT_LOG_INFO, "%s - write_size %d - read_size %d", __func__, listen_socket->write_size, listen_socket->read_size);

    newFlow->ctx                = ctx;
    newFlow->isServer           = 1;
    newFlow->isMultihoming      = flow->isMultihoming;
    newFlow->security_needed    = flow->security_needed;
    newFlow->eofSeen            = 0;

    newFlow->operations.on_connected   = flow->operations.on_connected;
    newFlow->operations.on_readable    = flow->operations.on_readable;
    newFlow->operations.on_writable    = flow->operations.on_writable;
    newFlow->operations.on_close       = flow->operations.on_close;
    newFlow->operations.on_error       = flow->operations.on_error;
    newFlow->operations.ctx            = ctx;
    newFlow->operations.flow           = flow;
    newFlow->operations.userData       = flow->operations.userData;

#ifdef NEAT_SCTP_DTLS
    if (flow->security_needed && newFlow->socket->stack == NEAT_STACK_SCTP) {
        if (copy_dtls_data(newFlow->socket, listen_socket) != NEAT_OK) {
            return NULL;
        }
        struct security_data *server = (struct security_data *) listen_socket->dtls_data->userData;
        SSL_CTX_up_ref(server->ctx);
    }
#endif

    switch (newFlow->socket->stack) {
        case NEAT_STACK_SCTP_UDP:
        case NEAT_STACK_SCTP:
#if defined(USRSCTP_SUPPORT)
            newFlow->socket->usrsctp_socket = newFlow->acceptusrsctpfx(ctx, newFlow, listen_socket);
            if (!newFlow->socket->usrsctp_socket) {
                nt_free_flow(newFlow);
                return NULL;
            } else {
                nt_log(ctx, NEAT_LOG_DEBUG, "USRSCTP io_connected");
                io_connected(ctx, newFlow, NEAT_OK);
                nt_sctp_init_events(newFlow->socket->usrsctp_socket);
                newFlow->acceptPending = 0;
            }
#else
            nt_log(ctx, NEAT_LOG_DEBUG, "Creating new SCTP socket");
            newFlow->socket->fd = newFlow->acceptfx(ctx, newFlow, listen_socket->fd);
            if (newFlow->socket->fd == -1) {
                nt_free_flow(newFlow);
                return NULL;
            } else {
#ifndef USRSCTP_SUPPORT
                // Subscribe to events needed for callbacks
                nt_sctp_init_events(newFlow->socket->fd);
#endif
                uv_poll_init(ctx->loop, newFlow->socket->handle, newFlow->socket->fd); // makes fd nb as side effect
                newFlow->socket->handle->data = newFlow->socket;
#ifdef NEAT_SCTP_DTLS
                if (newFlow->security_needed) {
                    struct security_data *private = (struct security_data *) newFlow->socket->dtls_data->userData;
                    private->ssl = SSL_new(private->ctx);
                    private->dtlsBIO = BIO_new_dgram_sctp(newFlow->socket->fd, BIO_CLOSE);
                    if (private->dtlsBIO != NULL) {
                        SSL_set_bio(private->ssl, private->dtlsBIO, private->dtlsBIO);
                    } else {
                        nt_log(ctx, NEAT_LOG_ERROR, "Creating new BIO failed");
                    }
                }
#endif
                io_connected(ctx, newFlow, NEAT_OK);
                uvpollable_cb(newFlow->socket->handle, NEAT_OK, 0);
            }

#if defined(SCTP_RECVRCVINFO)
            // Enable anciliarry data when receiving data from SCTP
            optval = 1;
            rc = setsockopt(newFlow->socket->fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &optval, sizeof(optval));
            if (rc < 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SCTP_RECVRCVINFO) failed");
            }
#endif // defined(SCTP_RECVRCVINFO)
#if defined(SCTP_RECVNXTINFO)
            // Enable anciliarry data when receiving data from SCTP
            optval = 1;
            rc = setsockopt(newFlow->socket->fd, IPPROTO_SCTP, SCTP_RECVNXTINFO, &optval, sizeof(optval));
            if (rc < 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SCTP_RECVNXTINFO) failed");
            }
#endif // defined(SCTP_RECVNXTINFO)
#endif
            break;
        case NEAT_STACK_UDP:
            nt_log(ctx, NEAT_LOG_DEBUG, "Creating new UDP socket");
            newFlow->socket->fd = socket(newFlow->socket->family, newFlow->socket->type, IPPROTO_UDP);

            if (newFlow->socket->fd == -1) {
                nt_free_flow(newFlow);
                return NULL;
            } else {

                if (newFlow->security_needed) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "UDP Server Security");
                    if (neat_security_install(newFlow->ctx, newFlow) != NEAT_OK) {
                        nt_io_error(flow->ctx, flow, NEAT_ERROR_SECURITY);
                    }
                }
                optval = 1;
                rc = setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SO_REUSEADDR) failed");
                }

                rc = setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SO_REUSEPORT) failed");
                }

                rc = bind(newFlow->socket->fd, (struct sockaddr*) &newFlow->socket->src_sockaddr, sizeof(struct sockaddr));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to bind() failed");
                    return NULL;
                }

                rc = connect(newFlow->socket->fd, (struct sockaddr*) &newFlow->socket->dst_sockaddr, sizeof(struct sockaddr));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to connect() failed");
                    return NULL;
                }

                newFlow->everConnected = 1;

                uv_poll_init(ctx->loop, newFlow->socket->handle, newFlow->socket->fd); // makes fd nb as side effect

                newFlow->socket->handle->data = newFlow->socket;

                io_connected(ctx, newFlow, NEAT_OK);
                uvpollable_cb(newFlow->socket->handle, NEAT_OK, 0);
            }
            break;
        case NEAT_STACK_UDPLITE:
#if defined(__NetBSD__) || defined(__APPLE__)
            assert(0); // Should not reach this point
#else
            nt_log(ctx, NEAT_LOG_DEBUG, "Creating new UDPLite socket");
            newFlow->socket->fd = socket(newFlow->socket->family, newFlow->socket->type, IPPROTO_UDPLITE);

            if (newFlow->socket->fd == -1) {
                nt_free_flow(newFlow);
                return NULL;
            } else {
                optval = 1;
                rc = setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SO_REUSEADDR) failed");
                }

                rc = setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SO_REUSEPORT) failed");
                }

                rc = bind(newFlow->socket->fd, (struct sockaddr*) &newFlow->socket->src_sockaddr, sizeof(struct sockaddr));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to bind() failed");
                    return NULL;
                }

                rc = connect(newFlow->socket->fd, (struct sockaddr*) &newFlow->socket->dst_sockaddr, sizeof(struct sockaddr));
                if (rc < 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "Call to connect() failed");
                    return NULL;
                }

                newFlow->everConnected = 1;

                uv_poll_init(ctx->loop, newFlow->socket->handle, newFlow->socket->fd); // makes fd nb as side effect

                newFlow->socket->handle->data = newFlow->socket;

                io_connected(ctx, newFlow, NEAT_OK);
                uvpollable_cb(newFlow->socket->handle, NEAT_OK, 0);
            }
#endif
            break;
    default:
        newFlow->socket->fd = newFlow->acceptfx(ctx, newFlow, listen_socket->fd);
        if (newFlow->socket->fd == -1) {
            nt_free_flow(newFlow);
            return NULL;
        } else {
            uv_poll_init(ctx->loop, newFlow->socket->handle, newFlow->socket->fd); // makes fd nb as side effect

            newFlow->socket->handle->data = newFlow->socket;

            if (newFlow->socket->fd > 0) {
                void *ptr;
                json_t *json;
                struct sockaddr_storage sockaddr;
                socklen_t socklen = sizeof(sockaddr);
                char buffer[INET6_ADDRSTRLEN+1];
                memset(buffer, 0, sizeof(buffer));

                rc = getpeername(newFlow->socket->fd, (struct sockaddr*)&sockaddr, &socklen);
                if (rc == -1) {
                    nt_log(ctx, NEAT_LOG_ERROR, "%s - getpeername(() failed - %s", __func__, strerror(errno));
                }
                assert(rc == 0);

                ptr = (void*)inet_ntop(AF_INET, (void*)&((struct sockaddr_in*)(&sockaddr))->sin_addr, buffer, INET6_ADDRSTRLEN);
                if (!ptr) {
                    nt_log(ctx, NEAT_LOG_ERROR, "%s - inet_ntop() failed", __func__);
                }
                assert(ptr);

                json = json_pack("{ss}", "value", buffer);

                json_object_set(newFlow->properties, "address", json);
                json_decref(json);
            }

            newFlow->acceptPending = 0;

            if ((newFlow->security_needed) && (newFlow->socket->stack == NEAT_STACK_TCP)) {
                nt_log(ctx, NEAT_LOG_DEBUG, "TCP Server Security");
                if (neat_security_install(newFlow->ctx, newFlow) != NEAT_OK) {
                    nt_io_error(flow->ctx, flow, NEAT_ERROR_SECURITY);
                }
            } else {
                io_connected(ctx, newFlow, NEAT_OK);
                uvpollable_cb(newFlow->socket->handle, NEAT_OK, 0);
            }
        }
    }

#if defined(SO_NOSIGPIPE)
    optval = 1;
    rc = setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));
    if (rc < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - Call to setsockopt(SO_NOSIGPIPE) failed", __func__);
    }
#endif //  defined(SO_NOSIGPIPE)

    switch (newFlow->socket->stack) {
#if defined(IPPROTO_SCTP) && defined(SCTP_STATUS)
        case NEAT_STACK_SCTP:
            optlen = sizeof(status);
            rc = getsockopt(newFlow->socket->fd, IPPROTO_SCTP, SCTP_STATUS, &status, &optlen);
            if (rc < 0) {
                nt_log(ctx, NEAT_LOG_DEBUG, "Call to getsockopt(SCTP_STATUS) failed");
                newFlow->socket->sctp_streams_available = 1;
            } else {
                newFlow->socket->sctp_streams_available = MIN(status.sstat_instrms, status.sstat_outstrms);
            }

            // number of outbound streams == number of inbound streams
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - SCTP - number of streams: %d", __func__, newFlow->socket->sctp_streams_available);
            break;
#endif
        default:
            //newFlow->sockestream_count = 1;
            break;
    }

    return newFlow;
}

static void on_pm_error(struct neat_ctx *ctx, struct neat_flow *flow, int error);

static void
build_he_candidates(neat_ctx *ctx, neat_flow *flow, json_t *json, struct neat_he_candidates *candidate_list)
{
    int rc;
    size_t i;
    int if_idx;
    json_t *value;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    json_array_foreach(json, i, value) {
        neat_protocol_stack_type stack;
        const char *interface = NULL, *local_ip  = NULL, *remote_ip = NULL, *transport = NULL;
        char dummy[sizeof(struct in6_addr)];
        struct neat_he_candidate *candidate;

        const char *so_key=NULL, *so_prefix = "SO/";
        json_t *so_value;

        nt_log(ctx, NEAT_LOG_DEBUG, "Now processing PM candidate %zu", i);

        interface = json_string_value(get_property(value, "interface", JSON_STRING));
        if (!interface)
            continue;

        remote_ip = json_string_value(get_property(value, "remote_ip", JSON_STRING));
        if (!remote_ip)
            continue;

        local_ip = json_string_value(get_property(value, "local_ip", JSON_STRING));
        if (!local_ip)
            continue;

        transport = json_string_value(get_property(value, "transport", JSON_STRING));
        // FIXME transport must be a single value, need to handle errors
        if ((stack = string_to_stack(transport)) == 0) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unknown transport stack %s", transport);
            continue;
        }

        if ((candidate = calloc(1, sizeof(*candidate))) == NULL)
            goto out_of_memory;

        TAILQ_INIT(&(candidate->sock_opts));

        // get socket options properties
        json_object_foreach(value, so_key, so_value) {
            if (strncmp(so_prefix, so_key, strlen(so_prefix))==0) {
                uint32_t level, optname, type;
                struct neat_he_sockopt *sockopt;

                if ((sockopt = calloc(1, sizeof(struct neat_he_sockopt))) == NULL)
                    goto out_of_memory;

                sscanf(so_key, "SO/%u/%u", &level, &optname);

                sockopt->level = level;
                sockopt->name = optname;
                type = json_typeof(json_object_get(json_object_get(value, so_key), "value"));

                switch (type) {
                case JSON_INTEGER:
                    sockopt->type = NEAT_SOCKOPT_INT;
                    sockopt->value.i_val = json_integer_value(get_property(value, so_key, JSON_INTEGER));
                    nt_log(ctx, NEAT_LOG_DEBUG, "Got socket option \"%s\" with value \"%d\"", so_key, sockopt->value.i_val);
                    break;
                case JSON_STRING:
                    sockopt->type = NEAT_SOCKOPT_STRING;
                    sockopt->value.s_val = strdup(json_string_value(get_property(value, so_key, JSON_STRING)));
                    if (!sockopt->value.s_val) {
                        free(sockopt);
                        goto out_of_memory;
                    }
                    nt_log(ctx, NEAT_LOG_DEBUG, "Got socket option \"%s\" with value \"%s\"", so_key, sockopt->value.s_val);
                    break;
                case JSON_TRUE:
                case JSON_FALSE:
                    sockopt->type = NEAT_SOCKOPT_INT;
                    sockopt->value.i_val = json_boolean_value(get_property(value, so_key, JSON_TRUE)); /* JSON_TRUE is just to get a "boolean" value, could be replaced with JSON_FALSE */
                    nt_log(ctx, NEAT_LOG_DEBUG, "Got socket option \"%s\" with value \"%s\"", so_key, sockopt->value.i_val ? "True" : "False");
                    break;
                default:
                    nt_log(ctx, NEAT_LOG_ERROR, "Socket option value type (\"%d\") not supported", type);
                    free(sockopt);
                    continue;
                }
                TAILQ_INSERT_TAIL(&(candidate->sock_opts), sockopt, next);
            }
         }

        if ((candidate->pollable_socket = calloc(1, sizeof(struct neat_pollable_socket))) == NULL)
            goto out_of_memory;

        if_idx = if_nametoindex(interface);
        if (!if_idx) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to get interface id for \"%s\"",
                     interface);
            if_idx = 0;
        }

        if ((candidate->pollable_socket->src_address = strdup(local_ip)) == NULL)
            goto out_of_memory;

        if ((candidate->if_name                      = strdup(interface)) == NULL)
            goto out_of_memory;

        if ((candidate->pollable_socket->dst_address = strdup(remote_ip)) == NULL)
            goto out_of_memory;

        candidate->pollable_socket->port        = flow->port;
        candidate->pollable_socket->stack       = stack;
        candidate->if_idx                       = if_idx;
        candidate->priority                     = i; // TODO: Get priority from PM
        candidate->properties                   = value;
        candidate->to_be_removed                = 0;
        json_incref(value);

        memset(dummy, 0, sizeof(dummy));

        // Determine the address family and initialize the sockaddr struct accordingly
        if (inet_pton(AF_INET6, candidate->pollable_socket->dst_address, &dummy) == 1) {
            candidate->pollable_socket->family  = AF_INET6;
            candidate->pollable_socket->src_len = sizeof(struct sockaddr_in6);
            candidate->pollable_socket->dst_len = sizeof(struct sockaddr_in6);

            memcpy(&((struct sockaddr_in6*) &candidate->pollable_socket->dst_sockaddr)->sin6_addr, dummy, sizeof(struct in6_addr));
            ((struct sockaddr*) &candidate->pollable_socket->dst_sockaddr)->sa_family = AF_INET6;
            ((struct sockaddr_in6*) &candidate->pollable_socket->dst_sockaddr)->sin6_port = htons(candidate->pollable_socket->port);

            assert(inet_pton(candidate->pollable_socket->family,
                             candidate->pollable_socket->src_address,
                             (void*)&((struct sockaddr_in6*)(&candidate->pollable_socket->src_sockaddr))->sin6_addr) == 1);
            ((struct sockaddr*) &candidate->pollable_socket->src_sockaddr)->sa_family = AF_INET6;
        } else if (inet_pton(AF_INET, candidate->pollable_socket->dst_address, &dummy) == 1) {
            candidate->pollable_socket->family = AF_INET;
            candidate->pollable_socket->src_len = sizeof(struct sockaddr_in);
            candidate->pollable_socket->dst_len = sizeof(struct sockaddr_in);

            memcpy(&((struct sockaddr_in*) &candidate->pollable_socket->dst_sockaddr)->sin_addr, dummy, sizeof(struct in_addr));
            ((struct sockaddr*) &candidate->pollable_socket->dst_sockaddr)->sa_family = AF_INET;
            ((struct sockaddr_in*) &candidate->pollable_socket->dst_sockaddr)->sin_port = htons(candidate->pollable_socket->port);

            assert(inet_pton(candidate->pollable_socket->family,
                             candidate->pollable_socket->src_address,
                             (void*)&((struct sockaddr_in*)(&candidate->pollable_socket->src_sockaddr))->sin_addr) == 1);
            ((struct sockaddr*) &candidate->pollable_socket->src_sockaddr)->sa_family = AF_INET;
        } else {
            // Not AF_INET or AF_INET6?...
            nt_log(ctx, NEAT_LOG_DEBUG, "Received candidate with address \"%s\" which neither AF_INET nor AF_INET6", candidate->pollable_socket->dst_address);
            rc = NEAT_ERROR_BAD_ARGUMENT;
            goto error;
        }

        TAILQ_INSERT_TAIL(candidate_list, candidate, next);
        continue;
out_of_memory:
        rc = NEAT_ERROR_OUT_OF_MEMORY;
error:
        if (candidate) {
            if (candidate->pollable_socket) {
                if (candidate->pollable_socket->src_address) {
                    free(candidate->pollable_socket->src_address);
                }
                if (candidate->pollable_socket->dst_address)
                    free(candidate->pollable_socket->dst_address);
                if (candidate->pollable_socket->dtls_data) {
                    free (candidate->pollable_socket->dtls_data->userData);
                    candidate->pollable_socket->dtls_data->userData = NULL;
                    free (candidate->pollable_socket->dtls_data);
                    candidate->pollable_socket->dtls_data = NULL;
                }
                free(candidate->pollable_socket);
            }
            if (candidate->if_name)
                free(candidate->if_name);
            if (!TAILQ_EMPTY(&(candidate->sock_opts))) {
                struct neat_he_sockopt *sockopt, *tmp;
                TAILQ_FOREACH_SAFE(sockopt, (&candidate->sock_opts), next, tmp) {
                    if (sockopt->type == NEAT_SOCKOPT_STRING)
                        free(sockopt->value.s_val);
                    TAILQ_REMOVE((&candidate->sock_opts), sockopt, next);
                }
            }
            free(candidate);
        }
        if (rc)
            nt_io_error(ctx, flow, rc);
        else
            continue;
    }
}

static void
combine_candidates(neat_flow *flow, struct neat_he_candidates *candidate_list)
{
    struct neat_he_candidate *candidate = NULL;
    if (!flow->isMultihoming) {
        return;
    }

    nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    TAILQ_FOREACH(candidate, candidate_list, next) {
        if (nt_base_stack(candidate->pollable_socket->stack) != NEAT_STACK_SCTP) {
            continue;
        }
        candidate->pollable_socket->nr_local_addr = 0;
        struct neat_he_candidate *cand;
        TAILQ_FOREACH(cand, candidate_list, next) {
            if (nt_base_stack(cand->pollable_socket->stack) != NEAT_STACK_SCTP) {
                continue;
            }
            if (cand->to_be_removed)
                continue;
            if (strcmp(candidate->pollable_socket->dst_address, cand->pollable_socket->dst_address)) {
                continue;
            } else {
                if (candidate->pollable_socket->nr_local_addr < MAX_LOCAL_ADDR) {
                    memcpy(&(candidate->pollable_socket->local_addr[candidate->pollable_socket->nr_local_addr]), &(candidate->pollable_socket->src_sockaddr), candidate->pollable_socket->src_len);
                    if (candidate->pollable_socket->nr_local_addr == 0) {
                        if (strcmp(candidate->pollable_socket->src_address, cand->pollable_socket->src_address)) {
                            if (candidate->pollable_socket->src_address != NULL) {
                                free(candidate->pollable_socket->src_address);
                            }
                            candidate->pollable_socket->src_address = strdup(cand->pollable_socket->src_address);
                            if (!candidate->pollable_socket->src_address)
                                return;
                        }
                    } else {
                        candidate->pollable_socket->src_address =
                            realloc(candidate->pollable_socket->src_address,
                                    strlen(candidate->pollable_socket->src_address) +
                                    strlen(cand->pollable_socket->src_address) +
                                    2 * sizeof(char));
                        if (!candidate->pollable_socket->src_address)
                            return;
                        strcat(candidate->pollable_socket->src_address, ",");
                        strcat(candidate->pollable_socket->src_address, cand->pollable_socket->src_address);
                    }
                    candidate->pollable_socket->nr_local_addr++;
                } else {
                    nt_log(flow->ctx, NEAT_LOG_ERROR, "The maximum number of local addresses (%d) is exceeded", MAX_LOCAL_ADDR);
                }
                if (!(TAILQ_EMPTY(candidate_list)) && strcmp(candidate->pollable_socket->src_address, cand->pollable_socket->src_address)) {
                    cand->to_be_removed = 1;
                }
            }
        }
    }
    struct neat_he_candidate *candid = NULL, *tmp = NULL;
    TAILQ_FOREACH_SAFE(candid, candidate_list, next, tmp) {
        if (!candid->to_be_removed) {
            continue;
        }
        TAILQ_REMOVE(candidate_list, candid, next);
        free(candid->pollable_socket->dst_address);
        free(candid->pollable_socket->src_address);
        if (candid->pollable_socket->dtls_data) {
            free(candid->pollable_socket->dtls_data->userData);
            candid->pollable_socket->dtls_data->userData = NULL;
            free(candid->pollable_socket->dtls_data);
            candid->pollable_socket->dtls_data = NULL;
        }
        free(candid->pollable_socket);
        free(candid->if_name);
        json_decref(candid->properties);
        free(candid);
    }
}

static void
on_pm_reply_post_resolve(neat_ctx *ctx, neat_flow *flow, json_t *json)
{
    struct neat_he_candidates *candidate_list = NULL;
    struct neat_he_candidate *candidate = NULL;
    struct sockaddr *sa = NULL;
    struct sockaddr *da = NULL;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#if 1
    char *str = json_dumps(json, JSON_INDENT(2));
    nt_log(ctx, NEAT_LOG_DEBUG, "Reply from PM was: %s", str);
    free(str);
#else
    nt_log(ctx, NEAT_LOG_DEBUG, "Received second reply from PM");
#endif

    candidate_list = calloc(1, sizeof(*candidate_list));
    if (!candidate_list) {
        nt_log(ctx, NEAT_LOG_WARNING, "Out of memory");
        return;
    }
    TAILQ_INIT(candidate_list);

    build_he_candidates(ctx, flow, json, candidate_list);
    TAILQ_FOREACH(candidate, candidate_list, next) {
        sa = (struct sockaddr*) &candidate->pollable_socket->src_sockaddr;
        da = (struct sockaddr*) &candidate->pollable_socket->dst_sockaddr;

        _unused(sa);
        _unused(da);

        assert(da->sa_family == AF_INET || da->sa_family == AF_INET6);
        assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);

        assert(candidate->pollable_socket->dst_address);
        assert(candidate->pollable_socket->src_address);
        assert(candidate->if_idx);
        assert(candidate->if_name);
        assert(candidate->pollable_socket->family == AF_INET ||
               candidate->pollable_socket->family == AF_INET6);
    }

    if (flow->isMultihoming) {
        combine_candidates(flow, candidate_list);
    }
    json_decref(json);

    nt_he_open(ctx, flow, candidate_list, he_connected_cb);
}

static void
on_candidates_resolved(neat_ctx *ctx, neat_flow *flow, struct neat_he_candidates *candidate_list)
{
    int rc;
    const char *home_dir;
    const char *socket_path;
    char socket_path_buf[128];
    struct neat_he_candidate *candidate, *tmp;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    // Now that the names in the list are resolved, append the new data to the
    // json objects and perform a new call to the PM

    json_t *array = json_array();

    TAILQ_FOREACH_SAFE(candidate, candidate_list, next, tmp) {
        json_t *dst_address, *str;

        if (candidate->if_idx == 0) {
            // nt_log(ctx, NEAT_LOG_DEBUG, "Removing...");
            continue;
        }

        // nt_log(ctx, NEAT_LOG_DEBUG, "%s %s", json_string_value(get_property(candidate->properties, "transport", JSON_STRING)), candidate->pollable_socket->dst_address);

        assert(candidate->pollable_socket->dst_address);

        //dst_address = json_pack();
        str = json_string(candidate->pollable_socket->dst_address);
        dst_address = json_object();

        json_object_set(dst_address, "value", str);
        json_object_set(candidate->properties, "remote_ip", dst_address);

        json_array_append(array, candidate->properties);

        // We're done with dst_address and str in this function.
        json_decref(dst_address);
        json_decref(str);
    }

    if (json_array_size(array) == 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "No usable candidates after name resolution");
        nt_io_error(ctx, flow, NEAT_ERROR_UNABLE);
        return;
    }

    nt_free_candidates(ctx, candidate_list);

#if 0
    nt_log(ctx, NEAT_LOG_DEBUG, "Sending post-resolve properties to PM\n%s\n", buffer);
#else

    socket_path = getenv("NEAT_PM_SOCKET");
    if (!socket_path) {
        if ((home_dir = getenv("HOME")) == NULL) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to locate the $HOME directory");
            nt_io_error(ctx, flow, NEAT_ERROR_INTERNAL);
            return;
        }

        rc = snprintf(socket_path_buf, 128, "%s/.neat/neat_pm_socket", home_dir);
        if (rc < 0 || rc >= 128) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to construct default path to PM socket");
            nt_io_error(ctx, flow, NEAT_ERROR_INTERNAL);
            return;
        }

        socket_path = socket_path_buf;
    }

    nt_log(ctx, NEAT_LOG_DEBUG, "Sending post-resolve properties to PM");
    // buffer is freed by the PM interface
    nt_json_send_once(flow->ctx, flow, socket_path, array, on_pm_reply_post_resolve, on_pm_error);
    json_decref(array);
#endif
}

struct candidate_resolver_data
{
    neat_flow *flow;
    struct neat_he_candidates *candidate_list;

    TAILQ_HEAD(list, neat_he_candidate) resolution_group;

    const char *domain_name;
    unsigned int port;

    int *status;
    int *remaining;

    TAILQ_ENTRY(candidate_resolver_data) next;
};

static neat_error_code
on_candidate_resolved(struct neat_resolver_results *results,
                      uint8_t code, void *user_data)
{
    int rc;
    char namebuf[NI_MAXHOST];
    struct sockaddr_storage dummy;
    struct neat_resolver_res *result;
    struct candidate_resolver_data *data = user_data;
    struct neat_ctx *ctx = data->flow->ctx;
    struct neat_flow *flow = data->flow;
    struct neat_he_candidate *candidate, *tmp;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (code == NEAT_RESOLVER_TIMEOUT)  {
        *data->status = -1;
        nt_io_error(ctx, flow, NEAT_ERROR_IO);
        nt_log(ctx, NEAT_LOG_DEBUG, "Resolution timed out");
    } else if ( code == NEAT_RESOLVER_ERROR ) {
        *data->status = -1;
        nt_io_error(ctx, flow, NEAT_ERROR_IO);
        nt_log(ctx, NEAT_LOG_DEBUG, "Resolver error");
    }

    LIST_FOREACH(result, results, next_res) {
        char ifname1[IF_NAMESIZE];
        char ifname2[IF_NAMESIZE];

        if ((rc = getnameinfo((struct sockaddr*)&result->dst_addr, result->dst_addr_len, namebuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
            nt_log(ctx, NEAT_LOG_DEBUG, "getnameinfo error");
            continue;
        }

        TAILQ_FOREACH_SAFE(candidate, &data->resolution_group, resolution_list, tmp) {

            // The interface index must be the same as the interface index of the candidate
            if (result->if_idx != candidate->if_idx) {
                nt_log(ctx, NEAT_LOG_DEBUG, "Interface did not match, %s [%d] != %s [%d]", if_indextoname(result->if_idx, ifname1), result->if_idx, if_indextoname(candidate->if_idx, ifname2), candidate->if_idx);
                continue;
            }

            // TODO: Move inet_pton out of the loop
            if (result->ai_family == AF_INET && inet_pton(AF_INET6, candidate->pollable_socket->src_address, &dummy) == 1) {
                nt_log(ctx, NEAT_LOG_DEBUG, "Address family did not match");
                continue;
            }

            // TODO: Move inet_pton out of the loop
            if (result->ai_family == AF_INET6 && inet_pton(AF_INET, candidate->pollable_socket->src_address, &dummy) == 1) {
                nt_log(ctx, NEAT_LOG_DEBUG, "Address family did not match");
                continue;
            }

            // dst_address was strdup'd in on_pm_reply_pre_resolve, free it
            free(candidate->pollable_socket->dst_address);

            if ((candidate->pollable_socket->dst_address = strdup(namebuf)) != NULL) {
                nt_log(ctx, NEAT_LOG_DEBUG, "%s -> %s", candidate->pollable_socket->src_address, namebuf);
            } else {
                *(data->status) = NEAT_ERROR_OUT_OF_MEMORY;
            }

            candidate->if_idx = result->if_idx;

            TAILQ_REMOVE(&data->resolution_group, candidate, resolution_list);
        }
    }

    // The remaining candidates in the resolution group have not been resolved.
    // Set the interface id to 0 to have them removed before sending them back
    // to the PM.
    TAILQ_FOREACH(candidate, &data->resolution_group, resolution_list) {
        candidate->if_idx = 0;
    }

    nt_resolver_free_results(results);

    if (!--*data->remaining /*&& *data->status == 0*/) {
        free(data->status);
        free(data->remaining);
        on_candidates_resolved(data->flow->ctx, data->flow, data->candidate_list);
        free(data);
    } else {
        free(data);
    }

    return NEAT_OK;
}

static void
nt_resolve_candidates(neat_ctx *ctx, neat_flow *flow,
                        struct neat_he_candidates *candidate_list)
{
    int *remaining, *status = NULL;
    struct neat_he_candidate *candidate;
    struct candidate_resolver_data *resolver_data, *tmp;

    TAILQ_HEAD(resolution_group_list, candidate_resolver_data) resolutions;
    TAILQ_INIT(&resolutions);

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    assert(candidate_list);

    if (TAILQ_EMPTY(candidate_list)) {
        nt_log(ctx, NEAT_LOG_WARNING, "neat_resolve_candidates called with an empty candidate list");
        return;
    }

    if ((remaining = calloc(1, sizeof(*remaining))) == NULL)
        goto error;
    if ((status = calloc(1, sizeof(*status))) == NULL)
        goto error;

    *status = 0;

    // TODO: Should this have been allocated before this point?
    if (!ctx->resolver)
        ctx->resolver = nt_resolver_init(ctx, "/etc/resolv.conf");

    if (!ctx->pvd)
        ctx->pvd = nt_pvd_init(ctx);

    TAILQ_FOREACH(candidate, candidate_list, next) {
        struct candidate_resolver_data *existing_resolution;

        TAILQ_FOREACH(existing_resolution, &resolutions, next) {
            // nt_log(ctx, NEAT_LOG_DEBUG, "%s - %s", existing_resolution->domain_name, candidate->pollable_socket->dst_address);

            if (strcmp(existing_resolution->domain_name, candidate->pollable_socket->dst_address) != 0)
                continue;

            if (existing_resolution->port != candidate->pollable_socket->port)
                continue;

            // TODO: Split on ipv4/ipv6/no preference

            nt_log(ctx, NEAT_LOG_DEBUG, "Adding candidate to existing resolution group for %s:%u",
                     existing_resolution->domain_name, existing_resolution->port);

            TAILQ_INSERT_TAIL(&existing_resolution->resolution_group, candidate, resolution_list);

            goto next_candidate;
        }

        if ((resolver_data = calloc(1, sizeof(*resolver_data))) == NULL)
            goto error;

        resolver_data->port = candidate->pollable_socket->port;
        resolver_data->domain_name = candidate->pollable_socket->dst_address;

        resolver_data->candidate_list = candidate_list;
        TAILQ_INIT(&resolver_data->resolution_group);
        resolver_data->flow = flow;

        resolver_data->status = status;
        resolver_data->remaining = remaining;
        (*remaining)++;

        nt_log(ctx, NEAT_LOG_DEBUG, "Creating new resolution group for %s:%u", resolver_data->domain_name, resolver_data->port);
        TAILQ_INSERT_TAIL(&resolver_data->resolution_group, candidate, resolution_list);
        TAILQ_INSERT_TAIL(&resolutions, resolver_data, next);
next_candidate:
        continue;
    }

    struct candidate_resolver_data *resolution;
    TAILQ_FOREACH(resolution, &resolutions, next) {
        nt_resolve(ctx->resolver, AF_UNSPEC, resolution->domain_name,
                     resolution->port, on_candidate_resolved, resolution);
    }

    return;
error:
    TAILQ_FOREACH_SAFE(resolver_data, &resolutions, next, tmp) {
        free(resolver_data);
    }

    nt_free_candidates(ctx, candidate_list);

    if (remaining)
        free(remaining);
    if (status)
        free(status);
    nt_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
}

static neat_error_code
open_resolve_cb(struct neat_resolver_results *results, uint8_t code,
                  void *user_data)
{
    struct neat_flow *flow = user_data;
    struct neat_ctx *ctx = flow->ctx;

    size_t nr_of_stacks = NEAT_STACK_MAX_NUM;
    neat_protocol_stack_type stacks[NEAT_STACK_MAX_NUM];

    struct neat_resolver_res *result;
    struct neat_he_candidates *candidates;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        nt_io_error(ctx, flow, code);
        return NEAT_ERROR_INTERNAL;
    }

    // Find the enabled stacks based on the properties
    // nr_of_stacks = nt_property_translate_protocols(flow->propertyAttempt, stacks);
    nt_find_enabled_stacks(flow->properties, stacks, &nr_of_stacks, NULL);
    if (!nr_of_stacks) {
        nt_io_error(ctx, flow, NEAT_ERROR_UNABLE);
        return NEAT_ERROR_UNABLE;
    }

    assert(results);

    flow->resolver_results = results;

    candidates = calloc(1, sizeof(*candidates));

    if (!candidates) {
        nt_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    TAILQ_INIT(candidates);

    size_t prio = 0;

    // For each available src/dst pair
    LIST_FOREACH(result, results, next_res) {
        int rc;
        char dst_buffer[NI_MAXHOST];
        char src_buffer[NI_MAXHOST];
        char iface[IF_NAMESIZE];
        const char *iface_name;

        iface_name = if_indextoname(result->if_idx, iface);

        if (iface_name == NULL) {
            continue;
        }

        rc = getnameinfo((struct sockaddr *)&result->dst_addr,
                         result->dst_addr_len,
                         dst_buffer, sizeof(dst_buffer), NULL, 0, NI_NUMERICHOST);

        if (rc != 0) {
            nt_log(ctx, NEAT_LOG_DEBUG, "getnameinfo() failed: %s\n", gai_strerror(rc));
            continue;
        }

        rc = getnameinfo((struct sockaddr *)&result->src_addr,
                         result->src_addr_len,
                         src_buffer, sizeof(src_buffer), NULL, 0, NI_NUMERICHOST);

        if (rc != 0) {
            nt_log(ctx, NEAT_LOG_DEBUG, "getnameinfo() failed: %s\n", gai_strerror(rc));
            continue;
        }

        for (unsigned int i = 0; i < nr_of_stacks; ++i) {
            // struct neat_he_candidate *tmp;

            if (flow->preserveMessageBoundaries &&
                (nt_base_stack(stacks[i]) != NEAT_STACK_SCTP && stacks[i] != NEAT_STACK_UDP && stacks[i] != NEAT_STACK_UDPLITE)) {
                continue;
            }

            struct neat_he_candidate *candidate = calloc(1, sizeof(*candidate));
            if (!candidate) {
                nt_free_candidates(ctx, candidates);
                return NEAT_ERROR_OUT_OF_MEMORY;
            }

            candidate->pollable_socket = calloc(1, sizeof(struct neat_pollable_socket));
            if (!candidate->pollable_socket) {
                free(candidate);
                nt_free_candidates(ctx, candidates);
                return NEAT_ERROR_OUT_OF_MEMORY;
            }


            // This ensures we use only one address from each address family for
            // each interface to reduce the number of candidates.
            // TAILQ_FOREACH(tmp, candidates, next) {
            //     if (tmp->if_idx == result->if_idx && tmp->pollable_socket->family == result->ai_family)
            //         goto skip;
            // }
            candidate->if_name                      = strdup(iface);
            if (!candidate->if_name) {
                free(candidate->pollable_socket);
                free(candidate);
                nt_free_candidates(ctx, candidates);
                return NEAT_ERROR_OUT_OF_MEMORY;
            }
            candidate->if_idx                       = result->if_idx;
            candidate->priority = prio++;

            candidate->pollable_socket->family      = result->ai_family;
            candidate->pollable_socket->src_address = strdup(src_buffer);
            if (!candidate->pollable_socket->src_address) {
                free(candidate->if_name);
                free(candidate->pollable_socket);
                free(candidate);
                nt_free_candidates(ctx, candidates);
                return NEAT_ERROR_OUT_OF_MEMORY;
            }
            candidate->pollable_socket->dst_address = strdup(dst_buffer);
            if (!candidate->pollable_socket->dst_address) {
                free(candidate->pollable_socket->src_address);
                free(candidate->if_name);
                free(candidate->pollable_socket);
                free(candidate);
                nt_free_candidates(ctx, candidates);
                return NEAT_ERROR_OUT_OF_MEMORY;
            }
            candidate->pollable_socket->port        = flow->port;
            candidate->pollable_socket->stack       = stacks[i];
            candidate->pollable_socket->dst_len     = result->src_addr_len;
            candidate->pollable_socket->src_len     = result->dst_addr_len;

            json_incref(flow->properties);
            candidate->properties = flow->properties;

            if (flow->user_ips != NULL) {
                size_t index;
                json_t *addr, *ipvalue;
                char *ip;
                char newIp[100];
                int srcfound = false;
                uint32_t j, k;
                for (index = 0; index < json_array_size(flow->user_ips); index++) {
                    addr = json_array_get(flow->user_ips, index);
                    ipvalue = json_object_get(addr, "value");
                    ip = json_dumps(ipvalue, JSON_ENCODE_ANY);
                    // Remove quotes
                    for (j = 1, k = 0; j <= strlen(ip) - 2; j++, k++) {
                        newIp[k] = ip[j];
                    }
                    newIp[k] = '\0';;
                    free (ip);
                    if (strcmp(src_buffer, newIp) != 0) {
                        continue;
                    } else {
                        srcfound = true;
                        nt_log(flow->ctx, NEAT_LOG_DEBUG, "Address found");
                        memcpy(&candidate->pollable_socket->src_sockaddr, &result->src_addr, result->src_addr_len);
                        break;
                    }
                }
                if (!srcfound) {
                    json_decref(candidate->properties);
                    free(candidate->pollable_socket->dst_address);
                    free(candidate->pollable_socket->src_address);
                    free(candidate->if_name);
                    if (candidate->pollable_socket->dtls_data) {
                        free (candidate->pollable_socket->dtls_data->userData);
                        candidate->pollable_socket->dtls_data->userData = NULL;
                        free (candidate->pollable_socket->dtls_data);
                        candidate->pollable_socket->dtls_data = NULL;
                    }
                    free(candidate->pollable_socket);
                    free(candidate);
                    prio--;
                    continue;
                }
            } else {
                free(candidate->pollable_socket->src_address);
                candidate->pollable_socket->src_address = strdup(src_buffer);
                if (!candidate->pollable_socket->src_address) {
                    free(candidate);
                    nt_free_candidates(ctx, candidates);
                    return NEAT_ERROR_OUT_OF_MEMORY;
                }

                candidate->pollable_socket->src_len     = result->src_addr_len;
                memcpy(&candidate->pollable_socket->src_sockaddr, &result->src_addr, result->src_addr_len);
            }
            free(candidate->pollable_socket->dst_address);
            candidate->pollable_socket->dst_address = strdup(dst_buffer);
            if (!candidate->pollable_socket->dst_address) {
                free(candidate->pollable_socket->src_address);
                free(candidate->if_name);
                free(candidate->pollable_socket);
                free(candidate);
                nt_free_candidates(ctx, candidates);
                return NEAT_ERROR_OUT_OF_MEMORY;
            }
            candidate->pollable_socket->dst_len     = result->dst_addr_len;

            memcpy(&candidate->pollable_socket->dst_sockaddr, &result->dst_addr, result->dst_addr_len);

            if (candidate->pollable_socket->family == AF_INET6) {
                ((struct sockaddr_in6*) &candidate->pollable_socket->dst_sockaddr)->sin6_port =
                    htons(candidate->pollable_socket->port);
            } else {
                ((struct sockaddr_in*) &candidate->pollable_socket->dst_sockaddr)->sin_port =
                    htons(candidate->pollable_socket->port);
            }
            TAILQ_INSERT_TAIL(candidates, candidate, next);
        }
    }

    combine_candidates(flow, candidates);

    nt_he_open(ctx, flow, candidates, he_connected_cb);

    return NEAT_OK;
}

static void
on_pm_error(struct neat_ctx *ctx, struct neat_flow *flow, int error)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    switch (error) {
        case PM_ERROR_SOCKET_UNAVAILABLE:
        case PM_ERROR_SOCKET:
        case PM_ERROR_INVALID_JSON:
            nt_log(ctx, NEAT_LOG_DEBUG, "===== Unable to communicate with PM, using fallback =====, error code = %d", error);
            nt_resolve(ctx->resolver, AF_UNSPEC, flow->name, flow->port,
                         open_resolve_cb, flow);
            break;
        case PM_ERROR_OOM:
            break;
        default:
            assert(0);
            break;
    }

}

static void
on_pm_he_error(struct neat_ctx *ctx, struct neat_flow *flow, int error)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    switch (error) {
        case PM_ERROR_SOCKET_UNAVAILABLE:
        case PM_ERROR_SOCKET:
        case PM_ERROR_INVALID_JSON:
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to communicate with PM, error code = %d", error);
            break;
        case PM_ERROR_OOM:
            break;
        default:
            assert(0);
            break;
    }

}

static void
on_pm_reply_pre_resolve(struct neat_ctx *ctx, struct neat_flow *flow, json_t *json)
{
    int rc = NEAT_OK;
    size_t i;
    json_t *value;
    struct neat_he_candidates *candidate_list;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#if 0
    char *str = json_dumps(json, JSON_INDENT(2));
    nt_log(ctx, NEAT_LOG_DEBUG, "Reply from PM was: %s", str);
    free(str);
#else
    nt_log(ctx, NEAT_LOG_DEBUG, "Received reply from PM");
#endif

    if ((candidate_list = calloc(1, sizeof(*candidate_list))) == NULL) {
        rc = NEAT_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    TAILQ_INIT(candidate_list);

    json_array_foreach(json, i, value) {
        const char *address = NULL, *interface = NULL, *local_ip  = NULL;
        struct neat_he_candidate *candidate = NULL;

        if ((candidate = calloc(1, sizeof(*candidate))) == NULL)
            goto error;

        if ((candidate->pollable_socket = calloc(1, sizeof(struct neat_pollable_socket))) == NULL)
            goto loop_oom;

        if ((address = json_string_value(get_property(value, "domain_name", JSON_STRING))) == NULL)
             goto loop_error;

        if ((interface = json_string_value(get_property(value, "interface", JSON_STRING))) == NULL)
            goto loop_error;

        if ((local_ip = json_string_value(get_property(value, "local_ip", JSON_STRING))) == NULL)
            goto loop_error;

        if ((candidate->pollable_socket->dst_address = strdup(address)) == NULL)
            goto loop_oom;

        if ((candidate->if_name = strdup(interface)) == NULL)
            goto loop_oom;

        if ((candidate->if_idx = if_nametoindex(candidate->if_name)) == 0) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unknown interface %s", candidate->if_name);
            goto loop_error;
        }
        if ((candidate->pollable_socket->src_address = strdup(local_ip)) == NULL)
            goto loop_oom;

        candidate->pollable_socket->port = flow->port;
        candidate->properties = value;
        json_incref(value);

        TAILQ_INSERT_TAIL(candidate_list, candidate, next);

        continue;
loop_oom:
        rc = NEAT_ERROR_OUT_OF_MEMORY;
loop_error:
        if (candidate->if_name)
            free(candidate->if_name);
        if (candidate->pollable_socket) {
            if (candidate->pollable_socket->src_address) {
                free(candidate->pollable_socket->src_address);
            }
            if (candidate->pollable_socket->dst_address)
                free(candidate->pollable_socket->dst_address);
            if (candidate->pollable_socket->dtls_data) {
                free (candidate->pollable_socket->dtls_data->userData);
                candidate->pollable_socket->dtls_data->userData = NULL;
                free (candidate->pollable_socket->dtls_data);
                candidate->pollable_socket->dtls_data = NULL;
            }
            free(candidate->pollable_socket);
        }
        free(candidate);
        if (rc == NEAT_OK)
            continue;
        else
            goto error;
    }

    json_decref(json);

#if 0
    struct neat_he_candidate *tmp;
    TAILQ_FOREACH(tmp, candidate_list, next) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s %s", json_string_value(get_property(tmp->properties, "transport", JSON_STRING)), tmp->pollable_socket->dst_address);
    }

    // Deallocation test
    nt_free_candidates(candidate_list);
    neat_free_ctx(ctx);
    exit(0);
#endif

    nt_resolve_candidates(ctx, flow, candidate_list);

    return;
error:
    json_decref(json);
    nt_free_candidates(ctx, candidate_list);

    nt_io_error(ctx, flow, rc);
}


static void
send_properties_to_pm(neat_ctx *ctx, neat_flow *flow)
{
    int rc = NEAT_ERROR_OUT_OF_MEMORY;
    struct ifaddrs *ifaddrs = NULL;
    json_t *array = NULL, *endpoints = NULL, *properties = NULL, *domains = NULL, *address, *port, *req_type;
    const char *home_dir;
    const char *socket_path;
    char socket_path_buf[128];

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    socket_path = getenv("NEAT_PM_SOCKET");
    if (!socket_path) {
        if ((home_dir = getenv("HOME")) == NULL) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to locate the $HOME directory");

            goto end;
        }

        rc = snprintf(socket_path_buf, 128, "%s/.neat/neat_pm_socket", home_dir);
        if (rc < 0 || rc >= 128) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Unable to construct default path to PM socket");
            goto end;
        }

        socket_path = socket_path_buf;
    }

    if ((array = json_array()) == NULL)
        goto end;

    if ((endpoints = json_array()) == NULL)
        goto end;

    assert(ctx);
    assert(flow);

    rc = getifaddrs(&ifaddrs);
    if (rc < 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "getifaddrs: %s", strerror(errno));
        goto end;
    }

    for (struct ifaddrs *ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        socklen_t addrlen;
        char namebuf[NI_MAXHOST];
        json_t *endpoint;

        // Doesn't actually contain any address (?)
        if (ifaddr->ifa_addr == NULL) {
            nt_log(ctx, NEAT_LOG_DEBUG, "ifaddr entry with no address");
            continue;
        }

        if (ifaddr->ifa_addr->sa_family != AF_INET &&
            ifaddr->ifa_addr->sa_family != AF_INET6)
            continue;

        addrlen = (ifaddr->ifa_addr->sa_family) == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

        rc = getnameinfo(ifaddr->ifa_addr, addrlen, namebuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if (rc != 0) {
            nt_log(ctx, NEAT_LOG_DEBUG, "getnameinfo: %s", gai_strerror(rc));
            continue;
        }

        if (strncmp(namebuf, "fe80::", 6) == 0) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s is a link-local address, skipping", namebuf);
            continue;
        }

        if (flow->user_ips != NULL) {
            size_t index;
            json_t *addr, *ipvalue;
            char *ip;
            char newIp[100];
            uint16_t found = 0;
            for (index = 0; index < json_array_size(flow->user_ips); index++) {
                uint32_t i, j;
                addr = json_array_get(flow->user_ips, index);
                ipvalue = json_object_get(addr, "value");
                ip = json_dumps(ipvalue, JSON_ENCODE_ANY);
                // Remove quotes
                for (i = 1, j = 0; i <= strlen(ip) - 2; i++, j++) {
                    newIp[j] = ip[i];
                }
                newIp[j] = '\0';;
                free (ip);
                if (strcmp(namebuf, newIp) != 0) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s: no match", __func__);
                    continue;
                } else {
                    found = 1;
                    break;
                }
            }
            if (found == 0) {
                continue;
            }
        }

        endpoint = json_pack("{ss++si}", "value", namebuf, "@", ifaddr->ifa_name, "precedence", 2);

        if (endpoint == NULL)
            goto end;

        nt_log(ctx, NEAT_LOG_DEBUG, "Added endpoint \"%s@%s\" to PM request", namebuf, ifaddr->ifa_name);
        json_array_append(endpoints, endpoint);
        json_decref(endpoint);
    }

    properties = json_copy(flow->properties);

    json_object_set(properties, "local_endpoint", endpoints);

    port = json_pack("{sisi}", "value", flow->port, "precedence", 2);
    if (port == NULL)
        goto end;

    json_object_set(properties, "port", port);
    json_decref(port);


    req_type = json_pack("{s:s}", "value", "pre-resolve");
    if (req_type == NULL)
        goto end;

    json_object_set(properties, "__request_type", req_type);
    json_decref(req_type);


    if ((domains = json_array()) == NULL)
        goto end;

    char *ptr = NULL;
    char *tmp = strdup(flow->name);

    if (!tmp) {
        rc = NEAT_ERROR_OUT_OF_MEMORY;
        goto end;
    }

    char *address_name = strtok_r((char *)tmp, ",", &ptr);
    if (address_name == NULL) {
        address = json_pack("{sssi}", "value", flow->name, "precedence", 2);
        if (address == NULL) {
            free (tmp);
            goto end;
        }
        json_object_set(properties, "domain_name", address);
        json_decref(address);
    } else {
        while (address_name != NULL) {
            address = json_pack("{sssi}", "value", address_name, "precedence", 2);
            if (address == NULL) {
                free (tmp);
                goto end;
            }

            json_array_append(domains, address);

            json_decref(address);
            address_name = strtok_r(NULL, ",", &ptr);
        }
        json_object_set(properties, "domain_name", domains);
    }
    free (tmp);
    json_array_append(array, properties);

    nt_json_send_once(ctx, flow, socket_path, array, on_pm_reply_pre_resolve, on_pm_error);

end:
    if (ifaddrs)
        freeifaddrs(ifaddrs);
    if (properties)
        json_decref(properties);
    if (endpoints)
        json_decref(endpoints);
    if (array)
        json_decref(array);
    if (domains)
        json_decref(domains);

    if (rc != NEAT_OK)
        nt_io_error(ctx, flow, rc);
}

neat_error_code
neat_open(neat_ctx *ctx, neat_flow *flow, const char *name, uint16_t port,
          struct neat_tlv optional[], unsigned int opt_count)
{
    int stream_count = 0;
    int group = 0;
    float priority = 0.5f;
    const char *cc_algorithm = NULL;
#if defined(WEBRTC_SUPPORT)
    const char *channel_name = NULL;
#endif
    json_t *multihoming = NULL;
    json_t *val = NULL;
    json_t *security = NULL;
    json_t *transport_type = NULL;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->name) {
        nt_log(ctx, NEAT_LOG_ERROR, "Flow appears to already be open");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    HANDLE_OPTIONAL_ARGUMENTS_START()
        OPTIONAL_INTEGER(NEAT_TAG_STREAM_COUNT, stream_count)
        OPTIONAL_INTEGER(NEAT_TAG_FLOW_GROUP, group)
        OPTIONAL_FLOAT(NEAT_TAG_PRIORITY, priority)
        OPTIONAL_STRING(NEAT_TAG_CC_ALGORITHM, cc_algorithm)
#if defined(WEBRTC_SUPPORT)
        OPTIONAL_STRING(NEAT_TAG_CHANNEL_NAME, channel_name)
#endif
    HANDLE_OPTIONAL_ARGUMENTS_END();

    if (stream_count > 1) {
        flow->streams_requested = stream_count;
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - %d streams", __func__, stream_count);
    }

    if (priority > 1.0f || priority < 0.1f) {
        nt_log(ctx, NEAT_LOG_ERROR, "Priority must be between 0.1 and 1.0");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    flow->name = strdup(name);
    if (flow->name == NULL) {
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    flow->port      = port;
    //flow->stream_count = stream_count;
    flow->group     = group;
    flow->priority  = priority;
    flow->eofSeen   = 0;

    if ((multihoming = json_object_get(flow->properties, "multihoming")) != NULL &&
        (val = json_object_get(multihoming, "value")) != NULL &&
        json_typeof(val) == JSON_TRUE)
    {
        flow->isMultihoming = 1;
    } else {
        flow->isMultihoming = 0;
    }

    if ((transport_type = json_object_get(flow->properties, "transport_type")) != NULL &&
        (val = json_object_get(transport_type, "value")) != NULL &&
        !strcmp(json_string_value(val), "message")) {
        flow->preserveMessageBoundaries = 1;
    } else {
        flow->preserveMessageBoundaries = 0;
    }


    if ((security = json_object_get(flow->properties, "security")) != NULL &&
        (val = json_object_get(security, "value")) != NULL &&
        json_typeof(val) == JSON_TRUE)
    {
        flow->security_needed = 1;
    } else {
        flow->security_needed = 0;
    }

    flow->user_ips = json_object_get(flow->properties, "local_ips");
    //json_object_del(flow->properties, "local_ips");

    if (!ctx->resolver)
        ctx->resolver = nt_resolver_init(ctx, "/etc/resolv.conf");

    if (!ctx->pvd)
        ctx->pvd = nt_pvd_init(ctx);

    if (cc_algorithm) {
        flow->cc_algorithm = strdup(cc_algorithm);
        if (flow->cc_algorithm == NULL) {
            return NEAT_ERROR_OUT_OF_MEMORY;
        }
    }

#if 1
    if (flow->webrtcEnabled) {
#if defined(WEBRTC_SUPPORT)
        nt_log(ctx, NEAT_LOG_DEBUG, "WEBRTC enabled\n");
        flow->state = NEAT_FLOW_OPEN;
        neat_webrtc_gather_candidates(ctx, flow, port, channel_name);
#else
        assert(false);
#endif
    } else {
        send_properties_to_pm(ctx, flow);
    }
#else
    // TODO: Add name resolution call
    nt_resolve(ctx->resolver, AF_UNSPEC, flow->name, flow->port,
                 open_resolve_cb, flow);
    // TODO: Generate candidates
    // TODO: Call HE
    // return neat_he_lookup(mgr, flow, he_connected_cb);
#endif
    return NEAT_OK;
}

neat_error_code
neat_change_timeout(neat_ctx *ctx, neat_flow *flow, unsigned int seconds)
{
#if defined(TCP_USER_TIMEOUT)
    unsigned int timeout_msec;
    int rc;
#endif

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#if defined(TCP_USER_TIMEOUT)
    if (nt_base_stack(flow->socket->stack) != NEAT_STACK_TCP)
#endif
    {
        nt_log(ctx, NEAT_LOG_DEBUG, "Timeout is supported on Linux TCP only");
        return NEAT_ERROR_UNABLE;
    }

#if defined(TCP_USER_TIMEOUT)
    if (flow->socket->fd == -1) {
        nt_log(ctx, NEAT_LOG_WARNING,
                 "Unable to change timeout for TCP socket: "
                 "Invalid socket value");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    if (seconds > UINT_MAX - 1000) {
        nt_log(ctx, NEAT_LOG_DEBUG, "Timeout value too large");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    timeout_msec = seconds * 1000;

    rc = setsockopt(flow->socket->fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout_msec, sizeof(timeout_msec));
    if (rc < 0) {
        nt_log(ctx, NEAT_LOG_ERROR, "Unable to change timeout for TCP socket: Call to setsockopt failed with errno=%d", errno);
        return NEAT_ERROR_IO;
    }

    return NEAT_ERROR_OK;
#endif // defined(TCP_USER_TIMEOUT)
}

static neat_error_code
set_primary_dest_resolve_cb(struct neat_resolver_results *results,
                            uint8_t code,
                            void *user_data)
{
    int rc;
    neat_flow *flow = user_data;
    struct neat_ctx *ctx = flow->ctx;
    char dest_addr[NI_MAXHOST];

#ifdef USRSCTP_SUPPORT
    struct sctp_setprim addr;
#elif defined(HAVE_NETINET_SCTP_H)
#ifdef __linux__
    struct sctp_prim addr;
#else
    struct sctp_setprim addr;
#endif
#endif

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        nt_io_error(ctx, flow, code);
        return NEAT_ERROR_DNS;
    }

    if (results->lh_first == NULL) {
        nt_io_error(ctx, flow, NEAT_ERROR_UNABLE);
        return NEAT_ERROR_UNABLE;
    }

#ifdef USRSCTP_SUPPORT
    memset(&addr, 0, sizeof(addr));
    addr.ssp_addr = results->lh_first->dst_addr;

    if (usrsctp_setsockopt(flow->socket->usrsctp_socket, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, &addr, sizeof(addr)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "Call to usrsctp_setsockopt(SCTP_PRIMARY_ADDR) failed");
        return NEAT_ERROR_IO;
    }
#elif defined(HAVE_NETINET_SCTP_H)
    memset(&addr, 0, sizeof(addr));
    addr.ssp_addr = results->lh_first->dst_addr;

    rc = setsockopt(flow->socket->fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, &addr, sizeof(addr));
    if (rc < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SCTP_PRIMARY_ADDR) failed");
        return NEAT_ERROR_IO;
    }
#endif
    rc = getnameinfo((struct sockaddr *)&results->lh_first->dst_addr,
                     results->lh_first->dst_addr_len,
                     dest_addr, sizeof(dest_addr), NULL, 0, 0);

    if (rc < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "getnameinfo failed for primary destination address");
    } else {
        nt_log(ctx, NEAT_LOG_DEBUG, "Updated primary destination address to: %s", dest_addr);
    }
    return NEAT_ERROR_OK;
}

neat_error_code
neat_set_primary_dest(struct neat_ctx *ctx, struct neat_flow *flow, const char *name)
{
    int8_t literal;
    uint8_t family = AF_UNSPEC;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        literal = nt_resolver_helpers_check_for_literal(&family, name);

        if (literal != 1) {
            nt_log(ctx, NEAT_LOG_ERROR, "%s: provided name '%s' is not an address literal.\n",
                 __func__, name);
            return NEAT_ERROR_BAD_ARGUMENT;
        }

            nt_resolve(ctx->resolver, AF_UNSPEC, name, flow->port,
                         set_primary_dest_resolve_cb, flow);

            return NEAT_ERROR_OK;
    }

    return NEAT_ERROR_UNABLE;
}

neat_error_code
neat_set_checksum_coverage(struct neat_ctx *ctx, struct neat_flow *flow, unsigned int send_coverage, unsigned int receive_coverage)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    switch (nt_base_stack(flow->socket->stack)) {
    case NEAT_STACK_UDP:
        {
#if defined(__linux__) && defined(SO_NO_CHECK)
            // Enable udp checksum if receive_coverage is non-zero
            // send_coverage is ignored in this case
            const int state = receive_coverage ? 1 : 0;

            if (setsockopt(flow->socket->fd, SOL_SOCKET, SO_NO_CHECK, &state, sizeof(state)) < 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "Unable to set SO_NO_CHECK to %d", state);
                return NEAT_ERROR_UNABLE;
            }

            return NEAT_OK;
#else
            nt_log(ctx, NEAT_LOG_DEBUG, "Disabling UDP checksum not supported");
            return NEAT_ERROR_UNABLE;
#endif
        }
    case NEAT_STACK_UDPLITE:
        {
#if defined(UDPLITE_SEND_CSCOV) && defined(UDPLITE_RECV_CSCOV)
        if (setsockopt(flow->socket->fd, IPPROTO_UDPLITE, UDPLITE_SEND_CSCOV, &send_coverage, sizeof(unsigned int)) < 0) {
            nt_log(ctx, NEAT_LOG_WARNING, "Failed to set UDP-Lite send checksum coverage");
            return NEAT_ERROR_UNABLE;
        }

        if (setsockopt(flow->socket->fd, IPPROTO_UDPLITE, UDPLITE_RECV_CSCOV, &receive_coverage, sizeof(unsigned int)) < 0) {
            nt_log(ctx, NEAT_LOG_WARNING, "Failed to set UDP-Lite receive checksum coverage");
            return NEAT_ERROR_UNABLE;
        }

        return NEAT_OK;
#else
        nt_log(ctx, NEAT_LOG_DEBUG, "Failed to set UDP-Lite checksum coverage, not supported");
        return NEAT_ERROR_UNABLE;
#endif
        }
    default:
        break;
    }

    nt_log(ctx, NEAT_LOG_DEBUG, "Failed to set checksum coverage, protocol not supported");
    return NEAT_ERROR_UNABLE;
}

static neat_error_code
accept_resolve_cb(struct neat_resolver_results *results,
                  uint8_t code,
                  void *user_data)
{
    int sctp_udp_encaps = 0;
    struct neat_pollable_socket *sctp_socket = NULL;
    size_t nr_of_stacks = NEAT_STACK_MAX_NUM;
    unsigned int socket_count = 0;
    neat_protocol_stack_type stacks[NEAT_STACK_MAX_NUM];
    neat_flow *flow = user_data;
    struct neat_ctx *ctx = flow->ctx;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        return NEAT_ERROR_DNS;
    }

    assert (results->lh_first);
    assert(flow->socket);
    flow->socket->family = results->lh_first->ai_family;
    //This is a HACK and is bogus, but it is no worse than what was here before.
    //The resolver doesn't care about transport protocol, only family. So they
    //would just get this first socket type, which is usually TCP. I guess these
    //variables should be determined by something else, like which listen socket
    //data arrives on

    // Hack until we support listening for multiple protocols (again?)
    // Assume that a transport protocol is specified with NEAT_PROPERTY_*_REQUIRED
    // nr_of_stacks = nt_property_translate_protocols(flow->propertyAttempt, stacks);
    json_t *empty_obj = json_object();
    if (json_equal(flow->properties, empty_obj)) {
        // No properties specified, listen to all available protocols
        nt_log(ctx, NEAT_LOG_DEBUG, "No properties specifying protocols to listen for");
        nt_log(ctx, NEAT_LOG_DEBUG, "Listening to all protocols...");

        nr_of_stacks = 0;
        stacks[nr_of_stacks++] = NEAT_STACK_UDP;
        stacks[nr_of_stacks++] = NEAT_STACK_UDPLITE;
        stacks[nr_of_stacks++] = NEAT_STACK_TCP;
        stacks[nr_of_stacks++] = NEAT_STACK_MPTCP;
        stacks[nr_of_stacks++] = NEAT_STACK_SCTP;
        stacks[nr_of_stacks++] = NEAT_STACK_SCTP_UDP;
    } else {
        nt_find_enabled_stacks(flow->properties, stacks, &nr_of_stacks, NULL);
    }
    json_decref(empty_obj);
    assert(nr_of_stacks > 0);

    flow->resolver_results = results;

    flow->isPolling = 1;
    flow->acceptPending = 1;
    flow->isServer = 1;

    //struct sockaddr *sockaddr = (struct sockaddr *) &(results->lh_first->dst_addr);

    for (uint8_t i = 0; i < nr_of_stacks; ++i) {
        struct neat_pollable_socket *listen_socket;
        int fd, socket_type;
        uv_poll_t *handle;

        socket_type = stacks[i] == NEAT_STACK_UDP ||
                      stacks[i] == NEAT_STACK_UDPLITE ?
                      SOCK_DGRAM : SOCK_STREAM;

        // Create only one SCTP socket, enable UDP encaps later
        if (stacks[i] == NEAT_STACK_SCTP_UDP) {
            sctp_udp_encaps = 1;

            stacks[i] = NEAT_STACK_SCTP; // Pretend it's just a normal SCTP socket

            if (sctp_socket != NULL)
                continue;
        } else if (stacks[i] == NEAT_STACK_SCTP && sctp_socket != NULL) {
            continue;
#if defined(__NetBSD__) || defined(__APPLE__)
        } else if (stacks[i] == NEAT_STACK_UDPLITE) {
            nt_log(ctx, NEAT_LOG_DEBUG, "UDPLite not supported on this platform");
            continue;
#endif
        }

        listen_socket = calloc(1, sizeof(struct neat_pollable_socket));
        if (listen_socket == NULL) {
            return NEAT_ERROR_OUT_OF_MEMORY;
        }

        listen_socket->flow     = flow;
        listen_socket->stack    = nt_base_stack(stacks[i]);
        listen_socket->family   = results->lh_first->ai_family;
        listen_socket->type     = socket_type;

        memcpy(&listen_socket->src_sockaddr, &(results->lh_first->dst_addr), sizeof(struct sockaddr_storage));
        memset(&listen_socket->dst_sockaddr, 0, sizeof(struct sockaddr_storage));

#ifdef USRSCTP_SUPPORT
        if (stacks[i] != NEAT_STACK_SCTP) {
            if ((fd = nt_listen_via_kernel(ctx, flow, listen_socket)) == -1) {
                free(listen_socket);
                continue;
            }

        } else {
            if (nt_listen_via_usrsctp(ctx, flow, listen_socket) != 0) {
                free(listen_socket);
                continue;
            }
            fd = -1;
        }
#else
        if ((fd = nt_listen_via_kernel(ctx, flow, listen_socket)) == -1) {
            free(listen_socket);
            continue;
        }
#endif
        listen_socket->fd = fd;

        handle = calloc(1, sizeof(*handle));
        if (handle == NULL) {
            free(listen_socket);
            return NEAT_ERROR_OUT_OF_MEMORY;
        }
        listen_socket->handle = handle;
        handle->data = listen_socket;

        if (stacks[i] == NEAT_STACK_SCTP) {
            sctp_socket = listen_socket;
#ifdef NEAT_SCTP_DTLS
        if (flow->security_needed) {
            nt_dtls_install(ctx, listen_socket);
        }
#endif
        }

        if (listen_socket->fd != -1) { // fd == -1 => USRSCTP
            uv_poll_init(ctx->loop, handle, fd);

            TAILQ_INSERT_TAIL(&flow->listen_sockets, listen_socket, next);

            if ((nt_base_stack(stacks[i]) == NEAT_STACK_SCTP) ||
                (nt_base_stack(stacks[i]) == NEAT_STACK_UDP) ||
                (nt_base_stack(stacks[i]) == NEAT_STACK_UDPLITE) ||
                (nt_base_stack(stacks[i]) == NEAT_STACK_TCP) ||
                (nt_base_stack(stacks[i]) == NEAT_STACK_MPTCP)) {
                uv_poll_start(handle, UV_READABLE, uvpollable_cb);
            } else {
                // do normal i/o events without accept() for non connected protocols
                nt_update_poll_handle(ctx, flow, handle);
            }
        } else {
            flow->acceptPending = 1;
        }

        socket_count++;
    }

    if (socket_count == 0) {
        nt_io_error(ctx, flow, NEAT_ERROR_IO);
        return NEAT_ERROR_IO;
    }

#ifdef USRSCTP_SUPPORT
    if (sctp_udp_encaps && sctp_socket) {
        struct sctp_udpencaps encaps;
        memset(&encaps, 0, sizeof(struct sctp_udpencaps));

        encaps.sue_address.ss_family = AF_INET;
        encaps.sue_port              = htons(SCTP_UDP_TUNNELING_PORT);

        if (usrsctp_setsockopt(sctp_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) != 0) {
            nt_log(ctx, NEAT_LOG_WARNING, "Unable to set UDP encapsulation port");
        }
    }
#else // ifdef USRSCTP_SUPPORT
#if defined(SCTP_REMOTE_UDP_ENCAPS_PORT)
    // Enable SCTP/UDP encaps if specified
    if (sctp_udp_encaps && sctp_socket) {
        struct sctp_udpencaps encaps;
        memset(&encaps, 0, sizeof(struct sctp_udpencaps));

        encaps.sue_address.ss_family = sctp_socket->family;
        encaps.sue_port              = htons(SCTP_UDP_TUNNELING_PORT);

        if (setsockopt(sctp_socket->fd, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT,
                       (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) != 0) {
            nt_log(ctx, NEAT_LOG_WARNING, "Unable to set UDP encapsulation port");
        }
    }

#else // if defined(__FreeBSD__)
    if (sctp_udp_encaps && sctp_socket) {
        nt_log(ctx, NEAT_LOG_DEBUG, "SCTP/UDP encapsulation not available");
    }
#endif // if defined(__FreeBSD__)
#endif // ifdef else USRSCTP_SUPPORT
    return NEAT_ERROR_OK;
}

neat_error_code
neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                            uint16_t port, struct neat_tlv optional[], unsigned int opt_count)
{
    const char *local_name  = NULL;
    json_t *val             = NULL;
    json_t *property        = NULL;
    int stream_count        = 0;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#if defined(WEBRTC_SUPPORT)
    if (flow->webrtcEnabled) {
        neat_set_listening_flow(ctx, flow);
        return NEAT_OK;
    }
#endif
    if (flow->name) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    HANDLE_OPTIONAL_ARGUMENTS_START()
        OPTIONAL_STRING(NEAT_TAG_LOCAL_NAME, local_name)
        OPTIONAL_INTEGER(NEAT_TAG_STREAM_COUNT, stream_count)
        // OPTIONAL_STRING(NEAT_TAG_SERVICE_NAME, service_name)
    HANDLE_OPTIONAL_ARGUMENTS_END();

    if (stream_count > 0) {
        flow->streams_requested = stream_count;
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - %d streams", __func__, flow->streams_requested);
    }

    if (!local_name) {
        local_name = "0.0.0.0";
    }

    ;
    if ((flow->name = strdup(local_name)) == NULL) {
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    flow->port  = port;
    flow->ctx   = ctx;

    if ((property = json_object_get(flow->properties, "security")) != NULL &&
        (val = json_object_get(property, "value")) != NULL &&
        json_typeof(val) == JSON_TRUE) {
        flow->security_needed = 1;
    } else {
        flow->security_needed = 0;
    }

    if ((property = json_object_get(flow->properties, "tproxy")) != NULL &&
        (val = json_object_get(property, "value")) != NULL &&
        json_typeof(val) == JSON_TRUE) {
        flow->tproxy = 1;
    } else {
        flow->tproxy = 0;
    }

    if (!ctx->resolver) {
        ctx->resolver = nt_resolver_init(ctx, "/etc/resolv.conf");
    }

    if (!ctx->pvd) {
        ctx->pvd = nt_pvd_init(ctx);
    }

    nt_resolve(ctx->resolver, AF_INET, flow->name, flow->port, accept_resolve_cb, flow);
    return NEAT_OK;
}

static neat_error_code
nt_write_flush(struct neat_ctx *ctx, struct neat_flow *flow)
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
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (TAILQ_EMPTY(&flow->bufferedMessages)) {
        return NEAT_OK;
    }

    TAILQ_FOREACH_SAFE(msg, &flow->bufferedMessages, message_next, next_msg) {
        do {
#ifdef NEAT_SCTP_DTLS
            if ((flow->socket->fd != -1) && flow->security_needed && nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
                struct security_data *private = (struct security_data *) flow->socket->dtls_data->userData;
                struct bio_dgram_sctp_sndinfo sinfo;
                memset(&sinfo, 0, sizeof(struct bio_dgram_sctp_sndinfo));
                BIO_ctrl(private->dtlsBIO, BIO_CTRL_DGRAM_SCTP_SET_SNDINFO, sizeof(struct bio_dgram_sctp_sndinfo), &sinfo);
                socklen_t size = SSL_write(private->ssl, msg->buffered + msg->bufferedOffset, msg->bufferedSize);
                if (SSL_get_error(private->ssl, size) == SSL_ERROR_WANT_WRITE || SSL_get_error(private->ssl, size) == SSL_ERROR_WANT_READ) {
                    uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE | UV_READABLE);
                } else if (size > 0) {
                    msg->bufferedOffset += size;
                    msg->bufferedSize -= size;
                }
            }
#endif
            if (!flow->security_needed || !(nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP)) {
                iov.iov_base = msg->buffered + msg->bufferedOffset;
                if ((nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) &&
                    (flow->socket->sctp_explicit_eor) &&
                    (flow->socket->write_limit > 0) &&
                    (msg->bufferedSize > flow->socket->write_limit)) {
                    len = flow->socket->write_limit;
                } else {
                    len = msg->bufferedSize;
                }
                iov.iov_len = len;
                msghdr.msg_name = NULL;
                msghdr.msg_namelen = 0;
                msghdr.msg_iov = &iov;
                msghdr.msg_iovlen = 1;

                if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
#if defined(SCTP_SNDINFO)
                    msghdr.msg_control = cmsgbuf;
                    msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndinfo));
                    cmsg = (struct cmsghdr *)cmsgbuf;
                    cmsg->cmsg_level = IPPROTO_SCTP;
                    cmsg->cmsg_type = SCTP_SNDINFO;
                    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
                    sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
                    memset(sndinfo, 0, sizeof(struct sctp_sndinfo));
                    sndinfo->snd_sid = msg->stream_id;

                    if (msg->unordered) {
                        sndinfo->snd_flags |= SCTP_UNORDERED;
                    }

#if defined(SCTP_EXPLICIT_EOR)
                    if ((flow->socket->sctp_explicit_eor) && (len == msg->bufferedSize)) {
                        sndinfo->snd_flags |= SCTP_EOR;
                    }
#endif // defined(SCTP_EXPLICIT_EOR)
#elif defined (SCTP_SNDRCV)
                    msghdr.msg_control = cmsgbuf;
                    msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
                    cmsg = (struct cmsghdr *)cmsgbuf;
                    cmsg->cmsg_level = IPPROTO_SCTP;
                    cmsg->cmsg_type = SCTP_SNDRCV;
                    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
                    sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
                    memset(sndrcvinfo, 0, sizeof(struct sctp_sndrcvinfo));
                    sndrcvinfo->sinfo_stream = msg->stream_id;

                    if (msg->unordered) {
                        sndrcvinfo->sinfo_flags |= SCTP_UNORDERED;
                    }

#if defined(SCTP_EXPLICIT_EOR)
                    if ((flow->socket->sctp_explicit_eor) && (len == msg->bufferedSize)) {
                        sndrcvinfo->sinfo_flags |= SCTP_EOR;
                    }
#endif // defined(SCTP_EXPLICIT_EOR)
#else // defined(SCTP_SNDINFO)
                    msghdr.msg_control = NULL;
                    msghdr.msg_controllen = 0;
#endif // defined(SCTP_SNDINFO)
                } else {
                    msghdr.msg_control = NULL;
                    msghdr.msg_controllen = 0;
                }

                msghdr.msg_flags = 0;
                if (flow->socket->fd != -1) {
#ifndef MSG_NOSIGNAL
                    rv = sendmsg(flow->socket->fd, (const struct msghdr *)&msghdr, 0);
#else
                    rv = sendmsg(flow->socket->fd, (const struct msghdr *)&msghdr, MSG_NOSIGNAL);
#endif
                } else {
#if defined(USRSCTP_SUPPORT)
                    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
                        nt_log(ctx, NEAT_LOG_INFO, "%s - send %zd bytes on flow %p and socket %p", __func__, msg->bufferedSize, (void *)flow, (void *)flow->socket->usrsctp_socket);
                        rv = usrsctp_sendv(flow->socket->usrsctp_socket, msg->buffered + msg->bufferedOffset, msg->bufferedSize,
                                           (struct sockaddr *) (flow->sockAddr), 1, (void *)sndinfo,
                                           (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
                                           0);
                    } else {
                        nt_log(ctx, NEAT_LOG_ERROR, "%s - fd == -1 and no SCTP used ... error!", __func__);
                    }
#else
                    nt_log(ctx, NEAT_LOG_ERROR, "%s - fd == -1 and not usrsctp support - fixme!", __func__);
                    assert(false);
#endif
                }
                if (!flow->security_needed) {
                    if (rv < 0) {
                        nt_log(ctx, NEAT_LOG_WARNING, "%s - sending failed - %s", __func__, strerror(errno));
                        if (errno == EWOULDBLOCK) {
                            return NEAT_ERROR_WOULD_BLOCK;
                        } else {
                            return NEAT_ERROR_IO;
                        }
                    }
                    msg->bufferedOffset += rv;
                    msg->bufferedSize -= rv;
                }
            }
        } while (msg->bufferedSize > 0);

        TAILQ_REMOVE(&flow->bufferedMessages, msg, message_next);
        free(msg->buffered);
        free(msg);
    }
    if (TAILQ_EMPTY(&flow->bufferedMessages)) {
        flow->isDraining = 0;
    }
    return NEAT_OK;
}

static neat_error_code
nt_write_fillbuffer(struct neat_ctx *ctx,
                        struct neat_flow *flow,
                        const unsigned char *buffer,
                        uint32_t amt,
                        int stream_id,
                        uint8_t unordered,
                        uint8_t pr_method,
                        uint32_t pr_value)
{
    struct neat_buffered_message *msg;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    // TODO: A better implementation here is a linked list of buffers
    // but this gets us started
    if (amt == 0) {
        return NEAT_OK;
    }

    if ((flow->socket->stack != NEAT_STACK_TCP) || TAILQ_EMPTY(&flow->bufferedMessages)) {
        msg = calloc(1, sizeof(struct neat_buffered_message));
        if (msg == NULL) {
            return NEAT_ERROR_OUT_OF_MEMORY;
        }
        msg->buffered = NULL;
        msg->bufferedOffset = 0;
        msg->bufferedSize = 0;
        msg->bufferedAllocation = 0;
        msg->stream_id = stream_id;
        msg->unordered = unordered;
        msg->pr_method = pr_method;
        msg->pr_value = pr_value;
        TAILQ_INSERT_TAIL(&flow->bufferedMessages, msg, message_next);
    } else {
        assert(stream_id == 0);
        msg = TAILQ_LAST(&flow->bufferedMessages, neat_message_queue_head);
    }
    // check if there is room to buffer without extending allocation
    if ((msg->bufferedOffset + msg->bufferedSize + amt) <= msg->bufferedAllocation) {
        memcpy(msg->buffered + msg->bufferedOffset + msg->bufferedSize, buffer, amt);
        msg->bufferedSize += amt;
        return NEAT_OK;
    }

    // round up to ~8K
    size_t needed = ((amt + msg->bufferedSize) + 8191) & ~8191;
    if (msg->bufferedOffset == 0) {
        msg->buffered = realloc(msg->buffered, needed);
        if (msg->buffered == NULL) {
            return NEAT_ERROR_OUT_OF_MEMORY;
        }
        msg->bufferedAllocation = needed;
    } else {
        void *newptr = malloc(needed);
        if (newptr == NULL) {
            return NEAT_ERROR_OUT_OF_MEMORY;
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
nt_write_to_lower_layer(struct neat_ctx *ctx, struct neat_flow *flow,
                      const unsigned char *buffer, uint32_t amt,
                      struct neat_tlv optional[], unsigned int opt_count)
{
    ssize_t rv = 0;
    size_t len;
    int atomic;
    neat_error_code code = NEAT_OK;
#ifdef NEAT_SCTP_DTLS
    struct security_data *private = NULL;
#endif

    int stream_id            = 0;
    int has_stream_id        = 0;
    // int has_context       = 0;
    // int context           = 0;
    int has_pr_method     = 0;
    int pr_method         = 0;
    int has_pr_value      = 0;
    int pr_value          = 0;
    int has_unordered     = 0;
    int unordered         = 0;
    // int has_priority      = 0;
    // float priority        = 0.5f;
    // int has_dest_addr     = 0;
    // const char *dest_addr = "";
    struct msghdr msghdr;
    struct iovec iov;
#if defined(SCTP_SNDINFO)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo)) +
#if defined(SCTP_PRINFO)
        CMSG_SPACE(sizeof(struct sctp_prinfo))
#else // defined(SCTP_PRINFO)
        0
#endif // defined(SCTP_PRINFO)
    ];
    struct sctp_sndinfo *sndinfo = NULL;
#elif defined(SCTP_SNDRCV)
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)) +
#if defined(SCTP_PRINFO)
        CMSG_SPACE(sizeof(struct sctp_prinfo))
#else // defined(SCTP_PRINFO)
        0
#endif // defined(SCTP_PRINFO)
    ];
    struct sctp_sndrcvinfo *sndrcvinfo;
#endif //defined(SCTP_SNDINFO) || defined (SCTP_SNDRCV)

#if defined(SCTP_SNDINFO) || defined (SCTP_SNDRCV)
    struct cmsghdr *cmsg;
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));
#if defined(SCTP_PRINFO)
    struct sctp_prinfo *prinfo;
#endif // defined(SCTP_PRINFO)
#endif // defined(SCTP_SNDINFO) || defined (SCTP_SNDRCV)

    memset(&msghdr, 0, sizeof(msghdr));
    memset(&iov, 0, sizeof(iov));

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    HANDLE_OPTIONAL_ARGUMENTS_START()
        OPTIONAL_INTEGER_PRESENT(NEAT_TAG_STREAM_ID, stream_id, has_stream_id)
        // OPTIONAL_INTEGER_PRESENT(NEAT_TAG_CONTEXT, context, has_context)
        OPTIONAL_INTEGER_PRESENT(NEAT_TAG_PARTIAL_RELIABILITY_METHOD, pr_method, has_pr_method)
        OPTIONAL_INTEGER_PRESENT(NEAT_TAG_PARTIAL_RELIABILITY_VALUE, pr_value, has_pr_value)
        OPTIONAL_INTEGER_PRESENT(NEAT_TAG_UNORDERED, unordered, has_unordered)
        // OPTIONAL_FLOAT_PRESENT(  NEAT_TAG_PRIORITY, priority, has_priority)
        // OPTIONAL_STRING_PRESENT( NEAT_TAG_DESTINATION_IP_ADDRESS, dest_addr, has_dest_addr)
    HANDLE_OPTIONAL_ARGUMENTS_END();


    if (has_stream_id && stream_id < 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - invalid stream id: Must be 0 or greater", __func__);
        return NEAT_ERROR_BAD_ARGUMENT;
    } else if (has_stream_id && flow->socket->sctp_streams_available == 1 && stream_id != 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - tried to specify stream id when only a single stream is in use - ignoring", __func__);
        stream_id = 0;
    } else if (has_stream_id && flow->socket->stack != NEAT_STACK_SCTP) {
        // For now, warn about this. Maybe we emulate multistreaming over TCP in
        // the future?
        nt_log(ctx, NEAT_LOG_WARNING, "%s - tried to specify stream id when using a protocol which does not support multistreaming - ignoring", __func__);
        stream_id = 0;
    }

#ifdef SCTP_MULTISTREAMING
    // multistream stream_id override - not very pretty
    if (flow->multistream_id) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - MULTISTREAM ID = %d", __func__, flow->multistream_id);
        stream_id = flow->multistream_id;
    }
#endif // SCTP_MULTISTREAMING

    if (has_pr_method && has_pr_value) {
#if !defined(SCTP_PRINFO)
        nt_log(ctx, NEAT_LOG_WARNING, "%s - partial reliability options set but not supported");
#endif
    }

    if (has_unordered) {
#if !defined(SCTP_SNDRCV) && !defined(SCTP_SNDINFO)
        nt_log(ctx, NEAT_LOG_WARNING, "%s - unordered delivery requested but not supported");
#endif
    }

    switch (flow->socket->stack) {
    case NEAT_STACK_TCP:
    case NEAT_STACK_MPTCP:
        atomic = 0;
        break;
    case NEAT_STACK_SCTP_UDP:
    case NEAT_STACK_SCTP:
        if (flow->socket->sctp_explicit_eor) {
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
    if (atomic && flow->socket->write_size > 0 && amt > flow->socket->write_size) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - message size exceeds limit - aborting transmission", __func__);
        return NEAT_ERROR_MESSAGE_TOO_BIG;
    }

    if (TAILQ_EMPTY(&flow->bufferedMessages) && code == NEAT_OK && amt > 0) {
        iov.iov_base = (void *)buffer;
        if ((nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) &&
            (flow->socket->sctp_explicit_eor) &&
            (flow->socket->write_limit > 0) &&
            (amt > flow->socket->write_limit)) {
            len = flow->socket->write_limit;
        } else {
            len = amt;
        }
        iov.iov_len         = len;
        msghdr.msg_name     = NULL;
        msghdr.msg_namelen  = 0;
        msghdr.msg_iov      = &iov;
        msghdr.msg_iovlen   = 1;

        if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
#ifdef NEAT_SCTP_DTLS
            if (flow->security_needed) {
                private = (struct security_data *) flow->socket->dtls_data->userData;
                struct bio_dgram_sctp_sndinfo sinfo;
                memset(&sinfo, 0, sizeof(struct bio_dgram_sctp_sndinfo));
                sinfo.snd_sid = stream_id;
                BIO_ctrl(private->dtlsBIO, BIO_CTRL_DGRAM_SCTP_SET_SNDINFO, sizeof(struct bio_dgram_sctp_sndinfo), &sinfo);
            }
#endif
            if (!flow->security_needed) {
#if defined(SCTP_SNDINFO)
                msghdr.msg_control = cmsgbuf;
                msghdr.msg_controllen = sizeof(cmsgbuf);
                cmsg = (struct cmsghdr *)cmsgbuf;
                cmsg->cmsg_level = IPPROTO_SCTP;
                cmsg->cmsg_type = SCTP_SNDINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
                sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
                memset(sndinfo, 0, sizeof(struct sctp_sndinfo));
                if (stream_id) {
                    sndinfo->snd_sid = stream_id;
                }
                if (has_unordered && unordered) {
                    sndinfo->snd_flags |= SCTP_UNORDERED;
                }
                cmsg = (struct cmsghdr *)((caddr_t)cmsg + CMSG_SPACE(sizeof(struct sctp_sndinfo)));


#if defined(SCTP_PRINFO)
                cmsg->cmsg_level = IPPROTO_SCTP;
                cmsg->cmsg_type = SCTP_PRINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_prinfo));
                prinfo = (struct sctp_prinfo *)CMSG_DATA(cmsg);
                memset(prinfo, 0, sizeof(struct sctp_prinfo));
                if (has_pr_method && has_pr_value) {
                    prinfo->pr_policy = pr_method;
                    prinfo->pr_value = pr_value;
                }
#endif

#if defined(SCTP_EXPLICIT_EOR)
                if ((flow->socket->sctp_explicit_eor) && (len == amt)) {
                    sndinfo->snd_flags |= SCTP_EOR;
                }
#endif // defined(SCTP_EXPLICIT_EOR)


#elif defined (SCTP_SNDRCV)
                msghdr.msg_control = cmsgbuf;
                msghdr.msg_controllen = sizeof(cmsgbuf);
                cmsg = (struct cmsghdr *)cmsgbuf;
                cmsg->cmsg_level = IPPROTO_SCTP;
                cmsg->cmsg_type = SCTP_SNDRCV;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
                sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
                memset(sndrcvinfo, 0, sizeof(struct sctp_sndrcvinfo));

                if (stream_id) {
                    sndrcvinfo->sinfo_stream = stream_id;
                }

                if (has_unordered && unordered) {
                    sndrcvinfo->sinfo_flags |= SCTP_UNORDERED;
                }

#if defined(SCTP_PRINFO)
                cmsg->cmsg_level = IPPROTO_SCTP;
                cmsg->cmsg_type = SCTP_PRINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_prinfo));
                prinfo = (struct sctp_prinfo *)CMSG_DATA(cmsg);
                memset(prinfo, 0, sizeof(struct sctp_prinfo));

                if (has_pr_value && has_pr_method) {
                    prinfo->pr_policy = pr_method;
                    prinfo->pr_value = pr_value;
                }
#endif

#if defined(SCTP_EXPLICIT_EOR)
                if ((flow->socket->sctp_explicit_eor) && (len == amt)) {
                    sndrcvinfo->sinfo_flags |= SCTP_EOR;
                }
#endif // defined(SCTP_EXPLICIT_EOR)
#else
                msghdr.msg_control = NULL;
                msghdr.msg_controllen = 0;
#endif
            }
        } else {
            msghdr.msg_control = NULL;
            msghdr.msg_controllen = 0;
        }

        msghdr.msg_flags = 0;
        if (flow->socket->fd != -1) {
#ifdef NEAT_SCTP_DTLS
            if (flow->security_needed && nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
                rv = SSL_write(private->ssl, buffer, len);
            } else {
#endif

#ifndef MSG_NOSIGNAL
                rv = sendmsg(flow->socket->fd, (const struct msghdr *)&msghdr, 0);
#else
                rv = sendmsg(flow->socket->fd, (const struct msghdr *)&msghdr, MSG_NOSIGNAL);
#endif

#ifdef NEAT_SCTP_DTLS
            }
#endif

        } else {
#if defined(USRSCTP_SUPPORT)
            nt_log(ctx, NEAT_LOG_INFO, "%s - send %zd bytes on flow %p and socket %p", __func__, len, (void *)flow, (void *)flow->socket->usrsctp_socket);
            rv = usrsctp_sendv(flow->socket->usrsctp_socket, buffer, len, NULL, 0,
                  (void *)sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
                  0);
            if (rv < 0) {
                perror("usrsctp_sendv");
            }
#endif
        }
#ifdef IPPROTO_SCTP
        if (flow->socket->stack == NEAT_STACK_SCTP) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%zd bytes sent on stream %d", rv, stream_id);
        } else {
            nt_log(ctx, NEAT_LOG_DEBUG, "%zd bytes sent", rv);
        }
#else
        nt_log(ctx, NEAT_LOG_DEBUG, "%zd bytes sent", rv);
#endif
        if (rv < 0 ) {
            nt_log(ctx, NEAT_LOG_WARNING, "%s - sending failed - %s", __func__, strerror(errno));
            if (errno == ENOENT) {
                flow->isClosing = 1;
            }
            if (errno != EWOULDBLOCK) {
                return NEAT_ERROR_IO;
            }
        }
        if (rv != -1) {
            amt -= rv;
            buffer += rv;
        }
    }

    /* Update flow statistics with the sent bytes */
    flow->flow_stats.bytes_sent += rv;

    code = nt_write_fillbuffer(ctx, flow, buffer, amt, stream_id, unordered, pr_method, pr_value);
    if (code != NEAT_OK) {
        return code;
    }
    if (TAILQ_EMPTY(&flow->bufferedMessages)) {
        flow->isDraining = 0;
        //io_all_written(ctx, flow, stream_id);
    } else {
        flow->isDraining = 1;
    }
#if defined(USRSCTP_SUPPORT)
    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP)
        return NEAT_OK;
#endif

    nt_update_poll_handle(ctx, flow, flow->socket->handle);
    return NEAT_OK;
}

static neat_error_code
nt_read_from_lower_layer(struct neat_ctx *ctx, struct neat_flow *flow,
                     unsigned char *buffer, uint32_t amt, uint32_t *actualAmt,
                      struct neat_tlv optional[], unsigned int opt_count)
{
    int stream_id = 0;
    ssize_t rv;
#ifdef SCTP_MULTISTREAMING
    struct neat_read_queue_message *multistream_message = NULL;
#endif // SCTP_MULTISTREAMING

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    HANDLE_OPTIONAL_ARGUMENTS_START()
        SKIP_OPTARG(NEAT_TAG_STREAM_ID)
        SKIP_OPTARG(NEAT_TAG_PARTIAL_MESSAGE_RECEIVED)
        SKIP_OPTARG(NEAT_TAG_PARTIAL_SEQNUM)
        SKIP_OPTARG(NEAT_TAG_UNORDERED)
        SKIP_OPTARG(NEAT_TAG_UNORDERED_SEQNUM)
        SKIP_OPTARG(NEAT_TAG_TRANSPORT_STACK)
    HANDLE_OPTIONAL_ARGUMENTS_END();

    if (flow->socket->stack == NEAT_STACK_WEBRTC) {
        assert(flow->readBuffer);
        if (flow->readBufferSize > amt) {
            /* this can only happen if message boundaries are not preserved */
            *actualAmt = amt;
            memcpy(buffer, flow->readBuffer, amt);
            /* This is very inefficient, we should also use a offset */
            memmove(flow->readBuffer, flow->readBuffer + amt, flow->readBufferSize - amt);
            flow->readBufferSize -= amt;
        } else {
            *actualAmt = flow->readBufferSize;
            memcpy(buffer, flow->readBuffer, flow->readBufferSize);
            flow->readBufferSize = 0;
            flow->readBufferMsgComplete = 0;
        }
        goto end;
    }

    if ((nt_base_stack(flow->socket->stack) == NEAT_STACK_UDP) ||
        (nt_base_stack(flow->socket->stack) == NEAT_STACK_UDPLITE) ||
        (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP)) {

        if (flow->socket->multistream) {
#ifdef SCTP_MULTISTREAMING
            if (TAILQ_EMPTY(&flow->multistream_read_queue)) {
                if (flow->multistream_reset_in) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - read queue empty, got incoming stream reset, returning 0", __func__);
                    *actualAmt = 0;
                    goto end;
                } else {
                    nt_log(ctx, NEAT_LOG_WARNING, "%s - read queue empty - would block", __func__);
                    return NEAT_ERROR_WOULD_BLOCK;
                }
            }

            multistream_message = TAILQ_FIRST(&flow->multistream_read_queue);

            if (amt < multistream_message->buffer_size) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - Message too big", __func__);
                return NEAT_ERROR_MESSAGE_TOO_BIG;
            }

            nt_log(ctx, NEAT_LOG_DEBUG, "%s - reading from multistream flow - stream_id %d", __func__, flow->multistream_id);

            stream_id = flow->multistream_id;

            memcpy(buffer, multistream_message->buffer, multistream_message->buffer_size);
            *actualAmt = multistream_message->buffer_size;
            TAILQ_REMOVE(&flow->multistream_read_queue, multistream_message, message_next);
            free(multistream_message->buffer);
            free(multistream_message);
#else // SCTP_MULTISTREAMING
            assert(false);
#endif // SCTP_MULTISTREAMING

        } else {
            if (flow->preserveMessageBoundaries) {
                if (!flow->readBufferMsgComplete) {
                    return NEAT_ERROR_WOULD_BLOCK;
                }
                if (flow->readBufferSize > amt) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s: Message too big", __func__);
                    return NEAT_ERROR_MESSAGE_TOO_BIG;
                }
            } else if (flow->readBufferSize == 0) {
                nt_log(ctx, NEAT_LOG_DEBUG, "%s nothing scheduled", __func__);
                if (flow->eofSeen) {
                    flow->eofSeen = 0;
                    return NEAT_OK;
                } else {
                    return NEAT_ERROR_WOULD_BLOCK;
                }
            }

            assert(flow->readBuffer);
            if (flow->readBufferSize > amt) {
                /* this can only happen if message boundaries are not preserved */
                *actualAmt = amt;
                memcpy(buffer, flow->readBuffer, amt);
                /* This is very inefficient, we should also use a offset */
                memmove(flow->readBuffer, flow->readBuffer + amt, flow->readBufferSize - amt);
                flow->readBufferSize -= amt;
            } else {
                *actualAmt = flow->readBufferSize;
                memcpy(buffer, flow->readBuffer, flow->readBufferSize);
                flow->readBufferSize = 0;
                flow->readBufferMsgComplete = 0;
            }
        }


        goto end;
    }

    rv = recv(flow->socket->fd, buffer, amt, 0);

    if (rv == -1) {
        if (errno == ECONNRESET) {
            nt_log(ctx, NEAT_LOG_ERROR, "%s: ECONNRESET", __func__);
            nt_notify_aborted(flow);
        } else if (errno == EWOULDBLOCK) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s would block", __func__);
            return NEAT_ERROR_WOULD_BLOCK;
        } else {
            nt_log(ctx, NEAT_LOG_ERROR, "%s: err %d (%s)", __func__, errno, strerror(errno));
        }
        return NEAT_ERROR_IO;
    }
    nt_log(ctx, NEAT_LOG_DEBUG, "%s %d", __func__, rv);
    *actualAmt = rv;

    /*Update flow statistics */
    flow->flow_stats.bytes_received += (int)rv;


end:
    // Fill in optional return values if they are requested
    if (optional != NULL && opt_count > 0) {\
        for (unsigned int i = 0; i < opt_count; ++i) {\
            switch (optional[i].tag) {
            case NEAT_TAG_STREAM_ID:
                optional[i].value.integer = stream_id;
                optional[i].type = NEAT_TYPE_INTEGER;
                break;
            case NEAT_TAG_PARTIAL_MESSAGE_RECEIVED:
            case NEAT_TAG_PARTIAL_SEQNUM:
            case NEAT_TAG_UNORDERED:
            case NEAT_TAG_UNORDERED_SEQNUM:
                // TODO: Assign meaningful values
                optional[i].value.integer = 0;
                optional[i].type = NEAT_TYPE_INTEGER;
                break;
            case NEAT_TAG_TRANSPORT_STACK:
                optional[i].value.integer = flow->socket->stack;
                optional[i].type = NEAT_TYPE_INTEGER;
                break;
            default:
                break;
            }
        }
    }

    return NEAT_OK;
}

static int
nt_accept_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow, int fd)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    return accept(fd, NULL, NULL);
}

int nt_stack_to_protocol(neat_protocol_stack_type stack)
{
    switch (stack) {
        case NEAT_STACK_UDP:
            return IPPROTO_UDP;
#ifdef IPPROTO_UDPLITE
        case NEAT_STACK_UDPLITE:
            return IPPROTO_UDPLITE;
#endif
        case NEAT_STACK_MPTCP:
#if !defined(MPTCP_SUPPORT)
            return 0;
#endif
        case NEAT_STACK_TCP:
            return IPPROTO_TCP;
#ifdef IPPROTO_SCTP
        case NEAT_STACK_SCTP_UDP:
        case NEAT_STACK_WEBRTC:
        case NEAT_STACK_SCTP:
            return IPPROTO_SCTP;
#endif
        default:
            return 0;
    }
}

int
nt_base_stack(neat_protocol_stack_type stack)
{
    switch (stack) {
        case NEAT_STACK_UDP:
        case NEAT_STACK_UDPLITE:
        case NEAT_STACK_TCP:
        case NEAT_STACK_MPTCP:
        case NEAT_STACK_SCTP:
            return stack;
        case NEAT_STACK_SCTP_UDP:
        case NEAT_STACK_WEBRTC:
            return NEAT_STACK_WEBRTC;
        default:
            return 0;
    }
}

static int
nt_connect(struct neat_he_candidate *candidate, uv_poll_cb callback_fx)
{
#if defined(__FreeBSD__)
    struct sctp_udpencaps encaps;
#if defined(FLOW_GROUPS)
    int group;
    int prio;
#endif // defined(FLOW_GROUPS)
#endif // defined(__FreeBSD__)

#ifdef TCP_CONGESTION
    const char *algo;
#endif
    int enable = 1;
    int retval;
    socklen_t len = 0;
    int size = 0, protocol;
#ifdef __linux__
    char if_name[IF_NAMESIZE];
#endif
    struct neat_he_sockopt *sockopt_ptr;
    struct neat_ctx *ctx = candidate->ctx;

    socklen_t slen =
            (candidate->pollable_socket->family == AF_INET) ?
                sizeof (struct sockaddr_in) :
                sizeof (struct sockaddr_in6);
    char addrsrcbuf[INET6_ADDRSTRLEN];
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#if defined(USRSCTP_SUPPORT)
    if (nt_base_stack(candidate->pollable_socket->stack) == NEAT_STACK_SCTP) {
        nt_connect_via_usrsctp(candidate);
        return(NEAT_ERROR_OK);
    }
#endif

    protocol = nt_stack_to_protocol(nt_base_stack(candidate->pollable_socket->stack));
    if (protocol == 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "Stack (%s) %d not supported", stack_to_string(candidate->pollable_socket->stack), candidate->pollable_socket->stack);
        return -1;
    }
    if ((candidate->pollable_socket->fd = socket(candidate->pollable_socket->family, candidate->pollable_socket->type, protocol)) < 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "Failed to create he socket (family:%d, type:%d, prodocol:%d)",
               candidate->pollable_socket->family,
               candidate->pollable_socket->type,
               protocol);
        return -1;
    }

    if (setsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SO_REUSEADDR) failed");
    }

    if (setsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "Call to setsockopt(SO_REUSEPORT) failed");
    }

#if defined(SO_NOSIGPIPE)
    if (setsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_NOSIGPIPE, &enable, sizeof(enable)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - Call to setsockopt(SO_NOSIGPIPE) failed", __func__);
    }
#endif //defined(SO_NOSIGPIPE)

    TAILQ_FOREACH(sockopt_ptr, &(candidate->sock_opts), next) {
        switch (sockopt_ptr->type) {
        case NEAT_SOCKOPT_INT:
            if (setsockopt(candidate->pollable_socket->fd, sockopt_ptr->level, sockopt_ptr->name, &(sockopt_ptr->value.i_val), sizeof(int)) < 0)
                nt_log(ctx, NEAT_LOG_ERROR, "Socket option error: %s", strerror(errno));
            break;
        case NEAT_SOCKOPT_STRING:
            if (setsockopt(candidate->pollable_socket->fd, sockopt_ptr->level, sockopt_ptr->name, sockopt_ptr->value.s_val, (socklen_t)strlen(sockopt_ptr->value.s_val)) < 0)
                nt_log(ctx, NEAT_LOG_ERROR, "Socket option error: %s", strerror(errno));
            break;
        default:
            nt_log(ctx, NEAT_LOG_ERROR, "Illegal socket option");
        }
    }

#if defined(MPTCP_SUPPORT)
    if (nt_base_stack(candidate->pollable_socket->stack) == NEAT_STACK_MPTCP) {
        if (candidate->pollable_socket->flow->isMultihoming) {
            // We fail MPTCP candidate in case MPTCP is not supported (no fallback to TCP)
            if (candidate->ctx->sys_mptcp_enabled == MPTCP_SYS_DISABLED) {
                nt_log(ctx, NEAT_LOG_ERROR, "Could not use MPTCP over for socket %d, MPTCP globaly disabled", candidate->pollable_socket->fd);
                return -2;
            } else if (candidate->ctx->sys_mptcp_enabled == MPTCP_SYS_APP_CTRL) {
                if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, MPTCP_ENABLED, &enable, sizeof(int)) < 0) {
                    nt_log(ctx, NEAT_LOG_ERROR, "Could not use MPTCP over for socket %d, setsockopt failed", candidate->pollable_socket->fd);
                    return -2;
                }
            }
        } else {
            // For disabled multihoming, MPTCP silently falls back to TCP
            if (candidate->ctx->sys_mptcp_enabled == MPTCP_SYS_ENABLED) {
                nt_log(ctx, NEAT_LOG_ERROR, "Could not disable MPTCP for socket %d, MPTCP globaly enabled", candidate->pollable_socket->fd);
                return -2;
            } else if (candidate->ctx->sys_mptcp_enabled == MPTCP_SYS_APP_CTRL) {
                int disable = 0;
                if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, MPTCP_ENABLED, &disable, sizeof(int)) < 0) {
                    nt_log(ctx, NEAT_LOG_ERROR, "Could not disable MPTCP for socket %d, setsockopt failed", candidate->pollable_socket->fd);
                    return -2;
                }
            }
        }
    } else if (nt_base_stack(candidate->pollable_socket->stack) == NEAT_STACK_TCP) {
        if (candidate->ctx->sys_mptcp_enabled == MPTCP_SYS_ENABLED) {
            nt_log(ctx, NEAT_LOG_ERROR, "Could not use TCP over for socket %d, MPTCP globaly enabled", candidate->pollable_socket->fd);
            return -2;
        } else if (candidate->ctx->sys_mptcp_enabled == MPTCP_SYS_APP_CTRL) {
            int disable = 0;
            if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, MPTCP_ENABLED, &disable, sizeof(int)) < 0) {
                nt_log(ctx, NEAT_LOG_ERROR, "Could not disable MPTCP for socket %d, setsockopt failed", candidate->pollable_socket->fd);
                return -2;
            }
        }
    }
#endif // MPTCP_SUPPORT

    if (candidate->pollable_socket->flow->isMultihoming && nt_base_stack(candidate->pollable_socket->stack) == NEAT_STACK_SCTP) {
        char *local_addr_ptr = (char*) (candidate->pollable_socket->local_addr);
        char *address_name, *ptr = NULL;
        char *tmp = strdup(candidate->pollable_socket->src_address);
        if (!tmp) {
            return -1;
        }

        address_name = strtok_r((char *)tmp, ",", &ptr);
        while (address_name != NULL) {
            struct sockaddr_in *s4 = (struct sockaddr_in*) local_addr_ptr;
            struct sockaddr_in6 *s6 = (struct sockaddr_in6*) local_addr_ptr;
            if (inet_pton(AF_INET6, address_name, &s6->sin6_addr)) {
                s6->sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
                s6->sin6_len = sizeof(struct sockaddr_in6);
#endif
                local_addr_ptr += sizeof(struct sockaddr_in6);
            } else {
                s4->sin_addr.s_addr = 0;
                if (inet_pton(AF_INET, address_name, &s4->sin_addr)) {
                    s4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
                    s4->sin_len = sizeof(struct sockaddr_in);
#endif
                    local_addr_ptr += sizeof(struct sockaddr_in);
                }
            }
            address_name = strtok_r(NULL, ",", &ptr);
        }
        free (tmp);
#if defined(HAVE_NETINET_SCTP_H) && !defined (USRSCTP_SUPPORT)
        if (sctp_bindx(candidate->pollable_socket->fd, (struct sockaddr *)candidate->pollable_socket->local_addr, candidate->pollable_socket->nr_local_addr, SCTP_BINDX_ADD_ADDR)) {
            nt_log(ctx, NEAT_LOG_ERROR,
                    "Failed to bindx fd %d socket to IP. Error: %s",
                    candidate->pollable_socket->fd,
                    strerror(errno));
            close(candidate->pollable_socket->fd);
            return -1;
        }
#endif
    } else {
        if (candidate->pollable_socket->family == AF_INET) {
            inet_ntop(AF_INET, &(((struct sockaddr_in *) &(candidate->pollable_socket->src_sockaddr))->sin_addr), addrsrcbuf, INET6_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &(candidate->pollable_socket->src_sockaddr))->sin6_addr), addrsrcbuf, INET6_ADDRSTRLEN);
        }
        nt_log(ctx, NEAT_LOG_INFO, "%s: Bind fd %d to %s", __func__, candidate->pollable_socket->fd, addrsrcbuf);

        /* Bind to address + interface (if Linux) */
        if (bind(candidate->pollable_socket->fd,
                 (struct sockaddr*) &(candidate->pollable_socket->src_sockaddr),
                 candidate->pollable_socket->src_len)) {
            nt_log(ctx, NEAT_LOG_ERROR,
                     "Failed to bind fd %d socket to IP. Error: %s",
                     candidate->pollable_socket->fd,
                     strerror(errno));
            close(candidate->pollable_socket->fd);
            return -1;
        }
    }

#ifdef __linux__
    if (if_indextoname(candidate->if_idx, if_name)) {
        // Not a critical error if it fails, ignore
        (void)setsockopt(candidate->pollable_socket->fd,
                         SOL_SOCKET,
                         SO_BINDTODEVICE,
                         if_name,
                         strlen(if_name));
    }
#endif

    len = (socklen_t)sizeof(int);
    if (getsockopt(candidate->pollable_socket->fd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &size,
                   &len) == 0) {
        candidate->pollable_socket->write_size = size;
    } else {
        candidate->pollable_socket->write_size = 0;
    }
    len = (socklen_t)sizeof(int);
    if (getsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        candidate->pollable_socket->read_size = size;
    } else {
        candidate->pollable_socket->read_size = 0;
    }

    switch (candidate->pollable_socket->stack) {
        case NEAT_STACK_TCP:
#if defined(__FreeBSD__) && defined(FLOW_GROUPS)
            group = candidate->pollable_socket->flow->group;
            if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, 8192 /* Group ID */, &group, sizeof(group)) != 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - Unable to set flow group: %s", __func__, strerror(errno));
            }

            // Map the priority range to some integer range
            prio = candidate->pollable_socket->flow->priority * 255;
            if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, 4096 /* Priority */, &prio, sizeof(prio)) != 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - Unable to set flow priority: %s", __func__, strerror(errno));
            }
#endif

#ifdef TCP_CONGESTION
            if (candidate->pollable_socket->flow->cc_algorithm) {
                algo = candidate->pollable_socket->flow->cc_algorithm;
                if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, TCP_CONGESTION, algo, strlen(algo)) != 0) {
                    nt_log(ctx, NEAT_LOG_WARNING, "%s - Unable to set CC algorithm: %s", __func__, strerror(errno));
                }
            }
#endif
            break;
        case NEAT_STACK_SCTP_UDP:
#if defined(__FreeBSD__)
            memset(&encaps, 0, sizeof(struct sctp_udpencaps));
            encaps.sue_address.ss_family = AF_INET;
            encaps.sue_port = htons(SCTP_UDP_TUNNELING_PORT);
            if (setsockopt(candidate->pollable_socket->fd, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - setsockopt(SCTP_REMOTE_UDP_ENCAPS_PORT) failed: %s", __func__, strerror(errno));
            }

#else
            close(candidate->pollable_socket->fd);
            nt_log(ctx, NEAT_LOG_ERROR, "%s - NEAT_STACK_SCTP_UDP unsupported on this platform", __func__);
            return -1; // Unavailable on other platforms
#endif
            // Fallthrough to case NEAT_STACK_SCTP:
            /* FALLTHRU */
        case NEAT_STACK_SCTP:
            candidate->pollable_socket->write_limit =  candidate->pollable_socket->write_size / 4;
            if (nt_prepare_sctp_socket(ctx, candidate->pollable_socket) != NEAT_ERROR_OK) {
                nt_log(ctx, NEAT_LOG_ERROR, "%s - nt_prepare_sctp_socket failed");
                exit(EXIT_FAILURE);
            }
        break;

        default:
            break;
    }

    candidate->pollable_socket->handle->data = candidate;
    assert(candidate->ctx);
    assert(candidate->ctx->loop);
    assert(candidate->pollable_socket->handle);
    assert(candidate->pollable_socket->fd);

    uv_poll_init(candidate->ctx->loop,
                 candidate->pollable_socket->handle,
                 candidate->pollable_socket->fd); // makes fd nb as side effect

#ifdef NEAT_SCTP_DTLS
    if (candidate->pollable_socket->flow->security_needed && nt_base_stack(candidate->pollable_socket->stack) == NEAT_STACK_SCTP) {
            nt_log(ctx, NEAT_LOG_DEBUG, "Start DTLS over SCTP");
            nt_dtls_install(ctx, candidate->pollable_socket);
    }
#endif

    retval = connect(candidate->pollable_socket->fd, (struct sockaddr *) &(candidate->pollable_socket->dst_sockaddr), slen);
    if (retval && errno != EINPROGRESS) {
        nt_log(ctx, NEAT_LOG_DEBUG,
                 "%s: Connect failed for fd %d connect error (%d): %s",
                 __func__,
                 candidate->pollable_socket->fd,
                 errno,
                 strerror(errno));
        return -2;
    }

    assert(candidate->pollable_socket->handle->data == candidate);
    uv_poll_start(candidate->pollable_socket->handle, UV_READABLE | UV_WRITABLE, callback_fx);

    return 0;
}

static int
nt_listen_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow, struct neat_pollable_socket *listen_socket)
{
    // TODO: This function should not write to any fields in neat_flow
#if defined(__FreeBSD__)
    struct sctp_udpencaps encaps;
#endif
    int enable = 1;
    int protocol, size;
    socklen_t len;
    const socklen_t slen = (listen_socket->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    protocol = nt_stack_to_protocol(nt_base_stack(listen_socket->stack));
    if (protocol == 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "Stack (%s) %d not supported", stack_to_string(listen_socket->stack), listen_socket->stack);
        return -1;
    }

    if ((listen_socket->fd = socket(listen_socket->family, listen_socket->type, protocol)) < 0) {
        nt_log(ctx, NEAT_LOG_ERROR, "%s: opening listening socket failed - %s", __func__, strerror(errno));
        return -1;
    }

    if (setsockopt(listen_socket->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) != 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "Unable to set socket option SOL_SOCKET:SO_REUSEADDR");
    }
    if (setsockopt(listen_socket->fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) != 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "Unable to set socket option SOL_SOCKET:SO_REUSEPORT");
    }

#ifdef __linux__
    if (flow->tproxy) {
        // Mark that this socket can be used for transparent proxying
        // This allows the socket to accept connections for non-local IPs
        if (setsockopt(listen_socket->fd, SOL_IP, IP_TRANSPARENT, &enable, sizeof(int)) != 0) {
           nt_log(ctx, NEAT_LOG_ERROR, "Unable to set socket option SOL_IP:IP_TRANSPARENT");
        } else {
            nt_log(ctx, NEAT_LOG_DEBUG, "Socket option SOL_IP:IP_TRANSPARENT set OK");
        }
    }
#endif // __linux__

    len = (socklen_t)sizeof(int);
    if (getsockopt(listen_socket->fd, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        listen_socket->write_size = size;
    } else {
        nt_log(ctx, NEAT_LOG_DEBUG, "Unable to get socket option SOL_SOCKET:SO_SNDBUF");
        listen_socket->write_size = 0;
    }

    len = (socklen_t)sizeof(int);
    if (getsockopt(listen_socket->fd, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        nt_log(ctx, NEAT_LOG_INFO, "%s - RCVBUF %d", __func__, size);
        listen_socket->read_size = size;
    } else {
        nt_log(ctx, NEAT_LOG_DEBUG, "Unable to get socket option SOL_SOCKET:SO_RCVBUF");
        listen_socket->read_size = 0;
    }

    switch (listen_socket->stack) {
        case NEAT_STACK_SCTP_UDP:
#if defined(__FreeBSD__)
            memset(&encaps, 0, sizeof(struct sctp_udpencaps));
            encaps.sue_address.ss_family = AF_INET;
            encaps.sue_port = htons(SCTP_UDP_TUNNELING_PORT);
            if (setsockopt(listen_socket->fd, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
                nt_log(ctx, NEAT_LOG_WARNING, "%s - setsockopt(SCTP_REMOTE_UDP_ENCAPS_PORT) failed: %s", __func__, strerror(errno));
            }

#else
            close(listen_socket->fd);
            nt_log(ctx, NEAT_LOG_ERROR, "%s - NEAT_STACK_SCTP_UDP unsupported on this platform", __func__);
            return -1; // Unavailable on other platforms
#endif
            // Fallthrough
        case NEAT_STACK_SCTP:
            if (nt_prepare_sctp_socket(ctx, listen_socket) != NEAT_ERROR_OK) {
                nt_log(ctx, NEAT_LOG_ERROR, "%s - nt_prepare_sctp_socket failed");
                exit(EXIT_FAILURE);
            }
            break;
        default:
            break;
    }

    if (listen_socket->stack == NEAT_STACK_UDP || listen_socket->stack == NEAT_STACK_UDPLITE) {
        if (bind(listen_socket->fd, (struct sockaddr *)(&listen_socket->src_sockaddr), slen) == -1) {
            nt_log(ctx, NEAT_LOG_ERROR, "%s: (%s) bind failed - %s", __func__, (listen_socket->stack == NEAT_STACK_UDP ? "UDP" : "UDPLite"), strerror(errno));
            close(listen_socket->fd);
            return -1;
        }
    } else {
        if (bind(listen_socket->fd, (struct sockaddr *)(&listen_socket->src_sockaddr), slen) == -1 || listen(listen_socket->fd, 100) == -1) {
            nt_log(ctx, NEAT_LOG_ERROR, "%s: bind/listen failed - %s", __func__, strerror(errno));
            close(listen_socket->fd);
            return -1;
        }
    }

    return listen_socket->fd;
}

#ifdef NEAT_SCTP_DTLS
static neat_error_code
neat_dtls_shutdown(struct neat_flow_operations *opCB)
{
    nt_log(opCB->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    struct security_data *private = (struct security_data *) opCB->flow->socket->dtls_data->userData;
    socklen_t len = SSL_shutdown(private->ssl);
    switch (SSL_get_error(private->ssl, len)) {
        case SSL_ERROR_NONE:
            nt_log(opCB->ctx, NEAT_LOG_DEBUG, "SSL shutdown finished");
            if (SSL_get_shutdown(private->ssl) & SSL_RECEIVED_SHUTDOWN) {
                nt_log(opCB->ctx, NEAT_LOG_DEBUG, "SSL_shutdown received: close socket");
                opCB->flow->closefx(opCB->ctx, opCB->flow);
                private->state = DTLS_CLOSED;
                return NEAT_OK;
            }
            break;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            /* Just try again later */
            break;
        case SSL_ERROR_SYSCALL:
            if (SSL_get_shutdown(private->ssl) & SSL_SENT_SHUTDOWN) {
                SSL_shutdown(private->ssl);
            }
            break;
        case SSL_ERROR_SSL:
            break;
        default:
            nt_log(opCB->ctx, NEAT_LOG_ERROR, "%s - Unexpected error while shutting down!", __func__);
            break;
    }
    return NEAT_OK;
}
#endif

static int
nt_shutdown_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
#ifdef SCTP_MULTISTREAMING
    neat_flow *flow_itr = NULL;
#endif // SCTP_MULTISTREAMING

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    // check for all multistream flows if they are ready to shutdown/close
    if (flow->socket->multistream) {
#ifdef SCTP_MULTISTREAMING

        // check if shutdown was alread called
        if (flow->multistream_shutdown) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - shutdown already called, skipping", __func__);
            return NEAT_OK;
        }

        flow->multistream_shutdown = 1;
        nt_sctp_reset_stream(flow->socket, flow->multistream_id);

        LIST_FOREACH(flow_itr, &flow->socket->sctp_multistream_flows, multistream_next_flow) {
            if (flow_itr->state != NEAT_FLOW_CLOSED) {
                nt_log(ctx, NEAT_LOG_DEBUG, "%s - not all streams closed, skipping socket shutdown", __func__);
                return NEAT_OK;
            }
        }

        nt_log(ctx, NEAT_LOG_INFO, "%s - all streames in closed state, calling socket shutdown", __func__);


#else // SCTP_MULTISTREAMING
        assert(false);
#endif // SCTP_MULTISTREAMING
    }

#ifdef NEAT_SCTP_DTLS
    if (flow->security_needed && nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        struct security_data *private = (struct security_data *) flow->socket->dtls_data->userData;
        socklen_t len = SSL_shutdown(private->ssl);
        switch (SSL_get_error(private->ssl, len)) {
            case SSL_ERROR_NONE:
                nt_log(ctx, NEAT_LOG_DEBUG, "SSL shutdown finished");
                if (SSL_get_shutdown(private->ssl) & SSL_RECEIVED_SHUTDOWN) {
                    nt_log(ctx, NEAT_LOG_DEBUG, "SSL_shutdown received: close socket");
                    flow->closefx(ctx, flow);
                    private->state = DTLS_CLOSED;
                    return NEAT_OK;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
            flow->operations.on_writable = neat_dtls_shutdown;
            neat_set_operations(ctx, flow, &flow->operations);
            break;
            case SSL_ERROR_WANT_READ:
                /* Just try again later */
                break;
            case SSL_ERROR_SYSCALL:
                if (SSL_get_shutdown(private->ssl) & SSL_SENT_SHUTDOWN) {
                    SSL_shutdown(private->ssl);
                }
                break;
            case SSL_ERROR_SSL:
                break;
            default:
                nt_log(ctx, NEAT_LOG_ERROR, "%s - Unexpected error while shutting down!", __func__);
                break;
        }
        return NEAT_OK;
    } else {
#endif
        if (shutdown(flow->socket->fd, SHUT_WR) == 0) {
            return NEAT_OK;
        } else {
            return NEAT_ERROR_IO;
        }
#ifdef NEAT_SCTP_DTLS
    }
#endif
}

#if defined(USRSCTP_SUPPORT)
static void nt_sctp_init_events(struct socket *sock)
#else
static void nt_sctp_init_events(int sock)
#endif
{

#if defined(IPPROTO_SCTP)
#if defined(SCTP_EVENT)
    // Set up SCTP event subscriptions using RFC6458 API
    // (does not work with current Linux kernel SCTP)
    struct sctp_event event;
    unsigned int i;
    uint16_t event_types[] = {
        SCTP_ASSOC_CHANGE,
        SCTP_PEER_ADDR_CHANGE,
        SCTP_REMOTE_ERROR,
        SCTP_SHUTDOWN_EVENT,
        SCTP_ADAPTATION_INDICATION,
        SCTP_PARTIAL_DELIVERY_EVENT,
#ifdef SCTP_SEND_FAILED_EVENT   //TD 22.07.2019: This seems to be deprecated!
        SCTP_SEND_FAILED_EVENT,
#else
        SCTP_SEND_FAILED,
#endif
        SCTP_STREAM_RESET_EVENT
    };

    memset(&event, 0, sizeof(event));
#ifdef SCTP_FUTURE_ASSOC   // TD 22.07.2019: This seems to be deprecated!
    event.se_assoc_id = SCTP_FUTURE_ASSOC;
#endif
    event.se_on = 1;

    for (i = 0; i < (unsigned int)(sizeof(event_types) / sizeof(uint16_t)); i++) {
        event.se_type = event_types[i];
#if defined(USRSCTP_SUPPORT)
        if (usrsctp_setsockopt(
#else //defined(USRSCTP_SUPPORT)
        if (setsockopt(
#endif // defined(USRSCTP_SUPPORT)
        sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(struct sctp_event)) < 0) {
            assert(false);
        }
    }
#elif defined(HAVE_SCTP_EVENT_SUBSCRIBE)
// Set up SCTP event subscriptions using deprecated API
// (for compatibility with Linux kernel SCTP)
    struct sctp_event_subscribe event;

    memset(&event, 0, sizeof(event));
    event.sctp_association_event        = 1;
    event.sctp_address_event            = 1;
    event.sctp_send_failure_event       = 1;
    event.sctp_peer_error_event         = 1;
    event.sctp_shutdown_event           = 1;
    event.sctp_partial_delivery_event   = 1;
    event.sctp_adaptation_layer_event   = 1;

    if (setsockopt(sock, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(struct sctp_event_subscribe)) < 0) {
        //nt_log(ctx, NEAT_LOG_ERROR, "%s: failed to subscribe to SCTP events - %s", __func__, strerror(errno));
        assert(false);
    }
#endif // defined(HAVE_SCTP_EVENT_SUBSCRIBE)
#endif // defined(IPPROTO_SCTP)
}

#ifdef USRSCTP_SUPPORT
static struct socket *
nt_accept_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow, struct neat_pollable_socket *listen_socket)
{
    struct sockaddr_in remote_addr;
    struct socket *new_socket = NULL;
    struct neat_pollable_socket *pollable_socket;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in));
    if (((new_socket = usrsctp_accept(listen_socket->usrsctp_socket, (struct sockaddr *) &remote_addr, &addr_len)) == NULL) && (errno != EINPROGRESS)) {
        nt_log(ctx, NEAT_LOG_ERROR, "%s: usrsctp_accept failed - %s", __func__, strerror(errno));
        return NULL;
    }

    pollable_socket = calloc(1, sizeof(*pollable_socket));
    if (!pollable_socket)
        return NULL;

    pollable_socket->fd = -1;
    pollable_socket->flow = flow;
    pollable_socket->handle = NULL;
    pollable_socket->usrsctp_socket = new_socket;
    usrsctp_set_upcall(new_socket, handle_upcall, (void*)pollable_socket);

    // Set after return by caller
    // pollable_socket->usrsctp_socket = new_socket;
    return new_socket;
}

static int
nt_connect_via_usrsctp(struct neat_he_candidate *candidate)
{
    int enable = 1;
    socklen_t len;
    int size, protocol;
    socklen_t slen =
            (candidate->pollable_socket->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    char addrdstbuf[slen];

    nt_log(candidate->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    protocol = nt_stack_to_protocol(nt_base_stack(candidate->pollable_socket->stack));
    if (protocol == 0) {
        nt_log(candidate->ctx, NEAT_LOG_INFO, "%s - Stack %d not supported", __func__, candidate->pollable_socket->stack);
        return -1;
    }

    candidate->pollable_socket->usrsctp_socket = usrsctp_socket(candidate->pollable_socket->family, candidate->pollable_socket->type, protocol, NULL, NULL, 0, NULL);
    if (!candidate->pollable_socket->usrsctp_socket) {
        return -1;
    }
    usrsctp_set_non_blocking(candidate->pollable_socket->usrsctp_socket, 1);
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(candidate->pollable_socket->usrsctp_socket, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        candidate->pollable_socket->write_size = size;
    } else {
        candidate->pollable_socket->write_size = 0;
    }
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(candidate->pollable_socket->usrsctp_socket, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        candidate->pollable_socket->read_size = size;
    } else {
        candidate->pollable_socket->read_size = 0;
    }

    if (candidate->pollable_socket->stack == NEAT_STACK_SCTP_UDP) {
        struct sctp_udpencaps encaps;
        memset(&encaps, 0, sizeof(struct sctp_udpencaps));
        encaps.sue_address.ss_family = AF_INET;
        encaps.sue_port = htons(SCTP_UDP_TUNNELING_PORT);
        usrsctp_setsockopt(candidate->pollable_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps));
    }

#ifdef SCTP_NODELAY
    usrsctp_setsockopt(candidate->pollable_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
    if (usrsctp_setsockopt(candidate->pollable_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0) {
        candidate->pollable_socket->sctp_explicit_eor = 1;
    }
#endif

    if (candidate->pollable_socket->flow->isMultihoming && nt_base_stack(candidate->pollable_socket->stack) == NEAT_STACK_SCTP && candidate->pollable_socket->nr_local_addr > 0) {
        char *local_addr_ptr = (char*) (candidate->pollable_socket->local_addr);
        char *address_name, *ptr = NULL;
        char *tmp = strdup(candidate->pollable_socket->src_address);

        if (!tmp)
            return -1;

        address_name = strtok_r((char *)tmp, ",", &ptr);
        while (address_name != NULL) {
            struct sockaddr_in *s4 = (struct sockaddr_in*) local_addr_ptr;
            struct sockaddr_in6 *s6 = (struct sockaddr_in6*) local_addr_ptr;
            if (inet_pton(AF_INET6, address_name, &s6->sin6_addr)) {
                s6->sin6_family = AF_INET6;
#ifdef HAVE_SIN_LEN
                s6->sin6_len = sizeof(struct sockaddr_in6);
#endif
                local_addr_ptr += sizeof(struct sockaddr_in6);
            } else {
                if (inet_pton(AF_INET, address_name, &s4->sin_addr)) {
                    s4->sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
                    s4->sin_len = sizeof(struct sockaddr_in);
#endif
                    local_addr_ptr += sizeof(struct sockaddr_in);
                }
            }
            address_name = strtok_r(NULL, ",", &ptr);
        }
        free (tmp);
        if (usrsctp_bindx(candidate->pollable_socket->usrsctp_socket, (struct sockaddr *)candidate->pollable_socket->local_addr, candidate->pollable_socket->nr_local_addr, SCTP_BINDX_ADD_ADDR)) {
            nt_log(candidate->ctx, NEAT_LOG_ERROR,
                    "Failed to bindx socket to IP. Error: %s",
                    strerror(errno));
            return -1;
        }
    } else {
        char addrsrcbuf[slen];
        if (candidate->pollable_socket->family == AF_INET) {
            inet_ntop(AF_INET, &(((struct sockaddr_in *) &(candidate->pollable_socket->src_sockaddr))->sin_addr), addrsrcbuf, INET6_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &(candidate->pollable_socket->src_sockaddr))->sin6_addr), addrsrcbuf, INET6_ADDRSTRLEN);
        }
        nt_log(candidate->ctx, NEAT_LOG_INFO, "%s: Bind fd %d to %s", __func__, candidate->pollable_socket->fd, addrsrcbuf);

        /* Bind to address + interface (if Linux) */
        if (usrsctp_bind(candidate->pollable_socket->usrsctp_socket,
                 (struct sockaddr*) &(candidate->pollable_socket->src_sockaddr),
                 candidate->pollable_socket->src_len)) {
            nt_log(candidate->ctx, NEAT_LOG_ERROR,
                     "Failed to bind to IP. Error: %s",
                     strerror(errno));
            return -1;
        }
    }

    // Subscribe to SCTP events
    nt_sctp_init_events(candidate->pollable_socket->usrsctp_socket);

    nt_log(candidate->ctx, NEAT_LOG_INFO, "%s: Connect to %s", __func__,
        inet_ntop(AF_INET, &(((struct sockaddr_in *) &(candidate->pollable_socket->dst_sockaddr))->sin_addr), addrdstbuf, slen));

    if (!(candidate->pollable_socket->usrsctp_socket) || (usrsctp_connect(candidate->pollable_socket->usrsctp_socket, (struct sockaddr *) &(candidate->pollable_socket->dst_sockaddr), slen) && (errno != EINPROGRESS))) {
        nt_log(candidate->ctx, NEAT_LOG_ERROR, "%s: usrsctp_connect failed - %s", __func__, strerror(errno));
        perror("usrsctp_connect");
        return -1;
    } else {
         nt_log(candidate->ctx, NEAT_LOG_INFO, "%s: usrsctp_socket connected", __func__);
    }
    usrsctp_set_upcall(candidate->pollable_socket->usrsctp_socket, handle_connect, (void *)candidate);

    return 0;
}

static int
nt_close_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->socket->usrsctp_socket) {
        usrsctp_close(flow->socket->usrsctp_socket);
    }
    nt_notify_close(flow);
    return 0;
}

static int
nt_shutdown_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (usrsctp_shutdown(flow->socket->usrsctp_socket, SHUT_WR) == 0) {
        return NEAT_OK;
    } else {
        return NEAT_ERROR_IO;
    }
}

static void
handle_connect(struct socket *sock, void *arg, int flags)
{
    const char *proto;
    const char *family;
    struct neat_he_candidate *candidate = (struct neat_he_candidate *) arg;
    struct neat_pollable_socket *poll_socket = candidate->pollable_socket;
    neat_flow *flow = poll_socket->flow;
    struct neat_he_candidates *candidate_list = flow->candidate_list;
    struct cib_he_res *he_res = NULL;

    nt_log(candidate->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    assert(flow);

    switch (candidate->pollable_socket->stack) {
    case NEAT_STACK_UDP:
        proto = "UDP";
        break;
    case NEAT_STACK_TCP:
        proto = "TCP";
        break;
    case NEAT_STACK_SCTP:
        proto = "SCTP";
        break;
    case NEAT_STACK_SCTP_UDP:
        proto = "SCTP/UDP";
        break;
    case NEAT_STACK_UDPLITE:
        proto = "UDPLite";
        break;
    default:
        proto = "?";
        break;
    };

    switch (candidate->pollable_socket->family) {
    case AF_INET:
        family = "IPv4";
        break;
    case AF_INET6:
        family = "IPv6";
        break;
    default:
        family = "?";
        break;
    };

    nt_log(candidate->ctx, NEAT_LOG_DEBUG,
             "HE Candidate connected: %8s [%2d] %8s/%s <saddr %s> <dstaddr %s> port %5d priority %d",
             candidate->if_name,
             candidate->if_idx,
             proto,
             family,
             candidate->pollable_socket->src_address,
             candidate->pollable_socket->dst_address,
             candidate->pollable_socket->port,
             candidate->priority);

    he_res = calloc(1, sizeof(struct cib_he_res));
    if (!he_res)
        return;

    he_res->interface = strdup(candidate->if_name);
    if (!he_res->interface) {
        free(he_res);
        return;
    }
    he_res->remote_ip = strdup(candidate->pollable_socket->dst_address);
    if (!he_res->remote_ip) {
        free(he_res->interface);
        free(he_res);
        return;
    }
    he_res->remote_port = candidate->pollable_socket->port;
    he_res->transport = candidate->pollable_socket->stack;

    if (usrsctp_get_events(sock) & SCTP_EVENT_WRITE) {
        if (flow->hefirstConnect) {
            flow->hefirstConnect = 0;
            nt_log(candidate->ctx, NEAT_LOG_DEBUG, "First successful connect (flow->hefirstConnect)");
            assert(flow->socket);
            flow->socket->fd = -1;
            flow->socket->usrsctp_socket = sock;
            flow->socket->flow = flow;
            assert(flow->socket->handle->loop == NULL);
            free(flow->socket->handle);
            flow->socket->handle = poll_socket->handle;
            flow->socket->handle->data = flow->socket;
            flow->socket->family = poll_socket->family;
            flow->socket->stack = poll_socket->stack;
            flow->socket->type = poll_socket->type;
            flow->socket->write_size = poll_socket->write_size;
            flow->socket->write_limit = poll_socket->write_limit;
            flow->socket->read_size = poll_socket->read_size;
            flow->socket->sctp_explicit_eor = poll_socket->sctp_explicit_eor;

            if (candidate->properties != flow->properties) {
                json_incref(candidate->properties);
                json_decref(flow->properties);
                flow->properties = candidate->properties;
            }

            flow->everConnected = 1;
            flow->isPolling = 1;

            send_result_connection_attempt_to_pm(flow->ctx, flow, he_res, true);

            if (!install_security(candidate)) {
                flow->firstWritePending = 1;
                usrsctp_set_upcall(sock, handle_upcall, (void*)flow->socket);
                io_connected(flow->ctx, flow, NEAT_OK);
            }
            if ((usrsctp_get_events(sock) & SCTP_EVENT_WRITE) && flow->operations.on_writable) {
                io_writable(flow->ctx, flow, NEAT_OK);
            }
        } else {
            nt_log(candidate->ctx, NEAT_LOG_DEBUG, "%s - NOT first connect", __func__);

            send_result_connection_attempt_to_pm(flow->ctx, flow, he_res, false);

            nt_log(candidate->ctx, NEAT_LOG_DEBUG, "%s:Release candidate", __func__);
            TAILQ_REMOVE(candidate_list, candidate, next);
            free(candidate->pollable_socket->dst_address);
            free(candidate->pollable_socket->src_address);
            free(candidate->pollable_socket);
            free(candidate->if_name);
            json_decref(candidate->properties);
            free(candidate);

            usrsctp_close(sock);

            if (!(--flow->heConnectAttemptCount)) {
                nt_io_error(flow->ctx, flow, NEAT_ERROR_UNABLE);
                return;
            }
        }
    } else {
      free(he_res->interface);
      free(he_res->remote_ip);
      free(he_res);
    }
}

static void
handle_upcall(struct socket *sock, void *arg, int flags)
{
    struct neat_pollable_socket *pollable_socket = arg;
    neat_flow *flow = pollable_socket->flow;
    neat_ctx *ctx;
    int events = 0;
    neat_error_code code;

    nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    assert(flow);

    ctx = flow->ctx;
    events = usrsctp_get_events(sock);

    if (events == -1) {
        nt_log(flow->ctx, NEAT_LOG_DEBUG, "Bad file descriptor");
        return;
    }

    if ((events & SCTP_EVENT_READ) && flow->acceptPending) {
        do_accept(ctx, flow, pollable_socket);
        return;
    }

    // remove "on_writable" callback check
    if (events & SCTP_EVENT_WRITE) {
        if (flow->state == NEAT_FLOW_OPEN) {
            flow->firstWritePending = 0;
            io_writable(ctx, flow, NEAT_OK);
        } else {
            nt_log(ctx, NEAT_LOG_WARNING, "%s - io_writable and flow in wrong state");
        }

    }

    if (events & SCTP_EVENT_READ) {
        if (flow->state == NEAT_FLOW_OPEN) {
            do {
                code = io_readable(ctx, flow, pollable_socket, NEAT_OK);
            } while (code == READ_OK);

            if (code == READ_WITH_ZERO) {
                nt_notify_close(flow);
                return;
            }
        } else {
            nt_log(ctx, NEAT_LOG_WARNING, "%s - io_readable and flow in wrong state");
        }
    }

    // xxx why two times?
    events = usrsctp_get_events(sock);
    if (events & SCTP_EVENT_WRITE && flow->operations.on_writable && flow->state == NEAT_FLOW_OPEN) {
        io_writable(ctx, flow, NEAT_OK);
    }

}

static int
nt_listen_via_usrsctp(struct neat_ctx *ctx,
                        struct neat_flow *flow,
                        struct neat_pollable_socket *listen_socket)
{
    int enable = 1;
    socklen_t len;
    int size, protocol;
    nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    socklen_t slen = (listen_socket->family == AF_INET) ?
                     sizeof (struct sockaddr_in) :
                     sizeof (struct sockaddr_in6);

    protocol = nt_stack_to_protocol(nt_base_stack(listen_socket->stack));
    if (protocol == 0) {
        nt_log(flow->ctx, NEAT_LOG_INFO, "%s - Stack %d not supported", __func__, listen_socket->stack);
        return -1;
    }

    if (!(listen_socket->usrsctp_socket = usrsctp_socket(listen_socket->family, listen_socket->type, protocol, NULL, NULL, 0, NULL))) {
        nt_log(flow->ctx, NEAT_LOG_ERROR, "%s: user_socket failed - %s", __func__, strerror(errno));
        return -1;
    }
    usrsctp_set_non_blocking(listen_socket->usrsctp_socket, 1);
    usrsctp_set_upcall(listen_socket->usrsctp_socket, handle_upcall, (void*)listen_socket);
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(listen_socket->usrsctp_socket, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        listen_socket->write_size = size;
    } else {
        listen_socket->write_size = 0;
    }
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(listen_socket->usrsctp_socket, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        listen_socket->read_size = size;
    } else {
        listen_socket->read_size = 0;
    }
    listen_socket->write_limit = listen_socket->write_size / 4;

#ifdef SCTP_NODELAY
    usrsctp_setsockopt(listen_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
    if (usrsctp_setsockopt(listen_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0) {
        listen_socket->sctp_explicit_eor = 1;
    }
#endif
    usrsctp_setsockopt(listen_socket->usrsctp_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    char addrbuf[slen];
    nt_log(flow->ctx, NEAT_LOG_INFO, "%s: Bind to %s", __func__,
        inet_ntop(AF_INET, &(((struct sockaddr_in *)(&listen_socket->src_sockaddr))->sin_addr), addrbuf, slen));
    if (usrsctp_bind(listen_socket->usrsctp_socket, (struct sockaddr *)(&listen_socket->src_sockaddr), slen) == -1) {
        nt_log(flow->ctx, NEAT_LOG_ERROR, "%s: Error binding usrsctp socket - %s", __func__, strerror(errno));
        return -1;
    }
    if (usrsctp_listen(listen_socket->usrsctp_socket, 1) == -1) {
        nt_log(flow->ctx, NEAT_LOG_ERROR, "%s: Error listening on usrsctp socket - %s", __func__, strerror(errno));
        return -1;
    }

    return 0;
}


#endif


// this function needs to accept all the data (buffering if necessary)
neat_error_code
neat_write(struct neat_ctx *ctx,
            struct neat_flow *flow,
            const unsigned char *buffer,
            uint32_t amt,
            struct neat_tlv optional[],
            unsigned int opt_count)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
#if defined(WEBRTC_SUPPORT)
    if (flow->socket->stack == NEAT_STACK_WEBRTC) {
        flow->notifyDrainPending = 1;
        return neat_webrtc_write_to_channel(ctx, flow, buffer, amt, optional, opt_count);
    }
#endif // #if defined(WEBRTC_SUPPORT)

#ifdef SCTP_MULTISTREAMING
    assert(flow->multistream_reset_out == false);
#endif

    flow->notifyDrainPending = 1;

    for (struct neat_iofilter *filter = flow->iofilters; filter; filter = filter->next) {
        // find the first filter and call it
        if (!filter->writefx) {
            continue;
        }
        return filter->writefx(ctx, flow, filter, buffer, amt, optional, opt_count);
    }

    // there were no filters. call the flow writefx
    return flow->writefx(ctx, flow, buffer, amt, optional, opt_count);
}

static neat_error_code
nt_recursive_filter_read(struct neat_ctx *ctx,
                            struct neat_flow *flow,
                            struct neat_iofilter *filter,
                            unsigned char *buffer,
                            uint32_t amt,
                            uint32_t *actualAmt,
                            struct neat_tlv optional[],
                            unsigned int opt_count)
{
    if (!filter) {
        return NEAT_OK;
    }
    neat_error_code rv = nt_recursive_filter_read(ctx, flow,
                                                    filter->next, buffer, amt, actualAmt, optional, opt_count);
    if (rv != NEAT_OK) {
        return rv;
    }
    if (!filter->readfx || !*actualAmt) {
        return NEAT_OK;
    }
    return filter->readfx(ctx, flow, filter, buffer, amt, actualAmt, optional, opt_count);
}

neat_error_code
neat_read(struct neat_ctx *ctx, struct neat_flow *flow,
          unsigned char *buffer, uint32_t amt, uint32_t *actualAmt,
          struct neat_tlv optional[], unsigned int opt_count)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    *actualAmt = 0;
    neat_error_code rv = flow->readfx(ctx, flow, buffer, amt, actualAmt, optional, opt_count);
    if (rv != NEAT_OK) {
        return rv;
    }

    // apply the filters backwards
    return nt_recursive_filter_read(ctx, flow, flow->iofilters, buffer, amt, actualAmt, optional, opt_count);
}

neat_error_code
neat_shutdown(struct neat_ctx *ctx, struct neat_flow *flow)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    flow->isClosing = 1;

#if defined(WEBRTC_SUPPORT)
    if (flow->webrtcEnabled) {
        return rawrtc_stop_client(flow->peer_connection);
    }
#endif

    if (flow->isDraining) {
        return NEAT_OK;
    }

#if defined(USRSCTP_SUPPORT)
    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        return nt_shutdown_via_usrsctp(ctx, flow);
    }
#endif
    return flow->shutdownfx(ctx, flow);
}

neat_flow *
neat_new_flow(neat_ctx *ctx)
{
    neat_flow *flow;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    flow = calloc(1, sizeof (struct neat_flow));
    if (flow == NULL) {
        return NULL;
    }

    flow->state               = NEAT_FLOW_CLOSED;
    flow->ctx                 = ctx;
    flow->writefx             = nt_write_to_lower_layer;
    flow->readfx              = nt_read_from_lower_layer;
    flow->acceptfx            = nt_accept_via_kernel;
    flow->connectfx           = nt_connect;
    flow->closefx             = nt_close_socket;
    flow->shutdownfx          = nt_shutdown_via_kernel;
#if defined(USRSCTP_SUPPORT)
    flow->acceptusrsctpfx     = nt_accept_via_usrsctp;
#endif

    TAILQ_INIT(&(flow->listen_sockets));
    TAILQ_INIT(&flow->bufferedMessages);

#ifdef SCTP_MULTISTREAMING
    TAILQ_INIT(&flow->multistream_read_queue);
#endif // SCTP_MULTISTREAMING

    flow->properties        = json_object();
    flow->user_ips          = NULL;
    flow->security_needed   = 0;

    flow->socket = calloc(1, sizeof(struct neat_pollable_socket));
    if (flow->socket == NULL) {
        free(flow);
        return NULL;
    }

    flow->socket->flow      = flow;
    flow->socket->fd        = 0;
    flow->readBufferSize    = 0;
#if defined(USRSCTP_SUPPORT)
    flow->socket->usrsctp_socket = NULL;
    if (nt_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        flow->socket->fd = -1;
    }
#endif

    flow->socket->handle = calloc(1, sizeof(uv_poll_t));
    if (flow->socket->handle == NULL) {
        free(flow->socket);
        free(flow);
        return NULL;
    }

    flow->socket->handle->loop    = NULL;
    flow->socket->handle->type    = UV_UNKNOWN_HANDLE;

    /* Initialise flow statistics */
    flow->flow_stats.bytes_sent       = 0;
    flow->flow_stats.bytes_received   = 0;

    LIST_INSERT_HEAD(&ctx->flows, flow, next_flow);

    nt_log(ctx, NEAT_LOG_INFO, "%s - new flow created: %p", __func__, flow);

    return flow;
}

// Notify application about congestion via callback
// Set ecn to true if ECN signalled congestion.
// Set rate to non-zero if wanting to signal a new *maximum* bitrate
void nt_notify_cc_congestion(neat_flow *flow, int ecn, uint32_t rate)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations.on_slowdown) {
        return;
    }

    READYCALLBACKSTRUCT;
    flow->operations.on_slowdown(&flow->operations, ecn, rate);
}

// Notify application about new max. bitrate
// Set rate to the new advised maximum bitrate
void nt_notify_cc_hint(neat_flow *flow, int ecn, uint32_t rate)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations.on_rate_hint) {
        return;
    }

    READYCALLBACKSTRUCT;
    flow->operations.on_rate_hint(&flow->operations, rate);
}

// Notify application about a failed send.
// Set errorcode in cause, context to msg.-context-id from WRITE,
// unsent_buffer points at the failed message. Context is optional,
// set to -1 if not specified.
void nt_notify_send_failure(neat_flow *flow, neat_error_code code,
                  int context, const unsigned char *unsent_buffer)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations.on_send_failure) {
        return;
    }

    READYCALLBACKSTRUCT;
    flow->operations.on_send_failure(&flow->operations, context, unsent_buffer);
}

// Notify application about timeout
void nt_notify_timeout(neat_flow *flow)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations.on_timeout) {
        return;
    }

    READYCALLBACKSTRUCT;
    flow->operations.on_timeout(&flow->operations);
}

// Notify application about an aborted connection
// TODO: this should perhaps return a status code?
void nt_notify_aborted(neat_flow *flow)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;
    neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations.on_aborted) {
        return;
    }

    READYCALLBACKSTRUCT;
    flow->operations.on_aborted(&flow->operations);
}

// Notify application a connection has closed
void
nt_notify_close(neat_flow *flow)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_error_code code = NEAT_ERROR_OK;

    assert(flow);

    neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s - state: %d", __func__, flow->state);

    if (flow->state == NEAT_FLOW_CLOSED) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - flow already closed - skipping", __func__);
        return;
    }

    flow->state = NEAT_FLOW_CLOSED;

    if (flow->operations.on_close) {
        READYCALLBACKSTRUCT;
        flow->operations.on_close(&flow->operations);
    }
    // this was the last callback - free all ressources
    nt_free_flow(flow);
}

// Notify application about network changes.
// Code should identify what happened.
void
nt_notify_network_status_changed(neat_flow *flow, neat_error_code code)
{
    const int stream_id = NEAT_INVALID_STREAM;
    //READYCALLBACKSTRUCT expects this:
    neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!flow->operations.on_network_status_changed) {
        return;
    }

    READYCALLBACKSTRUCT;
    flow->operations.on_network_status_changed(&flow->operations);
}

// CLOSE, D1.2 sect. 3.2.4
neat_error_code
neat_close(struct neat_ctx *ctx, struct neat_flow *flow)
{
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#if defined(WEBRTC_SUPPORT)
    if (flow->webrtcEnabled) {
        return rawrtc_close_flow(flow, flow->peer_connection);
    }
#endif

#ifdef SCTP_MULTISTREAMING
    if (flow->socket->multistream && flow->state == NEAT_FLOW_OPEN) {
        // flow was not in closed state before... now it is!
        flow->socket->sctp_streams_used--;
        //flow->multistream_state = NEAT_FLOW_CLOSED;
    }

    nt_log(ctx, NEAT_LOG_WARNING, "%s - %d", __func__, flow->socket->sctp_streams_used);

    if (!flow->socket->multistream || flow->socket->sctp_streams_used == 0) {
        nt_log(ctx, NEAT_LOG_INFO, "%s - not multistream socket or all streams closed", __func__);
#endif // SCTP_MULTISTREAMING
        if (flow->isPolling && uv_is_active((uv_handle_t*)flow->socket->handle)) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - stopping polling", __func__);
            uv_poll_stop(flow->socket->handle);
        }
        nt_close_socket(ctx, flow);
#ifdef SCTP_MULTISTREAMING
    }
#endif // SCTP_MULTISTREAMING

    nt_notify_close(flow);
    return NEAT_OK;
}

// ABORT, D1.2 sect. 3.2.4
neat_error_code
neat_abort(struct neat_ctx *ctx, struct neat_flow *flow)
{
    struct linger ling;

    ling.l_onoff = 1;
    ling.l_linger = 0;

#if !defined(USRSCTP_SUPPORT)
    if (setsockopt(flow->socket->fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger)) < 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "setsockopt(SO_LINGER) failed");
    }
#else
    if (usrsctp_setsockopt(flow->socket->usrsctp_socket, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger)) < 0) {
        nt_log(ctx, NEAT_LOG_DEBUG, "usrsctp_setsockopt(SO_LINGER) failed");
    }
#endif

    neat_close(ctx, flow);

    return NEAT_OK;
}

neat_flow *
nt_find_flow(neat_ctx *ctx, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
    neat_flow *flow;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    LIST_FOREACH(flow, &ctx->flows, next_flow) {
        if (flow->socket == NULL)
            continue;

        if (flow->acceptPending == 1)
            continue;

        if ((sockaddr_storage_cmp(&flow->socket->dst_sockaddr, dst) == 0) &&
               (sockaddr_storage_cmp(&flow->socket->src_sockaddr, src) == 0)) {
                       return flow;
        }
    }
    return NULL;
}

neat_error_code
neat_set_low_watermark(struct neat_ctx *ctx, struct neat_flow *flow, uint32_t watermark) {
#ifdef TCP_NOTSENT_LOWAT
    if (nt_base_stack(flow->socket->stack) != NEAT_STACK_TCP || flow->socket->fd == -1) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - cannot set TCP_NOTSENT_LOWAT - only supported for TCP", __func__);
        return NEAT_ERROR_UNABLE;
    }

    if (setsockopt(flow->socket->fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &watermark, (socklen_t) sizeof(watermark)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - cannot set TCP_NOTSENT_LOWAT - setsockopt failed", __func__);
        return NEAT_ERROR_UNABLE;
    }

    nt_log(ctx, NEAT_LOG_INFO, "%s - TCP_NOTSENT_LOWAT set to %d", __func__, watermark);
    return NEAT_OK;
#else
    nt_log(ctx, NEAT_LOG_WARNING, "%s - cannot set TCP_NOTSENT_LOWAT - unsupported", __func__);
    return NEAT_ERROR_UNABLE;
#endif
}

static int
nt_prepare_sctp_socket(struct neat_ctx* ctx, struct neat_pollable_socket* pollable_socket) {

#if defined(SCTP_INTERLEAVING_SUPPORTED) || defined(SCTP_ENABLE_STREAM_RESET)
    struct sctp_assoc_value assoc_value;
#endif

#if defined(SCTP_FRAGMENT_INTERLEAVE) || defined(SCTP_NODELAY) || defined(SCTP_RECVRCVINFO) || defined(SCTP_RECVNXTINFO)
    int optval;
#endif

#ifdef SCTP_ADAPTATION_LAYER
    // Set adaptation layer indication
    struct sctp_setadaptation adaptation;
    memset(&adaptation, 0, sizeof(adaptation));
    adaptation.ssb_adaptation_ind = SCTP_ADAPTATION_NEAT;
    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_ADAPTATION_LAYER, &adaptation, sizeof(adaptation)) < 0) {
        nt_log(ctx, NEAT_LOG_ERROR, "Call to setsockopt(SCTP_ADAPTATION_LAYER) failed - %s", strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }
#endif
    //candidate->pollable_socket->sctp_notification_wait = 1;

#ifdef SCTP_FRAGMENT_INTERLEAVE
    // Enable fragment interleaving
    optval = 2;
    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &optval, sizeof(optval)) < 0) {
        nt_log(ctx, NEAT_LOG_ERROR, "Call to setsockopt(SCTP_FRAGMENT_INTERLEAVE) failed - %s", strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }
#endif

#ifdef SCTP_INTERLEAVING_SUPPORTED
    // Enable anciliarry data when receiving data from SCTP
    memset(&assoc_value, 0, sizeof(assoc_value));
    assoc_value.assoc_value = 1;
    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &assoc_value, sizeof(struct sctp_assoc_value)) < 0) {
        nt_log(ctx, NEAT_LOG_ERROR, "Call to setsockopt(SCTP_INTERLEAVING_SUPPORTED) failed - %s", strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }
#endif

#ifdef SCTP_ENABLE_STREAM_RESET
    // Enable Stream Reset extension
    memset(&assoc_value, 0, sizeof(assoc_value));
    assoc_value.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ;
    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc_value, sizeof(assoc_value)) < 0) {
        nt_log(ctx, NEAT_LOG_ERROR, "Call to setsockopt(SCTP_ENABLE_STREAM_RESET) failed - %s", strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }
#endif

#ifdef SCTP_NODELAY
    optval = 1;
    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_NODELAY, &optval, sizeof(optval))) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - setsockopt(SCTP_NODELAY) failed: %s", __func__, strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }
#endif

#ifdef SCTP_EXPLICIT_EOR
    if (!pollable_socket->flow->security_needed) {
        optval = 1;
        if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &optval, sizeof(optval)) == 0) {
            pollable_socket->sctp_explicit_eor = 1;
        }
    }
#endif

#ifdef SCTP_RECVRCVINFO
    // Enable anciliarry data when receiving data from SCTP
    optval = 1;
    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &optval, sizeof(optval)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - setsockopt(SCTP_RECVRCVINFO) failed: %s", __func__, strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }
#endif

#ifdef SCTP_RECVNXTINFO
    // Enable anciliarry data when receiving data from SCTP
    optval = 1;
    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_RECVNXTINFO, &optval, sizeof(optval)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - setsockopt(SCTP_RECVNXTINFO) failed: %s", __func__, strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }
#endif

#ifdef SCTP_INITMSG
    struct sctp_initmsg init;
    memset(&init, 0, sizeof(init));

    init.sinit_num_ostreams = SCTP_STREAMCOUNT;
    init.sinit_max_instreams = SCTP_STREAMCOUNT;
    init.sinit_max_init_timeo = 3000;
    init.sinit_max_attempts = 3;

    if (setsockopt(pollable_socket->fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(struct sctp_initmsg)) < 0) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - setsockopt(SCTP_INITMSG) failed: %s", __func__, strerror(errno));
        return(NEAT_ERROR_INTERNAL);
    }

    nt_log(ctx, NEAT_LOG_DEBUG, "SCTP stream negotiation - offering : %d in / %d out", init.sinit_max_instreams, init.sinit_num_ostreams);
#endif

#ifdef USRSCTP_SUPPORT
    assert(false);
#else
    if (!pollable_socket->flow->security_needed) {
        nt_sctp_init_events(pollable_socket->fd);
    }
#endif

    return(NEAT_ERROR_OK);
}


#ifdef SCTP_MULTISTREAMING

/*
 * Search for SCTP assoc with multistreaming support and same remote host
 */
struct neat_pollable_socket *
nt_find_multistream_socket(neat_ctx *ctx, neat_flow *new_flow)
{
    neat_flow *flow_itr;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    LIST_FOREACH(flow_itr, &ctx->flows, next_flow) {
        //nt_log(ctx, NEAT_LOG_DEBUG, "%s - checking: %p - %s", __func__, flow, flow->name);

        // skipping self
        if (flow_itr == new_flow) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - self...", __func__, flow_itr);
            continue;
        }

        // flow should have a socket
        if (flow_itr->socket->fd < 1) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - no socket fd", __func__, flow_itr);
            continue;
        }

        // xxx todo : check needed?
        if (flow_itr->acceptPending == 1) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - accept pending", __func__, flow_itr);
            continue;
        }

        // DNS-name matches, flow is in connecting state, has the same group and supports NEAT multistreaming
        if (!strcmp(flow_itr->name, new_flow->name) &&
            flow_itr->group == new_flow->group &&
            flow_itr->socket->stack == NEAT_STACK_SCTP &&
            flow_itr->socket->sctp_neat_peer == 1 &&
            flow_itr->socket->sctp_streams_used < flow_itr->socket->sctp_streams_available
        ) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : match!", __func__, flow_itr);
            return flow_itr->socket;
        } else {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : no match!", __func__, flow_itr);

            nt_log(ctx, NEAT_LOG_WARNING, "%s - %d - %d - %d - %d - %d",
                __func__, !strcmp(flow_itr->name, new_flow->name), flow_itr->group == new_flow->group, flow_itr->socket->stack == NEAT_STACK_SCTP, flow_itr->socket->sctp_neat_peer, flow_itr->socket->sctp_streams_available);
        }
    }
    return NULL;
}

/*
 * Search and hook flows which can use the multistream association
 */
static void
nt_hook_mulitstream_flows(neat_flow *flow) {
    neat_flow *flow_itr = NULL;
    struct neat_he_candidate *candidate;
    struct neat_ctx *ctx = flow->ctx;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    LIST_FOREACH(flow_itr, &(flow->ctx->flows), next_flow) {
        nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p - checking", __func__, flow_itr);

        // skipping self
        if (flow_itr == flow) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - self...", __func__, flow);
            continue;
        }

        if (flow_itr->everConnected) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p - already connected", __func__, flow_itr);
        }

        // xxx todo : check needed?
        if (flow_itr->acceptPending == 1) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - accept pending", __func__, flow_itr);
            continue;
        }

        // DNS-name matches, flow is in connecting state and has the same group
        if (!strcmp(flow_itr->name, flow->name) &&
            flow_itr->hefirstConnect &&
            flow_itr->group == flow->group
        ) {
            TAILQ_FOREACH(candidate, flow_itr->candidate_list, next) {
                // Flow candidates include SCTP
                if (candidate->pollable_socket->stack == NEAT_STACK_SCTP) {
                    // we have a candidate
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : candidate matches - waiting", __func__, flow_itr);
                } else {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : no match for candidate", __func__, flow_itr);
                }
            }
        } else {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p - no match", __func__, flow_itr);
        }
    }

    return;
}


/*
 * Check if there is another HE in progress with the same target and return flow;
 */
uint8_t
nt_wait_for_multistream_socket(neat_ctx *ctx, neat_flow *flow)
{
    neat_flow *flow_itr;
    struct neat_he_candidate *candidate;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    LIST_FOREACH(flow_itr, &ctx->flows, next_flow) {
        //nt_log(ctx, NEAT_LOG_DEBUG, "%s - checking: %p - %s", __func__, flow_itr, flow_itr->name);

        // skipping self
        if (flow_itr == flow) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - self...", __func__, flow_itr);
            continue;
        }

        // flow should have a socket
        /*
        if (flow_itr->socket->fd < 1) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - no socket", __func__, flow_itr);
            continue;
        }
        */

        // xxx todo : check needed?
        if (flow_itr->acceptPending == 1) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : skipping - accept pending", __func__, flow_itr);
            continue;
        }

        // DNS-name matches, flow is in connecting state and has the same group
        if (!strcmp(flow_itr->name, flow->name) &&
            flow_itr->hefirstConnect &&
            flow_itr->group == flow->group
        ) {
            TAILQ_FOREACH(candidate, flow_itr->candidate_list, next) {
                // Flow candidates include SCTP
                if (candidate->pollable_socket->stack == NEAT_STACK_SCTP) {
                    // we have a candidate
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : candidate matches - waiting", __func__, flow_itr);
                    return 1;
                } else {
                    nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p : no match for candidate", __func__, flow_itr);
                }
            }
        } else {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - %p - no match", __func__, flow_itr);
        }
    }
    return 0;
}

/*
 *  Find multistream flow by stream id
 */
static neat_flow *
nt_sctp_get_flow_by_sid(struct neat_pollable_socket *socket, uint16_t sid)
{
    neat_flow *flow;
    //nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    if (!socket->multistream) {
        return NULL;
    }

    LIST_FOREACH(flow, &socket->sctp_multistream_flows, multistream_next_flow) {

        nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s - want %d - have %d", __func__, sid, flow->multistream_id);

        if (flow->multistream_id == sid) {
            return flow;
        }
    }
    return NULL;
}

/*
 * Initiate stream reset
 */
static void
nt_sctp_reset_stream(struct neat_pollable_socket *socket, uint16_t sid)
{

#ifdef SCTP_RESET_STREAMS
    struct sctp_reset_streams *srs;
    size_t len;

    //nt_log(NEAT_LOG_INFO, "%s - resetting outgoing stream %d", __func__, sid);

    len = sizeof(struct sctp_reset_streams) + sizeof(uint16_t);
    if ((srs = (struct sctp_reset_streams *) calloc(1, len)) == NULL) {
        //nt_log(NEAT_LOG_ERROR, "%s - calloc failed", __func__);
        return;
    }

    srs->srs_flags |= SCTP_STREAM_RESET_OUTGOING;
    //srs->srs_flags |= SCTP_STREAM_RESET_INCOMING;
    srs->srs_number_streams = 1;
    srs->srs_stream_list[0] = sid;

    if (setsockopt(socket->fd, IPPROTO_SCTP, SCTP_RESET_STREAMS, srs, (socklen_t)len) < 0) {
        //nt_log(NEAT_LOG_ERROR, "%s - resetting outgoing stream failed : %s", __func__, strerror(errno));
    }
    free(srs);
#endif // SCTP_RESET_STREAMS
    return;
}

/*
 * Handle stream reset event
 */

#ifdef SCTP_RESET_STREAMS
static void
nt_sctp_handle_reset_stream(struct neat_pollable_socket *socket, struct sctp_stream_reset_event *notfn)
{
    uint16_t list_length = 0;
    int itr = 0;
    struct neat_flow *flow = NULL;
    struct neat_ctx *ctx = NULL;
    uint16_t stream_id = 0;
    uint16_t code = NEAT_OK;

    list_length = (notfn->strreset_length - sizeof(struct sctp_stream_reset_event)) / sizeof(uint16_t);

    //nt_log(NEAT_LOG_DEBUG, "%s - incoming stream reset event for %d streams", __func__, list_length);

    for (itr = 0; itr < list_length; itr++) {
        stream_id   = notfn->strreset_stream_list[itr];
        flow        = nt_sctp_get_flow_by_sid(socket, stream_id);
        ctx         = flow->ctx;

        if (flow == NULL) {
            //nt_log(NEAT_LOG_ERROR, "%s - stream reset event for unknown flow", __func__);
            continue;
        }

        if (notfn->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
            //nt_log(NEAT_LOG_INFO, "%s - stream reset for incoming SSN on stream %d", __func__, stream_id);

            assert(flow->multistream_reset_in == 0);
            flow->multistream_reset_in = 1;

            if (flow->multistream_reset_out) {
                // outgoing stream already closed, call neat close, stream will not be used again
                // flow->multistream_state = NEAT_FLOW_CLOSED;
                flow->socket->sctp_streams_used--;
                nt_notify_close(flow);
            } else {
                // outgoing stream open, report incoming stream closed : neat_read should return 0
                if (flow->operations.on_readable) {
                    READYCALLBACKSTRUCT;
                    flow->operations.on_readable(&flow->operations);
                }
            }
        }

        if (notfn->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
            //nt_log(NEAT_LOG_INFO, "%s - stream reset for outgoing SSN on stream %d", __func__, stream_id);

            assert(flow->multistream_reset_out == 0);
            flow->multistream_reset_out = 1;

            if (flow->multistream_reset_in) {
                // incoming stream already closed, call neat close, stream will not be used again
                // flow->multistream_state = NEAT_FLOW_CLOSED;
                flow->socket->sctp_streams_used--;
                nt_notify_close(flow);
            }
        }
    }
    return;
}

#endif // SCTP_RESET_STREAMS

neat_error_code
nt_sctp_open_stream(struct neat_pollable_socket *socket, uint16_t sid)
{
    ssize_t rv = 0;
    uint8_t payload = 1;
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
    //nt_log(NEAT_LOG_DEBUG, "%s", __func__);

    iov.iov_base = &payload;
    iov.iov_len = sizeof(payload);
    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_iov = &iov;
    msghdr.msg_iovlen = 1;


#if defined(SCTP_SNDINFO)
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msghdr.msg_control = cmsgbuf;
    msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndinfo));
    cmsg = (struct cmsghdr *)cmsgbuf;
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_SNDINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
    sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
    //memset(sndinfo, 0, sizeof(struct sctp_sndinfo));
    sndinfo->snd_sid = sid;
    sndinfo->snd_ppid = htonl(1207);
#if defined(SCTP_EXPLICIT_EOR)
    sndinfo->snd_flags |= SCTP_EOR;
#endif
#elif defined (SCTP_SNDRCV)
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msghdr.msg_control = cmsgbuf;
    msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndrcvinfo));
    cmsg = (struct cmsghdr *)cmsgbuf;
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_SNDRCV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
    sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
    //memset(sndrcvinfo, 0, sizeof(struct sctp_sndrcvinfo));
    sndrcvinfo->sinfo_stream = sid;
    sndrcvinfo->sinfo_ppid = htonl(1207);
#if defined(SCTP_EXPLICIT_EOR)
    sndrcvinfo->sinfo_flags |= SCTP_EOR;
#endif
#else
    msghdr.msg_control = NULL;
    msghdr.msg_controllen = 0;
#endif

    msghdr.msg_flags = 0;

#ifndef MSG_NOSIGNAL
    rv = sendmsg(socket->fd, (const struct msghdr *)&msghdr, 0);
#else
    rv = sendmsg(socket->fd, (const struct msghdr *)&msghdr, MSG_NOSIGNAL);
#endif

    if (rv < 0) {
        if (errno == EWOULDBLOCK) {
            //nt_log(NEAT_LOG_ERROR, "%s - NEAT_LOG_ERROR - %s", __func__, strerror(errno));
            return NEAT_ERROR_WOULD_BLOCK;
        } else {
            //nt_log(NEAT_LOG_ERROR, "%s - NEAT_ERROR_IO - %s", __func__, strerror(errno));
            return NEAT_ERROR_IO;
        }
    }

    return NEAT_OK;
}

#endif // SCTP_MULTISTREAMING

#if defined(WEBRTC_SUPPORT)
void webrtc_io_connected(neat_ctx *ctx, neat_flow *flow, neat_error_code code)
{
    flow->socket->usrsctp_socket = flow->peer_connection->sctp_transport->socket;
    flow->socket->stack = NEAT_STACK_WEBRTC;
    flow->socket->family = AF_CONN;
    io_connected(ctx, flow, code);
}

void webrtc_io_readable(neat_ctx *ctx, neat_flow *flow, neat_error_code code, void *buffer, size_t size)
{
    int stream_id   = -1;
    if (resize_read_buffer(flow) != READ_OK) {
        nt_log(ctx, NEAT_LOG_WARNING, "%s - Could not resize read buffer", __func__);
    }
     memcpy(flow->readBuffer + flow->readBufferSize, buffer, size);
     flow->readBufferSize += size;
    if (flow->operations.on_readable) {
        READYCALLBACKSTRUCT;
        flow->operations.on_readable(&flow->operations);
    }
}

void webrtc_io_writable(neat_ctx *ctx, neat_flow *flow, neat_error_code code)
{
    io_writable(ctx, flow, code);
}

void webrtc_io_parameters(neat_ctx *ctx, neat_flow *flow, neat_error_code code)
{
nt_log(ctx, NEAT_LOG_WARNING, "%s", __func__);
    int stream_id   = -1;
    if (flow->operations.on_parameters) {
        READYCALLBACKSTRUCT;
        flow->operations.on_parameters(&flow->operations);
    }
}
#endif // defined(WEBRTC_SUPPORT)
