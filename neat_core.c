#include <sys/types.h>
#include <netinet/in.h>
#if defined(HAVE_NETINET_SCTP_H) && !defined(USRSCTP_SUPPORT)
#ifdef __linux__
    #include <linux/sctp.h>
#else
    #include <netinet/sctp.h>
    #include <netinet/udplite.h>
#endif
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include "neat_property_helpers.h"
#include "neat_stat.h"
#include "neat_resolver_helpers.h"
#include "neat_json_helpers.h"
#include "neat_unix_json_socket.h"
#include "neat_pm_socket.h"

#if defined(USRSCTP_SUPPORT)
    #include "neat_usrsctp_internal.h"
    #include <usrsctp.h>
#endif
#ifdef __linux__
    #include "neat_linux_internal.h"
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <net/if.h>
    #include "neat_bsd_internal.h"
#endif

static void updatePollHandle(neat_ctx *ctx, neat_flow *flow, uv_poll_t *handle);
static neat_error_code neat_write_flush(struct neat_ctx *ctx, struct neat_flow *flow);
static int neat_listen_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow,
                                  neat_protocol_stack_type stack,
                                  struct sockaddr *sockaddr, int family, int socket_type);
static int neat_close_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow);
static int neat_close_via_kernel_2(int fd);
#if defined(USRSCTP_SUPPORT)
static int neat_connect_via_usrsctp(struct neat_he_candidate *candidate);
static int neat_listen_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow,
                                   struct neat_pollable_socket *pollable_socket);
static int neat_close_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow);
static int neat_shutdown_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow);
static void handle_upcall(struct socket *s, void *arg, int flags);
static void handle_connect(struct socket *s, void *arg, int flags);
static void neat_sctp_init_events(struct socket *sock);
#else
static void neat_sctp_init_events(int sock);
#endif

static void neat_free_flow(struct neat_flow *flow);

static neat_flow * do_accept(neat_ctx *ctx, neat_flow *flow, struct neat_pollable_socket *socket);
neat_flow * neat_find_flow(neat_ctx *, struct sockaddr *, struct sockaddr *);

#define TAG_STRING(tag) [tag] = #tag
const char *neat_tag_name[NEAT_TAG_LAST] = {
    TAG_STRING(NEAT_TAG_STREAM_ID),
    TAG_STRING(NEAT_TAG_STREAM_COUNT),
    TAG_STRING(NEAT_TAG_LOCAL_NAME),
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
};

#define MIN(a,b) (((a)<(b))?(a):(b))

//Intiailize the OS-independent part of the context, and call the OS-dependent
//init function
struct neat_ctx *neat_init_ctx()
{
    struct neat_ctx *nc;
    struct neat_ctx *ctx = NULL;
    neat_log_init();
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    // TODO: Disable these checks for non-debug builds
    if (sizeof(neat_tag_name) / sizeof(neat_tag_name[0]) != NEAT_TAG_LAST) {
        neat_log(NEAT_LOG_DEBUG,
                 "Warning: Expected %d tag names, but found %d tag names",
                 NEAT_TAG_LAST,
                 sizeof(neat_tag_name) / sizeof(*neat_tag_name));
    }

    for (int i = 0; i < NEAT_TAG_LAST; ++i) {
        if (neat_tag_name[i] == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Warning: Missing one or more tag names (index %d)", i);
            break;
        }
    }

    nc = calloc(sizeof(struct neat_ctx), 1);

    if (!nc) {
        return NULL;
    }
    nc->loop = malloc(sizeof(uv_loop_t));
    nc->pvd = NULL;

    if (nc->loop == NULL) {
        free(nc);
        return NULL;
    }

    uv_loop_init(nc->loop);
    LIST_INIT(&(nc->src_addrs));
    LIST_INIT(&(nc->flows));

    uv_timer_init(nc->loop, &(nc->addr_lifetime_handle));
    nc->addr_lifetime_handle.data = nc;
    uv_timer_start(&(nc->addr_lifetime_handle),
                   neat_addr_lifetime_timeout_cb,
                   1000 * NEAT_ADDRESS_LIFETIME_TIMEOUT,
                   1000 * NEAT_ADDRESS_LIFETIME_TIMEOUT);
    neat_security_init(nc);
#if defined(USRSCTP_SUPPORT)
    neat_usrsctp_init_ctx(nc);
#endif
#if defined(__linux__)
    ctx = neat_linux_init_ctx(nc);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    ctx = neat_bsd_init_ctx(nc);
#else
    uv_loop_close(nc->loop);
#endif
    if (!ctx) {
      free(nc->loop);
      free(nc);
    }
    return ctx;

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

    //HACK: Can't stop the IDLE handle used by resolver. Should probably do
    //something more advanced in case we use other idle handles
    if (handle->type == UV_IDLE) {
        neat_log(NEAT_LOG_DEBUG, "%s - handle->type == UV_IDLE - skipping", __func__);
        return;
    }

    if (!uv_is_closing(handle)) {
        neat_log(NEAT_LOG_DEBUG, "%s - closing handle", __func__);
        uv_close(handle, NULL);
    }
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
    struct neat_flow *f, *prev = NULL;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (nc->resolver) {
        neat_resolver_release(nc->resolver);
    }

    while (!LIST_EMPTY(&nc->flows)) {
        f = LIST_FIRST(&nc->flows);

        /*
         * If this assert triggers, it means that a call to neat_free_flow did
         * not remove the flow pointed to by f from the list of flows. The
         * assert is present because clang-analyzer somehow doesn't see the fact
         * that the list is changed in neat_free_flow().
         */
        assert(f != prev);

        neat_free_flow(f);
        prev = f;
    }

    neat_core_cleanup(nc);

    if (nc->event_cbs)
        free(nc->event_cbs);

    if (nc->pvd) {
        neat_pvd_release(nc->pvd);
        free(nc->pvd);
    }

    free(nc->loop);

    neat_security_close(nc);
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

struct neat_iofilter *
insert_neat_iofilter(neat_ctx *ctx, neat_flow *flow)
{
    struct neat_iofilter *filter = calloc (1, sizeof (struct neat_iofilter));
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

void
on_handle_closed(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    free(handle);
}

void
neat_free_candidate(struct neat_he_candidate *candidate)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    free(candidate->pollable_socket->dst_address);
    free(candidate->pollable_socket->src_address);

    // We should close the handle of this candidate asynchronously, but only if
    // this handle is not being used by the flow.
    if (candidate->pollable_socket->handle != NULL) {
        if (candidate->pollable_socket->handle == candidate->pollable_socket->flow->socket->handle) {
            neat_log(NEAT_LOG_DEBUG,"%s: Handle used by flow, flow should release it", __func__);
        } else {
            if (!uv_is_closing((uv_handle_t*)candidate->pollable_socket->handle)) {
                neat_log(NEAT_LOG_DEBUG,"%s: Release candidate after closing", __func__);
                uv_close((uv_handle_t*)candidate->pollable_socket->handle, on_handle_closed);
            } else {
                neat_log(NEAT_LOG_DEBUG,"%s: Candidate handle is already closing", __func__);
            }
        }
    }

    free(candidate->pollable_socket);
    free(candidate->if_name);
    json_decref(candidate->properties);
    free(candidate);
}

void
neat_free_candidates(struct neat_he_candidates *candidates)
{
    struct neat_he_candidate *candidate, *tmp;

    if (candidates == NULL)
        return;

    TAILQ_FOREACH_SAFE(candidate, candidates, next, tmp) {
        neat_free_candidate(candidate);
    }

    free(candidates);
}

static void synchronous_free(neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    flow->closefx(flow->ctx, flow);
    free((char *)flow->name);
    free((char *)flow->server_pem);
    if (flow->cc_algorithm) {
        free((char*)flow->cc_algorithm);
    }
    if (flow->resolver_results) {
        neat_log(NEAT_LOG_DEBUG, "neat_resolver_free_results");
        neat_resolver_free_results(flow->resolver_results);
    } else {
       neat_log(NEAT_LOG_DEBUG, "NOT neat_resolver_free_results");
    }
    if (flow->ownedByCore) {
        free(flow->operations);
    }

    json_decref(flow->properties);

    free_iofilters(flow->iofilters);
    free(flow->readBuffer);
    free(flow->socket->handle);
    free(flow->socket);
    free(flow);
}

static void free_cb(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    struct neat_pollable_socket *pollable_socket = handle->data;
    synchronous_free(pollable_socket->flow);
}

static int neat_close_socket(struct neat_ctx *ctx, struct neat_flow *flow)
{
    struct neat_pollable_socket *s;
#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        neat_close_via_usrsctp(flow->ctx, flow);
        return 0;
    }
#endif

    TAILQ_FOREACH(s, &(flow->listen_sockets), next) {
        neat_close_via_kernel_2(s->fd);
    }

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

    LIST_REMOVE(flow, next_flow);

#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
       synchronous_free(flow);
        return;
    }
#endif

    neat_free_candidates(flow->candidate_list);

    if (flow->socket->handle != NULL &&
        flow->socket->handle->type != UV_UNKNOWN_HANDLE)
    {
        if (!uv_is_closing((uv_handle_t *)flow->socket->handle))
            uv_close((uv_handle_t *)(flow->socket->handle), free_cb);
        else {
            neat_log(NEAT_LOG_DEBUG, "handle is closing");
        }
    } else {
        synchronous_free(flow);
    }
}

neat_error_code
neat_set_property(neat_ctx *mgr, neat_flow *flow, const char *properties)
{
    json_t *prop, *props;
    json_error_t error;
    const char *key;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    props = json_loads(properties, 0, &error);
    if (props == NULL) {
        neat_log(NEAT_LOG_DEBUG, "Error in property string, line %d col %d",
                 error.line, error.position);
        neat_log(NEAT_LOG_DEBUG, "%s", error.text);

        return NEAT_ERROR_BAD_ARGUMENT;
    }

    json_object_foreach(props, key, prop) {

        // This step is not strictly required, but informs of overwritten keys
        if (json_object_del(flow->properties, key) == 0) {
            neat_log(NEAT_LOG_DEBUG, "Existing property %s was overwritten!", key);
        }

        json_object_set(flow->properties, key, prop);
    }

    json_decref(props);

#if 0
    char *buffer = json_dumps(flow->properties, JSON_INDENT(2));
    neat_log(NEAT_LOG_DEBUG, "Flow properties are now:\n%s\n", buffer);
    free(buffer);
#endif

    return NEAT_OK;
}

neat_error_code
neat_get_property(neat_ctx *ctx, neat_flow *flow, const char* name, void *ptr, size_t *size)
{
    json_t *prop;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->properties == NULL) {
        neat_log(NEAT_LOG_DEBUG, "Flow has no properties (properties == NULL)");
        return NEAT_ERROR_UNABLE;
    }

    prop = json_object_get(flow->properties, name);

    if (prop == NULL) {
        neat_log(NEAT_LOG_DEBUG, "Flow has no property named %s");
        return NEAT_ERROR_UNABLE;
    }

    prop = json_object_get(prop, "value");
    if (prop == NULL) {
        neat_log(NEAT_LOG_DEBUG, "Flow has property %s, but it contains no \"value\" key!");
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


int neat_get_stack(neat_ctx* mgr, neat_flow* flow)
{
    return flow->socket->stack;
}

neat_error_code neat_set_operations(neat_ctx *mgr, neat_flow *flow,
                                    struct neat_flow_operations *ops)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    flow->operations = ops;

    if (flow->socket == NULL)
        return NEAT_OK;

#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP)
        return NEAT_OK;
#endif
    updatePollHandle(mgr, flow, flow->socket->handle);
    return NEAT_OK;
}

/* Return statistics about the flow in JSON format
   NB - the memory allocated for the return string must be freed
   by the caller */
neat_error_code neat_get_stats(neat_ctx *mgr, char **json_stats)
{
      neat_log(NEAT_LOG_DEBUG, "%s", __func__);

      neat_stats_build_json(mgr, json_stats);

      return NEAT_OK;
}

#define READYCALLBACKSTRUCT \
    flow->operations->status = code;\
    flow->operations->stream_id = stream_id;\
    flow->operations->ctx = ctx;\
    flow->operations->flow = flow;


void
neat_io_error(neat_ctx *ctx, neat_flow *flow, neat_error_code code)
{
    const int stream_id = NEAT_INVALID_STREAM;
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
#if defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)
    unsigned int optlen;
    int rc;
    struct sctp_status status;
#endif // defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)


    char proto[16];

    flow->stream_count = 1;

    switch (flow->socket->stack) {
        case NEAT_STACK_UDP:
            snprintf(proto, 16, "UDP");
            break;
        case NEAT_STACK_TCP:
            snprintf(proto, 16, "TCP");
            break;
        case NEAT_STACK_SCTP:
            snprintf(proto, 16, "SCTP");
#if defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)
            optlen = sizeof(status);
            rc = getsockopt(flow->socket->fd, IPPROTO_SCTP, SCTP_STATUS, &status, &optlen);
            if (rc < 0) {
                neat_log(NEAT_LOG_DEBUG, "Call to getsockopt(SCTP_STATUS) failed");
                flow->stream_count = 1;
            } else {
                flow->stream_count = MIN(status.sstat_outstrms, status.sstat_outstrms);
            }
            // number of outbound streams == number of inbound streams
            neat_log(NEAT_LOG_INFO, "%s - SCTP - number of streams: %d", __func__, flow->stream_count);
#endif // defined(IPPROTO_SCTP) && defined(SCTP_STATUS) && !defined(USRSCTP_SUPPORT)
            break;
        case NEAT_STACK_UDPLITE:
            snprintf(proto, 16, "UDPLite");
            break;
        case NEAT_STACK_SCTP_UDP:
            snprintf(proto, 16, "SCTP/UDP");
            break;
        default:
            snprintf(proto, 16, "stack%d", flow->socket->stack);
            break;
    }

    neat_log(NEAT_LOG_INFO, "Connected: %s/%s - %d streams", proto, (flow->socket->family == AF_INET ? "IPv4" : "IPv6" ), flow->stream_count);


    if (!flow->operations || !flow->operations->on_connected) {
        return;
    }

    READYCALLBACKSTRUCT;
    flow->operations->on_connected(flow->operations);
}

static void io_writable(neat_ctx *ctx, neat_flow *flow, int stream_id, neat_error_code code)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->isDraining) {
        neat_write_flush(ctx, flow);
    }
    if (!flow->operations || !flow->operations->on_writable || flow->isDraining) {
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
        // TODO: Allocate send buffers here instead?
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
	neat_log(NEAT_LOG_DEBUG, "Got SCTP peer address change event");
	break;
    case SCTP_REMOTE_ERROR:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP remote error event");
	break;
    case SCTP_SHUTDOWN_EVENT:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP shutdown event");
	break;
    case SCTP_ADAPTATION_INDICATION:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP adaption indication event");
	break;
    case SCTP_PARTIAL_DELIVERY_EVENT:
	neat_log(NEAT_LOG_DEBUG, "Got SCTP partial delivery event");
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

int
resize_read_buffer(neat_flow *flow)
{
    ssize_t spaceFree;
    ssize_t spaceNeeded, spaceThreshold;

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
    return READ_OK;
}

static int io_readable(neat_ctx *ctx, neat_flow *flow,
                       struct neat_pollable_socket *socket,
                       neat_error_code code)
{
    struct sockaddr_storage peerAddr;
    socklen_t peerAddrLen = sizeof(struct sockaddr_storage);
    int stream_id = 0;
    ssize_t n;
    //Not used when notifications aren't available:
    int flags __attribute__((unused));
#if !defined(USRSCTP_SUPPORT)

#if defined(SCTP_RCVINFO)
    struct sctp_rcvinfo *rcvinfo;
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_rcvinfo))];
#elif defined (SCTP_SNDRCV)
    struct sctp_sndrcvinfo *sndrcvinfo;
    char cmsgbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
#endif
#if (defined(SCTP_RCVINFO) || defined (SCTP_SNDRCV))
    struct cmsghdr *cmsg;
#endif

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

    if (!flow->operations) {
        neat_log(NEAT_LOG_DEBUG, "%s - No operations", __func__);
        return READ_WITH_ERROR;
    }

    /*
     * The UDP Accept flow isn't going to have on_readable set,
     * anything else will.
     */
    if (!flow->operations->on_readable && flow->acceptPending) {

        if (socket->stack != NEAT_STACK_UDP && socket->stack != NEAT_STACK_UDPLITE) {
            neat_log(NEAT_LOG_DEBUG, "Exit 1");
            return READ_WITH_ERROR;
        }
    }

    if ((socket->stack == NEAT_STACK_UDP || socket->stack == NEAT_STACK_UDPLITE) && (!flow->readBufferMsgComplete)) {
        if (resize_read_buffer(flow) != READ_OK) {
            neat_log(NEAT_LOG_DEBUG, "Exit 2");
            return READ_WITH_ERROR;
        }

        if (socket->stack == NEAT_STACK_UDP || socket->stack == NEAT_STACK_UDPLITE) {
            if (!flow->acceptPending && !flow->operations->on_readable) {
                neat_log(NEAT_LOG_DEBUG, "Exit 3");
                return READ_WITH_ERROR;
            }

            if ((n = recvfrom(socket->fd, flow->readBuffer,
                flow->readBufferAllocation, 0, (struct sockaddr *)&peerAddr, &peerAddrLen)) < 0)  {
                neat_log(NEAT_LOG_DEBUG, "Exit 4");
                return READ_WITH_ERROR;
            }

            flow->readBufferSize = n;
            flow->readBufferMsgComplete = 1;

            if (n == 0) {
                flow->readBufferMsgComplete = 0;
                neat_log(NEAT_LOG_DEBUG, "Exit 5");
                return READ_WITH_ZERO;
            }

            if (flow->acceptPending) {
                flow->readBufferMsgComplete = 0;

                neat_flow *newFlow = neat_find_flow(ctx, &socket->srcAddr, (struct sockaddr *)&peerAddr);

                if (!newFlow) {
                    neat_log(NEAT_LOG_DEBUG, "%s - Creating new UDP flow", __func__);

                    memcpy(&socket->dstAddr, (struct sockaddr *)&peerAddr, sizeof(struct sockaddr));
                    newFlow = do_accept(ctx, flow, socket);
                }

                assert(newFlow);

                if (resize_read_buffer(newFlow) != READ_OK) {
                    neat_log(NEAT_LOG_DEBUG, "Exit 6");
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

    if ((neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) &&
        (!flow->readBufferMsgComplete)) {

        if (resize_read_buffer(flow) != READ_OK) {
            neat_log(NEAT_LOG_DEBUG, "Exit 7");
            return READ_WITH_ERROR;
        }

#if !defined(USRSCTP_SUPPORT)
        iov.iov_base = flow->readBuffer + flow->readBufferSize;
        iov.iov_len = flow->readBufferAllocation - flow->readBufferSize;
        msghdr.msg_name = NULL;
        msghdr.msg_namelen = 0;
        msghdr.msg_iov = &iov;
        msghdr.msg_iovlen = 1;
#if defined(SCTP_RCVINFO) || defined(SCTP_SNDRCV)
        msghdr.msg_control = cmsgbuf;
        msghdr.msg_controllen = sizeof(cmsgbuf);
#else
        msghdr.msg_control = NULL;
        msghdr.msg_controllen = 0;
#endif
        msghdr.msg_flags = 0;
#ifdef MSG_NOTIFICATION
        msghdr.msg_flags |= MSG_NOTIFICATION;
#endif

        if ((n = recvmsg(flow->socket->fd, &msghdr, 0)) < 0) {
            neat_log(NEAT_LOG_DEBUG, "Exit 8");
            return READ_WITH_ERROR;
        }

#if (defined(SCTP_RCVINFO) || defined (SCTP_SNDRCV))
        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
            if (cmsg->cmsg_len == 0) {
                neat_log(NEAT_LOG_DEBUG, "%s - Error in ancilliary data from recvmsg", __func__);
                break;
            }
#ifdef IPPROTO_SCTP
            if (cmsg->cmsg_level == IPPROTO_SCTP) {
#if defined (SCTP_RCVINFO)
                if (cmsg->cmsg_type == SCTP_RCVINFO) {
                    rcvinfo = (struct sctp_rcvinfo *)CMSG_DATA(cmsg);
                    neat_log(NEAT_LOG_DEBUG, "%s - Received data on SCTP stream %d", __func__, rcvinfo->rcv_sid);
                    stream_id = rcvinfo->rcv_sid;
                }
#elif defined (SCTP_SNDRCV)
                if (cmsg->cmsg_type == SCTP_SNDRCV) {
                    sndrcvinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
                    neat_log(NEAT_LOG_DEBUG, "%s - Received data on SCTP stream %d", __func__, sndrcvinfo->sinfo_stream);
                    stream_id = sndrcvinfo->sinfo_stream;
                }
#endif
            }
#endif // defined(IPPROTP_SCTP)
        }
#endif // (defined(SCTP_RCVINFO) || defined (SCTP_SNDRCV))

        flags = msghdr.msg_flags; // For notification handling
#else // !defined(USRSCTP_SUPPORT)
        len = sizeof(struct sockaddr);
        memset((void *)&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	addr.sin_family = AF_INET;

        n = usrsctp_recvv(socket->usrsctp_socket, flow->readBuffer + flow->readBufferSize,
                               flow->readBufferAllocation - flow->readBufferSize,
                               (struct sockaddr *) &addr, &len, (void *)&rn,
                                &infolen, &infotype, &flags);
        if (n < 0) {
            neat_log(NEAT_LOG_DEBUG, "usrsctp_recvv error");

            neat_log(NEAT_LOG_DEBUG, "Exit 9");
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
            neat_log(NEAT_LOG_DEBUG, "Exit 10");
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
            neat_log(NEAT_LOG_DEBUG, "Exit 11");
            return READ_WITH_ERROR;
        }
#else // !defined(USRSCTP_SUPPORT)
        neat_log(NEAT_LOG_INFO, " %zd bytes received", n);
        flow->readBufferSize += n;
        if ((flags & MSG_EOR) || (n == 0)) {
            flow->readBufferMsgComplete = 1;
        }
        if (!flow->readBufferMsgComplete) {
            neat_log(NEAT_LOG_DEBUG, "Message not complete, yet");
            neat_log(NEAT_LOG_DEBUG, "Exit 12");
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

static void
io_all_written(neat_ctx *ctx, neat_flow *flow, int stream_id)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    stream_id = NEAT_INVALID_STREAM;

    if (!flow->operations || !flow->operations->on_all_written) {
        return;
    }
    neat_error_code code = NEAT_OK;
    READYCALLBACKSTRUCT;
    flow->operations->on_all_written(flow->operations);
}

static void
io_timeout(neat_ctx *ctx, neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    const int stream_id = NEAT_INVALID_STREAM;

    if (!flow->operations || !flow->operations->on_timeout) {
        return;
    }
    neat_error_code code = NEAT_OK;
    READYCALLBACKSTRUCT;
    flow->operations->on_timeout(flow->operations);
}

static neat_error_code
neat_write_flush(struct neat_ctx *ctx, struct neat_flow *flow);

static void updatePollHandle(neat_ctx *ctx, neat_flow *flow, uv_poll_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->socket->handle != NULL) {
        if (handle->loop == NULL || uv_is_closing((uv_handle_t *)flow->socket->handle)) {
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

    if (flow->isDraining) {
        newEvents |= UV_WRITABLE;
    }

    if (newEvents) {
        flow->isPolling = 1;
        if (flow->socket->handle != NULL) {
            uv_poll_start(handle, newEvents, uvpollable_cb);
        }
    } else {
        flow->isPolling = 0;
        if (flow->socket->handle != NULL) {
            uv_poll_stop(handle);
        }
    }
}

static void free_he_handle_cb(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    free(handle);
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
    json_t *security = NULL, *val = NULL;

    c++;
    neat_log(NEAT_LOG_DEBUG, "Invokation count: %d", c);
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

    neat_log(NEAT_LOG_DEBUG,
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
    
        neat_log(NEAT_LOG_DEBUG, "Call to getsockopt failed: %s", strerror(errno));
        neat_io_error(candidate->ctx, flow, NEAT_ERROR_INTERNAL);
        return;
    }
    status = so_error;
    neat_log(NEAT_LOG_DEBUG,
             "Connection status: %d", status);

    // TODO: In which circumstances do we end up in the three different cases?
    if (flow->firstWritePending) {
        // assert(0);
        neat_log(NEAT_LOG_DEBUG, "First successful connect");

        assert(flow->socket);

        // Transfer this handle to the "main" polling callback
        // TODO: Consider doing this in some other way that directly calling
        // this callback
        uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE);
    } else if (flow->hefirstConnect && (status == 0)) {
        flow->hefirstConnect = 0;

        //neat_log(NEAT_LOG_DEBUG, "?");
        neat_log(NEAT_LOG_DEBUG, "First successful connect");


        assert(flow->socket);

        // TODO: Security code should be wired back in

        flow->socket->fd = candidate->pollable_socket->fd;
        flow->socket->flow = flow;
        // TODO: Ensure initialization (when using PM)
        assert(flow->socket->handle->loop == NULL);
        free(flow->socket->handle);
        flow->socket->handle = handle;
        flow->socket->handle->data = flow->socket;
        flow->socket->family = candidate->pollable_socket->family;
        flow->socket->type = candidate->pollable_socket->type;
        flow->socket->stack = candidate->pollable_socket->stack;
        json_decref(flow->properties);
        json_incref(candidate->properties);
        flow->properties = candidate->properties;
        flow->everConnected = 1;

#if defined(USRSCTP_SUPPORT)
        // TODO:
        // flow->socket->usrsctp_socket = he_ctx->sock;
#endif
        // TODO:
        // flow->ctx = he_ctx->nc;
        flow->writeSize = candidate->writeSize;
        flow->writeLimit = candidate->writeLimit;
        flow->readSize = candidate->readSize;
        flow->isSCTPExplicitEOR = candidate->isSCTPExplicitEOR;
        flow->isPolling = 1;

        if ((security = json_object_get(flow->properties, "security")) != NULL &&
            (val = json_object_get(security, "value")) != NULL &&
            json_typeof(val) == JSON_TRUE)
        {
            neat_log(NEAT_LOG_DEBUG, "client required security");
            if (neat_security_install(flow->ctx, flow) != NEAT_OK) {
                neat_io_error(flow->ctx, flow, NEAT_ERROR_SECURITY);
            }
        } else {
            // Transfer this handle to the "main" polling callback
            // TODO: Consider doing this in some other way that directly calling
            // this callback
            flow->firstWritePending = 1;
            uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE);
        }
    } else {
        // assert(0);
        neat_log(NEAT_LOG_DEBUG, "NOT first connect");

        uv_poll_stop(handle);
        uv_close((uv_handle_t*)handle, free_he_handle_cb);

        neat_log(NEAT_LOG_DEBUG, "%s:Release candidate", __func__);
        TAILQ_REMOVE(candidate_list, candidate, next);
        free(candidate->pollable_socket->dst_address);
        free(candidate->pollable_socket->src_address);
        free(candidate->pollable_socket);
        free(candidate->if_name);
        json_decref(candidate->properties);
        free(candidate);

        if (!(--flow->heConnectAttemptCount)) {
            neat_io_error(flow->ctx, flow, NEAT_ERROR_UNABLE);
        }
    }
}

void uvpollable_cb(uv_poll_t *handle, int status, int events)
{
    struct neat_pollable_socket *pollable_socket = handle->data;
    neat_flow *flow = pollable_socket->flow;
    neat_ctx *ctx = flow->ctx;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if ((events & UV_READABLE) && flow->acceptPending) {
        if(pollable_socket->stack == NEAT_STACK_UDP ||
           pollable_socket->stack == NEAT_STACK_UDPLITE) {
            neat_log(NEAT_LOG_DEBUG, "io_readable for UDP or UDPLite accept flow");
            io_readable(ctx, flow, pollable_socket, NEAT_OK);
        } else {
            do_accept(ctx, flow, pollable_socket);
        }
        return;
    }

    // TODO: Are there cases when we should keep polling?
    if (status < 0) {
        neat_log(NEAT_LOG_DEBUG, "ERROR: %s", uv_strerror(status));

#if !defined(USRSCTP_SUPPORT)
        if (neat_base_stack(pollable_socket->stack) == NEAT_STACK_TCP ||
            neat_base_stack(pollable_socket->stack) == NEAT_STACK_SCTP)
#else
        if (neat_base_stack(pollable_socket->stack) == NEAT_STACK_TCP)
#endif
        { // special bracing beacuse of ifdef
            int so_error = 0;
            unsigned int len = sizeof(so_error);
            if (getsockopt(flow->socket->fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                neat_log(NEAT_LOG_DEBUG, "Call to getsockopt failed: %s", strerror(errno));
                neat_io_error(ctx, flow, NEAT_ERROR_INTERNAL);
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
        neat_io_error(ctx, flow, NEAT_ERROR_INTERNAL);

        return;
    }

    if (!events && status < 0) {
        neat_io_error(ctx, flow, NEAT_ERROR_IO);
        return;
    }

    if ((events & UV_WRITABLE) && flow->firstWritePending) {
        flow->firstWritePending = 0;
        io_connected(ctx, flow, NEAT_OK);
    }
    if (events & UV_WRITABLE && flow->isDraining) {
        neat_error_code code = neat_write_flush(ctx, flow);
        if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
            neat_io_error(ctx, flow, code);
            return;
        }
        if (!flow->isDraining) {
            io_all_written(ctx, flow, 0);
        }
    }
    if (events & UV_WRITABLE) {
        io_writable(ctx, flow, 0, NEAT_OK); // TODO: Remove stream param
    }
    if (events & UV_READABLE) {
        io_readable(ctx, flow, pollable_socket, NEAT_OK);
    }
    updatePollHandle(ctx, flow, handle);
}

static neat_flow *
do_accept(neat_ctx *ctx, neat_flow *flow, struct neat_pollable_socket *listen_socket)
{
    const char *proto = NULL;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
#if defined(IPPROTO_SCTP)
#if defined(SCTP_RECVRCVINFO) && !defined(USRSCTP_SUPPORT)
    int optval;
#endif
#ifdef SCTP_STATUS
    unsigned int optlen;
    int rc;
    struct sctp_status status;
#endif
#endif

    neat_flow *newFlow = neat_new_flow(ctx);
    if (newFlow == NULL) {
        neat_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
        return NULL;
    }

    newFlow->name = strdup (flow->name);
    if (newFlow->name == NULL) {
        neat_io_error(ctx, newFlow, NEAT_ERROR_OUT_OF_MEMORY);
        return NULL;
    }

    if (flow->server_pem) {
        newFlow->server_pem = strdup (flow->server_pem);
        if (newFlow->server_pem == NULL) {
            neat_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
            return NULL;
        }
    }

    newFlow->port = flow->port;
    newFlow->propertyMask = flow->propertyMask;
    newFlow->propertyAttempt = flow->propertyAttempt;
    newFlow->propertyUsed = flow->propertyUsed;
    newFlow->everConnected = 1;

    switch (listen_socket->stack) {
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

    json_decref(newFlow->properties);
    newFlow->properties = json_pack("{"\
                 /* "transport" */  "s{ss}"\
                 /* "port"      */  "s{si}"\
                 /* "interface" */  "s{ss}"\
                                    "}",
                                    "transport", "value", proto,
                                    "port", "value", flow->port,
                                    "interface", "value", "(unknown)");

    newFlow->socket->stack   = listen_socket->stack;
    newFlow->socket->srcAddr = listen_socket->srcAddr;
    newFlow->socket->dstAddr = listen_socket->dstAddr;
    newFlow->socket->type    = listen_socket->type;
    newFlow->socket->family  = listen_socket->family;

    newFlow->ctx = ctx;
    newFlow->writeLimit = flow->writeLimit;
    newFlow->writeSize = flow->writeSize;
    newFlow->readSize = flow->readSize;

    newFlow->ownedByCore = 1;
    newFlow->isServer = 1;
    newFlow->isSCTPExplicitEOR = flow->isSCTPExplicitEOR;
    newFlow->operations = calloc (sizeof(struct neat_flow_operations), 1);

    if (newFlow->operations == NULL) {
        neat_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
        return NULL;
    }

    newFlow->operations->on_connected = flow->operations->on_connected;
    newFlow->operations->on_readable = flow->operations->on_readable;
    newFlow->operations->on_writable = flow->operations->on_writable;
    newFlow->operations->on_error = flow->operations->on_error;
    newFlow->operations->ctx = ctx;
    newFlow->operations->flow = flow;

    switch (newFlow->socket->stack) {
    case NEAT_STACK_SCTP_UDP:
    case NEAT_STACK_SCTP:
#if defined(USRSCTP_SUPPORT)
        newFlow->socket->usrsctp_socket = newFlow->acceptusrsctpfx(ctx, newFlow, listen_socket);
        if (!newFlow->socket->usrsctp_socket) {
            neat_free_flow(newFlow);
            return NULL;
        } else {
            neat_log(NEAT_LOG_DEBUG, "USRSCTP io_connected");
            io_connected(ctx, newFlow, NEAT_OK);
            newFlow->acceptPending = 0;
        }
#else
        neat_log(NEAT_LOG_DEBUG, "Creating new SCTP socket");
        newFlow->socket->fd = newFlow->acceptfx(ctx, newFlow, listen_socket->fd);
        if (newFlow->socket->fd == -1) {
            neat_free_flow(newFlow);
            return NULL;
        } else {
            uv_poll_init(ctx->loop, newFlow->socket->handle, newFlow->socket->fd); // makes fd nb as side effect
            newFlow->socket->handle->data = newFlow->socket;
            io_connected(ctx, newFlow, NEAT_OK);
            uvpollable_cb(newFlow->socket->handle, NEAT_OK, 0);
        }

#if defined(SCTP_RECVRCVINFO)
        // Enable anciliarry data when receiving data from SCTP
        optval = 1;
        optlen = sizeof(optval);
        rc = setsockopt(newFlow->socket->fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &optval, optlen);
        if (rc < 0)
            neat_log(NEAT_LOG_DEBUG, "Call to setsockopt(SCTP_RECVRCVINFO) failed");
#endif // defined(SCTP_RECVRCVINFO)
#endif
        break;
    case NEAT_STACK_UDP:
        neat_log(NEAT_LOG_DEBUG, "Creating new UDP socket");
        newFlow->socket->fd = socket(newFlow->socket->family, newFlow->socket->type, IPPROTO_UDP);

        if (newFlow->socket->fd == -1) {
            neat_free_flow(newFlow);
            return NULL;
        } else {
            int enable = 1;

            setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
            setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int));

            bind(newFlow->socket->fd, &newFlow->socket->srcAddr, sizeof(struct sockaddr));
            connect(newFlow->socket->fd, &newFlow->socket->dstAddr, sizeof(struct sockaddr));

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
        neat_log(NEAT_LOG_DEBUG, "Creating new UDPLite socket");
        newFlow->socket->fd = socket(newFlow->socket->family, newFlow->socket->type, IPPROTO_UDPLITE);

        if (newFlow->socket->fd == -1) {
            neat_free_flow(newFlow);
            return NULL;
        } else {
            int enable = 1;

            setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
            setsockopt(newFlow->socket->fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int));

            bind(newFlow->socket->fd, &newFlow->socket->srcAddr, sizeof(struct sockaddr));
            connect(newFlow->socket->fd, &newFlow->socket->dstAddr, sizeof(struct sockaddr));

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
            neat_free_flow(newFlow);
            return NULL;
        } else {
            uv_poll_init(ctx->loop, newFlow->socket->handle, newFlow->socket->fd); // makes fd nb as side effect

            newFlow->socket->handle->data = newFlow->socket;

            newFlow->acceptPending = 0;
            if ((newFlow->propertyMask & NEAT_PROPERTY_REQUIRED_SECURITY) &&
                (newFlow->socket->stack == NEAT_STACK_TCP)) {
                neat_log(NEAT_LOG_DEBUG, "TCP Server Security");
                if (neat_security_install(newFlow->ctx, newFlow) != NEAT_OK) {
                    neat_io_error(flow->ctx, flow, NEAT_ERROR_SECURITY);
                }
            } else {
                io_connected(ctx, newFlow, NEAT_OK);
                uvpollable_cb(newFlow->socket->handle, NEAT_OK, 0);
            }
        }
    }

    switch (newFlow->socket->stack) {
#if defined(IPPROTO_SCTP) && defined(SCTP_STATUS)
    case NEAT_STACK_SCTP:
        optlen = sizeof(status);
        rc = getsockopt(newFlow->socket->fd, IPPROTO_SCTP, SCTP_STATUS, &status, &optlen);
        if (rc < 0) {
            neat_log(NEAT_LOG_DEBUG, "Call to getsockopt(SCTP_STATUS) failed");
            newFlow->stream_count = 1;
        } else {
            newFlow->stream_count = MIN(status.sstat_instrms, status.sstat_outstrms);
        }

        // number of outbound streams == number of inbound streams
        neat_log(NEAT_LOG_DEBUG, "%s - SCTP - number of streams: %d", __func__, newFlow->stream_count);
        break;
#endif
    default:
        newFlow->stream_count = 1;
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

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    json_array_foreach(json, i, value) {
        neat_protocol_stack_type stack;
        const char *interface = NULL, *local_ip  = NULL, *remote_ip = NULL, *transport = NULL;
        char dummy[sizeof(struct sockaddr_storage)];
        struct neat_he_candidate *candidate;

        neat_log(NEAT_LOG_DEBUG, "Now processing PM candidate %zu", i);

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

        if ((stack = string_to_stack(transport)) == 0) {
            neat_log(NEAT_LOG_DEBUG, "Unkown transport stack %s", transport);
            continue;
        }

        if ((candidate = calloc(1, sizeof(*candidate))) == NULL)
            goto out_of_memory;

        if ((candidate->pollable_socket = calloc(1, sizeof(struct neat_pollable_socket))) == NULL)
            goto out_of_memory;

        if_idx = if_nametoindex(interface);
        if (!if_idx) {
            neat_log(NEAT_LOG_DEBUG, "Unable to get interface id for \"%s\"",
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
        json_incref(value);

        memset(dummy, 0, sizeof(dummy));

        // Determine the address family and initialize the sockaddr struct accordingly
        if (inet_pton(AF_INET6, candidate->pollable_socket->dst_address, &dummy) == 1) {
            candidate->pollable_socket->family  = AF_INET6;
            candidate->pollable_socket->src_len = sizeof(struct sockaddr_in6);
            candidate->pollable_socket->dst_len = sizeof(struct sockaddr_in6);

            memcpy(&((struct sockaddr_in6*) &candidate->pollable_socket->dst_sockaddr)->sin6_addr, dummy, sizeof(struct sockaddr_in6));
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

            memcpy(&((struct sockaddr_in*) &candidate->pollable_socket->dst_sockaddr)->sin_addr, dummy, sizeof(struct sockaddr_in));
            ((struct sockaddr*) &candidate->pollable_socket->dst_sockaddr)->sa_family = AF_INET;
            ((struct sockaddr_in*) &candidate->pollable_socket->dst_sockaddr)->sin_port = htons(candidate->pollable_socket->port);

            assert(inet_pton(candidate->pollable_socket->family,
                             candidate->pollable_socket->src_address,
                             (void*)&((struct sockaddr_in*)(&candidate->pollable_socket->src_sockaddr))->sin_addr) == 1);
            ((struct sockaddr*) &candidate->pollable_socket->src_sockaddr)->sa_family = AF_INET;
        } else {
            // Not AF_INET or AF_INET6?...
            neat_log(NEAT_LOG_DEBUG, "Received candidate with address \"%s\" which neither AF_INET nor AF_INET6", candidate->pollable_socket->dst_address);
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
                if (candidate->pollable_socket->src_address)
                    free(candidate->pollable_socket->src_address);
                if (candidate->pollable_socket->dst_address)
                    free(candidate->pollable_socket->dst_address);
                free(candidate->pollable_socket);
            }
            if (candidate->if_name)
                free(candidate->if_name);
            free(candidate);
        }
        if (rc)
            neat_io_error(ctx, flow, rc);
        else
            continue;
    }
}

static void
on_pm_reply_post_resolve(neat_ctx *ctx, neat_flow *flow, json_t *json)
{
    struct neat_he_candidates *candidate_list;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#if 0
    char *str = json_dumps(json, JSON_INDENT(2));
    neat_log(NEAT_LOG_DEBUG, "Reply from PM was: %s", str);
    free(str);
#else
    neat_log(NEAT_LOG_DEBUG, "Received second reply from PM");
#endif

    candidate_list = calloc(1, sizeof(*candidate_list));
    assert(candidate_list);
    TAILQ_INIT(candidate_list);

    build_he_candidates(ctx, flow, json, candidate_list);

    struct neat_he_candidate *candidate;
    TAILQ_FOREACH(candidate, candidate_list, next) {
        struct sockaddr *sa = (struct sockaddr*) &candidate->pollable_socket->src_sockaddr;
        struct sockaddr *da = (struct sockaddr*) &candidate->pollable_socket->dst_sockaddr;

        assert(da->sa_family == AF_INET || da->sa_family == AF_INET6);
        assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);

        assert(candidate->pollable_socket->dst_address);
        assert(candidate->pollable_socket->src_address);
        assert(candidate->if_idx);
        assert(candidate->if_name);
        assert(candidate->pollable_socket->family == AF_INET ||
               candidate->pollable_socket->family == AF_INET6);
    }

    json_decref(json);

    neat_he_open(ctx, flow, candidate_list, he_connected_cb);
}

static void
on_candidates_resolved(neat_ctx *ctx, neat_flow *flow, struct neat_he_candidates *candidate_list)
{
    int rc;
    const char *home_dir;
    const char *socket_path;
    char socket_path_buf[128];
    struct neat_he_candidate *candidate, *tmp;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    // Now that the names in the list are resolved, append the new data to the
    // json objects and perform a new call to the PM

    json_t *array = json_array();

    TAILQ_FOREACH_SAFE(candidate, candidate_list, next, tmp) {
        json_t *dst_address, *str;

        if (candidate->if_idx == 0) {
            // neat_log(NEAT_LOG_DEBUG, "Removing...");
            continue;
        }

        // neat_log(NEAT_LOG_DEBUG, "%s %s", json_string_value(get_property(candidate->properties, "transport", JSON_STRING)), candidate->pollable_socket->dst_address);

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
        neat_log(NEAT_LOG_DEBUG, "No usable candidates after name resolution");
        neat_io_error(ctx, flow, NEAT_ERROR_UNABLE);
        return;
    }

    neat_free_candidates(candidate_list);

#if 0
    neat_log(NEAT_LOG_DEBUG, "Sending post-resolve properties to PM\n%s\n", buffer);
#else

    socket_path = getenv("NEAT_PM_SOCKET");
    if (!socket_path) {
        if ((home_dir = getenv("HOME")) == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Unable to locate the $HOME directory");
            neat_io_error(ctx, flow, NEAT_ERROR_INTERNAL);
            return;
        }

        rc = snprintf(socket_path_buf, 128, "%s/.neat/neat_pm_socket", home_dir);
        if (rc < 0 || rc >= 128) {
            neat_log(NEAT_LOG_DEBUG, "Unable to construct default path to PM socket");
            neat_io_error(ctx, flow, NEAT_ERROR_INTERNAL);
            return;
        }

        socket_path = socket_path_buf;
    }

    neat_log(NEAT_LOG_DEBUG, "Sending post-resolve properties to PM");
    // buffer is freed by the PM interface
    neat_json_send_once(flow->ctx, flow, socket_path, array, on_pm_reply_post_resolve, on_pm_error);
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
    struct neat_he_candidate *candidate, *tmp;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (code == NEAT_RESOLVER_TIMEOUT)  {
        *data->status = -1;
        // neat_io_error(flow->ctx, flow, NEAT_ERROR_IO);
        neat_log(NEAT_LOG_DEBUG, "Resolution timed out");
    } else if ( code == NEAT_RESOLVER_ERROR ) {
        *data->status = -1;
        // neat_io_error(flow->ctx, flow, NEAT_ERROR_IO);
        neat_log(NEAT_LOG_DEBUG, "Resolver error");
    }

    LIST_FOREACH(result, results, next_res) {
        char ifname1[IF_NAMESIZE];
        char ifname2[IF_NAMESIZE];

        if ((rc = getnameinfo((struct sockaddr*)&result->dst_addr, result->dst_addr_len, namebuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
            neat_log(NEAT_LOG_DEBUG, "getnameinfo error");
            continue;
        }

        TAILQ_FOREACH_SAFE(candidate, &data->resolution_group, resolution_list, tmp) {

            // The interface index must be the same as the interface index of the candidate
            if (result->if_idx != candidate->if_idx) {
                neat_log(NEAT_LOG_DEBUG, "Interface did not match, %s [%d] != %s [%d]", if_indextoname(result->if_idx, ifname1), result->if_idx, if_indextoname(candidate->if_idx, ifname2), candidate->if_idx);
                continue;
            }

            // TODO: Move inet_pton out of the loop
            if (result->ai_family == AF_INET && inet_pton(AF_INET6, candidate->pollable_socket->src_address, &dummy) == 1) {
                neat_log(NEAT_LOG_DEBUG, "Address family did not match");
                continue;
            }

            // TODO: Move inet_pton out of the loop
            if (result->ai_family == AF_INET6 && inet_pton(AF_INET, candidate->pollable_socket->src_address, &dummy) == 1) {
                neat_log(NEAT_LOG_DEBUG, "Address family did not match");
                continue;
            }

            // dst_address was strdup'd in on_pm_reply_pre_resolve, free it
            free(candidate->pollable_socket->dst_address);

            if ((candidate->pollable_socket->dst_address = strdup(namebuf)) != NULL) {
                neat_log(NEAT_LOG_DEBUG, "%s -> %s", candidate->pollable_socket->src_address, namebuf);
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

    neat_resolver_free_results(results);

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
neat_resolve_candidates(neat_ctx *ctx, neat_flow *flow,
                        struct neat_he_candidates *candidate_list)
{
    int *remaining, *status = NULL;
    struct neat_he_candidate *candidate;
    struct candidate_resolver_data *resolver_data, *tmp;

    TAILQ_HEAD(resolution_group_list, candidate_resolver_data) resolutions;
    TAILQ_INIT(&resolutions);

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    assert(candidate_list);

    if (TAILQ_EMPTY(candidate_list)) {
        neat_log(NEAT_LOG_WARNING, "neat_resolve_candidates called with an empty candidate list");
        return;
    }

    if ((remaining = calloc(1, sizeof(*remaining))) == NULL)
        goto error;
    if ((status = calloc(1, sizeof(*status))) == NULL)
        goto error;

    *status = 0;

    // TODO: Should this have been allocated before this point?
    if (!ctx->resolver)
        ctx->resolver = neat_resolver_init(ctx, "/etc/resolv.conf");

    if (!ctx->pvd)
        ctx->pvd = neat_pvd_init(ctx);

    TAILQ_FOREACH(candidate, candidate_list, next) {
        struct candidate_resolver_data *existing_resolution;

        TAILQ_FOREACH(existing_resolution, &resolutions, next) {
            // neat_log(NEAT_LOG_DEBUG, "%s - %s", existing_resolution->domain_name, candidate->pollable_socket->dst_address);

            if (strcmp(existing_resolution->domain_name, candidate->pollable_socket->dst_address) != 0)
                continue;

            if (existing_resolution->port != candidate->pollable_socket->port)
                continue;

            // TODO: Split on ipv4/ipv6/no preference

            neat_log(NEAT_LOG_DEBUG, "Adding candidate to existing resolution group for %s:%u",
                     existing_resolution->domain_name, existing_resolution->port);

            TAILQ_INSERT_TAIL(&existing_resolution->resolution_group, candidate, resolution_list);

            goto next_candidate;
        }

        if ((resolver_data = malloc(sizeof(*resolver_data))) == NULL)
            goto error;

        resolver_data->port = candidate->pollable_socket->port;
        resolver_data->domain_name = candidate->pollable_socket->dst_address;

        resolver_data->candidate_list = candidate_list;
        TAILQ_INIT(&resolver_data->resolution_group);
        resolver_data->flow = flow;

        resolver_data->status = status;
        resolver_data->remaining = remaining;
        (*remaining)++;

        neat_log(NEAT_LOG_DEBUG, "Creating new resolution group for %s:%u", resolver_data->domain_name, resolver_data->port);
        TAILQ_INSERT_TAIL(&resolver_data->resolution_group, candidate, resolution_list);
        TAILQ_INSERT_TAIL(&resolutions, resolver_data, next);
next_candidate:
        continue;
    }

    struct candidate_resolver_data *resolution;
    TAILQ_FOREACH(resolution, &resolutions, next) {
        neat_resolve(ctx->resolver, AF_UNSPEC, resolution->domain_name,
                     resolution->port, on_candidate_resolved, resolution);
    }

    return;
error:
    TAILQ_FOREACH_SAFE(resolver_data, &resolutions, next, tmp) {
        free(resolver_data);
    }

    neat_free_candidates(candidate_list);

    if (remaining)
        free(remaining);
    if (status)
        free(status);
    neat_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
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

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        neat_io_error(ctx, flow, code);
        return NEAT_ERROR_INTERNAL;
    }

    // Find the enabled stacks based on the properties
    // nr_of_stacks = neat_property_translate_protocols(flow->propertyAttempt, stacks);
    neat_find_enabled_stacks(flow->properties, stacks, &nr_of_stacks, NULL);
    assert(nr_of_stacks);
    assert(results);

    flow->resolver_results = results;

    candidates = calloc(1, sizeof(*candidates));

    if (!candidates) {
        neat_io_error(ctx, flow, NEAT_ERROR_OUT_OF_MEMORY);
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

        if (iface_name == NULL)
            continue;

        rc = getnameinfo((struct sockaddr *)&result->dst_addr,
                         result->dst_addr_len,
                         dst_buffer, sizeof(dst_buffer), NULL, 0, NI_NUMERICHOST);

        if (rc != 0) {
            neat_log(NEAT_LOG_DEBUG, "getnameinfo() failed: %s\n",
                     gai_strerror(rc));
            continue;
        }

        rc = getnameinfo((struct sockaddr *)&result->src_addr,
                         result->src_addr_len,
                         src_buffer, sizeof(src_buffer), NULL, 0, NI_NUMERICHOST);

        if (rc != 0) {
            neat_log(NEAT_LOG_DEBUG, "getnameinfo() failed: %s\n",
                     gai_strerror(rc));
            continue;
        }

        for (unsigned int i = 0; i < nr_of_stacks; ++i) {
            // struct neat_he_candidate *tmp;

            struct neat_he_candidate *candidate = calloc(1, sizeof(*candidate));
            assert(candidate);
            candidate->pollable_socket = malloc(sizeof(struct neat_pollable_socket));
            assert(candidate->pollable_socket);


            // This ensures we use only one address from each address family for
            // each interface to reduce the number of candidates.
            // TAILQ_FOREACH(tmp, candidates, next) {
            //     if (tmp->if_idx == result->if_idx && tmp->pollable_socket->family == result->ai_family)
            //         goto skip;
            // }
            candidate->if_name                      = strdup(iface);
            candidate->if_idx                       = result->if_idx;
            candidate->priority = prio++;

            candidate->pollable_socket->family      = result->ai_family;
            candidate->pollable_socket->src_address = strdup(src_buffer);
            candidate->pollable_socket->dst_address = strdup(dst_buffer);
            candidate->pollable_socket->port        = flow->port;
            candidate->pollable_socket->stack = stacks[i];
            candidate->pollable_socket->dst_len     = result->src_addr_len;
            candidate->pollable_socket->src_len     = result->dst_addr_len;

            // assert(candidate->if_name);
            // assert(candidate->pollable_socket->src_address);

            memcpy(&candidate->pollable_socket->src_sockaddr, &result->src_addr, result->src_addr_len);
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

    neat_he_open(ctx, flow, candidates, he_connected_cb);

    return NEAT_OK;
}

static void
on_pm_error(struct neat_ctx *ctx, struct neat_flow *flow, int error)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    switch (error) {
        case PM_ERROR_SOCKET_UNAVAILABLE:
        case PM_ERROR_SOCKET:
        case PM_ERROR_INVALID_JSON:
            neat_log(NEAT_LOG_DEBUG, "===== Unable to communicate with PM, using fallback =====");
            neat_resolve(ctx->resolver, AF_UNSPEC, flow->name, flow->port,
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
on_pm_reply_pre_resolve(struct neat_ctx *ctx, struct neat_flow *flow, json_t *json)
{
    int rc = NEAT_OK;
    size_t i;
    json_t *value;
    struct neat_he_candidates *candidate_list;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#if 0
    char *str = json_dumps(json, JSON_INDENT(2));
    neat_log(NEAT_LOG_DEBUG, "Reply from PM was: %s", str);
    free(str);
#else
    neat_log(NEAT_LOG_DEBUG, "Received reply from PM");
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
            neat_log(NEAT_LOG_DEBUG, "Unknown interface %s", candidate->if_name);
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
            if (candidate->pollable_socket->src_address)
                free(candidate->pollable_socket->src_address);
            if (candidate->pollable_socket->dst_address)
                free(candidate->pollable_socket->dst_address);
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
        neat_log(NEAT_LOG_DEBUG, "%s %s", json_string_value(get_property(tmp->properties, "transport", JSON_STRING)), tmp->pollable_socket->dst_address);
    }

    // Deallocation test
    neat_free_candidates(candidate_list);
    neat_free_ctx(ctx);
    exit(0);
#endif

    neat_resolve_candidates(ctx, flow, candidate_list);

    return;
error:
    json_decref(json);
    neat_free_candidates(candidate_list);

    neat_io_error(ctx, flow, rc);
}

static void
send_properties_to_pm(neat_ctx *ctx, neat_flow *flow)
{
    int rc = NEAT_ERROR_OUT_OF_MEMORY;
    struct ifaddrs *ifaddrs = NULL;
    json_t *array = NULL, *endpoints = NULL, *properties = NULL, *address, *port;
    const char *home_dir;
    const char *socket_path;
    char socket_path_buf[128];

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    socket_path = getenv("NEAT_PM_SOCKET");
    if (!socket_path) {
        if ((home_dir = getenv("HOME")) == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Unable to locate the $HOME directory");

            goto end;
        }

        rc = snprintf(socket_path_buf, 128, "%s/.neat/neat_pm_socket", home_dir);
        if (rc < 0 || rc >= 128) {
            neat_log(NEAT_LOG_DEBUG, "Unable to construct default path to PM socket");
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
        neat_log(NEAT_LOG_DEBUG, "getifaddrs: %s", strerror(errno));
        goto end;
    }

    for (struct ifaddrs *ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        socklen_t addrlen;
        char namebuf[NI_MAXHOST];
        json_t *endpoint;

        // Doesn't actually contain any address (?)
        if (ifaddr->ifa_addr == NULL) {
            neat_log(NEAT_LOG_DEBUG, "ifaddr entry with no address");
            continue;
        }

        if (ifaddr->ifa_addr->sa_family != AF_INET &&
            ifaddr->ifa_addr->sa_family != AF_INET6)
            continue;

        addrlen = (ifaddr->ifa_addr->sa_family) == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

        rc = getnameinfo(ifaddr->ifa_addr, addrlen, namebuf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if (rc != 0) {
            neat_log(NEAT_LOG_DEBUG, "getnameinfo: %s", gai_strerror(rc));
            continue;
        }

        if (strncmp(namebuf, "fe80::", 6) == 0) {
            neat_log(NEAT_LOG_DEBUG, "%s is a link-local address, skipping", namebuf);
            continue;
        }

        endpoint = json_pack("{ss++si}", "value", namebuf, "@", ifaddr->ifa_name, "precedence", 1);

        if (endpoint == NULL)
            goto end;

        neat_log(NEAT_LOG_DEBUG, "Added endpoint \"%s@%s\" to PM request", namebuf, ifaddr->ifa_name);
        json_array_append(endpoints, endpoint);
        json_decref(endpoint);
    }

    properties = json_copy(flow->properties);

    json_object_set(properties, "local_endpoint", endpoints);

    port = json_pack("{sisi}", "value", flow->port, "precedence", 1);
    if (port == NULL)
        goto end;

    json_object_set(properties, "port", port);
    json_decref(port);

    address = json_pack("{sssi}", "value", flow->name, "precedence", 1);
    if (address == NULL)
        goto end;

    json_object_set(properties, "domain_name", address);
    json_decref(address);

    json_array_append(array, properties);

    neat_json_send_once(ctx, flow, socket_path, array, on_pm_reply_pre_resolve, on_pm_error);

end:
    if (ifaddrs)
        freeifaddrs(ifaddrs);
    if (properties)
        json_decref(properties);
    if (endpoints)
        json_decref(endpoints);
    if (array)
        json_decref(array);

    if (rc != NEAT_OK)
        neat_io_error(ctx, flow, rc);
}

neat_error_code
neat_open(neat_ctx *mgr, neat_flow *flow, const char *name, uint16_t port,
          struct neat_tlv optional[], unsigned int opt_count)
{
    int stream_count = 1;
    int group = 0;
    float priority = 0.5f;
    const char *cc_algorithm = NULL;
    // const char *local_name = NULL;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->name) {
        neat_log(NEAT_LOG_ERROR, "Flow appears to already be open");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    HANDLE_OPTIONAL_ARGUMENTS_START()
        OPTIONAL_INTEGER(NEAT_TAG_STREAM_COUNT, stream_count)
        OPTIONAL_INTEGER(NEAT_TAG_FLOW_GROUP, group)
        OPTIONAL_FLOAT(NEAT_TAG_PRIORITY, priority)
        OPTIONAL_STRING(NEAT_TAG_CC_ALGORITHM, cc_algorithm)
        // OPTIONAL_STRING(NEAT_TAG_LOCAL_NAME, local_name)
    HANDLE_OPTIONAL_ARGUMENTS_END();

    if (stream_count < 1) {
        neat_log(NEAT_LOG_ERROR, "Stream count must be 1 or more");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    neat_log(NEAT_LOG_DEBUG, "%s - %d streams", __func__, stream_count);

    if (priority > 1.0f || priority < 0.1f) {
        neat_log(NEAT_LOG_ERROR, "Priority must be between 0.1 and 1.0");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    flow->name = strdup(name);
    if (flow->name == NULL)
        return NEAT_ERROR_OUT_OF_MEMORY;
    flow->port = port;
    flow->propertyAttempt = flow->propertyMask;
    flow->stream_count = stream_count;
    flow->ctx = mgr;
    flow->group = group;
    flow->priority = priority;

    if (!mgr->resolver)
        mgr->resolver = neat_resolver_init(mgr, "/etc/resolv.conf");

    if (!mgr->pvd)
        mgr->pvd = neat_pvd_init(mgr);

    if (cc_algorithm) {
        flow->cc_algorithm = strdup(cc_algorithm);
        if (flow->cc_algorithm == NULL) {
            return NEAT_ERROR_OUT_OF_MEMORY;
        }
    }

#if 1
    send_properties_to_pm(mgr, flow);
#else
    // TODO: Add name resolution call
    neat_resolve(mgr->resolver, AF_UNSPEC, flow->name, flow->port,
                 open_resolve_cb, flow);
    // TODO: Generate candidates
    // TODO: Call HE
    // return neat_he_lookup(mgr, flow, he_connected_cb);
#endif
    return NEAT_OK;
}

neat_error_code
neat_change_timeout(neat_ctx *mgr, neat_flow *flow, unsigned int seconds)
{
#if defined(TCP_USER_TIMEOUT)
    unsigned int timeout_msec;
    int rc;
#endif

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#if defined(TCP_USER_TIMEOUT)
    if (neat_base_stack(flow->socket->stack) != NEAT_STACK_TCP)
#endif
    {
        neat_log(NEAT_LOG_DEBUG, "Timeout is supported on Linux TCP only");
        return NEAT_ERROR_UNABLE;
    }

#if defined(TCP_USER_TIMEOUT)
    if (flow->socket->fd == -1) {
        neat_log(NEAT_LOG_WARNING,
                 "Unable to change timeout for TCP socket: "
                 "Invalid socket value");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    if (seconds > UINT_MAX - 1000) {
        neat_log(NEAT_LOG_DEBUG, "Timeout value too large");
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    timeout_msec = seconds * 1000;

    rc = setsockopt(flow->socket->fd,
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

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        neat_io_error(ctx, flow, code);
        return NEAT_ERROR_DNS;
    }

    if (results->lh_first == NULL) {
        neat_io_error(ctx, flow, NEAT_ERROR_UNABLE);
        return NEAT_ERROR_UNABLE;
    }

#ifdef USRSCTP_SUPPORT
    addr.ssp_addr = results->lh_first->dst_addr;

    if (usrsctp_setsockopt(flow->socket->usrsctp_socket, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, &addr, sizeof(addr)) < 0) {
        neat_log(NEAT_LOG_DEBUG, "Call to usrsctp_setsockopt failed");
        return NEAT_ERROR_IO;
    }
#elif defined(HAVE_NETINET_SCTP_H)
    addr.ssp_addr = results->lh_first->dst_addr;

    rc = setsockopt(flow->socket->fd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR, &addr, sizeof(addr));
    if (rc < 0) {
        neat_log(NEAT_LOG_DEBUG, "Call to setsockopt failed");
        return NEAT_ERROR_IO;
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
    return NEAT_ERROR_OK;
}

neat_error_code
neat_set_primary_dest(struct neat_ctx *ctx, struct neat_flow *flow, const char *name)
{
    int8_t literal;
    uint8_t family = AF_UNSPEC;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
        literal = neat_resolver_helpers_check_for_literal(&family, name);

        if (literal != 1) {
            neat_log(NEAT_LOG_ERROR, "%s: provided name '%s' is not an address literal.\n",
                 __func__, name);
            return NEAT_ERROR_BAD_ARGUMENT;
        }

            neat_resolve(ctx->resolver, AF_UNSPEC, name, flow->port,
                         set_primary_dest_resolve_cb, flow);

            return NEAT_ERROR_OK;
    }

    return NEAT_ERROR_UNABLE;
}

neat_error_code
neat_request_capacity(struct neat_ctx *ctx, struct neat_flow *flow, int rate, int seconds)
{
    return NEAT_ERROR_UNABLE;
}

neat_error_code
neat_set_checksum_coverage(struct neat_ctx *ctx, struct neat_flow *flow, unsigned int send_coverage, unsigned int receive_coverage)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    switch (neat_base_stack(flow->socket->stack)) {
    case NEAT_STACK_UDP:
        {
#if defined(__linux__) && defined(SO_NO_CHECK)
            // Enable udp checksum if receive_coverage is non-zero
            // send_coverage is ignored in this case
            const int state = receive_coverage ? 1 : 0;

            if (setsockopt(flow->socket->fd, SOL_SOCKET, SO_NO_CHECK, &state, sizeof(state)) < 0) {
                neat_log(NEAT_LOG_DEBUG, "Unable to set SO_NO_CHECK to %d", state);
                return NEAT_ERROR_UNABLE;
            }

            return NEAT_OK;
#else
            neat_log(NEAT_LOG_DEBUG, "Disabling UDP checksum not supported");
            return NEAT_ERROR_UNABLE;
#endif
        }
    case NEAT_STACK_UDPLITE:
        {
#if defined(UDPLITE_SEND_CSCOV) && defined(UDPLITE_RECV_CSCOV)
        if (setsockopt(flow->socket->fd, IPPROTO_UDPLITE, UDPLITE_SEND_CSCOV, &send_coverage, sizeof(unsigned int)) < 0) {
            neat_log(NEAT_LOG_DEBUG, "Failed to set UDP-Lite send checksum coverage");
            return NEAT_ERROR_UNABLE;
        }

        if (setsockopt(flow->socket->fd, IPPROTO_UDPLITE, UDPLITE_RECV_CSCOV, &receive_coverage, sizeof(unsigned int)) < 0) {
            neat_log(NEAT_LOG_DEBUG, "Failed to set UDP-Lite receive checksum coverage");
            return NEAT_ERROR_UNABLE;
        }

        return NEAT_OK;
#else
        neat_log(NEAT_LOG_DEBUG, "Failed to set UDP-Lite checksum coverage, not supported");
        return NEAT_ERROR_UNABLE;
#endif
        }
    default:
        break;
    }

    neat_log(NEAT_LOG_DEBUG, "Failed to set checksum coverage, protocol not supported");
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
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (code != NEAT_RESOLVER_OK) {
        neat_io_error(ctx, flow, code);
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
    // nr_of_stacks = neat_property_translate_protocols(flow->propertyAttempt, stacks);
    json_t *empty_obj = json_object();
    if (json_equal(flow->properties, empty_obj)) {
        // No properties specified, listen to all available protocols
        neat_log(NEAT_LOG_DEBUG, "No properties specifying protocols to listen for");
        neat_log(NEAT_LOG_DEBUG, "Listening to all protocols...");

        nr_of_stacks = 0;
        stacks[nr_of_stacks++] = NEAT_STACK_UDP;
        stacks[nr_of_stacks++] = NEAT_STACK_UDPLITE;
        stacks[nr_of_stacks++] = NEAT_STACK_TCP;
        stacks[nr_of_stacks++] = NEAT_STACK_SCTP;
        stacks[nr_of_stacks++] = NEAT_STACK_SCTP_UDP;
    } else {
        neat_find_enabled_stacks(flow->properties, stacks, &nr_of_stacks, NULL);
    }
    json_decref(empty_obj);
    assert(nr_of_stacks > 0);

    flow->resolver_results = results;

    flow->isPolling = 1;
    flow->acceptPending = 1;

    struct sockaddr *sockaddr = (struct sockaddr *) &(results->lh_first->dst_addr);

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
            neat_log(NEAT_LOG_DEBUG, "UDPLite not supported on this platform");
            continue;
#endif
        }

#ifdef USRSCTP_SUPPORT
        if (stacks[i] != NEAT_STACK_SCTP) {
            fd = neat_listen_via_kernel(ctx, flow, stacks[i],
                                           sockaddr,
                                           results->lh_first->ai_family,
                                           socket_type);

            if (fd == -1) {
                continue;
            }
            listen_socket = malloc(sizeof(*listen_socket));

            listen_socket->flow = flow;
            listen_socket->stack = neat_base_stack(stacks[i]);
            listen_socket->family = results->lh_first->ai_family;
            listen_socket->type = socket_type;

            memcpy(&listen_socket->srcAddr, (struct sockaddr *) &(results->lh_first->dst_addr), sizeof(struct sockaddr));
            memset(&listen_socket->dstAddr, 0, sizeof(struct sockaddr));
        } else {
            listen_socket = malloc(sizeof(*listen_socket));
            assert(listen_socket);

            listen_socket->flow = flow;
            listen_socket->stack = neat_base_stack(stacks[i]);
            listen_socket->family = results->lh_first->ai_family;
            listen_socket->type = socket_type;

            memcpy(&listen_socket->srcAddr, (struct sockaddr *) &(results->lh_first->dst_addr), sizeof(struct sockaddr));
            memset(&listen_socket->dstAddr, 0, sizeof(struct sockaddr));

            if (neat_listen_via_usrsctp(ctx, flow, listen_socket) != 0) {
                free(listen_socket);
                continue;
            }
            fd = -1;
        }
#else
        fd = neat_listen_via_kernel(ctx, flow, stacks[i],
                                       sockaddr,
                                       results->lh_first->ai_family,
                                       socket_type);

        if (fd == -1) {
            continue;
        }

        listen_socket = malloc(sizeof(*listen_socket));
        assert(listen_socket);

        listen_socket->flow = flow;
        listen_socket->stack = neat_base_stack(stacks[i]);
        listen_socket->family = results->lh_first->ai_family;
        listen_socket->type = socket_type;

        memcpy(&listen_socket->srcAddr, (struct sockaddr *) &(results->lh_first->dst_addr), sizeof(struct sockaddr));
        memset(&listen_socket->dstAddr, 0, sizeof(struct sockaddr));
#endif
        listen_socket->fd = fd;

        handle = malloc(sizeof(*handle));
        assert(handle);
        listen_socket->handle = handle;
        handle->data = listen_socket;

        if (stacks[i] == NEAT_STACK_SCTP)
            sctp_socket = listen_socket;

        if (listen_socket->fd != -1) { // fd == -1 => USRSCTP
            uv_poll_init(ctx->loop, handle, fd);

            TAILQ_INSERT_TAIL(&flow->listen_sockets, listen_socket, next);

            if ((neat_base_stack(stacks[i]) == NEAT_STACK_SCTP) ||
                (neat_base_stack(stacks[i]) == NEAT_STACK_UDP) ||
                (neat_base_stack(stacks[i]) == NEAT_STACK_UDPLITE) ||
                (neat_base_stack(stacks[i]) == NEAT_STACK_TCP)) {
                uv_poll_start(handle, UV_READABLE, uvpollable_cb);
            } else {
                // do normal i/o events without accept() for non connected protocols
                updatePollHandle(ctx, flow, handle);
            }
        } else {
            flow->acceptPending = 1;
        }

        socket_count++;
    }

    if (socket_count == 0) {
        neat_io_error(ctx, flow, NEAT_ERROR_IO);
        return NEAT_ERROR_IO;
    }

#ifdef USRSCTP_SUPPORT
    if (sctp_udp_encaps && sctp_socket) {
        struct sctp_udpencaps encaps;
        memset(&encaps, 0, sizeof(struct sctp_udpencaps));

        encaps.sue_address.ss_family = AF_INET;
        encaps.sue_port              = htons(SCTP_UDP_TUNNELING_PORT);

        if (usrsctp_setsockopt(sctp_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) != 0) {
            neat_log(NEAT_LOG_DEBUG, "Unable to set UDP encapsulation port");
        }
    }
#else // ifdef USRSCTP_SUPPORT
#if defined(__FreeBSD__)
    // Enable SCTP/UDP encaps if specified
    if (sctp_udp_encaps && sctp_socket) {
        struct sctp_udpencaps encaps;
        memset(&encaps, 0, sizeof(struct sctp_udpencaps));

        encaps.sue_address.ss_family = sctp_socket->family;
        encaps.sue_port              = htons(SCTP_UDP_TUNNELING_PORT);

        if (setsockopt(sctp_socket->fd, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT,
                       (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) != 0) {
            neat_log(NEAT_LOG_DEBUG, "Unable to set UDP encapsulation port");
        }
    }

#else // if defined(__FreeBSD__)
    if (sctp_udp_encaps && sctp_socket) {
        neat_log(NEAT_LOG_DEBUG, "SCTP/UDP encapsulation not available");
    }
#endif // if defined(__FreeBSD__)
#endif // ifdef else USRSCTP_SUPPORT
    return NEAT_ERROR_OK;
}

neat_error_code neat_accept(struct neat_ctx *ctx, struct neat_flow *flow,
                            uint16_t port, struct neat_tlv optional[], unsigned int opt_count)
{
    // const char *service_name = NULL;
    const char *local_name = NULL;
    neat_protocol_stack_type stacks[NEAT_STACK_MAX_NUM]; /* We only support SCTP, TCP, UDP, and UDPLite */
    uint8_t nr_of_stacks;
    int stream_count = 1;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    nr_of_stacks = neat_property_translate_protocols(flow->propertyMask, stacks);

    if (nr_of_stacks == 0)
        return NEAT_ERROR_UNABLE;

    if (flow->name)
        return NEAT_ERROR_BAD_ARGUMENT;

    HANDLE_OPTIONAL_ARGUMENTS_START()
        OPTIONAL_STRING(NEAT_TAG_LOCAL_NAME, local_name)
        OPTIONAL_INTEGER(NEAT_TAG_STREAM_COUNT, stream_count)
        // OPTIONAL_STRING(NEAT_TAG_SERVICE_NAME, service_name)
    HANDLE_OPTIONAL_ARGUMENTS_END();

    if (stream_count < 1) {
        neat_log(NEAT_LOG_ERROR, "Stream count must be 1 or more");
        return NEAT_ERROR_BAD_ARGUMENT;
    }
    flow->stream_count = stream_count;
    neat_log(NEAT_LOG_DEBUG, "%s - %d streams", __func__, flow->stream_count);

    if (!local_name)
        local_name = "0.0.0.0";

    flow->name = strdup(local_name);
    if (flow->name == NULL) {
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    flow->port = port;
    flow->propertyAttempt = flow->propertyMask;
    flow->ctx = ctx;

    if (!ctx->resolver)
        ctx->resolver = neat_resolver_init(ctx, "/etc/resolv.conf");

    if (!ctx->pvd)
        ctx->pvd = neat_pvd_init(ctx);

    neat_resolve(ctx->resolver, AF_INET, flow->name, flow->port,
                 accept_resolve_cb, flow);
    return NEAT_OK;
}

static neat_error_code
neat_write_flush(struct neat_ctx *ctx, struct neat_flow *flow)
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

    if (TAILQ_EMPTY(&flow->bufferedMessages)) {
        return NEAT_OK;
    }
    TAILQ_FOREACH_SAFE(msg, &flow->bufferedMessages, message_next, next_msg) {
        do {
            iov.iov_base = msg->buffered + msg->bufferedOffset;
            if ((neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) &&
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

            if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
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
                sndrcvinfo->sinfo_stream = msg->stream_id;
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
            if (flow->socket->fd != -1) {
                rv = sendmsg(flow->socket->fd, (const struct msghdr *)&msghdr, 0);
            }
            else {
#if defined(USRSCTP_SUPPORT)
                rv = usrsctp_sendv(flow->socket->usrsctp_socket, msg->buffered + msg->bufferedOffset, msg->bufferedSize,
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

    if ((flow->socket->stack != NEAT_STACK_TCP) || TAILQ_EMPTY(&flow->bufferedMessages)) {
        msg = malloc(sizeof(struct neat_buffered_message));
        if (msg == NULL) {
            return NEAT_ERROR_OUT_OF_MEMORY;
        }
        msg->buffered = NULL;
        msg->bufferedOffset = 0;
        msg->bufferedSize = 0;
        msg->bufferedAllocation= 0;
        msg->stream_id = stream_id;
        TAILQ_INSERT_TAIL(&flow->bufferedMessages, msg, message_next);
    } else {
        assert(stream_id == 0);
        msg = TAILQ_LAST(&flow->bufferedMessages, neat_message_queue_head);
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
neat_write_to_lower_layer(struct neat_ctx *ctx, struct neat_flow *flow,
                      const unsigned char *buffer, uint32_t amt,
                      struct neat_tlv optional[], unsigned int opt_count)
{
    ssize_t rv = 0;
    size_t len;
    int atomic;

    int stream_id            = 0;
    int has_stream_id        = 0;
    // int has_context       = 0;
    // int context           = 0;
    // int has_pr_method     = 0;
    // int pr_method         = 0;
    // int has_pr_value      = 0;
    // int pr_value          = 0;
    // int has_unordered     = 0;
    // int unordered         = 0;
    // int has_priority      = 0;
    // float priority        = 0.5f;
    // int has_dest_addr     = 0;
    // const char *dest_addr = "";

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

    HANDLE_OPTIONAL_ARGUMENTS_START()
        OPTIONAL_INTEGER_PRESENT(NEAT_TAG_STREAM_ID, stream_id, has_stream_id)
        // OPTIONAL_INTEGER_PRESENT(NEAT_TAG_CONTEXT, context, has_context)
        // OPTIONAL_INTEGER_PRESENT(NEAT_TAG_PARTIAL_RELIABILITY_METHOD, pr_method, has_pr_method)
        // OPTIONAL_INTEGER_PRESENT(NEAT_TAG_PARTIAL_RELIABILITY_VALUE, pr_value, has_pr_value)
        // OPTIONAL_INTEGER_PRESENT(NEAT_TAG_UNORDERED, unordered, has_unordered)
        // OPTIONAL_FLOAT_PRESENT(  NEAT_TAG_PRIORITY, priority, has_priority)
        // OPTIONAL_STRING_PRESENT( NEAT_TAG_DESTINATION_IP_ADDRESS, dest_addr, has_dest_addr)
    HANDLE_OPTIONAL_ARGUMENTS_END();

    if (has_stream_id && stream_id < 0) {
        neat_log(NEAT_LOG_DEBUG, "Invalid stream id: Must be 0 or greater");
        return NEAT_ERROR_BAD_ARGUMENT;
    } else if (has_stream_id && flow->stream_count == 1 && stream_id != 0) {
        neat_log(NEAT_LOG_DEBUG,
                 "Tried to specify stream id when only a single stream "
                 "is in use. Ignoring.");
        stream_id = 0;
    } else if (has_stream_id && flow->socket->stack != NEAT_STACK_SCTP) {
        // For now, warn about this. Maybe we emulate multistreaming over TCP in
        // the future?
        neat_log(NEAT_LOG_DEBUG,
                 "Tried to specify stream id when using a protocol which does "
                 "not support multistreaming. Ignoring.");
        stream_id = 0;
    }

    switch (flow->socket->stack) {
    case NEAT_STACK_TCP:
        atomic = 0;
        break;
    case NEAT_STACK_SCTP_UDP:
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
    neat_error_code code = neat_write_flush(ctx, flow);
    if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
        return code;
    }
    if (TAILQ_EMPTY(&flow->bufferedMessages) && code == NEAT_OK && amt > 0) {
        iov.iov_base = (void *)buffer;
        if ((neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) &&
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

        if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP) {
#if defined(SCTP_SNDINFO)
            msghdr.msg_control = cmsgbuf;
            msghdr.msg_controllen = CMSG_SPACE(sizeof(struct sctp_sndinfo));
            cmsg = (struct cmsghdr *)cmsgbuf;
            cmsg->cmsg_level = IPPROTO_SCTP;
            cmsg->cmsg_type = SCTP_SNDINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
            sndinfo = (struct sctp_sndinfo *)CMSG_DATA(cmsg);
            memset(sndinfo, 0, sizeof(struct sctp_sndinfo));

            if (stream_id) {
                sndinfo->snd_sid = stream_id;
            }

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

            if (stream_id) {
                sndrcvinfo->sinfo_stream = stream_id;
            }
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
        if (flow->socket->fd != -1) {
            rv = sendmsg(flow->socket->fd, (const struct msghdr *)&msghdr, 0);
        } else {
#if defined(USRSCTP_SUPPORT)
            rv = usrsctp_sendv(flow->socket->usrsctp_socket, buffer, len, NULL, 0,
                  (void *)sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO,
                  0);
#endif
        }
#ifdef IPPROTO_SCTP
        if (flow->socket->stack == NEAT_STACK_SCTP) {
            neat_log(NEAT_LOG_DEBUG, "%zd bytes sent on stream %d", rv, stream_id);
        } else {
            neat_log(NEAT_LOG_DEBUG, "%zd bytes sent", rv);
        }
#else
        neat_log(NEAT_LOG_DEBUG, "%zd bytes sent", rv);
#endif
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

    /* Update flow statistics with the sent bytes */
    flow->flow_stats.bytes_sent += rv;

    code = neat_write_fillbuffer(ctx, flow, buffer, amt, stream_id);
    if (code != NEAT_OK) {
        return code;
    }
    if (TAILQ_EMPTY(&flow->bufferedMessages)) {
        flow->isDraining = 0;
        io_all_written(ctx, flow, stream_id);
    } else {
        flow->isDraining = 1;
    }
#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP)
        return NEAT_OK;
#endif

    updatePollHandle(ctx, flow, flow->socket->handle);
    return NEAT_OK;
}

static neat_error_code
neat_read_from_lower_layer(struct neat_ctx *ctx, struct neat_flow *flow,
                     unsigned char *buffer, uint32_t amt, uint32_t *actualAmt,
                      struct neat_tlv optional[], unsigned int opt_count)
{
    int stream_id = 0;
    ssize_t rv;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    HANDLE_OPTIONAL_ARGUMENTS_START()
        SKIP_OPTARG(NEAT_TAG_STREAM_ID)
        SKIP_OPTARG(NEAT_TAG_PARTIAL_MESSAGE_RECEIVED)
        SKIP_OPTARG(NEAT_TAG_PARTIAL_SEQNUM)
        SKIP_OPTARG(NEAT_TAG_UNORDERED)
        SKIP_OPTARG(NEAT_TAG_UNORDERED_SEQNUM)
    HANDLE_OPTIONAL_ARGUMENTS_END();

    if ((neat_base_stack(flow->socket->stack) == NEAT_STACK_UDP) ||
        (neat_base_stack(flow->socket->stack) == NEAT_STACK_UDPLITE) ||
        (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP)) {
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
        goto end;
    }

    rv = recv(flow->socket->fd, buffer, amt, 0);
    neat_log(NEAT_LOG_DEBUG, "%s %d", __func__, rv);
    if (rv == -1 && errno == EWOULDBLOCK){
        neat_log(NEAT_LOG_DEBUG, "%s would block", __func__);
        return NEAT_ERROR_WOULD_BLOCK;
    }
    if (rv == -1) {
        if (errno == ECONNRESET) {
            neat_log(NEAT_LOG_ERROR, "%s: ECONNRESET", __func__);
            neat_notify_aborted(flow);
        } else {
            neat_log(NEAT_LOG_ERROR, "%s: err %d (%s)", __func__,
                     errno, strerror(errno));
        }
        return NEAT_ERROR_IO;
    }
    neat_log(NEAT_LOG_DEBUG, "%s %d", __func__, rv);
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
            default:
                break;
            }
        }
    }

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
        case NEAT_STACK_SCTP_UDP:
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
        case NEAT_STACK_SCTP_UDP:
            return NEAT_STACK_SCTP;
        default:
            return 0;
    }
}

static int
neat_connect(struct neat_he_candidate *candidate, uv_poll_cb callback_fx)
{
#if defined(__FreeBSD__) && defined(FLOW_GROUPS)
    int group;
    int prio;
#endif
#ifdef TCP_CONGESTION
    const char *algo;
#endif
    int enable = 1, retval;
    socklen_t len = 0;
    int size = 0, protocol;
#ifdef __linux__
    char if_name[IF_NAMESIZE];
#endif

    socklen_t slen =
            (candidate->pollable_socket->family == AF_INET) ?
                sizeof (struct sockaddr_in) :
                sizeof (struct sockaddr_in6);
    char addrsrcbuf[INET6_ADDRSTRLEN];
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(candidate->pollable_socket->stack) == NEAT_STACK_SCTP) {
        neat_connect_via_usrsctp(candidate);
    } else {
#endif
    protocol = neat_stack_to_protocol(neat_base_stack(candidate->pollable_socket->stack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", candidate->pollable_socket->stack);
        return -1;
    }
    if ((candidate->pollable_socket->fd =
                            socket(candidate->pollable_socket->family,
                                   candidate->pollable_socket->type,
                                   protocol)) < 0) {
        neat_log(NEAT_LOG_ERROR, "Failed to create he socket");
        return -1;
    }
	setsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	setsockopt(candidate->pollable_socket->fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int));

    if (candidate->pollable_socket->family == AF_INET) {
        inet_ntop(AF_INET, &(((struct sockaddr_in *) &(candidate->pollable_socket->src_sockaddr))->sin_addr), addrsrcbuf, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &(candidate->pollable_socket->src_sockaddr))->sin6_addr), addrsrcbuf, INET6_ADDRSTRLEN);
    }
    neat_log(NEAT_LOG_INFO, "%s: Bind fd %d to %s", __func__, candidate->pollable_socket->fd, addrsrcbuf);

    /* Bind to address + interface (if Linux) */
    if (bind(candidate->pollable_socket->fd,
             (struct sockaddr*) &(candidate->pollable_socket->src_sockaddr),
             candidate->pollable_socket->src_len)) {
        neat_log(NEAT_LOG_ERROR,
                 "Failed to bind fd %d socket to IP. Error: %s",
                 candidate->pollable_socket->fd,
                 strerror(errno));
        return -1;
    }

#ifdef __linux__
    if (if_indextoname(candidate->if_idx, if_name)) {
        if (setsockopt(candidate->pollable_socket->fd,
                       SOL_SOCKET,
                       SO_BINDTODEVICE,
                       if_name,
                       strlen(if_name)) < 0) {
            //Not a critical error
            neat_log(NEAT_LOG_WARNING,
                     "Could not bind fd %d socket to interface %s",
                     candidate->pollable_socket->fd, if_name);
        }
    }
#endif

    len = (socklen_t)sizeof(int);
    if (getsockopt(candidate->pollable_socket->fd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &size,
                   &len) == 0) {
        candidate->writeSize = size;
    } else {
        candidate->writeSize = 0;
    }
    len = (socklen_t)sizeof(int);
    if (getsockopt(candidate->pollable_socket->fd,
                   SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        candidate->readSize = size;
    } else {
        candidate->readSize = 0;
    }

    switch (candidate->pollable_socket->stack) {
    case NEAT_STACK_TCP:
        setsockopt(candidate->pollable_socket->fd,
                   IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));

#if defined(__FreeBSD__) && defined(FLOW_GROUPS)
        group = candidate->pollable_socket->flow->group;
        if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, 8192 /* Group ID */, &group, sizeof(int)) != 0) {
            neat_log(NEAT_LOG_DEBUG, "Unable to set flow group: %s", strerror(errno));
        }

        // Map the priority range to some integer range
        prio = candidate->pollable_socket->flow->priority * 255;
        if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, 4096 /* Priority */, &prio, sizeof(int)) != 0) {
            neat_log(NEAT_LOG_DEBUG, "Unable to set flow priority: %s", strerror(errno));
        }
#endif

#ifdef TCP_CONGESTION
        if (candidate->pollable_socket->flow->cc_algorithm) {
            algo = candidate->pollable_socket->flow->cc_algorithm;
            if (setsockopt(candidate->pollable_socket->fd, IPPROTO_TCP, TCP_CONGESTION, algo, strlen(algo)) != 0) {
                neat_log(NEAT_LOG_DEBUG, "Unable to set CC algorithm: %s", strerror(errno));
            }
        }
#endif
        break;
    case NEAT_STACK_SCTP_UDP:
#if defined(__FreeBSD__)
        {
            struct sctp_udpencaps encaps;
            memset(&encaps, 0, sizeof(struct sctp_udpencaps));
            encaps.sue_address.ss_family = AF_INET;
            encaps.sue_port = htons(SCTP_UDP_TUNNELING_PORT);
            setsockopt(candidate->pollable_socket->fd,
                       IPPROTO_SCTP,
                       SCTP_REMOTE_UDP_ENCAPS_PORT,
                       (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps));
        }
        // Fallthrough to case NEAT_STACK_SCTP:
#else
        return -1; // Unavailable on other platforms
#endif
    case NEAT_STACK_SCTP:
        candidate->writeLimit =  candidate->writeSize / 4;
#ifdef SCTP_NODELAY
        setsockopt(candidate->pollable_socket->fd,
                   IPPROTO_SCTP,
                   SCTP_NODELAY,
                   &enable,
                   sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
        if (setsockopt(candidate->pollable_socket->fd,
                       IPPROTO_SCTP,
                       SCTP_EXPLICIT_EOR,
                       &enable,
                       sizeof(int)) == 0)
            candidate->isSCTPExplicitEOR = 1;
#endif
#ifndef USRSCTP_SUPPORT
        // Subscribe to events needed for callbacks
        neat_sctp_init_events(candidate->pollable_socket->fd);
#endif
        break;
#if 0
    case NEAT_STACK_UDP:
        // This is something leftover from the oystedal/pm_interface branch.
        // Added here in case this really should be enabled after all.
        // Probably it's not needed.
        recvfrom(candidate->pollable_socket->fd, NULL, 0, MSG_PEEK, NULL, 0);
        break;
#endif
    default:
        break;
    }

#if defined(IPPROTO_SCTP)
    if (candidate->pollable_socket->stack == NEAT_STACK_SCTP) {
#if defined(SCTP_RECVRCVINFO)
        // Enable anciliarry data when receiving data from SCTP
        if (setsockopt(candidate->pollable_socket->fd,
                        IPPROTO_SCTP,
                        SCTP_RECVRCVINFO,
                        &enable,
                        sizeof(int)) < 0) {
            neat_log(NEAT_LOG_DEBUG, "Call to setsockopt(SCTP_RECVRCVINFO) failed");
            return -1;
        }
#endif // defined(SCTP_RECVRCVINFO)
#if defined(SCTP_INITMSG)
        struct sctp_initmsg init;
        memset(&init, 0, sizeof(init));
        init.sinit_num_ostreams = candidate->pollable_socket->flow->stream_count;
        init.sinit_max_instreams = candidate->pollable_socket->flow->stream_count; // TODO: May depend on policy

        init.sinit_max_init_timeo = 3000;
        init.sinit_max_attempts = 3;

        if (setsockopt(candidate->pollable_socket->fd,
                       IPPROTO_SCTP,
                       SCTP_INITMSG,
                       &init,
                       sizeof(struct sctp_initmsg)) < 0) {
            neat_log(NEAT_LOG_ERROR, "Call to setsockopt(SCTP_INITMSG) failed - Unable to set inbound/outbound stream count");
            return -1;
        }

        neat_log(NEAT_LOG_DEBUG, "SCTP stream negotiation - offering : %d in / %d out", init.sinit_max_instreams, init.sinit_num_ostreams);
#endif //defined(SCTP_INITMSG)
    }
#endif //defined(IPPROTO_SCTP)

    candidate->pollable_socket->handle->data = candidate;
    assert(candidate->ctx);
    assert(candidate->ctx->loop);
    assert(candidate->pollable_socket->handle);
    assert(candidate->pollable_socket->fd);

    uv_poll_init(candidate->ctx->loop,
                 candidate->pollable_socket->handle,
                 candidate->pollable_socket->fd); // makes fd nb as side effect

    retval = connect(candidate->pollable_socket->fd,
                     (struct sockaddr *) &(candidate->pollable_socket->dst_sockaddr),
                     slen);
    if (retval && errno != EINPROGRESS) {
        neat_log(NEAT_LOG_DEBUG,
                 "%s: Connect failed for fd %d connect error (%d): %s",
                 __func__,
                 candidate->pollable_socket->fd,
                 errno,
                 strerror(errno));

        return -2;
    }

    uv_poll_start(candidate->pollable_socket->handle, UV_WRITABLE, callback_fx);
#if defined(USRSCTP_SUPPORT)
    }
#endif
    return 0;
}

static int
neat_close_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    if (flow->socket->fd != -1) {
        // we might want a fx callback here to split between
        // kernel and userspace.. same for connect read and write

        if (flow->socket->fd != 0) {
            neat_log(NEAT_LOG_DEBUG, "%s: Close fd %d", __func__, flow->socket->fd);
            close(flow->socket->fd);
        }

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
neat_listen_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow,
                       neat_protocol_stack_type stack,
                       struct sockaddr *sockaddr,
                       int family,
                       int socket_type)
{
    // TODO: This function should not write to any fields in neat_flow
    const int enable = 1;
    int fd, protocol, size;
    socklen_t len;
#if defined(SCTP_INITMSG) && !defined(USRSCTP_SUPPORT)
    struct sctp_initmsg initmsg;
#endif //defined(SCTP_INITMSG) && !defined(USRSCTP_SUPPORT)

    const socklen_t slen = (family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    protocol = neat_stack_to_protocol(neat_base_stack(stack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", stack);
        return -1;
    }

    if ((fd = socket(flow->socket->family, socket_type, protocol)) < 0) {
        neat_log(NEAT_LOG_ERROR, "%s: opening listening socket failed - %s", __func__, strerror(errno));
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) != 0) {
        neat_log(NEAT_LOG_DEBUG, "Unable to set socket option SOL_SOCKET:SO_REUSEADDR");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) != 0) {
        neat_log(NEAT_LOG_DEBUG, "Unable to set socket option SOL_SOCKET:SO_REUSEPORT");
    }

    len = (socklen_t)sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        flow->writeSize = size;
    } else {
        neat_log(NEAT_LOG_DEBUG, "Unable to get socket option SOL_SOCKET:SO_SNDBUF");
        flow->writeSize = 0;
    }

    len = (socklen_t)sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        flow->readSize = size;
    } else {
        neat_log(NEAT_LOG_DEBUG, "Unable to get socket option SOL_SOCKET:SO_RCVBUF");
        flow->readSize = 0;
    }

    switch (stack) {
    case NEAT_STACK_TCP:
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int)) != 0)
            neat_log(NEAT_LOG_DEBUG, "Unable to set socket option IPPROTO_TCP:TCP_NODELAY");
        break;
    case NEAT_STACK_SCTP_UDP:
#if defined(__FreeBSD__)
        {
            struct sctp_udpencaps encaps;
            memset(&encaps, 0, sizeof(struct sctp_udpencaps));
            encaps.sue_address.ss_family = AF_INET;
            encaps.sue_port = htons(SCTP_UDP_TUNNELING_PORT);
            neat_log(NEAT_LOG_DEBUG, "Setting UDP encapsulation port to %d", SCTP_UDP_TUNNELING_PORT);
            if (setsockopt(fd, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) != 0)
                neat_log(NEAT_LOG_DEBUG, "Failed enabling UDP encapsulation!");
            else
                neat_log(NEAT_LOG_DEBUG, "UDP encapsulation enabled");
        }
#endif
        // Fallthrough
    case NEAT_STACK_SCTP:
#if defined(SCTP_INITMSG) && !defined(USRSCTP_SUPPORT)
        memset(&initmsg, 0, sizeof(struct sctp_initmsg));
        initmsg.sinit_num_ostreams = flow->stream_count;
        initmsg.sinit_max_instreams = flow->stream_count;

        if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, (char*) &initmsg, sizeof(struct sctp_initmsg)) < 0) {
            neat_log(NEAT_LOG_ERROR, "Unable to set inbound/outbound stream count");
        }
        neat_log(NEAT_LOG_DEBUG, "Offering %d SCTP streams in/out", flow->stream_count);
#endif // defined(SCTP_INITMSG)
        flow->writeLimit = flow->writeSize / 4;
#ifdef SCTP_NODELAY
        if (setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int)) != 0)
            neat_log(NEAT_LOG_DEBUG, "Unable to set socket option IPPROTO_SCTP:SCTP_NODELAY");
#endif
#ifdef SCTP_EXPLICIT_EOR
        if (setsockopt(fd, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            flow->isSCTPExplicitEOR = 1;
        else
            neat_log(NEAT_LOG_DEBUG, "Unable to set socket option IPPROTO_SCTP:SCTP_EXPLICIT_EOR");
#endif
        break;
    default:
        break;
    }

    if (stack == NEAT_STACK_UDP || stack == NEAT_STACK_UDPLITE) {
        if (fd == -1 ||
            bind(fd, sockaddr, slen) == -1) {
            neat_log(NEAT_LOG_ERROR, "%s: (%s) bind failed - %s", __func__, (stack == NEAT_STACK_UDP ? "UDP" : "UDPLite"), strerror(errno));
            return -1;
        }
    } else {
        if (fd == -1 ||
            bind(fd, sockaddr, slen) == -1 ||
            listen(fd, 100) == -1) {
            neat_log(NEAT_LOG_ERROR, "%s: bind/listen failed - %s", __func__, strerror(errno));
            return -1;
        }
    }

    return fd;
}

static int
neat_shutdown_via_kernel(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (shutdown(flow->socket->fd, SHUT_WR) == 0) {
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
neat_accept_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow, struct neat_pollable_socket *listen_socket)
{
    struct sockaddr_in remote_addr;
    struct socket *new_socket;
    struct neat_pollable_socket *pollable_socket;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in));
    if (((new_socket = usrsctp_accept(listen_socket->usrsctp_socket, (struct sockaddr *) &remote_addr, &addr_len)) == NULL) && (errno != EINPROGRESS)) {
        neat_log(NEAT_LOG_ERROR, "%s: usrsctp_accept failed - %s", __func__, strerror(errno));
        return NULL;
    }

    pollable_socket = malloc(sizeof(*pollable_socket));
    assert(pollable_socket);

    pollable_socket->fd = -1;
    pollable_socket->flow = flow;
    pollable_socket->handle = NULL;

    usrsctp_set_upcall(pollable_socket->usrsctp_socket, handle_upcall, (void*)pollable_socket);

    // Set after return by caller
    // pollable_socket->usrsctp_socket = new_socket;
    return new_socket;
}

static int
neat_connect_via_usrsctp(struct neat_he_candidate *candidate)
{
    int enable = 1;
    socklen_t len;
    int size, protocol;
    socklen_t slen =
            (candidate->pollable_socket->family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    char addrsrcbuf[slen], addrdstbuf[slen];

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    protocol = neat_stack_to_protocol(neat_base_stack(candidate->pollable_socket->stack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", candidate->pollable_socket->stack);
        return -1;
    }

    candidate->pollable_socket->usrsctp_socket = usrsctp_socket(candidate->pollable_socket->family, candidate->pollable_socket->type, protocol, NULL, NULL, 0, NULL);
    if (candidate->pollable_socket->usrsctp_socket) {
        usrsctp_set_non_blocking(candidate->pollable_socket->usrsctp_socket, 1);
        len = (socklen_t)sizeof(int);
        if (usrsctp_getsockopt(candidate->pollable_socket->usrsctp_socket, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
            candidate->writeSize = size;
        } else {
            candidate->writeSize = 0;
        }
        len = (socklen_t)sizeof(int);
        if (usrsctp_getsockopt(candidate->pollable_socket->usrsctp_socket, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
            candidate->readSize = size;
        } else {
            candidate->readSize = 0;
        }
        // he_ctx->writeLimit =  he_ctx->writeSize / 4;
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
        if (usrsctp_setsockopt(candidate->pollable_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            candidate->isSCTPExplicitEOR = 1;
#endif

        // Subscribe to SCTP events
        neat_sctp_init_events(candidate->pollable_socket->usrsctp_socket);

        neat_log(NEAT_LOG_INFO, "%s: Connect from %s to %s", __func__,
           inet_ntop(AF_INET, &(((struct sockaddr_in *) &(candidate->pollable_socket->srcAddr))->sin_addr), addrsrcbuf, slen),
           inet_ntop(AF_INET, &(((struct sockaddr_in *) &(candidate->pollable_socket->dstAddr))->sin_addr), addrdstbuf, slen));

        if (!(candidate->pollable_socket->usrsctp_socket) || (usrsctp_connect(candidate->pollable_socket->usrsctp_socket, (struct sockaddr *) &(candidate->pollable_socket->dstAddr), slen) && (errno != EINPROGRESS))) {
            neat_log(NEAT_LOG_ERROR, "%s: usrsctp_connect failed - %s", __func__, strerror(errno));
            return -1;
        } else {
            neat_log(NEAT_LOG_INFO, "%s: usrsctp_socket connected", __func__);
        }
        usrsctp_set_upcall(candidate->pollable_socket->usrsctp_socket, handle_connect, (void *)candidate->pollable_socket);
    } else {
        return -1;
    }
    return 0;
}

static int
neat_close_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (flow->socket->usrsctp_socket) {
        usrsctp_close(flow->socket->usrsctp_socket);
    }
    return 0;
}

static int
neat_shutdown_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (usrsctp_shutdown(flow->socket->usrsctp_socket, SHUT_WR) == 0) {
        return NEAT_OK;
    } else {
        return NEAT_ERROR_IO;
    }
}

#define SCTP_EVENT_READ    0x0001
#define SCTP_EVENT_WRITE   0x0002
#define SCTP_EVENT_ERROR   0x0004

static void handle_connect(struct socket *sock, void *arg, int flags)
{
    struct he_cb_ctx *he_ctx = (struct he_cb_ctx *) arg;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_flow *flow = he_ctx->flow;
    if (usrsctp_get_events(sock) & SCTP_EVENT_WRITE) {
        if (flow && flow->hefirstConnect) {
            flow->socket->family = he_ctx->candidate->ai_family;
            flow->socket->handle = he_ctx->handle;
            flow->socket->handle->data = flow->socket;
            flow->socket->usrsctp_socket = sock;
            flow->socket->fd = -1;
            flow->socket->stack = he_ctx->ai_stack;
            flow->socket->type = he_ctx->ai_socktype;

            flow->hefirstConnect = 0;
            flow->everConnected = 1;
            flow->ctx = he_ctx->nc;
            flow->writeSize = he_ctx->writeSize;
            flow->writeLimit = he_ctx->writeLimit;
            flow->readSize = he_ctx->readSize;
            flow->isSCTPExplicitEOR = he_ctx->isSCTPExplicitEOR;
            flow->firstWritePending = 1;
            flow->isPolling = 0;
            flow->stream_count = 1;

            usrsctp_set_upcall(sock, handle_upcall, (void*)flow->socket);
            io_connected(flow->ctx, flow, NEAT_OK);
        } else {
            usrsctp_close(sock);
            free(he_ctx);
            return;
        }
    }
    if ((usrsctp_get_events(sock) & SCTP_EVENT_WRITE) && flow->operations->on_writable) {
        io_writable(flow->ctx, flow, 0, NEAT_OK);
    }
}

static void handle_upcall(struct socket *sock, void *arg, int flags)
{
    struct neat_pollable_socket *pollable_socket = arg;
    neat_flow *flow = pollable_socket->flow;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    assert(flow);

    if (flow) {
        neat_ctx *ctx = flow->ctx;
        neat_log(NEAT_LOG_DEBUG, "%s", __func__);

        int events = usrsctp_get_events(sock);

        if ((events & SCTP_EVENT_READ) && flow->acceptPending) {
            do_accept(ctx, flow, pollable_socket);
            return;
        }

        if ((events & SCTP_EVENT_WRITE) && flow->firstWritePending) {
            flow->firstWritePending = 0;
            io_connected(ctx, flow, NEAT_OK);
        }

        if (events & SCTP_EVENT_WRITE && flow->isDraining) {
            neat_error_code code = neat_write_flush(ctx, flow);
            if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
                neat_io_error(ctx, flow, code);
                return;
            }
            if (!flow->isDraining) {
                io_all_written(ctx, flow, 0);
            }
        }

        if (events & SCTP_EVENT_WRITE) {
            io_writable(ctx, flow, 0, NEAT_OK);
        }

        if (events & SCTP_EVENT_READ) {
            neat_error_code code;

            do {
                code = io_readable(ctx, flow, pollable_socket, NEAT_OK);
            } while (code == READ_OK);
        }
    }
}

static int
neat_listen_via_usrsctp(struct neat_ctx *ctx, struct neat_flow *flow,
                        struct neat_pollable_socket *listen_socket)
{
    int enable = 1;
    socklen_t len;
    int size, protocol;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    socklen_t slen = (listen_socket->family == AF_INET) ?
                     sizeof (struct sockaddr_in) :
                     sizeof (struct sockaddr_in6);

    protocol = neat_stack_to_protocol(neat_base_stack(listen_socket->stack));
    if (protocol == 0) {
        neat_log(NEAT_LOG_ERROR, "Stack %d not supported", listen_socket->stack);
        return -1;
    }

    if (!(listen_socket->usrsctp_socket = usrsctp_socket(listen_socket->family, listen_socket->type, protocol, NULL, NULL, 0, NULL))) {
        neat_log(NEAT_LOG_ERROR, "%s: user_socket failed - %s", __func__, strerror(errno));
        return -1;
    }
    usrsctp_set_non_blocking(listen_socket->usrsctp_socket, 1);
    usrsctp_set_upcall(listen_socket->usrsctp_socket, handle_upcall, (void*)listen_socket);
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(listen_socket->usrsctp_socket, SOL_SOCKET, SO_SNDBUF, &size, &len) == 0) {
        flow->writeSize = size;
    } else {
        flow->writeSize = 0;
    }
    len = (socklen_t)sizeof(int);
    if (usrsctp_getsockopt(listen_socket->usrsctp_socket, SOL_SOCKET, SO_RCVBUF, &size, &len) == 0) {
        flow->readSize = size;
    } else {
        flow->readSize = 0;
    }
    flow->writeLimit = flow->writeSize / 4;

#ifdef SCTP_NODELAY
    usrsctp_setsockopt(listen_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif
#ifdef SCTP_EXPLICIT_EOR
        if (usrsctp_setsockopt(listen_socket->usrsctp_socket, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            flow->isSCTPExplicitEOR = 1;
#endif
    usrsctp_setsockopt(listen_socket->usrsctp_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    char addrbuf[slen];
    neat_log(NEAT_LOG_INFO, "%s: Bind to %s", __func__,
        inet_ntop(AF_INET, &(((struct sockaddr_in *)(&listen_socket->srcAddr))->sin_addr), addrbuf, slen));
    if (usrsctp_bind(listen_socket->usrsctp_socket, (struct sockaddr *)(&listen_socket->srcAddr), slen) == -1) {
        neat_log(NEAT_LOG_ERROR, "%s: Error binding usrsctp socket - %s", __func__, strerror(errno));
        return -1;
    }
    if (usrsctp_listen(listen_socket->usrsctp_socket, 1) == -1) {
        neat_log(NEAT_LOG_ERROR, "%s: Error listening on usrsctp socket - %s", __func__, strerror(errno));
        return -1;
    }

    return 0;
}


#endif


// this function needs to accept all the data (buffering if necessary)
neat_error_code
neat_write(struct neat_ctx *ctx, struct neat_flow *flow,
           const unsigned char *buffer, uint32_t amt,
           struct neat_tlv optional[], unsigned int opt_count)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

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
neat_recursive_filter_read(struct neat_ctx *ctx, struct neat_flow *flow,
                           struct neat_iofilter *filter,
                           unsigned char *buffer, uint32_t amt, uint32_t *actualAmt,
                           struct neat_tlv optional[], unsigned int opt_count)
{
    if (!filter) {
        return NEAT_OK;
    }
    neat_error_code rv = neat_recursive_filter_read(ctx, flow,
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
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_error_code rv = flow->readfx(ctx, flow, buffer, amt, actualAmt, optional, opt_count);
    if (rv != NEAT_OK) {
        return rv;
    }

    // apply the filters backwards
    return neat_recursive_filter_read(ctx, flow, flow->iofilters, buffer, amt, actualAmt, optional, opt_count);
}

neat_error_code
neat_shutdown(struct neat_ctx *ctx, struct neat_flow *flow)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
#if defined(USRSCTP_SUPPORT)
    if (neat_base_stack(flow->socket->stack) == NEAT_STACK_SCTP)
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
        goto error;

    rv->writefx = neat_write_to_lower_layer;
    rv->readfx = neat_read_from_lower_layer;
    TAILQ_INIT(&(rv->listen_sockets));
    rv->acceptfx = neat_accept_via_kernel;
    rv->connectfx = neat_connect;
    rv->closefx = neat_close_socket;
    rv->close2fx = neat_close_socket_2;
    rv->listenfx = NULL; // TODO: Consider reimplementing
    rv->shutdownfx = neat_shutdown_via_kernel;
    rv->buffer_count = 0;
#if defined(USRSCTP_SUPPORT)
    rv->acceptusrsctpfx = neat_accept_via_usrsctp;
#endif

    TAILQ_INIT(&rv->bufferedMessages);

    rv->properties = json_object();

    rv->socket = malloc(sizeof(struct neat_pollable_socket));
    if (!rv->socket)
        goto error;

    rv->socket->fd = 0;
    rv->socket->flow = rv;

    rv->socket->handle  = (uv_poll_t *) malloc(sizeof(uv_poll_t));
    rv->socket->handle->loop = NULL;
    rv->socket->handle->type = UV_UNKNOWN_HANDLE;

    /* Initialise flow statistics */
    rv->flow_stats.bytes_sent = 0;
    rv->flow_stats.bytes_received = 0;

    LIST_INSERT_HEAD(&mgr->flows, rv, next_flow);

    return rv;
error:
    if (rv) {
        if (rv->socket) {
            if (rv->socket->handle)
                free(rv->socket->handle);
            free(rv->socket);
        }
        free(rv);
    }
    return NULL;
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
    if (flow->isPolling && uv_is_active((uv_handle_t*)flow->socket->handle))
        uv_poll_stop(flow->socket->handle);

    neat_free_flow(flow);

    return NEAT_OK;
}

// ABORT, D1.2 sect. 3.2.4
neat_error_code neat_abort(struct neat_ctx *ctx, struct neat_flow *flow)
{
    struct linger ling;

    ling.l_onoff = 1;
    ling.l_linger = 0;

#if !defined(USRSCTP_SUPPORT)
    setsockopt(flow->socket->fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));
#else
    usrsctp_setsockopt(flow->socket->usrsctp_socket, SOL_SOCKET, SO_LINGER, &ling, sizeof(struct linger));
#endif

    neat_close(ctx, flow);

    return NEAT_OK;
}

neat_flow *
neat_find_flow(neat_ctx *ctx, struct sockaddr *src, struct sockaddr *dst)
{
    neat_flow *flow;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    LIST_FOREACH(flow, &ctx->flows, next_flow) {
        if (flow->socket == NULL)
            continue;

        if (flow->acceptPending == 1)
            continue;

        if ((sockaddr_cmp(&flow->socket->dstAddr, dst) != 0) &&
               (sockaddr_cmp(&flow->socket->srcAddr, src) != 0)) {
                       return flow;
        }
    }
    return NULL;
}
