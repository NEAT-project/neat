#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "neat.h"
#include "neat_he.h"
#include "neat_internal.h"


static void
he_print_results(struct neat_resolver_results *results)
{
    struct neat_resolver_res *result;
    char addr_name_src[INET6_ADDRSTRLEN], addr_name_dst[INET6_ADDRSTRLEN];
    char serv_name_src[6], serv_name_dst[6];
    char family[16];

    //nt_log(NEAT_LOG_INFO, "Happy-Eyeballs results:");

    LIST_FOREACH(result, results, next_res) {
        switch (result->ai_family) {
            case AF_INET:
                snprintf(family, 16, "IPv4");
                break;
            case AF_INET6:
                snprintf(family, 16, "IPv6");
                break;
            default:
                snprintf(family, 16, "family%d", result->ai_family);
                break;
        }

        getnameinfo((struct sockaddr *)&result->src_addr, result->src_addr_len,
                    addr_name_src, sizeof(addr_name_src),
                    serv_name_src, sizeof(serv_name_src),
                    NI_NUMERICHOST | NI_NUMERICSERV);

        getnameinfo((struct sockaddr *)&result->dst_addr, result->dst_addr_len,
                    addr_name_dst, sizeof(addr_name_dst),
                    serv_name_dst, sizeof(serv_name_dst),
                    NI_NUMERICHOST | NI_NUMERICSERV);

        //nt_log(NEAT_LOG_INFO, "\t%s - %s:%s -> %s:%s", family,
        //    addr_name_src, serv_name_src, addr_name_dst, serv_name_dst);
    }
}


static void
free_handle_cb(uv_handle_t *handle)
{
    free(handle);
}

static void
on_he_connect_req(uv_timer_t *handle)
{
    struct neat_he_candidate *candidate       = (struct neat_he_candidate *) (handle->data);
    struct neat_he_candidates *candidate_list = candidate->pollable_socket->flow->candidate_list;
    uint8_t *heConnectAttemptCount            = &(candidate->pollable_socket->flow->heConnectAttemptCount);

    struct neat_ctx *ctx = candidate->ctx;
    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);
    uv_timer_stop(candidate->prio_timer);
    candidate->prio_timer->data = candidate;
    uv_close((uv_handle_t *) candidate->prio_timer, free_handle_cb);
    candidate->prio_timer = NULL;

    int ret = candidate->pollable_socket->flow->connectfx(candidate,
                   candidate->callback_fx);
    if ((ret == -1) || (ret == -2)) {

        nt_log(ctx, NEAT_LOG_DEBUG, "%s: Connect failed with ret = %d", __func__, ret);
        if (ret == -2) {
            uv_close((uv_handle_t *)(candidate->pollable_socket->handle), free_handle_cb);
            candidate->pollable_socket->handle = NULL;
        } else {
            free(candidate->pollable_socket->handle);
            candidate->pollable_socket->handle = NULL;
        }
        // nt_log(ctx, NEAT_LOG_DEBUG, "%s:Release candidate", __func__ );
        (*heConnectAttemptCount)--;

        nt_log(ctx, NEAT_LOG_DEBUG, "he_conn_attempt: %d", *heConnectAttemptCount);

        if (*heConnectAttemptCount == 0) {
            nt_io_error(candidate->pollable_socket->flow->ctx,
                          candidate->pollable_socket->flow,
                          NEAT_ERROR_IO);
        } else {
            TAILQ_REMOVE(candidate_list, candidate, next);
            nt_free_candidate(ctx, candidate);
        }
    } else {

        nt_log(ctx, NEAT_LOG_DEBUG,
            "%s: Connect successful for fd %d, ret = %d",
            __func__,
            candidate->pollable_socket->fd, ret);
    }
}


static void
delayed_he_connect_req(struct neat_he_candidate *candidate, uv_poll_cb callback_fx)
{
    candidate->prio_timer = (uv_timer_t *) calloc(1, sizeof(uv_timer_t));
    assert(candidate->prio_timer != NULL);
    uv_timer_init(candidate->pollable_socket->flow->ctx->loop, candidate->prio_timer);
    uv_timer_start(candidate->prio_timer, on_he_connect_req, 200, 0);
    candidate->callback_fx = callback_fx;
    candidate->prio_timer->data = (void *) candidate;

#if 0
    nt_log(ctx, NEAT_LOG_DEBUG,
             "%s: Priority = %d, Delay = %d ms",
             __func__,
             candidate->priority,
             HE_PRIO_DELAY * candidate->priority);
#endif
}

#ifdef SCTP_MULTISTREAMING
static void
on_delayed_he_open(uv_timer_t *handle)
{
    struct neat_flow *flow       = (struct neat_flow *) (handle->data);
    nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s - sctp multistream HE timer fired", __func__);
    uv_timer_stop(flow->multistream_timer);
    uv_close((uv_handle_t *) flow->multistream_timer, free_handle_cb);

    nt_he_open(flow->ctx, flow, flow->candidate_list, flow->callback_fx);
}


#endif // SCTP_MULTISTREAMING

neat_error_code
nt_he_open(neat_ctx *ctx, neat_flow *flow, struct neat_he_candidates *candidate_list, uv_poll_cb callback_fx)
{
    const char *proto;
    size_t i;
    const char *family;
    struct neat_he_candidate *candidate;
    struct neat_he_candidate *next_candidate;
    uint8_t multistream_probe = 0;

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

#ifdef SCTP_MULTISTREAMING
    struct neat_pollable_socket *multistream_socket = NULL;
#endif

    i = 0;
    TAILQ_FOREACH(candidate, candidate_list, next) {
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
            multistream_probe = 1;
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

        nt_log(ctx, NEAT_LOG_DEBUG, "HE Candidate %2d: %8s [%2d] %8s/%s <saddr %s> <dstaddr %s> port %5d priority %d",
                 i++,
                 candidate->if_name,
                 candidate->if_idx,
                 proto,
                 family,
                 candidate->pollable_socket->src_address,
                 candidate->pollable_socket->dst_address,
                 candidate->pollable_socket->port,
                 candidate->priority);

#if 0
        char *str = json_dumps(candidate->properties, JSON_INDENT(2));
        nt_log(ctx, NEAT_LOG_DEBUG, "Properties:\n%s", str);

        free(str);
#endif
    }

    flow->candidate_list = candidate_list;
    candidate = candidate_list->tqh_first;


    // SCTP is generally allowed
    if (multistream_probe) {
#ifdef SCTP_MULTISTREAMING
        // check if there is already a piggyback assoc
        if ((multistream_socket = nt_find_multistream_socket(ctx, flow)) != NULL) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - using piggyback assoc", __func__);
            // we have a piggyback assoc...

            LIST_INSERT_HEAD(&multistream_socket->sctp_multistream_flows, flow, multistream_next_flow);
            multistream_socket->sctp_streams_used++;

            flow->multistream_id        = multistream_socket->sctp_streams_used;
            //flow->multistream_state     = NEAT_FLOW_OPEN;
            flow->everConnected         = 1;
            flow->isPolling             = 1;
            flow->firstWritePending     = 1;

            //json_incref(flow->properties);

            flow->socket = multistream_socket;

            while (candidate) {
                next_candidate = TAILQ_NEXT(candidate, next);
                TAILQ_REMOVE(candidate_list, candidate, next);
                nt_free_candidate(ctx, candidate);
                candidate = next_candidate;
            }

            nt_sctp_open_stream(flow->socket, flow->multistream_id);

            uvpollable_cb(flow->socket->handle, NEAT_OK, UV_WRITABLE);
            return NEAT_ERROR_OK;

        // if there is no piggyback assoc, wait if we didnt already : We reschedule the *complete* he-process!
        } else if (flow->multistream_check == 0 && nt_wait_for_multistream_socket(ctx, flow)) {
            nt_log(ctx, NEAT_LOG_DEBUG, "%s - waiting for another assoc", __func__);
            flow->multistream_check = 1;

            flow->multistream_timer = (uv_timer_t *) calloc(1, sizeof(uv_timer_t));
            assert(flow->multistream_timer != NULL);
            flow->multistream_check = 1;

            uv_timer_init(flow->ctx->loop, flow->multistream_timer);
            uv_timer_start(flow->multistream_timer, on_delayed_he_open, 200, 0);
            flow->callback_fx = callback_fx;
            flow->multistream_timer->data = (void *) flow;

            return NEAT_ERROR_OK;
        }
#endif // SCTP_MULTISTREAMING
    }


    flow->hefirstConnect = 1;
    flow->heConnectAttemptCount = 0;

    nt_log(ctx, NEAT_LOG_DEBUG, "HE will now commence");
    while (candidate) {

#if 0
        nt_log(ctx, NEAT_LOG_DEBUG, "HE Candidate: %8s [%2d] <saddr %s> <dstaddr %s> port %5d priority %d",
                 candidate->if_name,
                 candidate->if_idx,
                 candidate->pollable_socket->src_address,
                 candidate->pollable_socket->dst_address,
                 candidate->pollable_socket->port,
                 candidate->priority);
#endif

        candidate->pollable_socket->handle = (uv_poll_t *) calloc(1, sizeof(uv_poll_t));
        assert(candidate->pollable_socket->handle != NULL);
        candidate->ctx = ctx;
        candidate->pollable_socket->flow = flow;

        switch (candidate->pollable_socket->stack) {

            case NEAT_STACK_UDP:
            case NEAT_STACK_UDPLITE:
                candidate->pollable_socket->type = SOCK_DGRAM;
                break;
            default:
                candidate->pollable_socket->type = SOCK_STREAM;
                break;
        }

#if defined(USRSCTP_SUPPORT)
        candidate->pollable_socket->usrsctp_socket = NULL;
#endif
        candidate->pollable_socket->fd = -1;
        candidate->prio_timer          = NULL;

#if 0
        if (candidate->priority > 0 || 1) {

            delayed_he_connect_req(candidate, callback_fx);
            candidate->pollable_socket->flow->heConnectAttemptCount++;
            candidate = TAILQ_NEXT(candidate, next);

        } else {

            int ret = candidate->pollable_socket->flow->connectfx(candidate, callback_fx);
            if ((ret == -1) || (ret == -2)) {

                nt_log(ctx, NEAT_LOG_DEBUG, "%s: Connect failed with ret = %d", __func__, ret);
                if (ret == -2) {
                    uv_close((uv_handle_t *)(candidate->pollable_socket->handle), free_handle_cb);
                    candidate->pollable_socket->handle = NULL;
                } else {
                    free(candidate->pollable_socket->handle);
                    candidate->pollable_socket->handle = NULL;
                }
                nt_log(ctx, NEAT_LOG_DEBUG, "%s:Release candidate", __func__ );
                next_candidate = TAILQ_NEXT(candidate, next);
                TAILQ_REMOVE(candidate_list, candidate, next);
                nt_free_candidate(ctx, candidate);
                candidate = next_candidate;
            } else {

                nt_log(ctx, NEAT_LOG_DEBUG, "%s: Connect successful for fd %d, ret = %d", __func__, candidate->pollable_socket->fd, ret);
                candidate->pollable_socket->flow->heConnectAttemptCount++;
                candidate = TAILQ_NEXT(candidate, next);

            }

        }
#else
        delayed_he_connect_req(candidate, callback_fx);
        candidate->pollable_socket->flow->heConnectAttemptCount++;
        candidate = TAILQ_NEXT(candidate, next);
#endif

    }

    if (flow->heConnectAttemptCount == 0) {
        nt_io_error(flow->ctx, flow, NEAT_ERROR_IO);
    }

    return NEAT_ERROR_OK;
}
