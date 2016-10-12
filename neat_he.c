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
#include "neat_property_helpers.h"


static void he_print_results(struct neat_resolver_results *results)
{
    struct neat_resolver_res *result;
    char addr_name_src[INET6_ADDRSTRLEN], addr_name_dst[INET6_ADDRSTRLEN];
    char serv_name_src[6], serv_name_dst[6];
    char family[16];

    neat_log(NEAT_LOG_INFO, "Happy-Eyeballs results:");

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

        neat_log(NEAT_LOG_INFO, "\t%s - %s:%s -> %s:%s", family,
            addr_name_src, serv_name_src, addr_name_dst, serv_name_dst);
    }
}


static void free_handle_cb(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    free(handle);
}


static void on_he_connect_req(uv_timer_t *handle)
{
   struct neat_he_candidate *candidate       = (struct neat_he_candidate *) (handle->data);
   struct neat_he_candidates *candidate_list = candidate->pollable_socket->flow->candidate_list;
   uint8_t *heConnectAttemptCount            = &(candidate->pollable_socket->flow->heConnectAttemptCount);

   uv_timer_stop(candidate->prio_timer);
   uv_close((uv_handle_t *) candidate->prio_timer, free_handle_cb);

   int ret = candidate->pollable_socket->flow->connectfx(candidate,
                   candidate->callback_fx);
   if ((ret == -1) || (ret == -2)) {

        neat_log(NEAT_LOG_DEBUG, "%s: Connect failed with ret = %d", __func__, ret);
        if (ret == -2) {
            uv_close((uv_handle_t *)(candidate->pollable_socket->handle), free_handle_cb);
            candidate->pollable_socket->handle = NULL;
        } else {
            free(candidate->pollable_socket->handle);
            candidate->pollable_socket->handle = NULL;
        }
        // neat_log(NEAT_LOG_DEBUG, "%s:Release candidate", __func__ );
        (*heConnectAttemptCount)--;

        neat_log(NEAT_LOG_DEBUG, "he_conn_attempt: %d", *heConnectAttemptCount);

        if (*heConnectAttemptCount == 0) {
            neat_io_error(candidate->pollable_socket->flow->ctx,
                          candidate->pollable_socket->flow,
                          NEAT_ERROR_IO);
        }

        TAILQ_REMOVE(candidate_list, candidate, next);
        neat_free_candidate(candidate);

   } else {

       neat_log(NEAT_LOG_DEBUG,
                "%s: Connect successful for fd %d, ret = %d",
                __func__,
                candidate->pollable_socket->fd, ret);

   }
}


static void delayed_he_connect_req(struct neat_he_candidate *candidate, uv_poll_cb callback_fx)
{
    candidate->prio_timer = (uv_timer_t *) malloc(sizeof(uv_timer_t));
    assert(candidate->prio_timer != NULL);
    uv_timer_init(candidate->pollable_socket->flow->ctx->loop, candidate->prio_timer);
    uv_timer_start(candidate->prio_timer, on_he_connect_req, HE_PRIO_DELAY * candidate->priority, 0);
    candidate->callback_fx = callback_fx;
    candidate->prio_timer->data = (void *) candidate;

#if 0
    neat_log(NEAT_LOG_DEBUG,
             "%s: Priority = %d, Delay = %d ms",
             __func__,
             candidate->priority,
             HE_PRIO_DELAY * candidate->priority);
#endif
}

neat_error_code
neat_he_open(neat_ctx *ctx, neat_flow *flow, struct neat_he_candidates *candidate_list, uv_poll_cb callback_fx)
{
    const char *proto;
    size_t i;
    const char *family;
    struct neat_he_candidate *candidate;
    struct neat_he_candidate *next_candidate;

    i = 0;
    TAILQ_FOREACH(candidate, candidate_list, next) {
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

        neat_log(NEAT_LOG_DEBUG, "HE Candidate %2d: %8s [%2d] %8s/%s <saddr %s> <dstaddr %s> port %5d priority %d",
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
        neat_log(NEAT_LOG_DEBUG, "Properties:\n%s", str);

        free(str);
#endif
    }

    neat_log(NEAT_LOG_DEBUG, "HE will now commence");

    flow->hefirstConnect = 1;
    flow->heConnectAttemptCount = 0;
    flow->candidate_list = candidate_list;
    candidate = candidate_list->tqh_first;
    while (candidate) {

#if 0
        neat_log(NEAT_LOG_DEBUG, "HE Candidate: %8s [%2d] <saddr %s> <dstaddr %s> port %5d priority %d",
                 candidate->if_name,
                 candidate->if_idx,
                 candidate->pollable_socket->src_address,
                 candidate->pollable_socket->dst_address,
                 candidate->pollable_socket->port,
                 candidate->priority);
#endif

        candidate->pollable_socket->handle = (uv_poll_t *) malloc(sizeof(uv_poll_t));
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

        if (candidate->priority > 0) {

            delayed_he_connect_req(candidate, callback_fx);
            candidate->pollable_socket->flow->heConnectAttemptCount++;
            candidate = TAILQ_NEXT(candidate, next);

        } else {

            int ret = candidate->pollable_socket->flow->connectfx(candidate, callback_fx);
            if ((ret == -1) || (ret == -2)) {

                neat_log(NEAT_LOG_DEBUG, "%s: Connect failed with ret = %d", __func__, ret);
                if (ret == -2) {
                    uv_close((uv_handle_t *)(candidate->pollable_socket->handle), free_handle_cb);
                    candidate->pollable_socket->handle = NULL;
                } else {
                    free(candidate->pollable_socket->handle);
                    candidate->pollable_socket->handle = NULL;
                }
                neat_log(NEAT_LOG_DEBUG, "%s:Release candidate", __func__ );
                next_candidate = TAILQ_NEXT(candidate, next);
                TAILQ_REMOVE(candidate_list, candidate, next);
                neat_free_candidate(candidate);
                candidate = next_candidate;
            } else {

                neat_log(NEAT_LOG_DEBUG, "%s: Connect successful for fd %d, ret = %d", __func__, candidate->pollable_socket->fd, ret);
                candidate->pollable_socket->flow->heConnectAttemptCount++;
                candidate = TAILQ_NEXT(candidate, next);

            }

        }

    }

    if (flow->heConnectAttemptCount == 0) {
        neat_io_error(flow->ctx, flow, NEAT_ERROR_IO);
    }

    return NEAT_ERROR_OK;
}
