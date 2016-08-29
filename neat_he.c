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

/* TODO: Used by Karl-Johan Grinnemo during test. Remove in final version. */
#if 0
static void
pm_filter(struct neat_resolver_results *results)
{
    struct neat_resolver_res *res_itr1 = results->lh_first;

    while (res_itr1 != NULL) {

        struct neat_resolver_res *tmp_itr1 = res_itr1;
        res_itr1 = res_itr1->next_res.le_next;
        if (((neat_base_stack(tmp_itr1->ai_stack) != NEAT_STACK_TCP) &&
            (neat_base_stack(tmp_itr1->ai_stack) != NEAT_STACK_SCTP)) ||
            (tmp_itr1->ai_family != AF_INET)) {

            LIST_REMOVE(tmp_itr1, next_res);
            free(tmp_itr1);

        } else {

            struct neat_resolver_res *res_itr2 = results->lh_first;
            while (res_itr2 != tmp_itr1) {
                struct neat_resolver_res *tmp_itr2 = res_itr2;
                res_itr2 = res_itr2->next_res.le_next;
                if ((tmp_itr1->ai_stack == tmp_itr2->ai_stack) &&
                    (memcmp(&tmp_itr1->dst_addr,
                            &tmp_itr2->dst_addr,
                            sizeof(struct sockaddr_storage)) == 0)) {

                    LIST_REMOVE(tmp_itr1, next_res);
                    free(tmp_itr1);
                    break;

                }

            }

        }

    }
}
#endif

static void free_he_handle_cb(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    free(handle);
}

static neat_error_code
he_resolve_cb(struct neat_resolver_results *results,
              uint8_t code,
              void *user_data)
{
    neat_protocol_stack_type stacks[NEAT_STACK_MAX_NUM]; /* We only support SCTP, TCP, UDP, and UDPLite */
    struct neat_he_resolver_data *resolver_data = user_data;
    struct neat_flow *flow = resolver_data->flow;
    uint8_t nr_of_stacks, i = 0;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (code == NEAT_RESOLVER_TIMEOUT)  {
        neat_io_error(flow->ctx, flow, NEAT_ERROR_IO);
    } else if ( code == NEAT_RESOLVER_ERROR ) {
        neat_io_error(flow->ctx, flow, NEAT_ERROR_IO);
    }

    nr_of_stacks = neat_property_translate_protocols(flow->propertyMask, stacks);

    assert (results->lh_first);
    assert (!flow->resolver_results);

    he_print_results(results);

    flow->resolver_results = results;
    flow->hefirstConnect = 1;
    flow->heConnectAttemptCount = 0;
    struct neat_resolver_res *candidate;
    LIST_FOREACH(candidate, results, next_res) {
        for (i = 0; i < nr_of_stacks; i++) {
            //TODO: Potential place to filter based on policy
            struct he_cb_ctx *he_ctx = (struct he_cb_ctx *) malloc(sizeof(struct he_cb_ctx));
            memset(he_ctx, 0, sizeof(struct he_cb_ctx));
            assert(he_ctx !=NULL);
            he_ctx->handle = (uv_poll_t *) malloc(sizeof(uv_poll_t));
            assert(he_ctx->handle != NULL);
            he_ctx->handle->data = (void *) he_ctx;
            he_ctx->nc = resolver_data->ctx;
            he_ctx->candidate = candidate;
            he_ctx->flow = flow;
            he_ctx->ai_stack = stacks[i];

            switch (stacks[i]) {
            case NEAT_STACK_UDP:
            case NEAT_STACK_UDPLITE:
                he_ctx->ai_socktype = SOCK_DGRAM;
            default:
                he_ctx->ai_socktype = SOCK_STREAM;
            }

#ifdef USRSCTP_SUPPORT
            he_ctx->sock = NULL;
#endif
            he_ctx->fd = -1;

            uv_poll_cb callback_fx;
            callback_fx = resolver_data->callback_fx;
            int ret = flow->connectfx(he_ctx, callback_fx);
            if (ret == -1) {
                neat_log(NEAT_LOG_DEBUG, "%s: Connect failed with ret = %d", __func__, ret);
                free(he_ctx->handle);
                free(he_ctx);
                continue;
            } else if (ret == -2) {
                neat_log(NEAT_LOG_DEBUG, "%s: Connect failed with ret = %d", __func__, ret);
                uv_close((uv_handle_t *)(he_ctx->handle), free_he_handle_cb);
                free(he_ctx);
                continue;
            } else {
                neat_log(NEAT_LOG_DEBUG, "%s: Connect successful for fd %d, ret = %d", __func__, he_ctx->fd, ret);
                flow->heConnectAttemptCount++;
                LIST_INSERT_HEAD(&(flow->he_cb_ctx_list), he_ctx, next_he_ctx);
            }
        }
    }

    if (flow->heConnectAttemptCount == 0) {
        neat_io_error(flow->ctx, flow, NEAT_ERROR_IO);
    }

    free(resolver_data);
    return NEAT_ERROR_OK;
}

neat_error_code neat_he_lookup(neat_ctx *ctx, neat_flow *flow, uv_poll_cb callback_fx)
{
    neat_protocol_stack_type stacks[NEAT_STACK_MAX_NUM]; /* We only support SCTP, TCP, UDP, and UDPLite */
    uint8_t nr_of_stacks;
    uint8_t family;
    struct neat_he_resolver_data *resolver_data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if ((flow->propertyMask & NEAT_PROPERTY_IPV4_REQUIRED) &&
        (flow->propertyMask & NEAT_PROPERTY_IPV4_BANNED))
        return NEAT_ERROR_UNABLE;
    if ((flow->propertyMask & NEAT_PROPERTY_IPV6_REQUIRED) &&
        (flow->propertyMask & NEAT_PROPERTY_IPV6_BANNED))
        return NEAT_ERROR_UNABLE;
    if ((flow->propertyMask & NEAT_PROPERTY_IPV4_BANNED) &&
        (flow->propertyMask & NEAT_PROPERTY_IPV6_BANNED))
        return NEAT_ERROR_UNABLE;
    if ((flow->propertyMask & NEAT_PROPERTY_IPV4_REQUIRED) &&
        (flow->propertyMask & NEAT_PROPERTY_IPV6_BANNED))
        family = AF_INET;
    else if ((flow->propertyMask & NEAT_PROPERTY_IPV6_REQUIRED) &&
             (flow->propertyMask & NEAT_PROPERTY_IPV4_BANNED))
        family = AF_INET6;
    else
        family = AF_UNSPEC; /* AF_INET and AF_INET6 */

    nr_of_stacks = neat_property_translate_protocols(flow->propertyMask,
            stacks);

    resolver_data = calloc(sizeof(struct neat_he_resolver_data), 1);

    if (!resolver_data) {
        return NEAT_ERROR_INTERNAL;
    }

    if (nr_of_stacks == 0) {
        free(resolver_data);
        return NEAT_ERROR_UNABLE;
    }

    if (!ctx->resolver) {
        ctx->resolver = neat_resolver_init(ctx, "/etc/resolv.conf");
    }

    if (!ctx->pvd)
        ctx->pvd = neat_pvd_init(ctx);

    /* FIXME: derivation of the socket type is wrong.
     * FIXME: Make use of the array of protocols
     */
    resolver_data->ctx = ctx;
    resolver_data->flow = flow;
    resolver_data->callback_fx = callback_fx;
    neat_resolve(ctx->resolver, family, flow->name, flow->port,
                 he_resolve_cb, resolver_data);

    return NEAT_OK;
}
