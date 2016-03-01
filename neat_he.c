#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_property_helpers.h"

static void he_print_results(struct neat_resolver_results *results)
{
    struct neat_resolver_res *result;
    char addr_name[INET6_ADDRSTRLEN];
    char serv_name[6];

    fprintf(stderr, "Results:\n");
    LIST_FOREACH(result, results, next_res) {
        switch (result->ai_protocol) {
        case IPPROTO_UDP:
            fprintf(stderr, "UDP/");
            break;
        case IPPROTO_TCP:
            fprintf(stderr, "TCP/");
            break;
#ifdef IPPROTO_SCTP
        case IPPROTO_SCTP:
            fprintf(stderr, "SCTP/");
            break;
#endif
#ifdef IPPROTO_UDPLITE
        case IPPROTO_UDPLITE:
            fprintf(stderr, "UDPLITE/");
            break;
#endif
        default:
            fprintf(stderr, "proto%d/", result->ai_protocol);
            break;
        }
        switch (result->ai_family) {
        case AF_INET:
            fprintf(stderr, "IPv4");
            break;
        case AF_INET6:
            fprintf(stderr, "IPv6");
            break;
        default:
            fprintf(stderr, "family%d", result->ai_family);
            break;
        }
        getnameinfo((struct sockaddr *)&result->src_addr, result->src_addr_len,
                    addr_name, sizeof(addr_name),
                    serv_name, sizeof(serv_name),
                    NI_NUMERICHOST | NI_NUMERICSERV);
        fprintf(stderr, ": %s:%s->", addr_name, serv_name);
        getnameinfo((struct sockaddr *)&result->dst_addr, result->dst_addr_len,
                    addr_name, sizeof(addr_name),
                    serv_name, sizeof(serv_name),
                    NI_NUMERICHOST | NI_NUMERICSERV);
        fprintf(stderr, "%s:%s\n", addr_name, serv_name);
    }
}

static void
pm_filter(struct neat_resolver_results *results)
{
    struct neat_resolver_res *res_itr1 = results->lh_first;

    while (res_itr1 != NULL) {

        struct neat_resolver_res *tmp_itr1 = res_itr1;
        res_itr1 = res_itr1->next_res.le_next;
        if (((tmp_itr1->ai_protocol != IPPROTO_TCP) &&
            (tmp_itr1->ai_protocol != IPPROTO_SCTP)) ||
            (tmp_itr1->ai_family != AF_INET)) {

            LIST_REMOVE(tmp_itr1, next_res);
            free(tmp_itr1);

        } else {

            struct neat_resolver_res *res_itr2 = results->lh_first;
            while (res_itr2 != tmp_itr1) {
                struct neat_resolver_res *tmp_itr2 = res_itr2;
                res_itr2 = res_itr2->next_res.le_next;
                if ((tmp_itr1->ai_protocol == tmp_itr2->ai_protocol) &&
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

// TODO: Remove when finished HE.
#if 0
static void
connect_thread_cb(void *arg)
{
    struct he_thread_arg *thread_arg = ( struct he_thread_arg *)arg;
    struct neat_resolver_res *candidate = thread_arg->candidate;
    neat_flow *flow = thread_arg->flow;
    uv_mutex_t *mutex_count = thread_arg->mutex_count;
    uv_mutex_t *mutex_first = thread_arg->mutex_first;
    uv_cond_t *cond_first = thread_arg->cond_first;
    uv_mutex_t *mutex_start = thread_arg->mutex_start;
    uv_cond_t *cond_start = thread_arg->cond_start;

    uv_mutex_lock(mutex_count);
    thread_arg->thread_count++;
    uv_mutex_unlock(mutex_count);

    uv_mutex_lock(mutex_start);
    uv_cond_wait(cond_start, mutex_start);
    uv_mutex_unlock(mutex_start);

    socklen_t slen = (socklen_t)(candidate->ai_family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6);
    int fd = socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (fd == -1) {
        goto cleanup;
    }

    if (connect(fd, (struct sockaddr *) &(candidate->dst_addr), slen) == -1) {
        goto cleanup;
    }

    if (uv_mutex_trylock(mutex_first) == 0) {
        flow->family = candidate->ai_family;
        flow->sockType = candidate->ai_socktype;
        flow->sockProtocol = candidate->ai_protocol;
        flow->sockAddr = (struct sockaddr *) &(candidate->dst_addr);

        flow->fd = fd;

        socklen_t len = (socklen_t)sizeof(int);
        int size;
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

        int enable = 1;
        switch (flow->sockProtocol) {
            case IPPROTO_TCP:
                setsockopt(flow->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(int));
                break;

#ifdef IPPROTO_SCTP
            case IPPROTO_SCTP:
                flow->writeLimit =  flow->writeSize / 4;
#ifdef SCTP_NODELAY
                setsockopt(flow->fd, IPPROTO_SCTP, SCTP_NODELAY, &enable, sizeof(int));
#endif

#ifdef SCTP_EXPLICIT_EOR
            if (setsockopt(flow->fd, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &enable, sizeof(int)) == 0)
            flow->isSCTPExplicitEOR = 1;
#endif
                break;
#endif
            default:
                break;
        }

        uv_cond_signal(cond_first);
        uv_mutex_unlock(mutex_first);
    } else {
        close(fd);
    }

    cleanup:
    free(thread_arg);
    uv_mutex_lock(mutex_count);
    thread_arg->thread_count--;
    if (thread_arg->thread_count == 0) {
        uv_mutex_unlock(mutex_count);
        uv_mutex_destroy(mutex_count);
        (void)free(mutex_count);
        uv_mutex_destroy(mutex_start);
        (void)free(mutex_start);
        uv_mutex_destroy(mutex_first);
        (void)free(mutex_first);
    } else {
        uv_mutex_unlock(mutex_count);
    }
}

static void
do_he(struct neat_resolver_results *candidates, neat_flow *flow)
{
    uv_mutex_t *mutex_count;
    uv_mutex_t *mutex_first;
    uv_cond_t *cond_first;
    uv_mutex_t *mutex_start;
    uv_cond_t *cond_start;

    mutex_count = (uv_mutex_t *) malloc(sizeof(uv_mutex_t));
    assert(mutex_count != NULL);
    uv_mutex_init(mutex_count);

    mutex_first = (uv_mutex_t *) malloc(sizeof(uv_mutex_t));
    assert(mutex_first != NULL);
    uv_mutex_init(mutex_first);
    uv_mutex_lock(mutex_first);
    cond_first = (uv_cond_t *) malloc(sizeof(uv_cond_t));
    assert(cond_first != NULL);
    uv_cond_init(cond_first);

    mutex_start = (uv_mutex_t *) malloc(sizeof(uv_mutex_t));
    assert(mutex_start != NULL);
    uv_mutex_init(mutex_start);
    cond_start = (uv_cond_t *) malloc(sizeof(uv_cond_t));
    assert(cond_start != NULL);
    uv_cond_init(cond_start);

    uv_thread_t tid;
    struct neat_resolver_res *candidate;
    uint32_t thread_count = 0;
    LIST_FOREACH(candidate, candidates, next_res) {

        struct he_thread_arg *arg = (struct he_thread_arg *) calloc(1, sizeof(struct he_thread_arg));
        assert(arg != NULL);
        arg->thread_count = &thread_count;
        arg->mutex_count = mutex_count;
        arg->candidate = candidate;
        arg->flow = flow;
        arg->mutex_first = mutex_first;
        arg->cond_first = cond_first;
        arg->mutex_start = mutex_start;
        arg->cond_start = cond_start;

        /* TODO: Create detached threads. */
        uv_thread_create(&tid,connect_thread_cb, (void *)arg);

    }

    usleep(1000); // Avoid race condition between main and connect threads.

    printf("Started waiting on threads...\n");
    uv_mutex_lock(mutex_start);
    uv_cond_broadcast(cond_start);
    uv_mutex_unlock(mutex_start);
    uv_cond_wait(cond_first, mutex_first);
    printf("Started waiting on threads...Done.\n");

    flow->resolver_results = candidates;
}
#endif

static void
he_resolve_cb(struct neat_resolver *resolver, struct neat_resolver_results *results, uint8_t code)
{
    neat_flow *flow = (neat_flow *)resolver->userData1;
    neat_he_callback_fx callback_fx;
    callback_fx = (neat_he_callback_fx) (neat_flow *)resolver->userData2;

    // TODO: Remove when finished HE.
#if 0
    if (code != NEAT_RESOLVER_OK) {
        callback_fx(resolver->nc, (neat_flow *)resolver->userData1, code,
                    0, 0, 0, -1);
        return;
    }
#endif

    assert (results->lh_first);
    assert (!flow->resolver_results);

    /* TODO: This is a fake Policy Manager that filters out TCP/SCTP/IPv4. */
    pm_filter(results);
    printf("Happy Eyeball candidates:\n"); fflush(stdout);
    he_print_results(results);

    // TODO: Remove when finished HE.
#if 0
    /* Do Happy Eyeballs on filtered out protocols and destination addesses. */
    flow->fd = -1; // HE fails.
    do_he(results, flow);

    flow->fd = -1;
    flow->family = results->lh_first->ai_family;
    flow->sockType = results->lh_first->ai_socktype;
    flow->sockProtocol = results->lh_first->ai_protocol;
    flow->resolver_results = results;
    flow->sockAddr = (struct sockaddr *) &(results->lh_first->dst_addr);

    callback_fx(resolver->nc, (neat_flow *)resolver->userData1, NEAT_OK,
                flow->family, flow->sockType, flow->sockProtocol, flow->fd);
#endif

    flow->resolver_results = results;
    flow->hefirstConnect = 1;
    struct neat_resolver_res *candidate;
    LIST_FOREACH(candidate, results, next_res) {

        struct he_cb_ctx *he_ctx = (struct he_cb_ctx *) malloc(sizeof(struct he_cb_ctx));
        assert(he_ctx !=NULL);
        he_ctx->handle = (uv_poll_t *) malloc(sizeof(uv_poll_t));
        assert(he_ctx->handle != NULL);
        he_ctx->handle->data = (void *)he_ctx;
        he_ctx->nc = resolver->nc;
        he_ctx->candidate = candidate;
        he_ctx->flow = flow;
        he_ctx->fd = -1;

        if (flow->connectfx(he_ctx) == -1) {
            /* TODO: Some error handling, or? */
            printf("Issue a connect for protocol = %u\n", he_ctx->candidate->ai_protocol); fflush(stdout);
            continue;
        }

        uv_timer_t *he_timer = (uv_timer_t *) malloc(sizeof(uv_timer_t));
        he_timer->data = (void *)he_ctx;
        uv_timer_init(resolver->nc->loop, he_timer);
        uv_timer_start(he_timer, callback_fx, 2000, 0);

    }

}

neat_error_code neat_he_lookup(neat_ctx *ctx, neat_flow *flow, neat_he_callback_fx callback_fx)
{
    int protocols[NEAT_MAX_NUM_PROTO]; /* We only support SCTP, TCP, UDP, and UDPLite */
    uint8_t nr_of_protocols;
    uint8_t family;

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

    nr_of_protocols = neat_property_translate_protocols(flow->propertyMask,
            protocols);
    if (nr_of_protocols == 0)
        return NEAT_ERROR_UNABLE;

    if (!ctx->resolver) {
        ctx->resolver = neat_resolver_init(ctx, he_resolve_cb, NULL);
    }
    ctx->resolver->userData1 = (void *)flow; // todo this doesn't allow multiple sockets
    ctx->resolver->userData2 = callback_fx;

    /* FIXME: derivation of the socket type is wrong.
     * FIXME: Make use of the array of protocols
     */
    neat_getaddrinfo(ctx->resolver, family, flow->name, flow->port,
            protocols, nr_of_protocols);

    return NEAT_OK;
}
