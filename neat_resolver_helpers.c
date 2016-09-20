#include <stddef.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "neat_resolver_helpers.h"
#include "neat_log.h"
#include "neat_internal.h"
#include "neat_addr.h"
#include "neat_resolver.h"

uint8_t
neat_resolver_helpers_addr_internal(struct sockaddr_storage *addr)
{
    struct sockaddr_in *addr4 = NULL;
    struct sockaddr_in6 *addr6 = NULL;
    uint32_t haddr4 = 0;

    if (addr->ss_family == AF_INET6) {
        addr6 = (struct sockaddr_in6*) addr;
        return (addr6->sin6_addr.s6_addr[0] & 0xfe) != 0xfc;
    }

    addr4 = (struct sockaddr_in*) addr;
    haddr4 = ntohl(addr4->sin_addr.s_addr);

    if ((haddr4 & IANA_A_MASK) == IANA_A_NW ||
        (haddr4 & IANA_B_MASK) == IANA_B_NW ||
        (haddr4 & IANA_C_MASK) == IANA_C_NW)
        return 1;
    else
        return 0;
}

//Check if node is an IP literal or not. Returns -1 on failure, 0 if not
//literal, 1 if literal
int8_t
neat_resolver_helpers_check_for_literal(uint8_t *family,
                                        const char *node)
{
    struct in6_addr dummy_addr;
    int32_t v4_literal = 0, v6_literal = 0;

    if (*family != AF_UNSPEC && *family != AF_INET && *family != AF_INET6) {
        neat_log(NEAT_LOG_ERROR, "%s - Unsupported address family", __func__);
        return -1;
    }

    //The only time inet_pton fails is if the system lacks v4/v6 support. This
    //should rather be handled with an ifdef + check at compile time
    v4_literal = inet_pton(AF_INET, node, &dummy_addr);
    v6_literal = inet_pton(AF_INET6, node, &dummy_addr);

    //These are the two possible error cases:
    //if family is v4 and address is v6 (or opposite), then user has made a
    //mistake and must be notifed
    if ((*family == AF_INET && v6_literal) ||
        (*family == AF_INET6 && v4_literal)) {
        neat_log(NEAT_LOG_ERROR, "%s - Mismatch between family and literal", __func__);
        return -1;
    }

    if (*family == AF_UNSPEC) {
        if (v4_literal)
            *family = AF_INET;
        if (v6_literal)
            *family = AF_INET6;
    }

    return v4_literal | v6_literal;
}

//Create all results for one match
uint8_t
neat_resolver_helpers_fill_results(struct neat_resolver_request *request,
                                   struct neat_resolver_results *result_list,
                                   struct neat_addr *src_addr,
                                   struct sockaddr_storage dst_addr)
{
    socklen_t addrlen;
    struct neat_resolver_res *result;
    uint8_t num_addr_added = 0;
    struct sockaddr_in *addr4;

    result = calloc(sizeof(struct neat_resolver_res), 1);

    if (result == NULL)
        return 0;

    addrlen = src_addr->family == AF_INET ?
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    result->ai_family = src_addr->family;
    result->if_idx = src_addr->if_idx;
    result->src_addr = src_addr->u.generic.addr;
    result->src_addr_len = addrlen;
    result->dst_addr = dst_addr;
    result->dst_addr_len = addrlen;
    result->internal = neat_resolver_helpers_addr_internal(&dst_addr);

    //Head of sockaddr_in and sockaddr_in6 is the same, so this is safe
    //for setting port
    addr4 = (struct sockaddr_in*) &(result->dst_addr);
    addr4->sin_port = request->dst_port;

    LIST_INSERT_HEAD(result_list, result, next_res);
    num_addr_added++;

    return num_addr_added;
}

uint8_t
neat_resolver_helpers_check_duplicate(struct neat_resolver_src_dst_addr *pair,
                                      const char *resolved_addr_str)
{
    //Accepts a src_dst_pair and an address, convert this address to struct
    //in{6}_addr, then check all pairs if this IP has seen before for same
    //(index, source)
    struct neat_addr *src_addr = pair->src_addr;
    struct sockaddr_in *src_addr_4 = NULL, *cmp_addr_4 = NULL;
    struct sockaddr_in6 *src_addr_6 = NULL, *cmp_addr_6 = NULL;
    union {
        struct in_addr resolved_addr_4;
        struct in6_addr resolved_addr_6;
    } u;
    struct neat_resolver_src_dst_addr *itr;
    uint8_t addr_equal = 0;
    int32_t i;

    if (src_addr->family == AF_INET) {
        src_addr_4 = &(src_addr->u.v4.addr4);
        i = inet_pton(AF_INET, resolved_addr_str,
                (void *) &u.resolved_addr_4);
    } else {
        src_addr_6 = &(src_addr->u.v6.addr6);
        i = inet_pton(AF_INET6, resolved_addr_str,
                (void *) &u.resolved_addr_6);
    }

    //the calleee also does pton, so that failure will currently be handled
    //elsewhere
    //TODO: SO UGLY!!!!!!!!!!!!!
    if (i <= 0)
        return 0;

    for (itr = pair->request->resolver_pairs.lh_first; itr != NULL;
            itr = itr->next_pair.le_next) {

        //Must match index
        if (src_addr->if_idx != itr->src_addr->if_idx ||
            src_addr->family != itr->src_addr->family)
            continue;

        if (src_addr->family == AF_INET) {
            cmp_addr_4 = &(itr->src_addr->u.v4.addr4);
            addr_equal = (src_addr_4 != NULL && cmp_addr_4->sin_addr.s_addr ==
                          src_addr_4->sin_addr.s_addr);
        } else {
            cmp_addr_6 = &(itr->src_addr->u.v6.addr6);
            addr_equal = neat_addr_cmp_ip6_addr(&(cmp_addr_6->sin6_addr),
                                                &(src_addr_6->sin6_addr));
        }

        if (!addr_equal)
            continue;

        //Check all resolved addresses
        for (i = 0; i < MAX_NUM_RESOLVED; i++) {
            if (!itr->resolved_addr[i].ss_family)
                break;

            if (src_addr->family == AF_INET) {
                cmp_addr_4 = (struct sockaddr_in*) &(itr->resolved_addr[i]);
                addr_equal = (u.resolved_addr_4.s_addr ==
                              cmp_addr_4->sin_addr.s_addr);
            } else {
                cmp_addr_6 = (struct sockaddr_in6*) &(itr->resolved_addr[i]);
                addr_equal = neat_addr_cmp_ip6_addr(&(cmp_addr_6->sin6_addr),
                                                    &(u.resolved_addr_6));
            }

            if (addr_equal)
                return 1;
        }
    }

    return 0;
}
