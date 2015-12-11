#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"
#include "neat_addr.h"

//Debug function for printing the current addresses seen by a context
static void neat_addr_print_src_addrs(struct neat_ctx *nc)
{
    struct neat_addr *nsrc_addr = NULL;
    char addr_str[INET6_ADDRSTRLEN];
    struct sockaddr_in *src_addr4;
    struct sockaddr_in6 *src_addr6;

    fprintf(stderr, "Available addresses:\n");
    for (nsrc_addr = nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {

        if (nsrc_addr->family == AF_INET) {
            src_addr4 = &(nsrc_addr->u.v4.addr4);
            inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str,
                    INET_ADDRSTRLEN);
            fprintf(stderr, "Addr: %s\n", addr_str);
        } else {
            src_addr6 = &(nsrc_addr->u.v6.addr6);
            inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str,
                    INET6_ADDRSTRLEN);
            fprintf(stderr, "Addr: %s pref %u valid %u\n", addr_str,
                    nsrc_addr->u.v6.ifa_pref, nsrc_addr->u.v6.ifa_valid);
        }
    }

    fprintf(stderr, "\n");
}

//Utility function for comparing two v6 addresses
uint8_t neat_addr_cmp_ip6_addr(struct in6_addr aAddr,
                               struct in6_addr aAddr2)
{
#ifdef __FreeBSD__
    return aAddr.__u6_addr.__u6_addr32[0] == aAddr2.__u6_addr.__u6_addr32[0] &&
           aAddr.__u6_addr.__u6_addr32[1] == aAddr2.__u6_addr.__u6_addr32[1] &&
           aAddr.__u6_addr.__u6_addr32[2] == aAddr2.__u6_addr.__u6_addr32[2] &&
           aAddr.__u6_addr.__u6_addr32[3] == aAddr2.__u6_addr.__u6_addr32[3];
#else
    return aAddr.s6_addr32[0] == aAddr2.s6_addr32[0] &&
           aAddr.s6_addr32[1] == aAddr2.s6_addr32[1] &&
           aAddr.s6_addr32[2] == aAddr2.s6_addr32[2] &&
           aAddr.s6_addr32[3] == aAddr2.s6_addr32[3];
#endif
}

//Add/remove/update a source address based on information received from OS
void neat_addr_update_src_list(struct neat_ctx *nc,
        struct sockaddr_storage *src_addr, uint32_t if_idx,
        uint8_t newaddr, uint32_t ifa_pref, uint32_t ifa_valid)
{
    struct sockaddr_in *src_addr4 = NULL, *org_addr4 = NULL;
    struct sockaddr_in6 *src_addr6 = NULL, *org_addr6 = NULL;
    struct neat_addr *nsrc_addr = NULL;
    char addr_str[INET6_ADDRSTRLEN];

    if (src_addr->ss_family == AF_INET) {
        src_addr4 = (struct sockaddr_in*) src_addr;
        inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str, INET6_ADDRSTRLEN);
    } else {
        src_addr6 = (struct sockaddr_in6*) src_addr;
        inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str,
                INET6_ADDRSTRLEN);
    }

    //Check if address is in src_list, has to be done for both add and delete
    for (nsrc_addr = nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {
        if (nsrc_addr->family != src_addr->ss_family)
            continue;

#ifdef __linux__
        if (nsrc_addr->if_idx != if_idx)
            continue;
#endif

        if (src_addr->ss_family == AF_INET) {
            org_addr4 = (struct sockaddr_in*) &(nsrc_addr->u.v4.addr4);

            if (org_addr4->sin_addr.s_addr == src_addr4->sin_addr.s_addr)
                break;
        } else {
            org_addr6 = (struct sockaddr_in6*) &(nsrc_addr->u.v6.addr6);

            if (neat_addr_cmp_ip6_addr(org_addr6->sin6_addr,
                                       src_addr6->sin6_addr))
                break;
        }
    }

    if (nsrc_addr != NULL) {
        //We found an address to delete, so do that
        if (!newaddr) {
            neat_run_event_cb(nc, NEAT_DELADDR, nsrc_addr);
            LIST_REMOVE(nsrc_addr, next_addr);
            --nc->src_addr_cnt;
            free(nsrc_addr);
            //neat_addr_print_src_addrs(nc);
        } else if (newaddr && nsrc_addr->family == AF_INET6) {
            //Currently, update is only relevant for v6 addresses and we only
            //use it with new pref/valid times
            nsrc_addr->u.v6.ifa_pref = ifa_pref;
            nsrc_addr->u.v6.ifa_valid = ifa_valid;
            //neat_addr_print_src_addrs(nc);
            neat_run_event_cb(nc, NEAT_UPDATEADDR, nsrc_addr);
        }

        return;
    }

    //No match found, so create a new address, add it to list and announce it to
    //any subscribers
    nsrc_addr = (struct neat_addr*) calloc(sizeof(struct neat_addr), 1);

    if (nsrc_addr == NULL) {
        fprintf(stderr, "Could not allocate memory for %s\n", addr_str);
        //TODO: Trigger a refresh of available addresses
        return;
    }

    nsrc_addr->family = src_addr->ss_family;
#ifdef __linux__
    nsrc_addr->if_idx = if_idx;
#endif

    memcpy(&(nsrc_addr->u.generic.addr), src_addr, sizeof(*src_addr));
    
    if (nsrc_addr->family == AF_INET6) {
        nsrc_addr->u.v6.ifa_pref = ifa_pref;
        nsrc_addr->u.v6.ifa_valid = ifa_valid;
    }

    LIST_INSERT_HEAD(&(nc->src_addrs), nsrc_addr, next_addr);
    ++nc->src_addr_cnt;
    neat_run_event_cb(nc, NEAT_NEWADDR, nsrc_addr);
    //neat_addr_print_src_addrs(nc);
}
