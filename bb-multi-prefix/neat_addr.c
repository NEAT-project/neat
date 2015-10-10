#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "neat_core.h"
#include "neat_addr.h"

static void neat_addr_print_src_addrs(struct neat_internal_ctx *nic)
{
    struct neat_src_addr *nsrc_addr = NULL;
    char addr_str[INET6_ADDRSTRLEN];

    fprintf(stdout, "Available addresses:\n");
    for (nsrc_addr = nic->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {
        if (nsrc_addr->family == AF_INET) {
            inet_ntop(AF_INET, &(nsrc_addr->u.v4.addr4), addr_str,
                    INET_ADDRSTRLEN);
            fprintf(stdout, "Addr: %s\n", addr_str);
        } else {
            inet_ntop(AF_INET6, &(nsrc_addr->u.v6.addr6), addr_str,
                    INET6_ADDRSTRLEN);
            fprintf(stdout, "Addr: %s pref %u valid %u\n", addr_str,
                    nsrc_addr->u.v6.ifa_pref, nsrc_addr->u.v6.ifa_valid);
        }
    }

    fprintf(stdout, "\n");
}

static uint8_t neat_addr_cmp_ip6_addr(struct in6_addr aAddr,
                                      struct in6_addr aAddr2)
{
    return aAddr.s6_addr32[0] == aAddr2.s6_addr32[0] &&
           aAddr.s6_addr32[1] == aAddr2.s6_addr32[1] &&
           aAddr.s6_addr32[2] == aAddr2.s6_addr32[2] &&
           aAddr.s6_addr32[3] == aAddr2.s6_addr32[3];
}

void neat_addr_update_src_list(struct neat_internal_ctx *nic,
        struct sockaddr_storage *src_addr, uint32_t if_idx,
        uint8_t newaddr, uint32_t ifa_pref, uint32_t ifa_valid)
{
    struct sockaddr_in *src_addr4 = NULL;
    struct sockaddr_in6 *src_addr6 = NULL;
    struct neat_src_addr *nsrc_addr = NULL;
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
    for (nsrc_addr = nic->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {
        if (nsrc_addr->family != src_addr->ss_family)
            continue;

#ifdef LINUX
        if (nsrc_addr->if_idx != if_idx)
            continue;
#endif

        if (src_addr->ss_family == AF_INET &&
                nsrc_addr->u.v4.addr4.s_addr == src_addr4->sin_addr.s_addr)
            break;
        else if (src_addr->ss_family == AF_INET6 &&
                 neat_addr_cmp_ip6_addr(nsrc_addr->u.v6.addr6,
                                        src_addr6->sin6_addr))
            break;
    }

    if (nsrc_addr != NULL) {
        if (!newaddr) {
            neat_run_event_cb(nic, NEAT_DELADDR, nsrc_addr);
            LIST_REMOVE(nsrc_addr, next_addr);
            free(nsrc_addr);
            neat_addr_print_src_addrs(nic);
        } else if (newaddr && nsrc_addr->family == AF_INET6) {
            nsrc_addr->u.v6.ifa_pref = ifa_pref;
            nsrc_addr->u.v6.ifa_valid = ifa_valid;
            neat_addr_print_src_addrs(nic);
            neat_run_event_cb(nic, NEAT_UPDATEADDR, nsrc_addr);
        }

        return;
    }

    nsrc_addr = (struct neat_src_addr*) calloc(sizeof(struct neat_src_addr), 1);

    if (nsrc_addr == NULL) {
        fprintf(stderr, "Could not allocate memory for %s\n", addr_str);
        //TODO: Trigger a refresh of available addresses
        return;
    }

    nsrc_addr->family = src_addr->ss_family;
#ifdef LINUX
    nsrc_addr->if_idx = if_idx;
#endif

    if (nsrc_addr->family == AF_INET) {
        nsrc_addr->u.v4.addr4 = src_addr4->sin_addr;
    } else {
        nsrc_addr->u.v6.addr6 = src_addr6->sin6_addr;
        nsrc_addr->u.v6.ifa_pref = ifa_pref;
        nsrc_addr->u.v6.ifa_valid = ifa_valid;
    }

    LIST_INSERT_HEAD(&(nic->src_addrs), nsrc_addr, next_addr);
    neat_run_event_cb(nic, NEAT_NEWADDR, nsrc_addr);
    neat_addr_print_src_addrs(nic);
    //TODO: Have a trigger when available addresses have changed? So that for
    //example resolve can get started if it is called before addresses are
    //available. Same goes for remove/update.
}
