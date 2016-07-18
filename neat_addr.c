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
    struct pvd* pvd;
    struct pvd_info* pvd_info;
    struct pvd_result* pvd_result;

    neat_log(NEAT_LOG_INFO, "Available src-addresses:");
    for (nsrc_addr = nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {

        if (nsrc_addr->family == AF_INET) {
            src_addr4 = &(nsrc_addr->u.v4.addr4);
            inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str,
                    INET_ADDRSTRLEN);
            neat_log(NEAT_LOG_INFO, "\tIPv4: %s/%u", addr_str, nsrc_addr->prefix_length);
        } else {
            src_addr6 = &(nsrc_addr->u.v6.addr6);
            inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str,
                    INET6_ADDRSTRLEN);
            neat_log(NEAT_LOG_INFO, "\tIPv6: %s/%u pref %u valid %u", addr_str,
                    nsrc_addr->prefix_length, nsrc_addr->u.v6.ifa_pref,
                    nsrc_addr->u.v6.ifa_valid);
        }

        if (nc->pvd == NULL)
            continue;

        LIST_FOREACH(pvd_result, &(nc->pvd->results), next_result) {
            if (pvd_result->src_addr != nsrc_addr) {
                continue;
            }
            LIST_FOREACH(pvd, &(pvd_result->pvds), next_pvd) {
                neat_log(NEAT_LOG_INFO, "\t\tPVD:");
                LIST_FOREACH(pvd_info, &(pvd->infos), next_info) {
                    neat_log(NEAT_LOG_INFO, "\t\t\t%s => %s", pvd_info->key, pvd_info->value);
                }
            }
        }
    }
}

//Utility function for comparing two v6 addresses
uint8_t neat_addr_cmp_ip6_addr(struct in6_addr *aAddr,
                               struct in6_addr *aAddr2)
{
    return (memcmp(aAddr, aAddr2, sizeof(struct in6_addr)) == 0);
}

//Add/remove/update a source address based on information received from OS
void neat_addr_update_src_list(struct neat_ctx *nc,
        struct sockaddr_storage *src_addr, uint32_t if_idx,
        uint8_t newaddr, uint8_t pref_length, uint32_t ifa_pref, uint32_t ifa_valid)
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

        if (nsrc_addr->if_idx != if_idx)
            continue;

        if (src_addr->ss_family == AF_INET) {
            org_addr4 = (struct sockaddr_in*) &(nsrc_addr->u.v4.addr4);

            if (src_addr4 != NULL && org_addr4->sin_addr.s_addr == src_addr4->sin_addr.s_addr)
                break;
        } else {
            org_addr6 = (struct sockaddr_in6*) &(nsrc_addr->u.v6.addr6);

            if (neat_addr_cmp_ip6_addr(&(org_addr6->sin6_addr),
                                       &(src_addr6->sin6_addr)))
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
        neat_log(NEAT_LOG_ERROR, "%s: Could not allocate memory for %s", __func__, addr_str);
        //TODO: Trigger a refresh of available addresses
        return;
    }

    nsrc_addr->family = src_addr->ss_family;
    nsrc_addr->if_idx = if_idx;
    nsrc_addr->prefix_length = pref_length;

    memcpy(&(nsrc_addr->u.generic.addr), src_addr, sizeof(*src_addr));

    if (nsrc_addr->family == AF_INET6) {
        nsrc_addr->u.v6.ifa_pref = ifa_pref;
        nsrc_addr->u.v6.ifa_valid = ifa_valid;
    }

    LIST_INSERT_HEAD(&(nc->src_addrs), nsrc_addr, next_addr);
    ++nc->src_addr_cnt;
    neat_addr_print_src_addrs(nc);
    neat_run_event_cb(nc, NEAT_NEWADDR, nsrc_addr);
}

void neat_addr_lifetime_timeout_cb(uv_timer_t *handle)
{
    struct neat_ctx *nc;
    struct neat_addr *addr;
    int notify;

    nc = (struct neat_ctx *)handle->data;
    LIST_FOREACH(addr, &(nc->src_addrs), next_addr) {
        notify = 0;
        if (addr->family != AF_INET6)
            continue;
        if (addr->u.v6.ifa_pref != NEAT_UNLIMITED_LIFETIME)
            if (addr->u.v6.ifa_pref > 0) {
                if (addr->u.v6.ifa_pref >= NEAT_ADDRESS_LIFETIME_TIMEOUT)
                    addr->u.v6.ifa_pref -= NEAT_ADDRESS_LIFETIME_TIMEOUT;
                else
                    addr->u.v6.ifa_pref = 0;
                if (addr->u.v6.ifa_pref == 0)
                    notify = 1;
            }
        if (addr->u.v6.ifa_valid != NEAT_UNLIMITED_LIFETIME)
            if (addr->u.v6.ifa_valid > 0) {
                if (addr->u.v6.ifa_valid >= NEAT_ADDRESS_LIFETIME_TIMEOUT)
                    addr->u.v6.ifa_valid -= NEAT_ADDRESS_LIFETIME_TIMEOUT;
                else
                    addr->u.v6.ifa_valid = 0;
                if (addr->u.v6.ifa_valid == 0)
                    notify = 1;
            }
        if (notify)
            neat_run_event_cb(nc, NEAT_UPDATEADDR, addr);
    }
    //neat_addr_print_src_addrs(nc);
}

void neat_addr_free_src_list(struct neat_ctx *nc)
{
    struct neat_addr *nsrc_addr = NULL;
    struct neat_addr *nsrc_addr_itr = nc->src_addrs.lh_first;

    while (nsrc_addr_itr != NULL) {
        nsrc_addr = nsrc_addr_itr;
        nsrc_addr_itr = nsrc_addr_itr->next_addr.le_next;

        free(nsrc_addr);
    }

}

/*
 * https://gist.github.com/kazuho/45eae4f92257daceb73e
 * Copyright (c) 2014 Kazuho Oku
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
uint8_t sockaddr_cmp(struct sockaddr *x, struct sockaddr *y)
{
#define CMP(a, b) if (a != b) return a < b ? -1 : 1

    CMP(x->sa_family, y->sa_family);

    if (x->sa_family == AF_INET) {
        struct sockaddr_in *xin = (void*)x, *yin = (void*)y;
        CMP(ntohs(xin->sin_port), ntohs(yin->sin_port));
        CMP(ntohl(xin->sin_addr.s_addr), ntohl(yin->sin_addr.s_addr));
    } else if (x->sa_family == AF_INET6) {
        struct sockaddr_in6 *xin6 = (void*)x, *yin6 = (void*)y;
        CMP(ntohs(xin6->sin6_port), ntohs(yin6->sin6_port));
        CMP(xin6->sin6_flowinfo, yin6->sin6_flowinfo);
        CMP(xin6->sin6_scope_id, yin6->sin6_scope_id);
        return memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
    }

#undef CMP
    return 0;
}
