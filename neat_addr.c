#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_core.h"
#include "neat_addr.h"

//Debug function for printing the current addresses seen by a context
static void
nt_addr_print_src_addrs(struct neat_ctx *nc)
{
    struct neat_addr *nsrc_addr = NULL;
    char addr_str[INET6_ADDRSTRLEN];
    struct sockaddr_in *src_addr4;
    struct sockaddr_in6 *src_addr6;
    struct pvd* pvd;
    struct pvd_info* pvd_info;
    struct pvd_result* pvd_result;

    nt_log(nc, NEAT_LOG_INFO, "Available src-addresses:");
    for (nsrc_addr = nc->src_addrs.lh_first; nsrc_addr != NULL;
            nsrc_addr = nsrc_addr->next_addr.le_next) {

        if (nsrc_addr->family == AF_INET) {
            src_addr4 = &(nsrc_addr->u.v4.addr4);
            inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str, INET_ADDRSTRLEN);
            nt_log(nc, NEAT_LOG_INFO, "\tIPv4: %s/%u", addr_str, nsrc_addr->prefix_length);
        } else {
            src_addr6 = &(nsrc_addr->u.v6.addr6);
            inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str, INET6_ADDRSTRLEN);
            nt_log(nc, NEAT_LOG_INFO, "\tIPv6: %s/%u pref %u valid %u", addr_str,
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
                nt_log(nc, NEAT_LOG_INFO, "\t\tPVD:");
                LIST_FOREACH(pvd_info, &(pvd->infos), next_info) {
                    nt_log(nc, NEAT_LOG_INFO, "\t\t\t%s => %s", pvd_info->key, pvd_info->value);
                }
            }
        }
    }
}

//Utility function for comparing two v6 addresses
uint8_t
neat_addr_cmp_ip6_addr(struct in6_addr *aAddr, struct in6_addr *aAddr2)
{
    return (memcmp(aAddr, aAddr2, sizeof(struct in6_addr)) == 0);
}

//Add/remove/update a source address based on information received from OS
neat_error_code
nt_addr_update_src_list(struct neat_ctx *nc,
        struct sockaddr *src_addr, uint32_t if_idx,
        uint8_t newaddr, uint8_t pref_length, uint32_t ifa_pref, uint32_t ifa_valid)
{
    struct sockaddr_in *src_addr4 = NULL, *org_addr4 = NULL;
    struct sockaddr_in6 *src_addr6 = NULL, *org_addr6 = NULL;
    struct neat_addr *nsrc_addr = NULL;
    char addr_str[INET6_ADDRSTRLEN];

    switch (src_addr->sa_family) {
        case AF_INET:
            src_addr4 = (struct sockaddr_in*) src_addr;
            inet_ntop(AF_INET, &(src_addr4->sin_addr), addr_str, INET6_ADDRSTRLEN);
            break;
        case AF_INET6:
            src_addr6 = (struct sockaddr_in6*) src_addr;
            inet_ntop(AF_INET6, &(src_addr6->sin6_addr), addr_str, INET6_ADDRSTRLEN);
            break;
        default:
            nt_log(nc, NEAT_LOG_WARNING, "%s - unknown address family", __func__);
            return NEAT_ERROR_BAD_ARGUMENT;
    }

    //Check if address is in src_list, has to be done for both add and delete
    for (nsrc_addr = nc->src_addrs.lh_first; nsrc_addr != NULL; nsrc_addr = nsrc_addr->next_addr.le_next) {
        if (nsrc_addr->family != src_addr->sa_family) {
            continue;
        }

        if (nsrc_addr->if_idx != if_idx) {
            continue;
        }

        if (src_addr4) {
            org_addr4 = (struct sockaddr_in*) &(nsrc_addr->u.v4.addr4 );

            if (src_addr4 != NULL && org_addr4->sin_addr.s_addr == src_addr4->sin_addr.s_addr) {
                break;
            }
        } else {
            org_addr6 = (struct sockaddr_in6*) &(nsrc_addr->u.v6.addr6);

            if (neat_addr_cmp_ip6_addr(&(org_addr6->sin6_addr), &(src_addr6->sin6_addr))) {
                break;
            }
        }
    }

    if (nsrc_addr != NULL) {
        //We found an address to delete, so do that
        if (!newaddr) {
            nt_run_event_cb(nc, NEAT_DELADDR, nsrc_addr);
            LIST_REMOVE(nsrc_addr, next_addr);
            --nc->src_addr_cnt;
            free(nsrc_addr);
            //nt_addr_print_src_addrs(nc);
        } else if (newaddr && nsrc_addr->family == AF_INET6) {
            //Currently, update is only relevant for v6 addresses and we only
            //use it with new pref/valid times
            nsrc_addr->u.v6.ifa_pref = ifa_pref;
            nsrc_addr->u.v6.ifa_valid = ifa_valid;
            //nt_addr_print_src_addrs(nc);
            nt_run_event_cb(nc, NEAT_UPDATEADDR, nsrc_addr);
        }

        return NEAT_ERROR_OK;
    }

    //No match found, so create a new address, add it to list and announce it to
    //any subscribers
    nsrc_addr = (struct neat_addr*) calloc(sizeof(struct neat_addr), 1);

    if (nsrc_addr == NULL) {
        nt_log(nc, NEAT_LOG_ERROR, "%s: Could not allocate memory for %s", __func__, addr_str);
        //TODO: Trigger a refresh of available addresses
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    nsrc_addr->family = src_addr->sa_family;
    nsrc_addr->if_idx = if_idx;
    nsrc_addr->prefix_length = pref_length;

    if (src_addr->sa_family == AF_INET) {
        memcpy(&(nsrc_addr->u.generic.addr), src_addr, sizeof(struct sockaddr_in));
    } else { // V6 case
        memcpy(&(nsrc_addr->u.generic.addr), src_addr, sizeof(struct sockaddr_in6));
        nsrc_addr->u.v6.ifa_pref = ifa_pref;
        nsrc_addr->u.v6.ifa_valid = ifa_valid;
    }

    LIST_INSERT_HEAD(&(nc->src_addrs), nsrc_addr, next_addr);
    ++nc->src_addr_cnt;
    nt_addr_print_src_addrs(nc);
    nt_run_event_cb(nc, NEAT_NEWADDR, nsrc_addr);
    return NEAT_ERROR_OK;
}

void
nt_addr_lifetime_timeout_cb(uv_timer_t *handle)
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
            nt_run_event_cb(nc, NEAT_UPDATEADDR, addr);
    }
    //nt_addr_print_src_addrs(nc);
}

void
nt_addr_free_src_list(struct neat_ctx *nc)
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

int
sockaddr_storage_cmp(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    struct sockaddr_in  *a_in   = (struct sockaddr_in *)    a;
    struct sockaddr_in  *b_in   = (struct sockaddr_in *)    b;
    struct sockaddr_in6 *a_in6  = (struct sockaddr_in6 *)   a;
    struct sockaddr_in6 *b_in6  = (struct sockaddr_in6 *)   b;

    #define CMP(a, b) if (a != b) return a < b ? -1 : 1

    CMP(a->ss_family, b->ss_family);

    if (a->ss_family == AF_INET) {
        CMP(ntohs(a_in->sin_port), ntohs(b_in->sin_port));
        CMP(ntohl(a_in->sin_addr.s_addr), ntohl(b_in->sin_addr.s_addr));
    } else if (a->ss_family == AF_INET6) {
        CMP(ntohs(a_in6->sin6_port), ntohs(a_in6->sin6_port));
        CMP(a_in6->sin6_flowinfo, b_in6->sin6_flowinfo);
        CMP(a_in6->sin6_scope_id, b_in6->sin6_scope_id);
        return memcmp(a_in6->sin6_addr.s6_addr, b_in6->sin6_addr.s6_addr, sizeof(b_in6->sin6_addr.s6_addr));
    } else {
        assert(false);
    }

    return 0;

    #undef CMP
}
