#ifndef NEAT_ADDR_H
#define NEAT_ADDR_H

#include <stdint.h>
#ifdef LINUX
    #include <netinet/in.h>
#elif WINDOWS
    #include <inaddr.h>
    #include <in6addr.h>
#endif

#include "include/queue.h"

struct neat_ctx;

//Define list type here, so that we can use it when subclassing
LIST_HEAD(neat_src_addrs, neat_src_addr);

struct neat_src_addr {
    //It seems windows only supports binding to src address, not interface
#ifdef LINUX
    uint32_t if_idx;
#endif
    union {
        struct {
            struct in_addr addr4;
        } v4;
        struct {
            struct in6_addr addr6;
            uint32_t ifa_pref;
            uint32_t ifa_valid;
        } v6;
    } u;
    LIST_ENTRY(neat_src_addr) next_addr;
    //Keep unaligned gap at the end of structure
    uint8_t family;
    uint8_t __pad;
    uint16_t __pad2;
};

//Add/remove addresses from src. address list
void neat_addr_update_src_list(struct neat_ctx *nc,
        struct sockaddr_storage *src_addr, uint32_t if_idx,
        uint8_t newaddr, uint32_t ifa_pref, uint32_t ifa_valid);

#endif
