#ifndef NEAT_ADDR_H
#define NEAT_ADDR_H

#include <stdint.h>
#ifdef __linux__
    #include <netinet/in.h>
#elif _WIN32
    #include <inaddr.h>
    #include <in6addr.h>
#endif

#include "neat_queue.h"

struct neat_ctx;

struct neat_addr {
    //It seems windows only supports binding to src address, not interface
#ifdef __linux__
    uint32_t if_idx;
#endif
    union {
        struct {
            struct sockaddr_storage addr;
        } generic;
        //Change these to _in/_in6?
        struct {
            struct sockaddr_in addr4;
        } v4;
        struct {
            struct sockaddr_in6 addr6;
            uint32_t ifa_pref;
            uint32_t ifa_valid;
        } v6;
    } u;
    LIST_ENTRY(neat_addr) next_addr;
    //Keep unaligned gap at the end of structure
    uint8_t family;
    uint8_t __pad;
    uint16_t __pad2;
};

//Add/remove addresses from src. address list
void neat_addr_update_src_list(struct neat_ctx *nc,
        struct sockaddr_storage *src_addr, uint32_t if_idx,
        uint8_t newaddr, uint32_t ifa_pref, uint32_t ifa_valid);

//Utility function for comparing two v6 addresses
uint8_t neat_addr_cmp_ip6_addr(struct in6_addr aAddr,
                               struct in6_addr aAddr2);
#endif
