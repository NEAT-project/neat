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
#include "neat_pvd.h"

#define NEAT_UNLIMITED_LIFETIME 0xffffffff
#define NEAT_ADDRESS_LIFETIME_TIMEOUT 1

struct neat_ctx;

struct neat_addr {
    uint32_t if_idx;
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
    uint8_t prefix_length;
};

//Add/remove addresses from src. address list
void neat_addr_update_src_list(struct neat_ctx *nc,
        struct sockaddr_storage *src_addr, uint32_t if_idx,
        uint8_t newaddr, uint8_t pref_length, uint32_t ifa_pref, uint32_t ifa_valid);

//Utility function for comparing two v6 addresses
uint8_t neat_addr_cmp_ip6_addr(struct in6_addr *aAddr,
                               struct in6_addr *aAddr2);

uint8_t sockaddr_cmp(struct sockaddr *, struct sockaddr *);

void neat_addr_lifetime_timeout_cb(uv_timer_t *handle);

//Free the list of source addresses
void neat_addr_free_src_list(struct neat_ctx *nc);
#endif
