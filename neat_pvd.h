#ifndef NEAT_PVD_H
#define NEAT_PVD_H

#include <stdint.h>
#ifdef __linux__
    #include <netinet/in.h>
#elif _WIN32
    #include <inaddr.h>
    #include <in6addr.h>
#endif

#include "neat_queue.h"

struct neat_ctx;
struct neat_addr;

struct pvd_infos;
LIST_HEAD(pvd_infos, pvd_info);

struct pvd_info {
    char* key;
    char* value;
    LIST_ENTRY(pvd_info) next_info;
};

struct pvd {
    struct pvd_infos infos;
    LIST_ENTRY(pvd) next_pvd;
    // Eventually an identifier
};

struct pvds;
LIST_HEAD(pvds, pvd);

struct pvd_result {
    struct neat_addr* src_addr;
    struct pvds pvds;
    LIST_ENTRY(pvd_result) next_result;
};

struct pvd_results;
LIST_HEAD(pvd_results, pvd_result);

struct pvd_dns_query {
    uv_loop_t* loop;
    struct neat_addr *src_addr;
    struct sockaddr_storage *dns_addr;
    struct pvd_result *pvd_result;
};

struct neat_pvd {
    struct neat_ctx *nc;
    struct neat_event_cb newaddr_cb;
    struct pvd_results results;
};
//Add/remove addresses from src. address list
// void neat_addr_update_src_list(struct neat_ctx *nc,
//         struct sockaddr_storage *src_addr, uint32_t if_idx,
//         uint8_t newaddr, uint32_t ifa_pref, uint32_t ifa_valid);

#endif
