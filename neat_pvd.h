#ifndef NEAT_PVD_H
#define NEAT_PVD_H

#include <stdint.h>
#ifdef __linux__
    #include <netinet/in.h>
#elif _WIN32
    #include <inaddr.h>
    #include <in6addr.h>
#endif
#include <ldns/ldns.h>

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

struct pvd_async_query {
    void *data;
    ldns_buffer *dns_snd_buf;
    uv_buf_t *dns_uv_snd_buf;
    uv_udp_send_t *dns_snd_handle;
    uv_udp_t *resolve_handle;
    struct sockaddr_in *dst_addr4;
    struct sockaddr_in6 *dst_addr6;
    struct neat_pvd *pvd;
    LIST_ENTRY(pvd_async_query) next_query;
};

struct pvd_async_query;
LIST_HEAD(pvd_async_queries, pvd_async_query);

struct neat_pvd {
    struct neat_ctx *nc;
    struct neat_event_cb newaddr_cb;
    struct pvd_results results;
    struct pvd_async_queries queries;
};
//Add/remove addresses from src. address list
// void neat_addr_update_src_list(struct neat_ctx *nc,
//         struct sockaddr_storage *src_addr, uint32_t if_idx,
//         uint8_t newaddr, uint32_t ifa_pref, uint32_t ifa_valid);

#endif
