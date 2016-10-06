#ifndef NEAT_STAT_H
#define NEAT_STAT_H

#include <stdint.h>
#include <string.h>
#include <jansson.h>
#include "neat_internal.h"

/* Stats to provide to NEAT about a given TCP flow.
 * TODO: Choose the right subset of stats */
struct neat_tcp_info {
    uint8_t retransmits;

    /* Metrics from the TCP_INFO struct */
    uint32_t tcpi_pmtu;
    uint32_t tcpi_rcv_ssthresh;
    uint32_t tcpi_rtt;
    uint32_t tcpi_rttvar;
    uint32_t tcpi_snd_ssthresh;
    uint32_t tcpi_snd_cwnd;
    uint32_t tcpi_advmss;
    uint32_t tcpi_reordering;

    uint32_t tcpi_rcv_rtt;
    uint32_t tcpi_rcv_space;
    uint32_t tcpi_total_retrans;
};

/* Struct to keep flow statistics
 * These stats could well be kept in the neat_flow struct */
struct neat_flow_statistics {
    uint64_t bytes_sent;
    uint64_t bytes_received;
};

void neat_stats_build_json(struct neat_ctx *ctx, char **json_stats);


#endif
