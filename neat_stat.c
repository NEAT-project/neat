#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "neat_internal.h"
#include "neat_core.h"
#include "neat_stat.h"
#ifdef __linux__
    #include "neat_linux_internal.h"
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    #include "neat_bsd_internal.h"
#endif


/* This function assumes it is only called when the flow is a TCP flow */
static int
get_tcp_info(neat_flow *flow, struct neat_tcp_info *tcpinfo)
{
    /* Call the os-specific TCP-info-gathering function and copy the outputs into the
     * relevant fields of the neat-generic tcp-info struct */
    nt_log(flow->ctx, NEAT_LOG_DEBUG, "%s", __func__);

    memset(tcpinfo, 0, sizeof(struct neat_tcp_info));

#ifdef __linux__
    return linux_get_tcp_info(flow, tcpinfo);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    return bsd_get_tcp_info(flow, tcpinfo);
#else
    // TODO: implement error reporting for not-supported OSes

#endif


    return RETVAL_FAILURE;
}

static int collect_global_statistics(struct neat_ctx *ctx, struct neat_global_statistics *gstats)
{
    struct neat_flow *flow;

    LIST_FOREACH(flow, &ctx->flows, next_flow) {
        gstats->global_bytes_received += flow->flow_stats.bytes_received;
        gstats->global_bytes_sent += flow->flow_stats.bytes_sent;
    }

    return NEAT_OK;
}
/* Traverse the relevant subsystems of NEAT and gather the stats
   then format the stats as a json string to return */
void
nt_stats_build_json(struct neat_ctx *ctx, char **json_stats)
{
    json_t *json_root, *protostat, *newflow;
    struct neat_flow *flow;
    struct neat_tcp_info *neat_tcpi;
    struct neat_global_statistics gstats;
    uint flowcount;
    char flow_name[128];

    nt_log(ctx, NEAT_LOG_DEBUG, "%s", __func__);

    flowcount = 0;
    json_root = json_object();

    /* Collect global statistics
     * - Can be inlined with JSON generation to avoid having 2 passes */
    memset(&gstats, 0, sizeof(struct neat_global_statistics));
    collect_global_statistics(ctx, &gstats);

    LIST_FOREACH(flow, &ctx->flows, next_flow) {
        flowcount++;

        /* Create entries for flow#n in a separate object
         * TODO: Make each flow generate a json object containing its own properties */
        newflow = json_object();;

        json_object_set_new(newflow, "flow number",     json_integer( flowcount));
        json_object_set_new(newflow, "remote_host",     json_string(  flow->name ));
        json_object_set_new(newflow, "socket type",     json_integer( flow->socket->type ));
        json_object_set_new(newflow, "sock_protocol",   json_integer( nt_stack_to_protocol(flow->socket->stack)));
        json_object_set_new(newflow, "port",            json_integer( flow->port )) ;
        json_object_set_new(newflow, "ecn",            json_integer( flow->ecn ));
        json_object_set_new(newflow, "qos",            json_integer( flow->qos ));
        json_object_set_new(newflow, "write_size",      json_integer( flow->socket->write_size));
        json_object_set_new(newflow, "read_size",       json_integer( flow->socket->read_size));
        json_object_set_new(newflow, "bytes sent",      json_integer( flow->flow_stats.bytes_sent));
        json_object_set_new(newflow, "bytes received",  json_integer( flow->flow_stats.bytes_received ));
        json_object_set_new(newflow, "priority",  json_real( flow->priority ));

        snprintf(flow_name, 128, "flow-%d", flowcount);
        json_object_set_new(json_root, flow_name, newflow);
        json_object_set(newflow, "flow_properties", flow->properties);
        /* Gather stack-specific info */
        switch (flow->socket->stack) {
            case NEAT_STACK_UDP:
                /* Any UDP-specific statistics?*/
                break;
            case NEAT_STACK_TCP:
                {
                    struct neat_tcp_info info;
                    int rc = get_tcp_info(flow, &info);
                    if (rc)
                        break;
                    neat_tcpi = &info;

                    protostat = json_object();

                    json_object_set_new(protostat, "retransmits", json_integer(neat_tcpi->retransmits));
                    json_object_set_new(protostat, "pmtu", json_integer(neat_tcpi->tcpi_pmtu));
                    json_object_set_new(protostat, "rcv_ssthresh", json_integer(neat_tcpi->tcpi_rcv_ssthresh));
                    json_object_set_new(protostat, "rtt", json_integer(neat_tcpi->tcpi_rtt));
                    json_object_set_new(protostat, "rttvar", json_integer(neat_tcpi->tcpi_rttvar));
                    json_object_set_new(protostat, "ssthresh", json_integer(neat_tcpi->tcpi_snd_ssthresh));
                    json_object_set_new(protostat, "snd_cwnd", json_integer(neat_tcpi->tcpi_snd_cwnd));
                    json_object_set_new(protostat, "advmss", json_integer(neat_tcpi->tcpi_advmss));
                    json_object_set_new(protostat, "reordering", json_integer(neat_tcpi->tcpi_reordering));
                    json_object_set_new(protostat, "total retrans", json_integer(neat_tcpi->tcpi_total_retrans));

                    json_object_set_new(newflow, "tcpstats", protostat);
                    break;
                }
            case NEAT_STACK_MPTCP:
                /* TODO: add statistics */
                break;
            case NEAT_STACK_SCTP:
                break;
            case NEAT_STACK_UDPLITE:
                /* Any UDPLite-specific statistics? */
                break;
            case NEAT_STACK_SCTP_UDP:
                break;
        }
    }
    /* Global statistics */
    json_object_set_new( json_root, "Number of flows", json_integer( flowcount ));
    json_object_set_new( json_root, "Total bytes sent", json_integer(gstats.global_bytes_sent));
    json_object_set_new( json_root, "Total bytes received", json_integer(gstats.global_bytes_received));

    /* Callers must remember to free the output */
    *json_stats = json_dumps(json_root, JSON_INDENT(4));

    json_decref(json_root);

    return;
}
