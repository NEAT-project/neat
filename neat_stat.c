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

/* This function assumes it is only called when the flow is a TCP flow */
void neat_get_tcp_info(neat_flow *flow, struct neat_tcp_info *tcpinfo)
{
    /* Call the os-specific TCP-info-gathering function and copy the outputs into the
     * relevant fields of the neat-generic tcp-info struct */
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

#ifdef __linux__
    linux_get_tcp_info(flow, tcpinfo);
#else
    // TODO: implement error reporting for not-supported OSes
    memset(tcpinfo, 0, sizeof(struct neat_tcp_info));
#endif
}

/* Traverse the relevant subsystems of NEAT and gather the stats
   then format the stats as a json string to return */
void neat_stats_build_json(struct neat_ctx *mgr, char **json_stats)
{
	json_t *json_root, *protostat, *newflow;
    struct neat_flow *flow;
    struct neat_tcp_info *neat_tcpi;
    uint flowcount;

	neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    flowcount = 0;
	json_root = json_object();

    LIST_FOREACH(flow, &mgr->flows, next_flow) {
        flowcount++;

        /* Create entries for flow#n in a separate object */
        newflow = json_object();;

        json_object_set_new( newflow, "flow number", json_integer(flowcount));
        json_object_set_new( newflow, "remote_host", json_string( flow->name ));
        json_object_set_new( newflow, "socket type", json_integer( flow->socket->type ));
        json_object_set_new( newflow, "sock_protocol",
                json_integer( neat_stack_to_protocol(flow->socket->stack)));
        json_object_set_new( newflow, "port", json_integer( flow->port ));
        json_object_set_new( newflow, "writeSize", json_integer( flow->writeSize));
        json_object_set_new( newflow, "readSize", json_integer( flow->readSize));
        json_object_set_new( newflow, "bytes sent", json_integer( flow->flow_stats.bytes_sent));
        json_object_set_new( newflow, "bytes received", json_integer( flow->flow_stats.bytes_received ));
        json_object_set_new(json_root, "flow", newflow);
        /* Gather stack-specific info */
        switch (flow->socket->stack) {
            case NEAT_STACK_UDP:
                break;
            case NEAT_STACK_TCP:
                {
                    struct neat_tcp_info info;
                    neat_get_tcp_info(flow, &info);
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
                    json_object_set_new(protostat, "rcv_rtt", json_integer(neat_tcpi->tcpi_rcv_rtt));
                    json_object_set_new(protostat, "rcv_space", json_integer(neat_tcpi->tcpi_rcv_space));
                    json_object_set_new(protostat, "total retrans", json_integer(neat_tcpi->tcpi_total_retrans));

                    json_object_set_new(newflow, "tcpstats", protostat);
                    break;
                }
            case NEAT_STACK_SCTP:
                break;
            case NEAT_STACK_UDPLITE:
                break;
            case NEAT_STACK_SCTP_UDP:
                break;
        }
    }
    json_object_set_new( json_root, "Number of flows", json_integer( flowcount ));

	/* Callers must remember to free the output */
	*json_stats = json_dumps(json_root, 0);

	json_decref(json_root);

	return;
}



