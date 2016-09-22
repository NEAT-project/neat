#include <sys/socket.h>
#include <stdint.h>

#include "neat.h"
#include "neat_qos.h"

#if defined(USRSCTP_SUPPORT)          
    #include "neat_usrsctp_internal.h"
    #include <usrsctp.h>              
#endif                                
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    #include "neat_bsd_internal.h"
#endif


uint8_t 
neat_map_qos_to_dscp(uint8_t qos)
{
    /*
     * Mask out the top two bits of the NEAT QoS, the TOS field uses the bottom
     * two bits for ECN, shift up to allow for this.
     */
    return (0x3F & qos) << 2;
}

neat_error_code
neat_set_tos(struct neat_ctx *ctx, struct neat_flow *flow)
{
    uint8_t dscp; 
    int tos;

    dscp = neat_map_qos_to_dscp(flow->qos);
    tos = dscp | flow->ecn;

    switch (flow->socket->stack) {
#if defined(SCTP_PEER_ADDR_PARAMS)
    case NEAT_STACK_SCTP:
    {
        struct sctp_paddrparams params;
        params.spp_dscp = dscp;
        params.spp_flags = SPP_DSCP;

#if defined(USRSCTP_SUPPORT)  
        if(usrsctp_setsockopt(flow->socket->usrsctp_socket, 
            IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &params, sizeof(params)) == -1) {
            return NEAT_ERROR_UNABLE;
        }
#else
        if(setsockopt(flow->socket->fd, 
            IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &params, sizeof(params)) == -1) {
            return NEAT_ERROR_UNABLE;
        }
#endif //USRSCTP

        return NEAT_OK;
    }
#endif //SCTP_PEER_ADDR_PARAMS
    case NEAT_STACK_UDP:
    {
        if(setsockopt(flow->socket->fd, 
            IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
            return NEAT_ERROR_UNABLE;
        }
        return NEAT_OK;
    }
    default:
        return NEAT_OK;
    }
}

neat_error_code
neat_set_qos(struct neat_ctx *ctx, struct neat_flow *flow, uint8_t qos)
{
    flow->qos = qos;
    return neat_set_tos(ctx, flow);
}

neat_error_code
neat_set_ecn(struct neat_ctx *ctx, struct neat_flow *flow, uint8_t ecn)
{
    flow->ecn = 0x03 & ecn;
    return neat_set_tos(ctx, flow);
}
