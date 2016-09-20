#include <sys/socket.h>
#include <stdint.h>

#include "neat.h"
#include "neat_qos.h"

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
    uint8_t dscp, tos;

    switch (flow->socket->stack) {
    case NEAT_STACK_UDP:
        dscp = neat_map_qos_to_dscp(flow->qos);
        tos = dscp | flow->ecn;

        if(setsockopt(flow->socket->fd, 
            IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
            return NEAT_ERROR_UNABLE;
        }
        return NEAT_OK;
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

