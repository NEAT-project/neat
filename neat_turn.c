#include <sys/types.h>
#include <netinet/in.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "neat.h"

static neat_error_code
neat_write_via_turn(struct neat_ctx *ctx, struct neat_flow *flow,
                      const unsigned char *buffer, uint32_t amt)
{
    // TODO: send data via TURN connection

    return NEAT_OK;
}

static neat_error_code
neat_read_via_turn(struct neat_ctx *ctx, struct neat_flow *flow,
                     unsigned char *buffer, uint32_t amt, uint32_t *actualAmt)
{
    // TODO: read data via TURN connection

    return NEAT_OK;
}

static int
neat_accept_via_turn(struct neat_ctx *ctx, struct neat_flow *flow, int fd)
{
    // TODO: accept new client via TURN connection

    return -1;
}

static int
neat_connect_via_turn(struct neat_ctx *ctx, struct neat_flow *flow)
{
    // Operation not supported by TURN
    return -1;
}

static int
neat_close_via_turn(struct neat_ctx *ctx, struct neat_flow *flow)
{
    // TODO
    return 0;
}

static int
neat_listen_via_turn(struct neat_ctx *ctx, struct neat_flow *flow)
{
    // TODO: TURN allocation and permissions
}

