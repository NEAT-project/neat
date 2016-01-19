#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../neat.h"

/*
    This is simple chargen server (RFC 862) for neat
*/

#define NO_DEBUG_INFO
#define CHARLEN 72

#ifdef NO_DEBUG_INFO
#define debug_info(M, ...)
#else
#define debug_info(M, ...) fprintf(stderr, "[INFO][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

static struct neat_flow_operations ops;
static uint32_t chargen_offset = 0;

static uint64_t on_error(struct neat_flow_operations *opCB) {
    exit(EXIT_FAILURE);
}

/*
    send CHARLEN chars to client
*/
static uint64_t on_writable(struct neat_flow_operations *opCB) {
    neat_error_code code;
    unsigned char buffer[CHARLEN];

    for (int i = 0; i < CHARLEN; i++) {
        buffer[i] = 33+((chargen_offset+i)%72);
    }

    chargen_offset++;
    if (chargen_offset >= 72) {
        chargen_offset = 0;
    }

    code = neat_write(opCB->ctx, opCB->flow, buffer, CHARLEN);
    if (code) {
        debug_error("neat_write - code: %d", (int)code);
        return on_error(opCB);
    } else {
        debug_info("neat_write - %d byte", CHARLEN);
    }

    return 0;
}

static uint64_t on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    debug_info();
    opCB->on_writable = on_writable;
    return 0;
}

int main(int argc, char *argv[])
{
    struct neat_ctx *ctx = neat_init_ctx();
    struct neat_flow *flow;
    uint64_t prop;

    // check for successful context
    if (ctx == NULL) {
        debug_error("could not initialize context");
        exit(EXIT_FAILURE);
    }

    // new neat flow
    if((flow = neat_new_flow(ctx)) == NULL) {
        debug_error("neat_new_flow");
        exit(EXIT_FAILURE);
    }

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    //ops.on_all_written = on_all_written;
    if (neat_set_operations(ctx, flow, &ops)) {
        debug_error("neat_set_operations");
        exit(EXIT_FAILURE);
    }

    // get properties
    if (neat_get_property(ctx, flow, &prop)) {
        debug_error("neat_get_property");
        exit(EXIT_FAILURE);
    }

    prop |= NEAT_PROPERTY_TCP_REQUIRED;
    prop |= NEAT_PROPERTY_IPV4_REQUIRED;

    // set properties
    if (neat_set_property(ctx, flow, prop)) {
        debug_error("neat_set_property");
        exit(EXIT_FAILURE);
    }

    // wait for on_connected or on_error to be invoked
    if (neat_accept(ctx, flow, "*", "8080")) {
        debug_error("neat_accept");
        exit(EXIT_FAILURE);
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    // cleanup
    neat_free_flow(flow);
    neat_free_ctx(ctx);
    exit(EXIT_SUCCESS);
}
