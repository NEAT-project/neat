#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../neat.h"

/*
    This is simple daytime server (RFC 867) for neat
*/

//#define NO_DEBUG_INFO
#define BUFFERSIZE 32

#ifdef NO_DEBUG_INFO
#define debug_info(M, ...)
#else
#define debug_info(M, ...) fprintf(stderr, "[INFO][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)


static struct neat_flow_operations ops;
struct sessionData {
    int toread;
    int iter;
};

static uint64_t on_error(struct neat_flow_operations *opCB) {
    debug_error("unexpected error!");
    exit(EXIT_FAILURE);
}

static uint64_t on_readable(struct neat_flow_operations *opCB);

static uint64_t on_writable(struct neat_flow_operations *opCB) {
    struct sessionData *sd = (struct sessionData *)opCB->userData;
    neat_error_code code;
    debug_info();

    code = neat_write(opCB->ctx, opCB->flow, (unsigned char *)"N", 1);
    if (code != NEAT_OK) {
        return on_error(opCB);
    }

    if (sd->iter < 2) {
        // read now
        opCB->on_writable = NULL;
        opCB->on_readable = on_readable;
    } else {
        // we are done
        opCB->on_writable = NULL;
        free (opCB->userData);
        opCB->userData = NULL;
        neat_free_flow(opCB->flow);
    }
    return 0;
}

static uint64_t on_readable(struct neat_flow_operations *opCB) {
    // data is available to read
    unsigned char buffer[BUFFERSIZE];
    uint32_t amt, needed;
    neat_error_code code;
    struct sessionData *sd = (struct sessionData *)opCB->userData;

    debug_info();

    needed = (sd->toread > BUFFERSIZE) ? BUFFERSIZE : sd->toread;
    if (!needed) {
        return 0;
    }
    code = neat_read(opCB->ctx, opCB->flow, buffer, needed, &amt);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    }
    if (code != NEAT_OK) {
        return on_error(opCB);
    }
    if (!amt) { // eof is unexpected
        return on_error(opCB);
    } else if (amt > 0) {
        fwrite(buffer, 1, amt, stdout);
        sd->toread -= amt;
        if (sd->toread == 0) {
            sd->toread = 100;
            sd->iter++;
            opCB->on_readable = NULL;
            opCB->on_writable = on_writable;
        }
    }
    return 0;
}

static uint64_t
on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    debug_info();
    opCB->userData = malloc(sizeof(struct sessionData));
    ((struct sessionData *)(opCB->userData))->toread = 100;
    ((struct sessionData *)(opCB->userData))->iter = 0;
    opCB->on_writable = on_writable;
    return 0;
}

int main(int argc, char *argv[])
{
    struct neat_ctx *ctx = neat_init_ctx();
    struct neat_flow *flow;
    uint64_t prop;

    if (ctx == NULL) {
        fprintf(stderr, "could not initialize context\n");
        exit(EXIT_FAILURE);
    }

    // new neat flow
    if((flow = neat_new_flow(ctx)) == NULL) {
        debug_error("neat_new_flow");
        exit(EXIT_FAILURE);
    }

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    if (neat_set_operations(ctx, flow, &ops)) {
        debug_error("neat_set_operations");
        exit(EXIT_FAILURE);
    }

    // set properties (TCP only etc..)
    if (neat_get_property(ctx, flow, &prop)) {
        debug_error("neat_get_property");
        exit(EXIT_FAILURE);
    }
    prop |= NEAT_PROPERTY_TCP_REQUIRED;
    prop |= NEAT_PROPERTY_IPV4_REQUIRED;

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

    neat_free_flow(flow);
    neat_free_ctx(ctx);
    exit(EXIT_SUCCESS);
}
