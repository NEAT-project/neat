#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../neat.h"

#define BUFFERSIZE 32
#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

static struct neat_flow_operations ops;
struct neat_ctx *ctx;
struct neat_flow *flow;

static uint64_t on_writable(struct neat_flow_operations *opCB);

/*
    Error handler
*/
static uint64_t on_error(struct neat_flow_operations *opCB) {
    exit(EXIT_FAILURE);
}

/*
    Read data until buffered_amount == 0 - then stop event loop!
*/
static uint64_t on_readable(struct neat_flow_operations *opCB) {
    // data is available to read
    neat_error_code code;
    unsigned char buffer[BUFFERSIZE];
    uint32_t buffer_filled;

    code = neat_read(opCB->ctx, opCB->flow, buffer, BUFFERSIZE, &buffer_filled);
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            return 0;
        } else {
            debug_error("code: %d", (int)code);
            return on_error(opCB);
        }
    }
    return 0;
}

/*
    Send data from stdin
*/
static uint64_t on_writable(struct neat_flow_operations *opCB) {
    neat_error_code code;
    time_t time_now;
    char* time_string;

    // get current time
	time_now = time(NULL);
	time_string = ctime(&time_now);

    code = neat_write(opCB->ctx, opCB->flow, (const unsigned char *) time_string, strlen(time_string));
    if (code) {
        debug_error("code: %d", (int)code);
        return on_error(opCB);
    }

    // stop writing
    opCB->on_readable = NULL;
    opCB->on_writable = NULL;
    neat_free_flow(opCB->flow);
    return 0;
}


static uint64_t on_connected(struct neat_flow_operations *opCB) {
    opCB->on_readable = on_readable;
    opCB->on_writable = on_writable;

    return 0;
}

int main(int argc, char *argv[]) {
    uint64_t prop;
    ctx = neat_init_ctx();

    if (ctx == NULL) {
        debug_error("could not initialize context");
        exit(EXIT_FAILURE);
    }

    // new neat flow
    if((flow = neat_new_flow(ctx)) == NULL) {
        debug_error("neat_new_flow");
        exit(EXIT_FAILURE);
    }

    // set properties (TCP only etc..)
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

    // set callbacks
    ops.on_connected = on_connected;
    ops.on_error = on_error;

    if (neat_set_operations(ctx, flow, &ops)) {
        debug_error("neat_set_operations");
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
