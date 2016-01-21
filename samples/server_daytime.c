#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
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
static uint64_t on_readable(struct neat_flow_operations *opCB);

static uint64_t on_error(struct neat_flow_operations *opCB) {
    exit(EXIT_FAILURE);
}

/*
    Write time and date as string - then close flow
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
        debug_error("neat_write - code: %d", (int)code);
        return on_error(opCB);
    }

    // close flow after sending
    debug_info("time sent - closing flow");
    opCB->on_writable = NULL;
    free(opCB->userData);
    opCB->userData = NULL;
    neat_free_flow(opCB->flow);
    return 0;
}

static uint64_t on_readable(struct neat_flow_operations *opCB) {
    // data is available to read
    unsigned char buffer[BUFFERSIZE];
    uint32_t buffer_filled;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer, BUFFERSIZE, &buffer_filled);
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            debug_error("NEAT_ERROR_WOULD_BLOCK");
            return 0;
        } else {
            debug_error("neat_read - code: %d", (int)code);
            return on_error(opCB);
        }
    }

    if (!buffer_filled) {
        // remote side should not shutdown...
        debug_error("eof unexpected");
        return on_error(opCB);
    }

    debug_info("got some data - discarding...");
    //opCB->on_readable = NULL;
    //opCB->on_writable = on_writable;
    return 0;
}

static uint64_t
on_connected(struct neat_flow_operations *opCB)
{
    debug_info();
    opCB->on_writable = on_writable;
    opCB->on_readable = on_readable;
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

    debug_info("freeing (flow + ctx) and bye bye!");
    neat_free_flow(flow);
    neat_free_ctx(ctx);
    exit(EXIT_SUCCESS);
}
