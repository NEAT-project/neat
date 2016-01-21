#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include "../neat.h"

/*
    Simple neat client for echo, discard and daytime server
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

static uint64_t on_error(struct neat_flow_operations *opCB) {
    exit(EXIT_FAILURE);
}

/*
    Read data until buffered_amount == 0 - then stop event loop!
*/
static uint64_t on_readable(struct neat_flow_operations *opCB) {
    // data is available to read
    unsigned char buffer[BUFFERSIZE];
    uint32_t buffered_amount;
    neat_error_code code;


    code = neat_read(opCB->ctx, opCB->flow, buffer, BUFFERSIZE, &buffered_amount);
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            debug_info("NEAT_ERROR_WOULD_BLOCK");
            return 0;
        } else {
            debug_error("code: %d", (int)code);
            return on_error(opCB);
        }
    }

    if (buffered_amount > 0) {
        debug_info("got some data - %d byte", buffered_amount);
        fwrite(buffer, sizeof(char), buffered_amount, stdout);
        printf("\n");
        fflush(stdout);
    } else {
        debug_info("buffered_amount is <= 0 - neat_stop_event_loop()");
        ops.on_readable = NULL;
        neat_stop_event_loop(opCB->ctx);
    }
    return 0;
}

/*
    Read from stdin and send it
*/
static uint64_t on_writable(struct neat_flow_operations *opCB) {
    neat_error_code code;
    unsigned char buffer[BUFFERSIZE];
    struct pollfd fds;
    int ret, bytes_read;

    debug_info("wohoo!");

    fds.fd = 0; /* this is STDIN */
    fds.events = POLLIN;
    ret = poll(&fds, 1, 1000);

    if (ret > 0) {
        while ((bytes_read = read(0, buffer, BUFFERSIZE)) > 0) {
            debug_info("trying to send..");
            code = neat_write(opCB->ctx, opCB->flow, buffer, bytes_read);
            if (code) {
                debug_error("code: %d", (int)code);
                return on_error(opCB);
            }
            debug_info("data sent - %d bytes", bytes_read);
        }
    } else if (ret == 0) {
        debug_info("poll timeout!");
    } else {
        debug_info("poll error!");
    }

    return 0;
}


static uint64_t on_connected(struct neat_flow_operations *opCB) {
    debug_info();

    opCB->on_writable = on_writable;
    opCB->on_writable = on_writable;
    return 0;
}

int main(int argc, char *argv[]) {
    struct neat_ctx *ctx = neat_init_ctx();
    struct neat_flow *flow;
    uint64_t prop;

    // check for argumets
    if (argc != 3) {
        fprintf(stderr, "Insufficient arguments!\n");
        fprintf(stderr, "Usage: %s ADDRESS PORT\n",argv[0]);
        exit(EXIT_FAILURE);
    }

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
    //prop |= NEAT_PROPERTY_OPTIONAL_SECURITY;
    prop |= NEAT_PROPERTY_TCP_REQUIRED; /* FIXME: Remove this once HE works */
    //prop |= NEAT_PROPERTY_UDP_REQUIRED;
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
    if (neat_open(ctx, flow, argv[1], argv[2])) {
        debug_error("neat_open");
        exit(EXIT_FAILURE);
    }
    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    // cleanup
    neat_free_flow(flow);
    neat_free_ctx(ctx);

    exit(EXIT_SUCCESS);
}
