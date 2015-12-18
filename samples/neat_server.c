#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../neat.h"

// clang -g neat_server.c ../build/libneatS.a -luv -lldns -lmnl

/*
 This is a very simple example of a basic server.
 Send a N, read 100 bytes, send one N, read 100 bytes, send
 a N and close.
*/

static struct neat_flow_operations ops;
struct sessionData {
    int toread;
    int iter;
};

static uint64_t
on_error(struct neat_flow_operations *opCB)
{
    fprintf(stderr,"neatserver unexpected error\n");
    exit (1);
    return 0;
}

static uint64_t on_readable(struct neat_flow_operations *opCB);

static uint64_t
on_writable(struct neat_flow_operations *opCB)
{
    struct sessionData *sd = (struct sessionData *)opCB->userData;
    uint32_t rv;
    neat_error_code code;
    code = neat_write(opCB->ctx, opCB->flow, (unsigned char *)"N", 1, &rv);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    }
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

static uint64_t
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    unsigned char buffer[32];
    uint32_t amt, needed;
    neat_error_code code;
    struct sessionData *sd = (struct sessionData *)opCB->userData;

    needed = (sd->toread > 32) ? 32 : sd->toread;
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

    if (ctx == NULL) {
        fprintf(stderr, "could not initialize context\n");
        exit(EXIT_FAILURE);
    }
    flow = neat_new_flow(ctx);
    ops.on_connected = on_connected;
    ops.on_error = on_error;
    neat_set_operations(ctx, flow, &ops);

    // wait for on_connected or on_error to be invoked
    neat_accept(ctx, flow, "localhost.ducksong.com", "8080");
    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    neat_free_flow(flow);
    neat_free_ctx(ctx);
    exit(EXIT_SUCCESS);
}
