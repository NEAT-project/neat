#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../neat.h"

// clang -g neat_basic.c ../build/libneatS.a -luv -lldns -lmnl

/*
 This is a very simple example of a basic client application.
 Connect by name, write out some data, and read some data while
 printing that to stdout.
*/

static struct neat_flow_operations ops;

static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    fprintf(stderr,"unexpected error\n");
    exit (1);
    return 0;
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    unsigned char buffer[32];
    uint32_t amt;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer, 32, &amt);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    }
    if (code != NEAT_OK) {
        return on_error(opCB);
    }
    if (!amt) { // eof
        fflush(stdout);
        ops.on_readable = NULL; // do not read more
        neat_stop_event_loop(opCB->ctx);
    } else if (amt > 0) {
        fwrite(buffer, 1, amt, stdout);
    }
    return 0;
}

static const char *request =
    "GET / HTTP/1.0\r\nHost:www.neat-project.org\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    ops.on_readable = on_readable;
    return 0;
}

static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    code = neat_write(opCB->ctx, opCB->flow,
                      (const unsigned char *)request,
                      strlen(request));
    if (code != NEAT_OK) {
        return on_error(opCB);
    }
    ops.on_writable = NULL;
    return 0;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    ops.on_writable = on_writable;
    return 0;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    struct neat_flow *flow = NULL;
    uint64_t prop;
    int result;

    result = EXIT_SUCCESS;

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "could not initialize context\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }
    if ((flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "could not initialize context\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }
    neat_get_property(ctx, flow, &prop);
    prop |= NEAT_PROPERTY_OPTIONAL_SECURITY;
    prop |= NEAT_PROPERTY_TCP_REQUIRED; /* FIXME: Remove this once HE works */
    neat_set_property(ctx, flow, prop);

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    ops.on_all_written = on_all_written;
    neat_set_operations(ctx, flow, &ops);

    // wait for on_connected or on_error to be invoked
    if (neat_open(ctx, flow, "www.neat-project.org", "80") == NEAT_OK)
        neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    else {
        fprintf(stderr, "Could not open flow\n");
        result = EXIT_FAILURE;
    }
cleanup:
    if (flow != NULL) {
        neat_free_flow(flow);
    }
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
