#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "../neat.h"
#include "../neat_internal.h"
#include <usrsctp.h>
#include "../neat_usrsctp_internal.h"

// clang -g neat_server.c ../build/libneatS.a -luv -lldns -lmnl

#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)


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

static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    printf("neat_usrsctp_server: on_error\n");
    exit (EXIT_FAILURE);
}


static uint64_t
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    printf("received bytes=%zd\n", (opCB->flow)->readlen);
    if (!((opCB->flow)->readlen)) { // eof
        fflush(stdout);
        opCB->on_readable = NULL; // do not read more
        neat_usrsctp_close_sockflow(opCB->flow);
    } else if ((opCB->flow)->readlen > 0) {
        fwrite((opCB->flow)->readbuffer, 1, (opCB->flow)->readlen, stdout);
    }
    return 0;
}


static uint64_t
on_writable(struct neat_flow_operations *opCB)
{
    printf("on_writable \n");
    return 0;
}


static uint64_t
on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    printf("neat_usrsctp_server: on_connected\n");
    opCB->on_writable = on_writable;
    opCB->on_readable = on_readable;
    return 0;
}

void
debug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}


int main(int argc, char *argv[])
{
    struct neat_ctx *ctx = neat_init_ctx();
    struct neat_flow *flow;
    uint64_t prop;
    int result = 0;

    if (ctx == NULL) {
        fprintf(stderr, "could not initialize context\n");
        exit(EXIT_FAILURE);
    }
    usrsctp_init(0, NULL, debug_printf);
    usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
    flow = neat_new_flow(ctx);
    ops.on_connected = on_connected;
    ops.on_error = on_error;
    ops.on_readable = on_readable;
    neat_set_operations(ctx, flow, &ops);
    neat_get_property(ctx, flow, &prop);
    prop |= NEAT_PROPERTY_SCTP_REQUIRED;
    prop |= NEAT_PROPERTY_IPV4_REQUIRED;
    prop |= NEAT_PROPERTY_IPV6_BANNED;
    neat_set_property(ctx, flow, prop);
    ctx->flow = flow;
    // wait for on_connected or on_error to be invoked
    if (neat_accept(ctx, flow, "172.16.204.131", "5001")) {
        debug_error("neat_accept");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    // cleanup
cleanup:
    if (flow != NULL) {
        neat_free_flow(flow);
    }
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
