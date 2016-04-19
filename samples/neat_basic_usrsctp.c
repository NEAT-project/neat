#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "../neat.h"
#include "../neat_internal.h"
#include "../neat_usrsctp_internal.h"
#include <usrsctp.h>

// clang -g neat_basic_sctp.c ../build/libneatS.a -luv -lldns -lmnl

/*
 This is a very simple example of a basic client application.
 Connect by name, write out some data, and read some data while
 printing that to stdout.
*/

static struct neat_flow_operations ops;

static uint64_t
on_error(struct neat_flow_operations *opCB)
{
    fprintf(stderr,"unexpected error\n");
    exit (1);
    return 0;
}

static uint64_t
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
printf("on_readable\n");

    printf("received bytes=%zd\n", (opCB->flow)->readlen);
    if (!((opCB->flow)->readlen)) { // eof
        fflush(stdout);
        ops.on_readable = NULL; // do not read more
        neat_stop_event_loop(opCB->ctx);
    } else if ((opCB->flow)->readlen > 0) {
        fwrite((opCB->flow)->readbuffer, 1, (opCB->flow)->readlen, stdout);
    }
    return 0;
}

static const char *request =
    "GET / HTTP/1.0\r\nHost:bsd10.fh-muenster.de\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";

/*static uint64_t
on_all_written(struct neat_flow_operations *opCB)
{
    ops.on_readable = on_readable;
    return 0;
}*/

static uint64_t
on_writable(struct neat_flow_operations *opCB)
{

    neat_error_code code;
    printf("on_writable send request of length %lu\n %s\n", strlen(request), request);
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
on_all_written(struct neat_flow_operations *opCB)
{
    ops.on_readable = on_readable;
    return 0;
}


static uint64_t
on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    printf("on_connected\n");
    on_writable(opCB);
    ops.on_writable = on_writable;
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

    if (ctx == NULL) {
        fprintf(stderr, "could not initialize context\n");
        exit(EXIT_FAILURE);
    }
    usrsctp_init(0, NULL, debug_printf);

    flow = neat_new_flow(ctx);
    neat_get_property(ctx, flow, &prop);
    prop |= NEAT_PROPERTY_SCTP_REQUIRED;
    prop |= NEAT_PROPERTY_IPV4_REQUIRED;
    prop |= NEAT_PROPERTY_IPV6_BANNED;
    prop |= NEAT_PROPERTY_TCP_BANNED;
    prop |= NEAT_PROPERTY_UDP_BANNED;
    prop |= NEAT_PROPERTY_UDPLITE_BANNED;
    neat_set_property(ctx, flow, prop);

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    ops.on_writable = on_writable;
    ops.on_all_written = on_all_written;
    neat_set_operations(ctx, flow, &ops);
    // wait for on_connected or on_error to be invoked
    neat_open(ctx, flow, "212.201.121.100", "80");
    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    neat_usrsctp_close_sockflow(flow);
    neat_free_ctx(ctx);
    exit(EXIT_SUCCESS);
}
