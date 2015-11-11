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

static struct neat_socket_operations ops;

static uint64_t
on_error(struct neat_socket_operations *opCB)
{
    fprintf(stderr,"unexpected error\n");
    exit (1);
    return 0;
}

static uint64_t
on_readable(struct neat_socket_operations *opCB)
{
    // data is available to read
    unsigned char buffer[32];
    uint32_t amt;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->sock, buffer, 32, &amt);
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

int written = 0;
int towrite;
static const char *request =
    "GET / HTTP/1.0\r\nHost:www.neat-project.org\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";

static uint64_t
on_writable(struct neat_socket_operations *opCB)
{
    uint32_t rv;
    neat_error_code code;
    code = neat_write(opCB->ctx, opCB->sock,
                      (const unsigned char *)request + written ,
                      towrite - written, &rv);
    if (code != NEAT_OK && code != NEAT_ERROR_WOULD_BLOCK) {
        return on_error(opCB);
    }

    written += rv;
    if ((towrite - written) <= 0) {
        // everything is written out - stop writing and start reading
        ops.on_writable = NULL;
        ops.on_readable = on_readable;
    }
    return 0;
}

static uint64_t
on_connected(struct neat_socket_operations *opCB)
{
    // now we can start writing
    ops.on_writable = on_writable;
    return 0;
}

int main(int argc, char *argv[])
{
    struct neat_ctx *ctx = neat_init_ctx();
    struct neat_socket *sock;
    uint64_t prop;

    towrite = strlen(request);
    sock = neat_new_socket(ctx);
    neat_get_property(ctx, sock, &prop);
    prop |= NEAT_PROPERTY_OPTIONAL_SECURITY;
    neat_set_property(ctx, sock, prop);

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    neat_set_operations(ctx, sock, &ops);

    // wait for on_connected or on_error to be invoked
    neat_open(ctx, sock, "www.neat-project.org", "80");
    neat_start_event_loop(ctx);

    neat_free_socket(sock);
    neat_free_ctx(ctx);
    return 0;
}
