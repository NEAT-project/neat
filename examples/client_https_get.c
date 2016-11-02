#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../neat.h"

/**********************************************************************

    HTTPS-GET client in neat

    client_https_get HOST [URI]

    * connect to HOST and send GET request
    * write response to stdout

**********************************************************************/

static uint32_t config_rcv_buffer_size = 1024;
static char request[512];
static const char *request_tail = "User-agent: libneat\r\nConnection: close\r\n\r\n";
static char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"SCTP\",\
            \"precedence\": 1\
        },\
        {\
            \"value\": \"TCP\",\
            \"precedence\": 1\
        }\
    ],\
    \"security\": {\
        \"value\": true,\
        \"precedence\": 2\
    }\
}";\

static neat_error_code on_error(struct neat_flow_operations *opCB)
{
    fprintf(stderr, "%s\n", __func__);
    exit(EXIT_FAILURE);
}

static neat_error_code on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    unsigned char buffer[config_rcv_buffer_size];
    uint32_t bytes_read = 0;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer, config_rcv_buffer_size, &bytes_read, NULL, 0);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    } else if (code != NEAT_OK) {
        return on_error(opCB);
    }

    if (!bytes_read) { // eof
        fflush(stdout);
        opCB->on_readable = NULL; // do not read more
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
        neat_stop_event_loop(opCB->ctx);
    } else if (bytes_read > 0) {
        fwrite(buffer, sizeof(char), bytes_read, stdout);
    }
    return 0;
}

static neat_error_code on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    code = neat_write(opCB->ctx, opCB->flow, (const unsigned char *)request, strlen(request), NULL, 0);
    if (code != NEAT_OK) {
        return on_error(opCB);
    }
    opCB->on_writable = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return 0;
}

static neat_error_code on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    opCB->on_readable = on_readable;
    opCB->on_writable = on_writable;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return 0;
}

int main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    struct neat_flow *flow = NULL;
    struct neat_flow_operations ops;
    int result;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: neat_https_get HOST [URI]\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (argc == 3) {
        snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\n%s",
                 argv[2], argv[1], request_tail);
    } else {
        snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: %s\r\n%s",
                 "/", argv[1], request_tail);

    }
    printf("requesting: %s\n", request);

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

    neat_set_property(ctx, flow, config_property);

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    neat_set_operations(ctx, flow, &ops);

    // wait for on_connected or on_error to be invoked
    if (neat_open(ctx, flow, argv[1], 443, NULL, 0) == NEAT_OK)
        neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    else {
        fprintf(stderr, "Could not open flow\n");
        result = EXIT_FAILURE;
    }

cleanup:
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
