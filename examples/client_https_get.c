#include <neat.h>
#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**********************************************************************

    HTTPS-GET client in neat

    client_https_get [OPTIONS] HOST

    -u : URI
    -P : property file
    -v : log level (0 .. 2)

    * connect to HOST and send GET request
    * write response to stdout

**********************************************************************/

static uint32_t config_rcv_buffer_size = 1024;
static char request[512];
static uint8_t config_log_level = 0;
static const char *request_tail = "HTTP/1.1\r\nHost: %s\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";
static char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"SCTP\",\
            \"precedence\": 1\
        },\
        {\
            \"value\": \"SCTP/UDP\",\
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
    int arg = 0;
    char *arg_property = NULL;
    int result;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    snprintf(request, sizeof(request), "GET %s %s", "/", request_tail);

    while ((arg = getopt(argc, argv, "P:u:v:")) != -1) {
        switch(arg) {
        case 'P':
            if (read_file(optarg, &arg_property) < 0) {
                fprintf(stderr, "Unable to read properties from %s: %s", optarg, strerror(errno));
                result = EXIT_FAILURE;
                goto cleanup;
            }
            if (config_log_level >= 1) {
                fprintf(stderr, "%s - option - properties: %s\n", __func__, arg_property);
            }
            break;
        case 'u':
            snprintf(request, sizeof(request), "GET %s %s", optarg, request_tail);
            break;
        case 'v':
            config_log_level = atoi(optarg);
            if (config_log_level >= 1) {
                fprintf(stderr, "%s - option - log level: %d\n", __func__, config_log_level);
            }
            break;
        default:
            fprintf(stderr, "usage: client_https_get [OPTIONS] HOST\n");
            goto cleanup;
            break;
        }
    }

    if (optind + 1 != argc) {
        fprintf(stderr, "usage: client_https_get [OPTIONS] HOST\n");
        goto cleanup;
    }
    printf("requesting: %s\n", request);

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "could not initialize context\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (config_log_level == 0) {
        neat_log_level(ctx, NEAT_LOG_ERROR);
    } else if (config_log_level == 1){
        neat_log_level(ctx, NEAT_LOG_WARNING);
    } else {
        neat_log_level(ctx, NEAT_LOG_DEBUG);
    }

    if ((flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "could not initialize context\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (neat_set_property(ctx, flow, arg_property ? arg_property : config_property)) {
        fprintf(stderr, "%s - error: neat_set_property\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    neat_set_operations(ctx, flow, &ops);
    neat_log_level(ctx, NEAT_LOG_DEBUG);

    // wait for on_connected or on_error to be invoked
    if (neat_open(ctx, flow, argv[argc - 1], 443, NULL, 0) == NEAT_OK)
        neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    else {
        fprintf(stderr, "Could not open flow\n");
        result = EXIT_FAILURE;
    }

cleanup:
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    if (arg_property) {
        free(arg_property);
    }
    exit(result);
}
