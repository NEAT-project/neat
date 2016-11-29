#include <neat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "util.h"
#include <errno.h>

/**********************************************************************

    http server

    server_daytime [OPTIONS]

**********************************************************************/

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
    ]\
}";
static uint16_t config_log_level = 1;
static const char *response_header = "HTTP/1.0 200 OK\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";

#define BUFFERSIZE 33768

static neat_error_code on_writable(struct neat_flow_operations *opCB);

/*
    print usage and exit
*/
static void
print_usage()
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    printf("server_http [OPTIONS]\n");
    printf("\t- P <filename> \tneat properties, default properties:\n%s\n", config_property);
    printf("\t- v \tlog level 0..2 (%d)\n", config_log_level);
}

/*
    Error handler
*/
static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    exit(EXIT_FAILURE);
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    neat_error_code code;
    unsigned char buffer[BUFFERSIZE];
    uint32_t buffer_filled;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, buffer, BUFFERSIZE, &buffer_filled, NULL, 0);
    if (code != NEAT_OK) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read failed - code: %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }

    if (buffer_filled > 0) {
        if (config_log_level >= 1) {
            printf("received data - %d byte\n", buffer_filled);
        }
        if (config_log_level >= 2) {
            fwrite(buffer, sizeof(char), buffer_filled, stdout);
            printf("\n");
            fflush(stdout);
        }

        opCB->on_writable = on_writable;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);

    } else { // peer disconnected
        if (config_log_level >= 1) {
            printf("peer disconnected\n");
        }
        opCB->on_readable = NULL;
        opCB->on_writable = NULL;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
        neat_close(opCB->ctx, opCB->flow);
    }
    return NEAT_OK;
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    opCB->on_writable = NULL;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    neat_shutdown(opCB->ctx, opCB->flow);
    return NEAT_OK;
}

static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    char *stats = NULL;
    char buffer[BUFFERSIZE];

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_get_stats(opCB->ctx, &stats);
    if (code != NEAT_OK){
        fprintf(stderr, "%s - neat_get_stats() failed\n", __func__);
        return on_error(opCB);
    }

    if (config_log_level >= 2) {
        fprintf(stderr, "%s", stats);
    }

    snprintf(buffer, BUFFERSIZE, "%s%s%s%s%s\r\n", response_header, "<h1>Welcome to NEAT</h1>", "<pre>", stats, "</pre>");


    code = neat_write(opCB->ctx, opCB->flow, (const unsigned char *) buffer, strlen(buffer), NULL, 0);
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write failed - code: %d\n", __func__, (int)code);
        return on_error(opCB);
    }

    opCB->on_writable = NULL;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    neat_shutdown(opCB->ctx, opCB->flow);

    return NEAT_OK;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (config_log_level >= 1) {
        printf("peer connected\n");
    }

    opCB->on_readable = on_readable;
    opCB->on_writable = NULL;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    // uint64_t prop;
    int arg, result;
    char *arg_property = NULL;
    struct neat_ctx *ctx = NULL;
    struct neat_flow *flow = NULL;
    struct neat_flow_operations ops;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "P:v:")) != -1) {
        switch(arg) {
        case 'P':
            if (read_file(optarg, &arg_property) < 0) {
                fprintf(stderr, "Unable to read properties from %s: %s",
                        optarg, strerror(errno));
                result = EXIT_FAILURE;
                goto cleanup;
            }
            if (config_log_level >= 1) {
                printf("option - properties: %s\n", arg_property);
            }
            break;
        case 'v':
            config_log_level = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - log level: %d\n", config_log_level);
            }
            break;
        default:
            print_usage();
            goto cleanup;
            break;
        }
    }

    if (config_log_level == 0) {
        neat_log_level(NEAT_LOG_ERROR);
    } else if (config_log_level == 1){
        neat_log_level(NEAT_LOG_WARNING);
    } else {
        neat_log_level(NEAT_LOG_DEBUG);
    }

    if (optind != argc) {
        fprintf(stderr, "%s - argument error\n", __func__);
        print_usage();
        goto cleanup;
    }

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "%s - neat_init_ctx failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // new neat flow
    if ((flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set properties
    if (neat_set_property(ctx, flow, arg_property ? arg_property : config_property)) {
        fprintf(stderr, "%s - neat_set_property failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set callbacks
    ops.on_connected = on_connected;
    ops.on_error = on_error;

    if (neat_set_operations(ctx, flow, &ops)) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // wait for on_connected or on_error to be invoked
    if (neat_accept(ctx, flow, 8080, NULL, 0)) {
        fprintf(stderr, "%s - neat_accept failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    // cleanup
cleanup:
    if (arg_property)
        free(arg_property);

    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
