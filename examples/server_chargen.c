#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../neat.h"
#include "util.h"
#include <errno.h>

/**********************************************************************

    chargen server

    server_chargen [OPTIONS]

    https://tools.ietf.org/html/rfc864

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
static uint16_t chargen_offset = 0;

#define BUFFERSIZE 32


static neat_error_code on_writable(struct neat_flow_operations *opCB);

static void
print_usage()
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    printf("server_chargen [OPTIONS]\n");
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

/*
    Read data and discard
*/
static neat_error_code on_readable(struct neat_flow_operations *opCB)
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
            fprintf(stderr, "%s - neat_read error: %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }

    if (buffer_filled > 0) {
        if (config_log_level >= 1) {
            printf("data received - %d byte\n", buffer_filled);
        }
        if (config_log_level >= 2) {
            fwrite(buffer, sizeof(char), buffer_filled, stdout);
            printf("\n");
            fflush(stdout);
        }
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

    opCB->on_writable = on_writable;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

/*
    //XXX behave more like specified in the rfc (UDP, TCP)
*/
static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    unsigned char buffer[BUFFERSIZE];
    int i;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    for (i = 0; i < BUFFERSIZE - 2; i++) {
        buffer[i] = 33 + ((chargen_offset + i) % 72);
    }

    buffer[i++] = '\r';
    buffer[i++] = '\n';

    chargen_offset = (chargen_offset + 1)%72;

    opCB->on_writable = NULL;
    opCB->on_all_written = on_all_written;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    code = neat_write(opCB->ctx, opCB->flow, buffer, BUFFERSIZE, NULL, 0);
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write error: %d\n", __func__, (int)code);
        return on_error(opCB);
    }

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
    opCB->on_writable = on_writable;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
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
