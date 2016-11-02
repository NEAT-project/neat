#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../neat.h"
#include "../neat_internal.h"
#include "util.h"
#include <errno.h>

/**********************************************************************

    echo server

    server_echo [OPTIONS]

    https://tools.ietf.org/html/rfc862

A TLS example:
 server_echo -P NEAT_PROPERTY_REQUIRED_SECURITY,NEAT_PROPERTY_TCP_REQUIRED,NEAT_PROPERTY_IPV4_REQUIRED -v 2 -p cert.pem

**********************************************************************/

static uint32_t config_buffer_size = 512;
static uint16_t config_log_level = 2;
static uint16_t config_number_of_streams = 1988;
static char *config_property = "{\n\
    \"transport\": [\n\
        {\n\
            \"value\": \"SCTP\",\n\
            \"precedence\": 1\n\
        },\n\
        {\n\
            \"value\": \"TCP\",\n\
            \"precedence\": 1\n\
        }\n\
    ]\n\
}";
static char *pem_file = NULL;

static neat_error_code on_writable(struct neat_flow_operations *opCB);

struct echo_flow {
    unsigned char *buffer;
    uint32_t bytes;
    int stream_id;
};

/*
    print usage and exit
*/
static void
print_usage()
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    printf("server_echo [OPTIONS]\n");
    printf("\t- P <filename> \tneat properties, default properties:\n%s\n", config_property);
    printf("\t- S \tbuffer in byte (%d)\n", config_buffer_size);
    printf("\t- v \tlog level 0..2 (%d)\n", config_log_level);
    printf("\t- p \tpem file (none)\n");
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
    Read data until buffered_amount == 0 - then stop event loop!
*/
static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    neat_error_code code;
    struct echo_flow *ef = opCB->userData;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, ef->buffer, config_buffer_size, &ef->bytes, NULL, 0);
    if (code != NEAT_OK) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            if (config_log_level >= 1) {
                printf("on_readable - NEAT_ERROR_WOULD_BLOCK\n");
            }
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read error: %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }

    // we got some data
    if (ef->bytes > 0) {
        if (config_log_level >= 1) {
            printf("received data - %d bytes on stream %d of %d\n", ef->bytes, opCB->stream_id, opCB->flow->stream_count);
        }
        if (config_log_level >= 2) {
            fwrite(ef->buffer, sizeof(char), ef->bytes, stdout);
            printf("\n");
            fflush(stdout);
        }

        // remember stream_id
        ef->stream_id = opCB->stream_id;

        // echo data
        opCB->on_readable = NULL;
        opCB->on_writable = on_writable;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
    // peer disconnected - stop callbacks and free ressources
    } else {
        if (config_log_level >= 1) {
            printf("peer disconnected\n");
        }
        opCB->on_readable = NULL;
        opCB->on_writable = NULL;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
        free(ef->buffer);
        free(ef);
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

    opCB->on_readable = on_readable;
    opCB->on_writable = NULL;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    struct echo_flow *ef = opCB->userData;
    struct neat_tlv options[1];

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    options[0].tag           = NEAT_TAG_STREAM_ID;
    options[0].type          = NEAT_TYPE_INTEGER;
    options[0].value.integer = ef->stream_id;


    // set callbacks
    opCB->on_readable = NULL;
    opCB->on_writable = NULL;
    opCB->on_all_written = on_all_written;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    code = neat_write(opCB->ctx, opCB->flow, ef->buffer, ef->bytes, options, 1);
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write error: %d\n", __func__, (int)code);
        return on_error(opCB);
    }

    if (config_log_level >= 1) {
        printf("sent data - %d byte on stream %d\n", ef->bytes, ef->stream_id);
    }

    return NEAT_OK;
}


static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    struct echo_flow *ef = NULL;

    if (config_log_level >= 1) {
        printf("%s - available streams : %d\n", __func__, opCB->flow->stream_count);
    }

    if ((opCB->userData = calloc(1, sizeof(struct echo_flow))) == NULL) {
        fprintf(stderr, "%s - could not allocate echo_flow\n", __func__);
        exit(EXIT_FAILURE);
    }

    ef = opCB->userData;

    if ((ef->buffer = malloc(config_buffer_size)) == NULL) {
        fprintf(stderr, "%s - could not allocate buffer\n", __func__);
        exit(EXIT_FAILURE);
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
    int arg, result;
    char *arg_property = NULL;
    static struct neat_ctx *ctx = NULL;
    static struct neat_flow *flow = NULL;
    static struct neat_flow_operations ops;

    NEAT_OPTARGS_DECLARE(NEAT_OPTARGS_MAX);
    NEAT_OPTARGS_INIT();

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "P:S:p:v:")) != -1) {
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
        case 'S':
            config_buffer_size = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - buffer size: %d\n", config_buffer_size);
            }
            break;
        case 'p':
            pem_file = optarg;
            if (config_log_level >= 1) {
                printf("option - pem file: %s\n", pem_file);
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

    if (pem_file && neat_secure_identity(ctx, flow, pem_file)) {
        fprintf(stderr, "%s - neat_get_secure_identity failed\n", __func__);
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

    // set number of streams
    NEAT_OPTARG_INT(NEAT_TAG_STREAM_COUNT, config_number_of_streams);

    if (neat_set_operations(ctx, flow, &ops)) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // wait for on_connected or on_error to be invoked
    if (neat_accept(ctx, flow, 8080, NEAT_OPTARGS, NEAT_OPTARGS_COUNT)) {
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
