#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../neat.h"

/**********************************************************************

    echo server

    server_echo [OPTIONS]

    https://tools.ietf.org/html/rfc862

**********************************************************************/

static uint32_t config_buffer_size = 512;
static uint16_t config_log_level = 1;
static char config_property[] = "NEAT_PROPERTY_SCTP_REQUIRED,NEAT_PROPERTY_IPV4_REQUIRED";

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

    printf("server_echo [OPTIONS]\n");
    printf("\t- P \tneat properties (%s)\n", config_property);
    printf("\t- S \tbuffer in byte (%d)\n", config_buffer_size);
    printf("\t- v \tlog level 0..2 (%d)\n", config_log_level);
}

struct echo_flow {
    unsigned char *buffer;
    uint32_t bytes;
    int stream_id;
};

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
            printf("received data - %d byte\n", ef->bytes);
        }
        if (config_log_level >= 2) {
            fwrite(ef->buffer, sizeof(char), ef->bytes, stdout);
            printf("\n");
            fflush(stdout);
        }

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
        neat_free_flow(opCB->flow);
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

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    // set callbacks
    opCB->on_readable = NULL;
    opCB->on_writable = NULL;
    opCB->on_all_written = on_all_written;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    /*
    if (ef->stream_id != -1) {
        code = neat_write_ex(opCB->ctx, opCB->flow, ef->buffer, ef->bytes, ef->stream_id);
    } else {
    */
        code = neat_write(opCB->ctx, opCB->flow, ef->buffer, ef->bytes, NULL, 0);
    // }
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write error: %d\n", __func__, (int)code);
        return on_error(opCB);
    }

    if (config_log_level >= 1) {
        if (ef->stream_id != -1) {
            printf("sent data - %d bytes to stream %d\n", ef->bytes, ef->stream_id);
        } else {
            printf("sent data - %d bytes\n", ef->bytes);
        }
    }

    return NEAT_OK;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    struct echo_flow *ef = NULL;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (config_log_level >= 1) {
        printf("peer connected\n");
    }

    // TODO: neat_get_stream_count()
    // TODO: Allocate a buffer for each no. of streams
    // TODO: Ensure on_writable/on_readable is only called for streams that isn't blocked?

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
    uint64_t prop;
    int arg, result;
    char *arg_property = config_property;
    char *arg_property_ptr = NULL;
    char arg_property_delimiter[] = ",;";
    static struct neat_ctx *ctx = NULL;
    static struct neat_flow *flow = NULL;
    static struct neat_flow_operations ops;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "P:S:v:")) != -1) {
        switch(arg) {
        case 'P':
            arg_property = optarg;
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

    // set properties (TCP only etc..)
    if (neat_get_property(ctx, flow, &prop)) {
        fprintf(stderr, "%s - neat_get_property failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // read property arguments
    arg_property_ptr = strtok(arg_property, arg_property_delimiter);

    while (arg_property_ptr != NULL) {
        if (config_log_level >= 1) {
            printf("setting property: %s\n", arg_property_ptr);
        }

        if (strcmp(arg_property_ptr,"NEAT_PROPERTY_OPTIONAL_SECURITY") == 0) {
            prop |= NEAT_PROPERTY_TCP_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_REQUIRED_SECURITY") == 0) {
            prop |= NEAT_PROPERTY_REQUIRED_SECURITY;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_MESSAGE") == 0) {
            prop |= NEAT_PROPERTY_MESSAGE;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_IPV4_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_IPV4_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_IPV4_BANNED") == 0) {
            prop |= NEAT_PROPERTY_IPV4_BANNED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_IPV6_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_IPV6_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_IPV6_BANNED") == 0) {
            prop |= NEAT_PROPERTY_IPV6_BANNED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_SCTP_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_SCTP_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_SCTP_BANNED") == 0) {
            prop |= NEAT_PROPERTY_SCTP_BANNED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_TCP_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_TCP_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_TCP_BANNED") == 0) {
            prop |= NEAT_PROPERTY_TCP_BANNED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_UDP_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_UDP_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_UDP_BANNED") == 0) {
            prop |= NEAT_PROPERTY_UDP_BANNED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_UDPLITE_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_UDPLITE_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_UDPLITE_BANNED") == 0) {
            prop |= NEAT_PROPERTY_UDPLITE_BANNED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_CONGESTION_CONTROL_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_CONGESTION_CONTROL_BANNED") == 0) {
            prop |= NEAT_PROPERTY_CONGESTION_CONTROL_BANNED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED") == 0) {
            prop |= NEAT_PROPERTY_RETRANSMISSIONS_REQUIRED;
        } else if (strcmp(arg_property_ptr,"NEAT_PROPERTY_RETRANSMISSIONS_BANNED") == 0) {
            prop |= NEAT_PROPERTY_RETRANSMISSIONS_BANNED;
        } else {
            printf("error - unknown property: %s\n", arg_property_ptr);
            print_usage();
            goto cleanup;
        }

       // get next property
       arg_property_ptr = strtok(NULL, arg_property_delimiter);
    }

    // set properties
    if (neat_set_property(ctx, flow, prop)) {
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
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
