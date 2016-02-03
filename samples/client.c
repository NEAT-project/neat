#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <uv.h>
#include "../neat.h"
#include "../neat_internal.h"

/*
    Simple neat client
*/

static uint32_t config_rcv_buffer_size = 256;
static uint32_t config_snd_buffer_size = 128;
static uint16_t config_log_level = 1;
static char config_property[] = "NEAT_PROPERTY_TCP_REQUIRED,NEAT_PROPERTY_IPV4_REQUIRED";

#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

struct std_buffer {
    unsigned char *buffer;
    uint32_t buffer_filled;
};

static struct neat_flow_operations ops;
static struct std_buffer stdin_buffer;
static struct neat_ctx *ctx = NULL;
static struct neat_flow *flow = NULL;
uv_loop_t *uv_loop;
uv_tty_t tty;
static unsigned char *buffer_rcv = NULL;
static unsigned char *buffer_snd= NULL;

void tty_read(uv_stream_t *stream, ssize_t bytes_read, const uv_buf_t *buffer);
void tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf);

/*
    print usage and exit
*/
static void print_usage()
{
    printf("client [OPTIONS] HOST PORT\n");
    printf("\t- P \tneat properties (%s)\n", config_property);
    printf("\t- R \treceive buffer in byte (%d)\n", config_rcv_buffer_size);
    printf("\t- S \tsend buffer in byte (%d)\n", config_snd_buffer_size);
    printf("\t- v \tlog level 0..2 (%d)\n", config_log_level);
}

/*
    Error handler
*/
static neat_error_code on_error(struct neat_flow_operations *opCB)
{
    exit(EXIT_FAILURE);
}

/*
    Read data until buffered_amount == 0 - then stop event loop!
*/
static neat_error_code on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    uint32_t buffer_filled;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer_rcv, config_rcv_buffer_size, &buffer_filled);
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            if (config_log_level >= 1) {
                printf("on_readable - NEAT_ERROR_WOULD_BLOCK\n");
            }
            return 0;
        } else {
            debug_error("code: %d", (int)code);
            return on_error(opCB);
        }
    }

    if (buffer_filled > 0) {
        if (config_log_level >= 1) {
            printf("received %d byte\n", buffer_filled);
        }

        fwrite(buffer_rcv, sizeof(char), buffer_filled, stdout);
        fflush(stdout);

    } else {
        if (config_log_level >= 1) {
            printf("disconnected\n");
        }
        ops.on_readable = NULL;
        neat_stop_event_loop(opCB->ctx);
    }
    return 0;
}

/*
    Send data from stdin
*/
static neat_error_code on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;

    code = neat_write(opCB->ctx, opCB->flow, stdin_buffer.buffer, stdin_buffer.buffer_filled);
    if (code) {
        debug_error("code: %d", (int)code);
        return on_error(opCB);
    }

    if (config_log_level >= 1) {
        printf("sent %d bytes\n", stdin_buffer.buffer_filled);
    }

    // stop writing
    opCB->on_writable = NULL;
    // data sent - continue reading from stdin
    uv_read_start((uv_stream_t*) &tty, tty_alloc, tty_read);
    return 0;
}


static neat_error_code on_connected(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 1) {
        printf("connected - ");

        if (opCB->flow->family == AF_INET) {
            printf("IPv4 - ");
        } else if (opCB->flow->family == AF_INET6) {
            printf("IPv6 - ");
        }

        switch (opCB->flow->sockProtocol) {
        case IPPROTO_TCP:
            printf("TCP ");
            break;
        case IPPROTO_UDP:
            printf("UDP ");
            break;
#ifdef IPPROTO_SCTP
        case IPPROTO_SCTP:
            printf("SCTP ");
            break;
#endif
#ifdef IPPROTO_UDPLITE
        case IPPROTO_UDPLITE:
            printf("UDPLite ");
            break;
#endif
        default:
            printf("protocol #%d", opCB->flow->sockProtocol);
            break;
        }
        printf("\n");
    }

    opCB->on_readable = on_readable;
    return 0;
}

/*
    Read from stdin
*/
void tty_read(uv_stream_t *stream, ssize_t buffer_filled, const uv_buf_t *buffer)
{
    if (config_log_level >= 1) {
        printf("tty_read called with buffer_filled %zd\n", buffer_filled);
    }
    if (buffer_filled == UV_EOF) {
        if (config_log_level >= 1) {
            printf("stdin closed\n");
        }
        uv_read_stop(stream);
        ops.on_writable = NULL;
        neat_set_operations(ctx, flow, &ops);
        neat_stop_event_loop(ctx);
    }
    if (buffer_filled > 0) {

        // copy input to app buffer
        stdin_buffer.buffer_filled = buffer_filled;
        memcpy(stdin_buffer.buffer, buffer->base, buffer_filled);

        // stop reading from stdin and set write callback
        uv_read_stop(stream);
        ops.on_writable = on_writable;
        neat_set_operations(ctx, flow, &ops);
    }
}

void tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf)
{
    buf->len = config_rcv_buffer_size;
    buf->base = malloc(config_rcv_buffer_size);
}

int main(int argc, char *argv[])
{
    uint64_t prop;
    int arg, result;
    char *arg_property = config_property;
    char *arg_property_ptr;
    char arg_property_delimiter[] = ",;";

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "P:R:S:v:")) != -1) {
        switch(arg) {
        case 'P':
            arg_property = optarg;
            if (config_log_level >= 1) {
                printf("option - properties: %s\n", arg_property);
            }
            break;
        case 'R':
            config_rcv_buffer_size = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - receive buffer size: %d\n", config_rcv_buffer_size);
            }
            break;
        case 'S':
            config_snd_buffer_size = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - send buffer size: %d\n", config_snd_buffer_size);
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

    if (optind + 2 != argc) {
        debug_error("argument error");
        print_usage();
        goto cleanup;
    }

    if ((buffer_rcv = malloc(config_rcv_buffer_size)) == NULL) {
        debug_error("could not allocate receive buffer");
        result = EXIT_FAILURE;
        goto cleanup;
    }
    if ((buffer_snd = malloc(config_snd_buffer_size)) == NULL) {
        debug_error("could not allocate send buffer");
        result = EXIT_FAILURE;
        goto cleanup;
    }
    if ((stdin_buffer.buffer = malloc(config_snd_buffer_size)) == NULL) {
        debug_error("could not allocate stdin buffer");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if ((ctx = neat_init_ctx()) == NULL) {
        debug_error("could not initialize context");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    uv_loop = ctx->loop;
    uv_tty_init(uv_loop, &tty, 0, 1);
    uv_read_start((uv_stream_t*) &tty, tty_alloc, tty_read);

    // new neat flow
    if ((flow = neat_new_flow(ctx)) == NULL) {
        debug_error("neat_new_flow");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set properties (TCP only etc..)
    if (neat_get_property(ctx, flow, &prop)) {
        debug_error("neat_get_property");
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
        debug_error("neat_set_property");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set callbacks
    ops.on_connected = on_connected;
    ops.on_error = on_error;

    if (neat_set_operations(ctx, flow, &ops)) {
        debug_error("neat_set_operations");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // wait for on_connected or on_error to be invoked
    if (neat_open(ctx, flow, argv[argc - 2], argv[argc - 1]) == NEAT_OK) {
        neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    } else {
        debug_error("neat_open");
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    free(buffer_rcv);
    free(buffer_snd);
    free(stdin_buffer.buffer);

    // cleanup
    if (flow != NULL) {
        neat_free_flow(flow);
    }
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
