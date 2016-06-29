#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uv.h>
#include "../neat.h"
#include "../neat_internal.h"

/**********************************************************************

    simple neat client

    * connect to HOST and PORT
    * read from stdin and send data to HOST
    * write received data from peer to stdout

    client [OPTIONS] HOST PORT
    -P : neat properties
    -R : receive buffer in byte
    -S : send buffer in byte
    -v : log level (0 .. 2)
    -A : set primary destination address

**********************************************************************/

static uint32_t config_rcv_buffer_size = 256;
static uint32_t config_snd_buffer_size = 128;
static uint16_t config_log_level = 1;
static char *config_primary_dest_addr = NULL;
static char config_property[] = "NEAT_PROPERTY_TCP_REQUIRED,NEAT_PROPERTY_IPV4_REQUIRED";

struct std_buffer {
    unsigned char *buffer;
    uint32_t buffer_filled;
};

static struct neat_flow_operations ops;
static struct std_buffer stdin_buffer;
static struct neat_ctx *ctx = NULL;
static struct neat_flow *flow = NULL;
static unsigned char *buffer_rcv = NULL;
static unsigned char *buffer_snd= NULL;
static uv_tty_t tty;

void tty_read(uv_stream_t *stream, ssize_t bytes_read, const uv_buf_t *buffer);
void tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf);
static neat_error_code on_all_written(struct neat_flow_operations *opCB);

/*
    Print usage and exit
*/
static void
print_usage()
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    printf("client [OPTIONS] HOST PORT\n");
    printf("\t- P \tneat properties (%s)\n", config_property);
    printf("\t- R \treceive buffer in byte (%d)\n", config_rcv_buffer_size);
    printf("\t- S \tsend buffer in byte (%d)\n", config_snd_buffer_size);
    printf("\t- v \tlog level 0..2 (%d)\n", config_log_level);
    printf("\t- A \tprimary dest. addr. (auto)\n");
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
    Abort handler
*/
static neat_error_code
on_abort(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    fprintf(stderr, "The flow was aborted!\n");

    exit(EXIT_FAILURE);
}

/*
    Network change handler
*/
static neat_error_code
on_network_changed(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (config_log_level >= 1) {
	fprintf(stderr, "Something happened in the network: %d\n", (int)opCB->status);
    }

    return NEAT_OK;
}


/*
    Read data from neat
*/
static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    uint32_t buffer_filled;
    neat_error_code code;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, buffer_rcv, config_rcv_buffer_size, &buffer_filled);
    if (code != NEAT_OK) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            if (config_log_level >= 1) {
                fprintf(stderr, "%s - neat_read - NEAT_ERROR_WOULD_BLOCK\n", __func__);
            }
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read - error: %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }

    // all fine
    if (buffer_filled > 0) {
        if (config_log_level >= 1) {
            if (opCB->stream_id != -1) {
                fprintf(stderr, "%s - received %d bytes on stream %d\n", __func__, buffer_filled, opCB->stream_id);
            } else {
                fprintf(stderr, "%s - received %d bytes\n", __func__, buffer_filled);
            }
        }

        fwrite(buffer_rcv, sizeof(char), buffer_filled, stdout);
        fflush(stdout);

    } else {
        if (config_log_level >= 1) {
            fprintf(stderr, "%s - disconnected\n", __func__);
        }
        ops.on_readable = NULL;
        ops.on_writable = NULL;
        neat_set_operations(ctx, flow, &ops);
        neat_stop_event_loop(opCB->ctx);
    }

    return NEAT_OK;
}

/*
    Send data from stdin
*/
static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    static int message_number = 0;
    static int last_message_number = 0;
    neat_error_code code;
    struct neat_tlv options[1];
    unsigned char buf[64];
    int len;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    switch (opCB->stream_id) {
        case 0:
            if (message_number > last_message_number) {
                break;
            }

            options[0].tag           = NEAT_TAG_STREAM_ID;
            options[0].type          = NEAT_TYPE_INTEGER;
            options[0].value.integer = 0;

            code = neat_write(opCB->ctx, opCB->flow,
                              stdin_buffer.buffer, stdin_buffer.buffer_filled,
                              options, 1);

            if (code != NEAT_OK) {
                fprintf(stderr, "%s - neat_write_ex - error: %d\n", __func__, (int)code);
                return on_error(opCB);
            }

            if (config_log_level >= 1) {
                fprintf(stderr, "%s - sent %d bytes\n", __func__, stdin_buffer.buffer_filled);
            }

            message_number++;
            break;
        case 1:
            if (message_number <= last_message_number) {
                break;
            }

            last_message_number = message_number;

            len = snprintf((char*)buf, 64, "Sent message number %d\n", message_number);

            options[0].tag           = NEAT_TAG_STREAM_ID;
            options[0].type          = NEAT_TYPE_INTEGER;
            options[0].value.integer = 1;
            code = neat_write(opCB->ctx, opCB->flow, buf, len, options, 1);

            if (code != NEAT_OK) {
                fprintf(stderr, "%s - neat_write_ex - error: %d\n", __func__, (int)code);
                return on_error(opCB);
            }

            // stop writing
            ops.on_writable = NULL;
            neat_set_operations(ctx, flow, &ops);

            break;
        default:
            fprintf(stderr, "Illegal stream id %d passed to on_writable\n", opCB->stream_id);
            return NEAT_ERROR_BAD_ARGUMENT;
    }

    return NEAT_OK;
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    // data sent completely - continue reading from stdin
    uv_read_start((uv_stream_t*) &tty, tty_alloc, tty_read);
    return NEAT_OK;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    int rc;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    uv_tty_init(ctx->loop, &tty, 0, 1);
    uv_read_start((uv_stream_t*) &tty, tty_alloc, tty_read);

    ops.on_readable = on_readable;
    neat_set_operations(ctx, flow, &ops);

    if (config_primary_dest_addr != NULL) {
	rc = neat_set_primary_dest(ctx, flow, config_primary_dest_addr);
	if (rc) {
	    fprintf(stderr, "Failed to set primary dest. addr.: %u\n", rc);
	} else {
	    if (config_log_level > 1)
		fprintf(stderr, "Primary dest. addr. set to: '%s'.\n",
			config_primary_dest_addr);
	}
    }

    return NEAT_OK;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
  if (config_log_level >= 2) {
    fprintf(stderr, "%s()\n", __func__);
  }

  fprintf(stderr, "%s - flow closed OK!\n", __func__);

  return NEAT_OK;
}

/*
    Read from stdin
*/
void
tty_read(uv_stream_t *stream, ssize_t buffer_filled, const uv_buf_t *buffer)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (config_log_level >= 1) {
        fprintf(stderr, "%s - tty_read called with buffer_filled %zd\n", __func__, buffer_filled);
    }

    // error case
    if (buffer_filled == UV_EOF) {
        if (config_log_level >= 1) {
            fprintf(stderr, "%s - tty_read - UV_EOF\n", __func__);
        }
        uv_read_stop(stream);
        ops.on_writable = NULL;
        neat_set_operations(ctx, flow, &ops);
        neat_shutdown(ctx, flow);
    } else if (strncmp(buffer->base, "close\n", buffer_filled) == 0) {
	if (config_log_level >= 1) {
            fprintf(stderr, "%s - tty_read - CLOSE\n", __func__);
        }
        uv_read_stop(stream);
        ops.on_writable = NULL;
        neat_set_operations(ctx, flow, &ops);
        neat_close(ctx, flow);
	buffer_filled = UV_EOF;
    } else if (strncmp(buffer->base, "abort\n", buffer_filled) == 0) {
	if (config_log_level >= 1) {
            fprintf(stderr, "%s - tty_read - ABORT\n", __func__);
        }
        uv_read_stop(stream);
        ops.on_writable = NULL;
        neat_set_operations(ctx, flow, &ops);
        neat_abort(ctx, flow);
	buffer_filled = UV_EOF;
    }

    // all fine
    if (buffer_filled > 0) {
        // copy input to app buffer
        stdin_buffer.buffer_filled = buffer_filled;
        memcpy(stdin_buffer.buffer, buffer->base, buffer_filled);

        // stop reading from stdin and set write callbacks
        uv_read_stop(stream);
        ops.on_writable = on_writable;
        ops.on_all_written = on_all_written;
        neat_set_operations(ctx, flow, &ops);
    }

    free(buffer->base);
}

void
tty_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buffer)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    buffer->len = config_rcv_buffer_size;
    buffer->base = malloc(config_rcv_buffer_size);
}

int
main(int argc, char *argv[])
{
    uint64_t prop;
    int arg, result;
    char *arg_property = config_property;
    char *arg_property_ptr = NULL;
    char arg_property_delimiter[] = ",;";

    memset(&ops, 0, sizeof(ops));
    memset(&stdin_buffer, 0, sizeof(stdin_buffer));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "P:R:S:v:A:")) != -1) {
        switch(arg) {
        case 'P':
            arg_property = optarg;
            if (config_log_level >= 1) {
                fprintf(stderr, "%s - option - properties: %s\n", __func__, arg_property);
            }
            break;
        case 'R':
            config_rcv_buffer_size = atoi(optarg);
            if (config_log_level >= 1) {
                fprintf(stderr, "%s - option - receive buffer size: %d\n", __func__, config_rcv_buffer_size);
            }
            break;
        case 'S':
            config_snd_buffer_size = atoi(optarg);
            if (config_log_level >= 1) {
                fprintf(stderr, "%s - option - send buffer size: %d\n", __func__, config_snd_buffer_size);
            }
            break;
        case 'v':
            config_log_level = atoi(optarg);
            if (config_log_level >= 1) {
                fprintf(stderr, "%s - option - log level: %d\n", __func__, config_log_level);
            }
            break;
	case 'A':
	    config_primary_dest_addr = optarg;
	    if (config_log_level >= 1) {
                fprintf(stderr, "%s - option - primary dest. address: %s\n", __func__,
			config_primary_dest_addr);
            }
            break;
        default:
            print_usage();
            goto cleanup;
            break;
        }
    }

    if (optind + 2 != argc) {
        fprintf(stderr, "%s - error: option - argument error\n", __func__);
        print_usage();
        goto cleanup;
    }

    if ((buffer_rcv = malloc(config_rcv_buffer_size)) == NULL) {
        fprintf(stderr, "%s - error: could not allocate receive buffer\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }
    if ((buffer_snd = malloc(config_snd_buffer_size)) == NULL) {
        fprintf(stderr, "%s - error: could not allocate send buffer\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }
    if ((stdin_buffer.buffer = malloc(config_snd_buffer_size)) == NULL) {
        fprintf(stderr, "%s - error: could not allocate stdin buffer\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "%s - error: could not initialize context\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // new neat flow
    if ((flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "%s - error: could not create new neat flow\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set properties (TCP only etc..)
    if (neat_get_property(ctx, flow, &prop)) {
        fprintf(stderr, "%s - error: neat_get_property\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // read property arguments
    arg_property_ptr = strtok(arg_property, arg_property_delimiter);

    while (arg_property_ptr != NULL) {
        if (config_log_level >= 1) {
            fprintf(stderr, "%s - setting property: %s\n", __func__, arg_property_ptr);
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
            fprintf(stderr, "%s - error: unknown property: %s\n", __func__, arg_property_ptr);
            print_usage();
            goto cleanup;
        }

        // get next property
        arg_property_ptr = strtok(NULL, arg_property_delimiter);
    }

    // set properties
    if (neat_set_property(ctx, flow, prop)) {
        fprintf(stderr, "%s - error: neat_set_property\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set callbacks
    ops.on_connected = on_connected;
    ops.on_error = on_error;
    ops.on_close = on_close;
    ops.on_aborted = on_abort;
    ops.on_network_status_changed = on_network_changed;

    if (neat_set_operations(ctx, flow, &ops)) {
        fprintf(stderr, "%s - error: neat_set_operations\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // wait for on_connected or on_error to be invoked
    if (neat_open_multistream(ctx, flow, argv[argc - 2], strtoul (argv[argc - 1], NULL, 0), 2) == NEAT_OK) {
        neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    } else {
        fprintf(stderr, "%s - error: neat_open\n", __func__);
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
