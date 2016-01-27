#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>
#include "../neat.h"

static uint32_t config_buffer_size = 8;
static uint16_t config_log_level = 1;
static uint16_t config_echo = 1;
static char config_property[] = "NEAT_PROPERTY_TCP_REQUIRED,NEAT_PROPERTY_IPV4_REQUIRED";


#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

static struct neat_flow_operations ops;
struct neat_ctx *ctx;
struct neat_flow *flow;
static unsigned char *buffer;
uint32_t buffer_filled;

static uint64_t on_writable(struct neat_flow_operations *opCB);

/*
    print usage and exit
*/
static void print_usage() {
    printf("server_discard_echo [OPTIONS]\n");
    printf("\t- E \techo (%d)\n", config_echo);
    printf("\t- S \tbuffer in byte (%d)\n", config_buffer_size);
    printf("\t- v \tlog level 0..2 (%d)\n", config_log_level);
    printf("\t- P \tneat properties (%s)\n", config_property);

    exit(EXIT_FAILURE);
}

/*
    Error handler
*/
static uint64_t on_error(struct neat_flow_operations *opCB) {
    exit(EXIT_FAILURE);
}

/*
    Read data until buffered_amount == 0 - then stop event loop!
*/
static uint64_t on_readable(struct neat_flow_operations *opCB) {
    // data is available to read
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer, config_buffer_size, &buffer_filled);
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
            printf("received data - %d byte\n", buffer_filled);
        }
        if (config_log_level >= 2) {
            fwrite(buffer, sizeof(char), buffer_filled, stdout);
            printf("\n");
            fflush(stdout);
        }

        if (config_echo) {
            opCB->on_readable = NULL;
            opCB->on_writable = on_writable;
        }

    } else {
        if (config_log_level >= 1) {
            printf("client disconncted\n");
        }
        opCB->on_readable = NULL;
        opCB->on_writable = NULL;
    }
    return 0;
}

/*
    Send data from stdin
*/
static uint64_t on_writable(struct neat_flow_operations *opCB) {
    neat_error_code code;

    code = neat_write(opCB->ctx, opCB->flow, buffer, buffer_filled);
    if (code) {
        debug_error("code: %d", (int)code);
        return on_error(opCB);
    }

    if (config_log_level >= 1) {
        printf("sent data - %d byte\n", buffer_filled);
    }

    // stop writing
    opCB->on_writable = NULL;
    opCB->on_readable = on_readable;
    return 0;
}


static uint64_t on_connected(struct neat_flow_operations *opCB) {
    if (config_log_level >= 1) {
        printf("connected\n");
    }

    opCB->on_readable = on_readable;
    return 0;
}

int main(int argc, char *argv[]) {
    uint64_t prop;
    int arg;
    char *arg_property = config_property;
    char *arg_property_ptr;
    char arg_property_delimiter[] = ",;";
    ctx = neat_init_ctx();

    while ((arg = getopt(argc, argv, "E:R:S:v:P:")) != -1) {
		switch(arg) {
            case 'E':
                config_echo = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - echo: %d\n", config_echo);
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
            case 'P':
                arg_property = optarg;
                if (config_log_level >= 1) {
                    printf("option - properties: %s\n", arg_property);
                }
                break;
            default:
                print_usage();
                break;
        }
    }

    if (config_echo) {
        printf("acting as echo server\n");
    } else {
        printf("acting as discard server\n");
    }

    if (optind != argc) {
        debug_error("argument error");
        print_usage();
    }

    buffer = malloc(config_buffer_size);

    if (ctx == NULL) {
        debug_error("could not initialize context");
        exit(EXIT_FAILURE);
    }

    // new neat flow
    if((flow = neat_new_flow(ctx)) == NULL) {
        debug_error("neat_new_flow");
        exit(EXIT_FAILURE);
    }

    // set properties (TCP only etc..)
    if (neat_get_property(ctx, flow, &prop)) {
        debug_error("neat_get_property");
        exit(EXIT_FAILURE);
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
        }

    	// get next property
     	arg_property_ptr = strtok(NULL, arg_property_delimiter);
    }

    // set properties
    if (neat_set_property(ctx, flow, prop)) {
        debug_error("neat_set_property");
        exit(EXIT_FAILURE);
    }

    // set callbacks
    ops.on_connected = on_connected;
    ops.on_error = on_error;

    if (neat_set_operations(ctx, flow, &ops)) {
        debug_error("neat_set_operations");
        exit(EXIT_FAILURE);
    }

    // wait for on_connected or on_error to be invoked
    if (neat_accept(ctx, flow, "*", "8080")) {
        debug_error("neat_accept");
        exit(EXIT_FAILURE);
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    // cleanup
    free(buffer);
    neat_free_flow(flow);
    neat_free_ctx(ctx);

    exit(EXIT_SUCCESS);
}
