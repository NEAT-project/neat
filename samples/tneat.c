#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include "../neat.h"

/*
    tneat
    testing tool for neat
*/

/*
    default values
*/
static uint32_t config_rcv_buffer_size = 512;
static uint32_t config_message_size = 1024;
static uint32_t config_message_count = 16;
static uint32_t config_runtime = 0;
static uint16_t config_active = 0;
static uint16_t config_chargen_offset = 0;
static uint16_t config_port = 8080;
static uint16_t config_log_level = 2;
static char config_property[] = "NEAT_PROPERTY_TCP_REQUIRED,NEAT_PROPERTY_IPV4_REQUIRED";

/*
    macros for debug output
*/
#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

struct stats {
    uint64_t msgs;
    uint64_t bytes;
    struct timeval tv_first;
    struct timeval tv_last;
};

static struct neat_flow_operations ops;
static struct stats stats_rcv;
static struct stats stats_snd;
static unsigned char *buffer_rcv;
static unsigned char *buffer_snd;

/*
    print usage and exit
*/
static void print_usage() {
    printf("tneat [OPTIONS] [DESTINATION]\n");
    printf("\t- l \tsize for each message in byte (%d)\n", config_message_size);
    printf("\t- n \tmax number of messages to send (%d)\n", config_message_count);
    printf("\t- T \tmax runtime in seconds (%d)\n", config_runtime);
    printf("\t- R \tsize of apps receive buffer in byte (%d)\n", config_rcv_buffer_size);
    printf("\t- p \tport [receive on|send to] (%d)\n", config_port);
    printf("\t- v \tprint verbose (%d)\n", config_log_level);
    printf("\t- P \tneat properties (%s)\n", config_property);

    exit(EXIT_FAILURE);
}

/*
    print human readable file sizes - keep attention to provide enough buffer space
*/
char* filesize_human(double bytes, char *buffer) {
    uint8_t i = 0;
    const char* units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    while (bytes > 1000) {
        bytes /= 1000;
        i++;
    }
    sprintf(buffer, "%.*f %s", i, bytes, units[i]);
    return buffer;
}

/*
    error handler
*/
static uint64_t on_error(struct neat_flow_operations *opCB) {
    exit(EXIT_FAILURE);
}

/*
    send *config_message_size* chars to peer
*/
static uint64_t on_writable(struct neat_flow_operations *opCB) {
    neat_error_code code;
    double time_elapsed;

    // every buffer is filled with chars - increased by every run
    memset(buffer_snd, 33+config_chargen_offset++, config_message_size);
    config_chargen_offset = config_chargen_offset % 72;

    code = neat_write(opCB->ctx, opCB->flow, buffer_snd, config_message_size);
    if (code) {
        debug_error("neat_write - code: %d", (int)code);
        return on_error(opCB);
    }

    // record start time
    if (stats_snd.msgs == 0) {
        gettimeofday(&stats_snd.tv_first, NULL);
    }

    stats_snd.msgs++;
    stats_snd.bytes += config_message_size;
    gettimeofday(&stats_snd.tv_last, NULL);

    if (config_log_level >= 2) {
        printf("neat_write - # %" PRIu64 " - %d byte\n", stats_snd.msgs, config_message_size);
    }
    
    if (config_log_level >= 2) {
        printf("neat_write - content\n");
        fwrite(buffer_snd, sizeof(char), config_message_size, stdout);
        printf("\n");
    }

    time_elapsed = stats_snd.tv_last.tv_sec - stats_snd.tv_first.tv_sec; // sec
    time_elapsed += (stats_snd.tv_last.tv_usec - stats_snd.tv_first.tv_usec) / 1000000.0; // us >> sec

    // stop writing if config_runtime reached or config_message_count msgs sent
    if ((config_runtime > 0 && time_elapsed >= config_runtime) || (config_message_count > 0 && stats_snd.msgs >= config_message_count)) {
        printf("neat_write finished - %" PRIu64 " calls - %" PRIu64 " bytes in %.2f s\n", stats_snd.msgs, stats_snd.bytes, time_elapsed);
        opCB->on_writable = NULL;
        neat_stop_event_loop(opCB->ctx);
    }

    return 0;
}

static uint64_t on_readable(struct neat_flow_operations *opCB) {
    uint32_t buffer_filled;
    neat_error_code code;
    char buffer_filesize_human[16];
    double time_elapsed;


    code = neat_read(opCB->ctx, opCB->flow, buffer_rcv, config_rcv_buffer_size, &buffer_filled);
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            debug_error("NEAT_ERROR_WOULD_BLOCK");
            return 0;
        } else {
            debug_error("neat_read - code: %d", (int)code);
            return on_error(opCB);
        }
    }

    if (buffer_filled > 0) {
        // we got data!
        if (stats_rcv.msgs == 0) {
            gettimeofday(&stats_rcv.tv_first, NULL);
        }
        stats_rcv.msgs++;
        stats_rcv.bytes += buffer_filled;
        gettimeofday(&stats_rcv.tv_last, NULL);

        if (config_log_level >= 1) {
            printf("neat_read - # %" PRIu64 " - %d byte\n", stats_rcv.msgs, buffer_filled);
        }
        
        if (config_log_level >= 2) {
            printf("neat_read - content\n");
            fwrite(buffer_rcv, sizeof(char), buffer_filled, stdout);
            printf("\n");
        }

    } else {
        // client disconnected - print statistics
        time_elapsed = stats_rcv.tv_last.tv_sec - stats_rcv.tv_first.tv_sec; // sec
        time_elapsed += (stats_rcv.tv_last.tv_usec - stats_rcv.tv_first.tv_usec) / 1000000.0; // us >> sec

        printf("%" PRIu64 ", %" PRIu64 ", %.2f, %.2f, %s\n", stats_rcv.bytes, stats_rcv.msgs, time_elapsed, stats_rcv.bytes/time_elapsed, filesize_human(stats_rcv.bytes/time_elapsed, buffer_filesize_human));
        opCB->on_readable = NULL;
    }

    return 0;
}

/*
    Connection established - set callbacks and reset statistics
*/
static uint64_t on_connected(struct neat_flow_operations *opCB) {

    if (config_log_level >= 1) {
        printf("connected\n");
    }

    // reset stats
    stats_rcv.msgs = 0;
    stats_rcv.bytes = 0;
    stats_snd.msgs = 0;
    stats_snd.bytes = 0;

    // set callbacks
    opCB->on_readable = on_readable;
    if (config_active) {
        opCB->on_writable = on_writable;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    struct neat_ctx *ctx = neat_init_ctx();
    struct neat_flow *flow;
    uint64_t prop;
    int arg;
    char *arg_property = config_property;
    char *arg_property_ptr;
    char arg_property_delimiter[] = ",;";

    while ((arg = getopt(argc, argv, "l:n:T:R:p:vP:")) != -1) {
		switch(arg) {
			case 'l':
				config_message_size = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - message size: %d\n", config_message_size);
                }
				break;
            case 'n':
                config_message_count = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - message limit: %d\n", config_message_count);
                }
                break;
            case 'T':
                config_runtime = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - runtime limit: %d\n", config_runtime);
                }
                break;
            case 'R':
                config_rcv_buffer_size = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - receive buffer size: %d\n", config_log_level);
                }
                break;
            case 'p':
                config_port = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - port: %d\n", config_port);
                }
                break;
            case 'v':
                config_log_level = 1;
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

    if (optind == argc) {
		config_active = 0;
        if (config_log_level >= 1) {
            printf("role: passive\n");
        }
	} else if (optind + 1 == argc) {
		config_active = 1;
        if (config_log_level >= 1) {
            printf("role: active\n");
        }
	} else {
        debug_error("argument error");
        print_usage();
    }


    buffer_rcv = malloc(config_rcv_buffer_size);
    buffer_snd = malloc(config_message_size);

    // check for successful context
    if (ctx == NULL) {
        debug_error("could not initialize context");
        exit(EXIT_FAILURE);
    }

    // new neat flow
    if ((flow = neat_new_flow(ctx)) == NULL) {
        debug_error("neat_new_flow");
        exit(EXIT_FAILURE);
    }

    ops.on_connected = on_connected;
    ops.on_error = on_error;

    //ops.on_all_written = on_all_written;
    if (neat_set_operations(ctx, flow, &ops)) {
        debug_error("neat_set_operations");
        exit(EXIT_FAILURE);
    }

    // get properties
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

    // workaround until port is notated in int..
    // XXX
    char port[10];
    sprintf(port, "%d", config_port);

    if (config_active) {
        // connect to peer
        if (neat_open(ctx, flow, argv[optind], port)) {
            debug_error("neat_open");
            exit(EXIT_FAILURE);
        }

        if (config_log_level >= 1) {
            printf("neat_open - connecting to %s:%d\n", argv[optind], config_port);
        }
    } else {
        // wait for on_connected or on_error to be invoked
        if (neat_accept(ctx, flow, "*", port)) {
            debug_error("neat_accept - *:%d\n", config_port);
            exit(EXIT_FAILURE);
        }
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    if (config_log_level >= 1) {
        printf("freeing (flow + ctx) and bye bye!\n");
    }


    // cleanup
    free(buffer_rcv);
    free(buffer_snd);
    neat_free_flow(flow);
    neat_free_ctx(ctx);
    exit(EXIT_SUCCESS);
}
