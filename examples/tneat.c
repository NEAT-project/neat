#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "../neat.h"

/**********************************************************************

    tneat - neat testing tool

    tneat [OPTIONS] [HOST]
    -l : message length in byte (client)
    -n : number off messages to send (client)
    -p : port
    -P : neat properties
    -R : receive buffer in byte (server)
    -T : max runtime (client)
    -v : log level (0 .. 2)

**********************************************************************/

/*
    default values
*/
static uint32_t config_rcv_buffer_size = 1024;
static uint32_t config_snd_buffer_size = 1024;
static uint32_t config_message_count = 32;
static uint32_t config_runtime_max = 0;
static uint16_t config_active = 0;
static uint16_t config_chargen_offset = 0;
static uint16_t config_port = 8080;
static uint16_t config_log_level = 2;
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
static uint8_t done = 0;

/*
    macro - tvp-uvp=vvp
*/

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                 \
    do {                                                        \
        (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
        (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
        if ((vvp)->tv_usec < 0) {                               \
            (vvp)->tv_sec--;                                    \
            (vvp)->tv_usec += 1000000;                          \
        }                                                       \
    } while (0)
#endif

struct tneat_flow_direction {
    unsigned char *buffer;
    uint32_t calls;
    uint32_t bytes;
    struct timeval tv_first;
    struct timeval tv_last;
};

struct tneat_flow {
    struct tneat_flow_direction rcv;
    struct tneat_flow_direction snd;
};

static neat_error_code on_writable(struct neat_flow_operations *opCB);
static neat_error_code on_close(struct neat_flow_operations *opCB);

/*
    print usage
*/
static void
print_usage()
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    printf("tneat [OPTIONS] [HOST]\n");
    printf("\t- l \tsize for each message in byte (%d)\n", config_snd_buffer_size);
    printf("\t- n \tmax number of messages to send (%d)\n", config_message_count);
    printf("\t- p \tport [receive on|send to] (%d)\n", config_port);
    printf("\t- P \tneat properties (%s)\n", config_property);
    printf("\t- R \treceive buffer in byte (%d)\n", config_rcv_buffer_size);
    printf("\t- T \tmax runtime in seconds (%d)\n", config_runtime_max);
    printf("\t- v \tlog level 0..3 (%d)\n", config_log_level);
}

/*
    print human readable file sizes - helper function
*/
static char
*filesize_human(double bytes, char *buffer, size_t buffersize)
{
    uint8_t i = 0;
    const char* units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    while (bytes > 1000) {
        bytes /= 1000;
        i++;
    }
    snprintf(buffer, buffersize, "%.*f %s", i, bytes, units[i]);
    return buffer;
}

/*
    error handler
*/
static neat_error_code
on_error(struct neat_flow_operations *opCB)
{

    fprintf(stderr, "%s()\n", __func__);
    exit(EXIT_FAILURE);
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    struct timeval now, diff_time;
    double time_elapsed;
    char buffer_filesize_human[32];

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    gettimeofday(&now, NULL);
    timersub(&(tnf->snd.tv_last), &(tnf->snd.tv_first), &diff_time);
    time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

    // runtime- or message-limit reached
    if ((config_runtime_max > 0 && time_elapsed >= config_runtime_max) ||
        (config_message_count > 0 && tnf->snd.calls >= config_message_count)) {

        // print statistics
        printf("neat_write finished - statistics\n");
        printf("\tbytes\t\t: %u\n", tnf->snd.bytes);
        printf("\tsnd-calls\t: %u\n", tnf->snd.calls);
        printf("\tduration\t: %.2fs\n", time_elapsed);
        printf("\tbandwidth\t: %s/s\n", filesize_human(tnf->snd.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));

        done = 1;
    }

    opCB->on_writable = on_writable;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

/*
    send *config_message_size* chars to peer
*/
static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    neat_error_code code;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    // record first send call
    if (tnf->snd.calls == 0) {
        gettimeofday(&(tnf->snd.tv_first), NULL);
    }

    // set callbacks
    opCB->on_writable = NULL;
    opCB->on_all_written = on_all_written;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    // increase stats
    tnf->snd.calls++;
    tnf->snd.bytes += config_snd_buffer_size;
    gettimeofday(&(tnf->snd.tv_last), NULL);

    // every message contains a different payload (i++)
    config_chargen_offset = (config_chargen_offset+1) % 72;
    memset(tnf->snd.buffer, 33 + config_chargen_offset, config_snd_buffer_size);

    if (config_log_level >= 2) {
        printf("neat_write - # %u - %d byte\n", tnf->snd.calls, config_snd_buffer_size);
        if (config_log_level >= 3) {
            printf("neat_write - content\n");
            fwrite(tnf->snd.buffer, sizeof(char), config_snd_buffer_size, stdout);
            printf("\n");
        }
    }

    code = neat_write(opCB->ctx, opCB->flow, tnf->snd.buffer, config_snd_buffer_size, NULL, 0);

    if (done) {
        opCB->on_writable = NULL;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
        neat_shutdown(opCB->ctx, opCB->flow);
        return NEAT_OK;
    }

    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write error: code %d\n", __func__, (int)code);
        return on_error(opCB);
    }

    return NEAT_OK;
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    uint32_t buffer_filled;
    struct timeval diff_time;
    neat_error_code code;
    char buffer_filesize_human[32];
    double time_elapsed;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, tnf->rcv.buffer, config_rcv_buffer_size, &buffer_filled, NULL, 0);
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            fprintf(stderr, "%s - neat_read warning: NEAT_ERROR_WOULD_BLOCK\n", __func__);
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read error: code %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }

    if (buffer_filled > 0) {
        // we got data!
        if (tnf->rcv.calls == 0) {
            gettimeofday(&(tnf->rcv.tv_first), NULL);
        }
        tnf->rcv.calls++;
        tnf->rcv.bytes += buffer_filled;
        gettimeofday(&(tnf->rcv.tv_last), NULL);

        if (config_log_level >= 2) {
            printf("neat_read - # %u - %d byte\n", tnf->rcv.calls, buffer_filled);
            if (config_log_level >= 3) {
                fwrite(tnf->rcv.buffer, sizeof(char), buffer_filled, stdout);
                printf("\n");
            }
        }
    // peer disconnected
    } else if (buffer_filled == 0){
        if (config_log_level >= 1) {
            printf("connection closed\n");
        }

        opCB->on_readable = NULL;
        opCB->on_writable = NULL;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);

        if (!config_active) {
            // we are server
            // print statistics
            timersub(&(tnf->rcv.tv_last), &(tnf->rcv.tv_first), &diff_time);
            time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

            printf("%u, %u, %.2f, %.2f, %s\n", tnf->rcv.bytes, tnf->rcv.calls, time_elapsed, tnf->rcv.bytes/time_elapsed, filesize_human(tnf->rcv.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));

            if (config_log_level >= 1) {
                printf("client disconnected - statistics\n");
                printf("\tbytes\t\t: %u\n", tnf->rcv.bytes);
                printf("\trcv-calls\t: %u\n", tnf->rcv.calls);
                printf("\tduration\t: %.2fs\n", time_elapsed);
                printf("\tbandwidth\t: %s/s\n", filesize_human(tnf->rcv.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));
            }
        }
        on_close(opCB);

        fprintf(stderr, "%s - free complete\n", __func__);
    }

    return NEAT_OK;
}

/*
    Connection established - set callbacks and reset statistics
*/
static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = NULL;

    if (config_log_level >= 1) {
        fprintf(stderr, "%s() - connection established\n", __func__);
    }

    if ((opCB->userData = calloc(1, sizeof(struct tneat_flow))) == NULL) {
        fprintf(stderr, "%s - could not allocate tneat_flow\n", __func__);
        exit(EXIT_FAILURE);
    }

    tnf = opCB->userData;

    if ((tnf->snd.buffer = malloc(config_snd_buffer_size)) == NULL) {
        fprintf(stderr, "%s - could not allocate send buffer\n", __func__);
        exit(EXIT_FAILURE);
    }

    if ((tnf->rcv.buffer = malloc(config_rcv_buffer_size)) == NULL) {
        fprintf(stderr, "%s - could not allocate receive buffer\n", __func__);
        exit(EXIT_FAILURE);
    }

    // reset stats
    tnf->snd.calls = 0;
    tnf->snd.bytes = 0;
    tnf->rcv.calls = 0;
    tnf->rcv.bytes = 0;

    // set callbacks
    opCB->on_readable = on_readable;
    if (config_active) {
        opCB->on_writable = on_writable;
    }
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    return NEAT_OK;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;

    // cleanup
    opCB->on_close = NULL;
    opCB->on_readable = NULL;
    opCB->on_writable = NULL;
    opCB->on_error = NULL;

    free(tnf->snd.buffer);
    free(tnf->rcv.buffer);
    free(tnf);

    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    fprintf(stderr, "%s - flow closed OK!\n", __func__);

    // stop event loop if we are active part
    if (config_active) {
        fprintf(stderr, "%s - stopping event loop\n", __func__);
        neat_stop_event_loop(opCB->ctx);
    }

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    struct neat_flow *flow = NULL;
    struct neat_flow_operations ops;
    int arg, result;
    char *arg_property = config_property;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "l:n:p:P:R:T:v:")) != -1) {
        switch(arg) {
        case 'l':
            config_snd_buffer_size = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - send buffer size: %d\n", config_snd_buffer_size);
            }
            break;
        case 'n':
            config_message_count = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - message limit: %d\n", config_message_count);
            }
            break;
        case 'p':
            config_port = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - port: %d\n", config_port);
            }
            break;
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
        case 'T':
            config_runtime_max = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - runtime limit: %d\n", config_runtime_max);
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

    ops.on_connected = on_connected;
    ops.on_error = on_error;

    //ops.on_all_written = on_all_written;
    if (neat_set_operations(ctx, flow, &ops)) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set properties
    if (neat_set_property(ctx, flow, arg_property)) {
        fprintf(stderr, "%s - neat_set_property failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (config_active) {
        // connect to peer
        if (neat_open(ctx, flow, argv[optind], config_port, NULL, 0) == NEAT_OK) {
            if (config_log_level >= 1) {
                printf("neat_open - connecting to %s:%d\n", argv[optind], config_port);
            }
            neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
        } else {
            fprintf(stderr, "%s - neat_open failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }
    } else {
        // wait for on_connected or on_error to be invoked
        if (neat_accept(ctx, flow, config_port, NULL, 0)) {
            fprintf(stderr, "%s - neat_accept failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    }

    if (config_log_level >= 1) {
        printf("freeing ctx bye bye!\n");
    }

    // cleanup
cleanup:
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
