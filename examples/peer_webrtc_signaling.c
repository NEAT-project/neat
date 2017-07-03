#include "util.h"
#include "webrtc_signaling.h"

#include <neat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

/**********************************************************************

    WebRTC peer in neat
    * connect to peer and send and receive DATA

    peer_webrtc [OPTIONS] SESSION
    -n : number of requests/flows
    -R : receive buffer size in byte
    -v : log level (0 .. 2)

**********************************************************************/

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

static uint32_t config_rcv_buffer_size      = 10240;
static uint32_t config_snd_buffer_size      = 1024;
static uint32_t config_message_count        = 0;
static uint32_t config_runtime_max          = 0;
static uint16_t config_chargen_offset       = 0;
static uint16_t config_port                 = 23232;
static uint16_t config_log_level            = 1;
static uint16_t config_num_flows            = 1;
static uint16_t config_max_flows            = 100;
static uint16_t config_active               = 0;

static char          *config_property        = "\
{\
    \"transport\": [\
        {\
            \"value\": \"WEBRTC\",\
            \"precedence\": 1\
        }\
    ]\
}";

static uint32_t flows_active = 0;
static struct neat_signaling_context *sctx;

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

static neat_error_code on_close(struct neat_flow_operations *opCB);
static neat_error_code on_writable(struct neat_flow_operations *opCB);

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

static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    fprintf(stderr, "%s\n", __func__);
    neat_stop_event_loop(opCB->ctx);
    return NEAT_OK;
}

static neat_error_code
on_parameters(struct neat_flow_operations *opCB)
{
    fprintf(stderr, "%s\n", __func__);

    printf("LocalParameters: %s\n", (char *)opCB->userData);
    printf("Got local parameters from WebRTC. Now send them to signalling server\n");

    neat_signaling_send(sctx, opCB->userData, strlen(opCB->userData) + 1);

    free(opCB->userData);
    opCB->userData = NULL;
    return NEAT_OK;
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    uint32_t buffer_filled;
   // struct timeval diff_time;
    neat_error_code code;
  //  char buffer_filesize_human[32];
  //  double time_elapsed;
printf("peer_webrtc: on_readable\n");
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
            printf("%s: neat_read - # %u - %d byte\n", opCB->label, tnf->rcv.calls, buffer_filled);
            if (config_log_level >= 4) {
                fwrite(tnf->rcv.buffer, sizeof(char), buffer_filled, stdout);
                printf("\n");
            }
        }
    // peer disconnected
    }

    return NEAT_OK;
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    struct timeval now, diff_time;
    double time_elapsed;

printf("peer_webrtc: on_all_written\n");
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    gettimeofday(&now, NULL);
    timersub(&(tnf->snd.tv_last), &(tnf->snd.tv_first), &diff_time);
    time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;
printf("sndCalls=%d message_count=%d time=%f config_runtime_max=%d\n", tnf->snd.calls, config_message_count, time_elapsed, config_runtime_max);
    // runtime- or message-limit reached
    if ((config_runtime_max > 0 && time_elapsed >= config_runtime_max) ||
        (config_message_count > 0 && tnf->snd.calls >= config_message_count)) {
        neat_close(opCB->ctx, opCB->flow);
    } else {
        opCB->on_writable = on_writable;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
    }
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
printf("peer_webrtc: on_writable\n");
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
        printf("%s: neat_write - # %u - %d byte\n", opCB->label, tnf->snd.calls, config_snd_buffer_size);
        if (config_log_level >= 4) {
            printf("neat_write - content\n");
            fwrite(tnf->snd.buffer, sizeof(char), config_snd_buffer_size, stdout);
            printf("\n");
        }
    }

    code = neat_write(opCB->ctx, opCB->flow, tnf->snd.buffer, config_snd_buffer_size, NULL, 0);

    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write error: code %d\n", __func__, (int)code);
        return on_error(opCB);
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
 printf("!!!!!!!Connected!!!!!!\n");
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
        printf("set on_writable\n");
    } else {
        opCB->on_writable = NULL;
        printf("set writable = NULL\n");
    }

    flows_active++;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    return NEAT_OK;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
    printf("on_close\n");
    struct tneat_flow *tnf = opCB->userData;
    char buffer_filesize_human[32];
    double time_elapsed;
    struct timeval diff_time;

    fprintf(stderr, "%s\n", __func__);

    if (tnf == NULL && flows_active == 0) {
        fprintf(stderr, "%s - stopping event loop\n", __func__);
        neat_stop_event_loop(opCB->ctx);
        return NEAT_OK;
    }

    timersub(&(tnf->rcv.tv_last), &(tnf->rcv.tv_first), &diff_time);
    time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

    printf("flow closed - read statistics\n");
    printf("\tbytes\t\t: %u\n", tnf->rcv.bytes);
    printf("\trcv-calls\t: %u\n", tnf->rcv.calls);
    printf("\tduration\t: %.2fs\n", time_elapsed);
    printf("\tbandwidth\t: %s/s\n", filesize_human(tnf->rcv.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));

    // write print statistics
    timersub(&(tnf->snd.tv_last), &(tnf->snd.tv_first), &diff_time);
    time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

    printf("flow closed - write statistics\n");
    printf("\tbytes\t\t: %u\n", tnf->snd.bytes);
    printf("\tsnd-calls\t: %u\n", tnf->snd.calls);
    printf("\tduration\t: %.2fs\n", time_elapsed);
    printf("\tbandwidth\t: %s/s\n", filesize_human(tnf->snd.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));

    // cleanup
    if (tnf->snd.buffer) {
        free(tnf->snd.buffer);
        tnf->snd.buffer = NULL;
    }

    if (tnf->rcv.buffer) {
        free(tnf->rcv.buffer);
        tnf->rcv.buffer = NULL;
    }

    if (tnf) {
        free(tnf);
        tnf = 0;
    }

    fprintf(stderr, "%s - flow closed OK!\n", __func__);

    // stop event loop if we are active part
    flows_active--;
    printf("active flows left: %d\n", flows_active);
  /*  if (config_active && !flows_active) {
        fprintf(stderr, "%s - stopping event loop\n", __func__);
        neat_stop_event_loop(opCB->ctx);
    }*/

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    int i = 0;
    struct neat_tlv options[1];
    char name[20];

    struct neat_flow *flows[config_max_flows];
    struct neat_flow_operations ops[config_max_flows];
    // create listening flow for accepted new data channels
    struct neat_flow *listening_flow;
    struct neat_flow_operations operation;

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


    if (config_port == 0) {
        config_active = 1;
        printf("role: active\n");
    } else {
        config_active = 0;
        printf("role: passive\n");
    }
    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "%s - neat_init_ctx failed\n", __func__);
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

    options[0].tag = NEAT_TAG_CHANNEL_NAME;
    options[0].type = NEAT_TYPE_STRING;


    if ((listening_flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    memset(&operation, 0, sizeof(struct neat_flow_operations));
    operation.on_connected = on_connected;
    operation.on_error     = on_error;
    operation.on_close     = on_close;
    operation.on_parameters = on_parameters;
    char *params = calloc(1, 2048);
    operation.userData     = params;

    if (neat_set_operations(ctx, listening_flow, &operation)) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set properties
    if (neat_set_property(ctx, listening_flow, arg_property)) {
        fprintf(stderr, "%s - neat_set_property failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }


    // wait for on_connected or on_error to be invoked
    if (neat_accept(ctx, listening_flow, config_port, NULL, 0)) {
        fprintf(stderr, "%s - neat_accept failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }
printf("neat_accept returned\n");

    for (i = 0; i < config_num_flows; i++) {
        if (config_port == 0) {
            sprintf(name, "Channel %d", 2 * i);
        } else {
            sprintf(name, "Channel %d", 2 * i + 1);
        }
        options[0].value.string = name;
        if ((flows[i] = neat_new_flow(ctx)) == NULL) {
            fprintf(stderr, "could not initialize context\n");
            result = EXIT_FAILURE;
            goto cleanup;
        }

        // set properties
        if (neat_set_property(ctx, flows[i], arg_property)) {
            fprintf(stderr, "%s - error: neat_set_property\n", __func__);
            result = EXIT_FAILURE;
             goto cleanup;
        }

        ops[i].on_connected = on_connected;
        ops[i].on_error = on_error;
        ops[i].on_close = on_close;
        ops[i].userData = &result; // allow on_error to modify the result variable
        neat_set_operations(ctx, flows[i], &(ops[i]));

        // wait for on_connected or on_error to be invoked
        if (neat_open(ctx, flows[i], argv[optind], config_port, options, 1) != NEAT_OK) {
            fprintf(stderr, "Could not open flow\n");
            exit(EXIT_FAILURE);
        } else {
            fprintf(stderr, "Opened flow %d\n", i);
           // flows_active++;
        }
    }

    sctx = neat_signaling_init(ctx, listening_flow, 10);


    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    // cleanup
cleanup:
printf("cleanup\n");
    if (config_log_level >= 1) {
        printf("freeing ctx bye bye!\n");
    }

    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
