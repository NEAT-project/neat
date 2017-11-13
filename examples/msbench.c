#include "util.h"

#include <neat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <uv.h>

#define QUOTE(...) #__VA_ARGS__

/*
    default values
*/
static uint32_t config_rcv_buffer_size      = 100000;
static uint32_t config_snd_buffer_size      = 100000;
static uint32_t config_message_count        = 1;
static uint32_t config_runtime_max          = 10;
static uint16_t config_chargen_offset       = 0;
static uint16_t config_active               = 0;
static uint16_t config_port                 = 8080;
static uint16_t config_log_level            = 1;
static uint16_t config_num_flows            = 6;
static uint16_t config_max_flows            = 100;
static uint32_t config_delay                = 0;
static uint32_t config_loss                 = 0;
static char *config_property = QUOTE({
    "transport": {
            "value": "SCTP",
            "precedence": 1
        },
    "multihoming": {
        "value": true,
        "precedence": 2
    },
    "local_ips": [
        {
            "value": "10.1.1.2",
            "precedence": 1
        },
        {
            "value": "10.1.2.2",
            "precedence": 2
        }
    ]
      });

static uint32_t flows_active = 0;
static uint32_t flows_connected = 0;
enum payload_type {PAYLOAD_DATA = 1, PAYLOAD_RESET, PAYLOAD_BULK};
static uint32_t global_rcv_calls = 0;
static uint32_t global_delay = 0;

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

struct tneat_payload {
    uint8_t         id;
    uint8_t         type;
    struct timeval  tv;
    uint32_t        delay;
    uint32_t        loss; // plr * 1000
};

struct tneat_flow_direction {
    unsigned char   *buffer;
    uint32_t        calls;
    uint32_t        bytes;
    struct timeval  tv_first;
    struct timeval  tv_last;
    uint64_t        delay_sum;
};

struct tneat_flow {
    uint8_t                     done;
    struct tneat_flow_direction rcv;
    struct tneat_flow_direction snd;
    uint16_t                    send_interval;
    uv_timer_t                  send_timer;
    struct                      neat_flow_operations *ops;
    struct tneat_payload        payload;
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
    error handler
*/
static neat_error_code
on_error(struct neat_flow_operations *opCB)
{

    fprintf(stderr, "%s()\n", __func__);
    return NEAT_OK;
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
        (config_message_count > 0 && tnf->snd.calls >= config_message_count && tnf->payload.type != PAYLOAD_BULK)) {

        if (tnf->payload.id == 0) {
            tnf->done++;
        } else {
            tnf->done = 2;
        }

        if (tnf->done == 2) {
            // print statistics
            printf("neat_write finished - statistics - %d\n", tnf->payload.type);
            printf("\tbytes\t\t: %u\n", tnf->snd.bytes);
            printf("\tsnd-calls\t: %u\n", tnf->snd.calls);
            printf("\tduration\t: %.2fs\n", time_elapsed);
            if (time_elapsed > 0.0) {
                printf("\tbandwidth\t: %s/s\n", filesize_human(tnf->snd.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));
            }

            uv_close((uv_handle_t*)&(tnf->send_timer), NULL);
        }
    }

    if (tnf->send_interval && !tnf->done) {
        uv_timer_again(&(tnf->send_timer));
    } else {
        opCB->on_writable = on_writable;
    }

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
    tnf->snd.bytes += (int)sizeof(struct timeval);
    gettimeofday(&(tnf->snd.tv_last), NULL);

    // every message contains a different payload (i++)
    config_chargen_offset = (config_chargen_offset+1) % 72;
    memset(tnf->snd.buffer, 33 + config_chargen_offset, config_snd_buffer_size);

    if (config_snd_buffer_size < sizeof(struct timeval)) {
        fprintf(stderr, "%s - error : buffer to small for timestamp\n", __func__);
        exit(EXIT_FAILURE);
    }


    if (tnf->done) {
        fprintf(stderr, "sending reset\n");
        tnf->payload.type = PAYLOAD_RESET;
    }

    tnf->payload.tv     = tnf->snd.tv_last;
    tnf->payload.loss   = config_loss;
    tnf->payload.delay  = config_delay;
    memcpy(tnf->snd.buffer, &(tnf->payload), sizeof(struct tneat_payload));

    if (config_log_level >= 2) {
        printf("neat_write - # %u - %d byte\n", tnf->snd.calls, config_snd_buffer_size);
    }

    code = neat_write(opCB->ctx, opCB->flow, tnf->snd.buffer, config_snd_buffer_size, NULL, 0);

    if (tnf->done == 2) {
        if (config_log_level >= 2) {
            printf("neat_write - done!\n");
        }
        fprintf(stderr, "sending reset\n");
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
    struct tneat_payload *payload;
    neat_error_code code;
    char buffer_filesize_human[32];
    double time_elapsed;
    struct neat_tlv options[1];
    double app_delay;
    FILE *logfile = NULL;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    options[0].tag = NEAT_TAG_STREAM_ID;

    code = neat_read(opCB->ctx, opCB->flow, tnf->rcv.buffer, config_rcv_buffer_size, &buffer_filled, options, sizeof(options)/sizeof(struct neat_tlv));
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            fprintf(stderr, "%s - neat_read warning: NEAT_ERROR_WOULD_BLOCK\n", __func__);
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read error: code %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }

    //fprintf(stderr, "%s - %d bytes - stream %d\n", __func__, buffer_filled, options[0].value.integer);

    if (buffer_filled > 0) {
        // we got data!
        if (tnf->rcv.calls == 0) {
            gettimeofday(&(tnf->rcv.tv_first), NULL);
        }
        tnf->rcv.calls++;
        tnf->rcv.bytes += buffer_filled;
        gettimeofday(&(tnf->rcv.tv_last), NULL);

        payload = (struct tneat_payload*) tnf->rcv.buffer;
        timersub(&(tnf->rcv.tv_last), &(payload->tv), &diff_time);
        app_delay = (double) diff_time.tv_sec * 1000.0 + (double) diff_time.tv_usec / 1000.0;
        app_delay += 0.5;
        tnf->rcv.delay_sum += (int) app_delay;
        tnf->payload.delay = payload->delay;
        tnf->payload.loss = payload->loss;

        fprintf(stderr, "id: %d - payload: %d\n", payload->id, payload->type);

        if (payload->type == PAYLOAD_DATA) {
            global_delay += (uint32_t) app_delay;
            global_rcv_calls++;
        } else if (payload->type == PAYLOAD_RESET) {
            fprintf(stderr, "GOT RESET!!!\n");
            printf("\tavg-delay\t: %.2f ms\n",  (double) global_delay / global_rcv_calls);
            timersub(&(tnf->rcv.tv_last), (struct timeval*) &(tnf->rcv.tv_first), &diff_time);
            time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;
            if (time_elapsed > 0.0) {
                filesize_human(tnf->rcv.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human));
            } else {
                sprintf(buffer_filesize_human, "0.0");
            }
            logfile = fopen("global_delay.txt", "a+");
            fprintf(logfile, "%u, %.2f, %d, %d\n", global_rcv_calls, (double) global_delay / global_rcv_calls, tnf->payload.loss, tnf->payload.delay);
            fclose(logfile);

            global_delay = 0;
            global_rcv_calls = 0;
        }
        //fprintf(stderr, "%s - app_delay %f\n", __func__, app_delay);
        //fprintf(stderr, "%s - app_delay s:%d - usec:%d\n", __func__, (int)diff_time.tv_sec, (int)diff_time.tv_usec);

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
            timersub(&(tnf->rcv.tv_last), (struct timeval*) &(tnf->rcv.tv_first), &diff_time);
            time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

            if (time_elapsed > 0.0) {
                filesize_human(tnf->rcv.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human));
            } else {
                sprintf(buffer_filesize_human, "0.0");
            }

            logfile = fopen("msbench.txt", "a+");
            fprintf(logfile, "%u, %u, %.2f, %.2f, %s, %.2f, %d, %d\n", tnf->rcv.bytes, tnf->rcv.calls, time_elapsed, tnf->rcv.bytes/time_elapsed, buffer_filesize_human, (double) tnf->rcv.delay_sum / tnf->rcv.calls, tnf->payload.loss, tnf->payload.delay);
            fclose(logfile);

            if (config_log_level >= 1) {
                printf("client disconnected - statistics\n");
                printf("\tbytes\t\t: %u\n",         tnf->rcv.bytes);
                printf("\trcv-calls\t: %u\n",       tnf->rcv.calls);
                printf("\tduration\t: %.2f s\n",    time_elapsed);
                printf("\tavg-delay\t: %.2f ms\n",  (double) tnf->rcv.delay_sum / tnf->rcv.calls);
                printf("\tbandwidth\t: %s/s\n", buffer_filesize_human);
            }
        }

        neat_shutdown(opCB->ctx, opCB->flow);
    }

    return NEAT_OK;
}

static void
timer_cb_writable(uv_timer_t *handle) {
    struct neat_flow_operations *opCB = (struct neat_flow_operations*) handle->data;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s() - timer finished\n", __func__);
    }

    opCB->on_writable = on_writable;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    uv_timer_stop(handle);
}

/*
    Connection established - set callbacks and reset statistics
*/
static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = NULL;
    uv_loop_t *uv_loop = NULL;

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

    // set callbacks
    opCB->on_readable = on_readable;
    if (config_active) {
        tnf->send_interval = 100;
        tnf->payload.id = flows_connected;

        if (tnf->send_interval) {
            uv_loop = neat_get_event_loop(opCB->ctx);
            uv_timer_init(uv_loop, &(tnf->send_timer));
            tnf->send_timer.data = opCB;
            tnf->ops = opCB;
            //int uv_timer_start(uv_timer_t* handle, uv_timer_cb cb, uint64_t timeout, uint64_t repeat)
            if (flows_connected == 0) {
                tnf->payload.type = PAYLOAD_BULK;
                uv_timer_start(&(tnf->send_timer), timer_cb_writable, 0, tnf->send_interval);
            } else {
                tnf->payload.type = PAYLOAD_DATA;
                uv_timer_start(&(tnf->send_timer), timer_cb_writable, 1000 * flows_connected, 0);
            }
        } else {
            opCB->on_writable = on_writable;
        }

        flows_connected++;
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

    if (tnf->snd.buffer) {
        free(tnf->snd.buffer);
    }

    if (tnf->rcv.buffer) {
        free(tnf->rcv.buffer);
    }

    if (tnf) {
        free(tnf);
    }

    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    fprintf(stderr, "%s - flow closed OK!\n", __func__);

    // stop event loop if we are active part
    if (config_active) {
        flows_active--;
        if (!flows_active) {
            fprintf(stderr, "%s - stopping event loop\n", __func__);
            neat_stop_event_loop(opCB->ctx);
        }
    }

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    int i = 0;

    struct neat_flow *flows[config_max_flows];
    struct neat_flow_operations ops[config_max_flows];

    int arg, result;
    char *arg_property = config_property;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "l:n:p:P:R:T:v:D:L:")) != -1) {
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
        case 'L':
            config_loss = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - log loss: %d\n", config_loss);
            }
            break;
        case 'D':
            config_delay = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - log delay: %d\n", config_delay);
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

    if (config_log_level == 0) {
        neat_log_level(ctx, NEAT_LOG_ERROR);
    } else if (config_log_level == 1) {
        neat_log_level(ctx, NEAT_LOG_WARNING);
    } else if (config_log_level == 2) {
        neat_log_level(ctx, NEAT_LOG_INFO);
    } else {
        neat_log_level(ctx, NEAT_LOG_DEBUG);
    }

    if (config_active) {
        for (i = 0; i < config_num_flows; i++) {
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
            if (neat_open(ctx, flows[i], argv[optind], config_port, NULL, 0) != NEAT_OK) {
                fprintf(stderr, "Could not open flow\n");
                exit(EXIT_FAILURE);
            }

            flows_active++;
        }
    } else {
        // new neat flow
        if ((flows[0] = neat_new_flow(ctx)) == NULL) {
            fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        ops[0].on_connected = on_connected;
        ops[0].on_error     = on_error;

        if (neat_set_operations(ctx, flows[0], &(ops[0]))) {
            fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        // set properties
        if (neat_set_property(ctx, flows[0], arg_property)) {
            fprintf(stderr, "%s - neat_set_property failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }


        // wait for on_connected or on_error to be invoked
        if (neat_accept(ctx, flows[0], config_port, NULL, 0)) {
            fprintf(stderr, "%s - neat_accept failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

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
