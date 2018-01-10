#include "util.h"
#include <neat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#define QUOTE(...) #__VA_ARGS__

/**********************************************************************

    tneat - neat testing tool

    tneat [OPTIONS] [HOST]
    -c : path to server certificate 
    -f : number of outgoing flows
    -k : path to server key 
    -l : message length in byte (client)
    -L : loop mode - tneat talking to itself
    -n : number of messages to send (client)
    -p : port [received on|send to]
    -P : neat properties
    -R : receive buffer in byte (server)
    -T : max runtime (client)
    -v : log level (0 .. 3)
    -w : set low watermark 

**********************************************************************/

/*
    default values
*/
#define NEAT_MODE_CLIENT    1
#define NEAT_MODE_SERVER    2
#define NEAT_MODE_LOOP      3

static uint32_t config_rcv_buffer_size      = 10240;
static uint32_t config_snd_buffer_size      = 4096;
static uint32_t config_message_count        = 128;
static uint32_t config_runtime_max          = 0;
static uint16_t config_mode                 = 0;
static uint16_t config_chargen_offset       = 0;
static uint16_t config_port                 = 23232;
static uint16_t config_log_level            = 1;
static uint16_t config_num_flows            = 10;
static uint16_t config_max_flows            = 1000;
static uint16_t config_max_server_runs      = 0;
static uint32_t config_low_watermark        = 0;
static float    config_prio                 = 1.0f; 
static uint16_t config_fg                   = 0; 
static char *config_property = QUOTE({
    "transport": {
        "value": ["SCTP", "TCP"],
        "precedence": 2
    },
        "__he_delay": {
        "value": 100
        }
    }
);


static uint32_t flows_active    = 0;
static uint32_t server_runs     = 0;
static char *cert_file          = NULL;
static char *key_file           = NULL;
static char *loop_hostname      = "127.0.0.1";
static int result               = EXIT_SUCCESS;

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
    uint8_t active;
    struct  tneat_flow_direction rcv;
    struct  tneat_flow_direction snd;
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
    printf("\t- c \tpath to server certificate (%s)\n", cert_file);
    printf("\t- f \tnumber of outgoing flows (%d)\n", config_num_flows);
    printf("\t- k \tpath to server key (%s)\n", key_file);
    printf("\t- l \tsize for each message in byte (%d)\n", config_snd_buffer_size);
    printf("\t- L \tloop mode - tneat talking to itself\n");
    printf("\t- n \tmax number of messages to send (%d)\n", config_message_count);
    printf("\t- p \tport [receive on|send to] (%d)\n", config_port);
    printf("\t- P \tneat properties (%s)\n", config_property);
    printf("\t- R \treceive buffer in byte (%d)\n", config_rcv_buffer_size);
    printf("\t- T \tmax runtime in seconds (%d)\n", config_runtime_max);
    printf("\t- v \tlog level 0..3 (%d)\n", config_log_level);
    printf("\t- w \tset low watermark (%d)\n", config_low_watermark);
    printf("\t- W \tflow priority (0..1) (w/ TCP: FreeBSD only) (%.2f)\n", config_prio); 
    printf("\t- g \tflow group number (%d)\n", config_fg);   
}

/*
    error handler
*/
static neat_error_code
on_error(struct neat_flow_operations *opCB)
{

    fprintf(stderr, "%s()\n", __func__);
    neat_stop_event_loop(opCB->ctx);
    result = EXIT_FAILURE;
    return NEAT_OK;
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    struct timeval now, diff_time;
    double time_elapsed;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    gettimeofday(&now, NULL);
    timersub(&(tnf->snd.tv_last), &(tnf->snd.tv_first), &diff_time);
    time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

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

    // update stats
    tnf->snd.calls++;
    tnf->snd.bytes += config_snd_buffer_size;
    gettimeofday(&(tnf->snd.tv_last), NULL);

    // every message contains a different payload (i++)
    config_chargen_offset = (config_chargen_offset+1) % 72;
    memset(tnf->snd.buffer, 33 + config_chargen_offset, config_snd_buffer_size);

    if (config_log_level >= 2) {
        printf("neat_write - # %u - %d byte\n", tnf->snd.calls, config_snd_buffer_size);
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

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    uint32_t buffer_filled;
    neat_error_code code;

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

    // we got data!
    if (buffer_filled > 0) {

        if (tnf->rcv.calls == 0) {
            gettimeofday(&(tnf->rcv.tv_first), NULL);
        }
        tnf->rcv.calls++;
        tnf->rcv.bytes += buffer_filled;
        gettimeofday(&(tnf->rcv.tv_last), NULL);

        if (config_log_level >= 2) {
            printf("neat_read - # %u - %d byte\n", tnf->rcv.calls, buffer_filled);
            if (config_log_level >= 4) {
                fwrite(tnf->rcv.buffer, sizeof(char), buffer_filled, stdout);
                printf("\n");
            }
        }
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

    if ((tnf = calloc(1, sizeof(struct tneat_flow))) == NULL) {
        fprintf(stderr, "%s - could not allocate tneat_flow\n", __func__);
        exit(EXIT_FAILURE);
    }

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

    // hacky but quick and easy solution
    if (opCB->userData) {
        tnf->active = 1;
    }

    opCB->userData = tnf;

    // set callbacks
    opCB->on_readable = on_readable;
    if (tnf->active) {
        opCB->on_writable = on_writable;
    }
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    if (config_low_watermark) {
        neat_set_low_watermark(opCB->ctx, opCB->flow, config_low_watermark);
    }

    return NEAT_OK;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;
    char buffer_filesize_human[32];
    double time_elapsed;
    struct timeval diff_time;

    fprintf(stderr, "%s\n", __func__);

    if (tnf->active == 0) {
        // print statistics
        timersub(&(tnf->rcv.tv_last), &(tnf->rcv.tv_first), &diff_time);
        time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

        //rintf("%u, %u, %.2f, %.2f, %s\n", tnf->rcv.bytes, tnf->rcv.calls, time_elapsed, tnf->rcv.bytes/time_elapsed, filesize_human(tnf->rcv.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));
        printf("flow closed - statistics\n");
        printf("\tbytes\t\t: %u\n", tnf->rcv.bytes);
        printf("\trcv-calls\t: %u\n", tnf->rcv.calls);
        printf("\tduration\t: %.2fs\n", time_elapsed);
        if (time_elapsed > 0.0) {
            printf("\tbandwidth\t: %s/s\n", filesize_human(tnf->rcv.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));
        }

    } else {
        // print statistics
        timersub(&(tnf->snd.tv_last), &(tnf->snd.tv_first), &diff_time);
        time_elapsed = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;

        printf("flow closed - statistics\n");
        printf("\tbytes\t\t: %u\n", tnf->snd.bytes);
        printf("\tsnd-calls\t: %u\n", tnf->snd.calls);
        printf("\tduration\t: %.2fs\n", time_elapsed);
        if (time_elapsed > 0.0) {
            printf("\tbandwidth\t: %s/s\n", filesize_human(tnf->snd.bytes/time_elapsed, buffer_filesize_human, sizeof(buffer_filesize_human)));
        }
    }

    // stop event loop if we are active part
    if (tnf->active) {
        flows_active--;

        fprintf(stderr, "%d flows active\n", flows_active);
        if (!flows_active && config_mode != NEAT_MODE_LOOP) {
            fprintf(stderr, "%s - stopping event loop (active)\n", __func__);
            neat_stop_event_loop(opCB->ctx);
        }
    } else {
        if (tnf->rcv.calls > 0) {
            server_runs++;
        }

        if ((config_max_server_runs > 0 && server_runs >= config_max_server_runs) || (config_mode == NEAT_MODE_LOOP && server_runs >= config_num_flows)) {
            fprintf(stderr, "%s - stopping event loop (passive)\n", __func__);
            neat_stop_event_loop(opCB->ctx);
        }
    }

    if (tnf->snd.buffer) {
        free(tnf->snd.buffer);
    }

    if (tnf->rcv.buffer) {
        free(tnf->rcv.buffer);
    }

    free(tnf);

    fprintf(stderr, "%s - flow closed OK!\n", __func__);
    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    int i = 0;

    struct neat_flow *flows_client[config_max_flows];
    struct neat_flow *flow_server;
    struct neat_flow_operations ops_client[config_max_flows];
    struct neat_flow_operations op_server;

    int arg;
    char *arg_property = config_property;
    char *remote_addr = NULL;

    memset(&ops_client, 0, sizeof(ops_client));
    memset(&op_server, 0, sizeof(op_server));

    while ((arg = getopt(argc, argv, "c:f:k:l:Ln:p:P:R:T:v:w:W:g:")) != -1) {
        switch(arg) {
            case 'c':
                cert_file = optarg;
                if (config_log_level >= 1) {
                    printf("option - server certificate file: %s\n", cert_file);
                }
                break;
            case 'f':
                config_num_flows = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - number of flows: %d\n", config_num_flows);
                }
                if (config_num_flows > config_max_flows) {
                    printf("number of flows exceeds max number of flows (%d) - exit\n", config_max_flows);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'k':
                key_file = optarg;
                if (config_log_level >= 1) {
                    printf("option - server key file: %s\n", key_file);
                }
                break;
            case 'l':
                config_snd_buffer_size = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - send buffer size: %d\n", config_snd_buffer_size);
                }
                break;
            case 'L':
                config_mode = NEAT_MODE_LOOP;
                if (config_log_level >= 1) {
                    printf("option - LOOP MODE\n");
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
                    fprintf(stderr, "Unable to read properties from %s: %s", optarg, strerror(errno));
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
            case 'w':
                config_low_watermark = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - low watermark: %d\n", config_low_watermark);
                }
                break;
            case 'W':
                config_prio = atof(optarg);
                if (config_log_level >= 1) {
                    printf("option - flow priority: %.2f\n", config_prio);
                }
                break;
            case 'g':
                config_fg = atoi(optarg);
                if (config_log_level >= 1) {
                    printf("option - flow group number: %d\n", config_fg);
                }
                break;	 
            default:
                print_usage();
                goto cleanup;
                break;
        }
    }

    if (config_mode != NEAT_MODE_LOOP) {
        if (optind == argc) {
            config_mode = NEAT_MODE_SERVER;
            printf("role: passive\n");
        } else if (optind + 1 == argc) {
            config_mode = NEAT_MODE_CLIENT;
            printf("role: active\n");
        } else {
            fprintf(stderr, "%s - argument error\n", __func__);
            print_usage();
            goto cleanup;
        }
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
    } else if (config_log_level == 2) {
        neat_log_level(ctx, NEAT_LOG_INFO);
    } else if (config_log_level >= 3) {
        neat_log_level(ctx, NEAT_LOG_DEBUG);
    }

    if (config_mode == NEAT_MODE_CLIENT || config_mode == NEAT_MODE_LOOP) {
        for (i = 0; i < config_num_flows; i++) {
            if ((flows_client[i] = neat_new_flow(ctx)) == NULL) {
                fprintf(stderr, "could not initialize context\n");
                result = EXIT_FAILURE;
                goto cleanup;
            }

            // set properties
            if (neat_set_property(ctx, flows_client[i], arg_property)) {
                fprintf(stderr, "%s - error: neat_set_property\n", __func__);
                result = EXIT_FAILURE;
                goto cleanup;
            }

            ops_client[i].on_connected = on_connected;
            ops_client[i].on_error = on_error;
            ops_client[i].on_close = on_close;
            ops_client[i].userData = &result; // allow on_error to modify the result variable
            neat_set_operations(ctx, flows_client[i], &(ops_client[i]));

            if (config_mode == NEAT_MODE_LOOP) {
                remote_addr = loop_hostname;
            } else {
                remote_addr = argv[optind];
            }

            NEAT_OPTARGS_DECLARE(NEAT_OPTARGS_MAX);
	        NEAT_OPTARGS_INIT();
            if (config_fg) {
                NEAT_OPTARG_INT(NEAT_TAG_FLOW_GROUP, config_fg);
                NEAT_OPTARG_FLOAT(NEAT_TAG_PRIORITY, config_prio);
#ifdef __FreeBSD__                 
                NEAT_OPTARG_STRING(NEAT_TAG_CC_ALGORITHM, "newreno_afse");
#endif                
	    }
            // wait for on_connected or on_error to be invoked
            if (neat_open(ctx, flows_client[i], remote_addr, config_port, NEAT_OPTARGS, NEAT_OPTARGS_COUNT) != NEAT_OK) {
                fprintf(stderr, "Could not open flow\n");
                exit(EXIT_FAILURE);
            }

            fprintf(stderr, "Opened flow %d\n", i);
            flows_active++;
        }
    }

    if (config_mode == NEAT_MODE_SERVER || config_mode == NEAT_MODE_LOOP) {

        // new neat flow
        if ((flow_server = neat_new_flow(ctx)) == NULL) {
            fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        op_server.on_connected = on_connected;
        op_server.on_error     = on_error;
        op_server.on_close     = on_close;

        if (neat_set_operations(ctx, flow_server, &(op_server))) {
            fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        if (cert_file && neat_secure_identity(ctx, flow_server, cert_file, NEAT_CERT_PEM)) {
            fprintf(stderr, "%s - neat_get_secure_identity failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        if (key_file && neat_secure_identity(ctx, flow_server, key_file, NEAT_KEY_PEM)) {
            fprintf(stderr, "%s - neat_get_secure_identity failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        // set properties
        if (neat_set_property(ctx, flow_server, arg_property)) {
            fprintf(stderr, "%s - neat_set_property failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }


        // wait for on_connected or on_error to be invoked
        if (neat_accept(ctx, flow_server, config_port, NULL, 0)) {
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

    if (arg_property != config_property && arg_property != NULL) {
        free(arg_property);
    }
    exit(result);
}
