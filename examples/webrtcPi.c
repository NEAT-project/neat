#include "util.h"
#include "webrtc_signaling.h"

#include <neat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include "gyropi.h"


#define QUOTE(...) #__VA_ARGS__
/**********************************************************************

    WebRTC peer in neat
    * connect to peer and send and receive DATA

    peer_webrtc [OPTIONS] SESSION
    -n : number of requests/flows
    -R : receive buffer size in byte
    -v : log level (0 .. 2)

**********************************************************************/

static uint32_t config_runtime_max          = 0;
static uint16_t config_port                 = 23232;
static uint16_t config_log_level            = 1;
static uint16_t config_num_flows            = 1;
static uint16_t config_active               = 0;
static uint16_t config_max_flows            = 100;

#define BUFSIZE    2048
static char *config_property = QUOTE(
{
    "transport":  {
        "value": "WEBRTC",
        "precedence": 1
    }
}
);

static uint32_t flows_active = 0;
static struct neat_signaling_context *sctx;

//static int pipeFd;

struct tneat_flow_direction {
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
    printf("\t- n \tmax number of messages to send (%d)\n", config_message_count);
    printf("\t- p \tport [receive on|send to] (%d)\n", config_port);
    printf("\t- P \tneat properties (%s)\n", config_property);
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
    uint32_t buffer_filled;
    char buffer[BUFSIZ];
    neat_error_code code;
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, (unsigned char *) &buffer, BUFSIZ, &buffer_filled, NULL, 0);
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
        if (config_log_level >= 2) {
            printf("%s: neat_read  - %d byte\n", opCB->label, buffer_filled);
            if (config_log_level >= 4) {
                fwrite(&buffer, sizeof(char), buffer_filled, stdout);
                printf("\n");
            }
        }
    }

    return NEAT_OK;
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
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
    int n;
    float gyro_x, gyro_y, gyro_z;
    char buf[BUFSIZE];

    printf("peer_webrtc: on_writable\n");
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (sensehat_get_gyro(&gyro_x, &gyro_y, &gyro_z)) {
        return NEAT_OK;
    }

    n = snprintf(buf, BUFSIZE, "{\"x\": %f, \"y\": %f, \"z\": %f, \"valcount\": %d}\r\n", gyro_x, gyro_y, gyro_z, tnf->snd.calls++);
    code = neat_write(opCB->ctx, opCB->flow, (const unsigned char *) buf, n, NULL, 0);

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

    if (config_log_level >= 1) {
        fprintf(stderr, "%s() - connection established\n", __func__);
    }
    if ((opCB->userData = calloc(1, sizeof(struct tneat_flow))) == NULL) {
        fprintf(stderr, "%s - could not allocate tneat_flow\n", __func__);
        exit(EXIT_FAILURE);
    }
    tnf = opCB->userData;

    // reset stats
    tnf->snd.calls = 0;
    tnf->snd.bytes = 0;
    tnf->rcv.calls = 0;
    tnf->rcv.bytes = 0;

    // set callbacks
    opCB->on_readable = on_readable;
    opCB->on_writable = on_writable;

    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
    struct tneat_flow *tnf = opCB->userData;

    fprintf(stderr, "%s\n", __func__);

    if (tnf) {
        free(tnf);
        tnf = 0;
    }

    fprintf(stderr, "%s - flow closed OK!\n", __func__);

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    int i = 0;
    struct neat_tlv options[1];
    char name[20];
    float gyro_x, gyro_y, gyro_z;
    int returncodefuermichael;

    struct neat_flow *flows[config_max_flows];
    struct neat_flow_operations ops[config_max_flows];
    // create listening flow for accepted new data channels
    struct neat_flow *listening_flow;
    struct neat_flow_operations operation;

    int arg, result;
    char *arg_property = config_property;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    sensehat_init();
    returncodefuermichael = sensehat_get_gyro(&gyro_x, &gyro_y, &gyro_z);
    fprintf(stderr, "returncodefuermichael = %d\n", returncodefuermichael);
    fprintf(stderr, "x: %f - y: %f - z: %f\n", gyro_x, gyro_y, gyro_z);

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

    sctx = neat_signaling_init(ctx, listening_flow, atoi(argv[optind]));
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
