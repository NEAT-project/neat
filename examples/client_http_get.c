#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "../neat.h"

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)
#endif

/**********************************************************************

    HTTP-GET client in neat
    * connect to HOST and send GET request
    * write response to stdout

    client_http_get [OPTIONS] HOST
    -u : URI
    -n : number of requests/flows

**********************************************************************/

static uint32_t config_rcv_buffer_size = 6553600;
static uint32_t config_max_flows = 50;
static char request[512];
static uint32_t flows_active = 0;
static struct timeval start_time;
static const char *request_tail = "HTTP/1.0\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";
/*
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
}";\
*/
static char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"SCTP\",\
            \"precedence\": 1\
        }\
    ]\
}";\


static neat_error_code on_close(struct neat_flow_operations *opCB);

static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    fprintf(stderr, "%s\n", __func__);

    int *result = (int*)opCB->userData;
    if (*result != EXIT_FAILURE)
        *result = EXIT_FAILURE;

    neat_close(opCB->ctx, opCB->flow);
    return NEAT_OK;
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    unsigned char buffer[config_rcv_buffer_size];
    uint32_t bytes_read = 0;
    neat_error_code code;
    struct timeval now, diff_time;
    double seconds;

    fprintf(stderr, "%s - reading from flow\n", __func__);
    code = neat_read(opCB->ctx, opCB->flow, buffer, config_rcv_buffer_size, &bytes_read, NULL, 0);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    } else if (code != NEAT_OK) {
        return on_error(opCB);
    }

    if (!bytes_read) { // eof
        fprintf(stderr, "%s - neat_read() got 0 bytes - connection closed\n", __func__);
        fflush(stdout);
        on_close(opCB);

    } else if (bytes_read > 0) {
        fprintf(stderr, "%s - received %d bytes\n", __func__, bytes_read);
        fwrite(buffer, sizeof(char), bytes_read, stdout);
    }
    gettimeofday(&now, NULL);
	timersub(&now, &start_time, &diff_time);
	seconds = diff_time.tv_sec + (double)diff_time.tv_usec/1000000.0;
	fprintf(stdout, "transfer time: %f seconds bytes: %ul throughput: %f bit/s\n", seconds, bytes_read, (double)((bytes_read*8)/seconds));
    return 0;
}

static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    fprintf(stderr, "%s - writing to flow\n", __func__);
    code = neat_write(opCB->ctx, opCB->flow, (const unsigned char *)request, strlen(request), NULL, 0);
    if (code != NEAT_OK) {
        return on_error(opCB);
    }
    opCB->on_writable = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return 0;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    fprintf(stderr, "%s - connection established\n", __func__);
    opCB->on_readable = on_readable;
    opCB->on_writable = on_writable;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    gettimeofday(&start_time, NULL);
    return 0;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
    fprintf(stderr, "%s - flow closed OK!\n", __func__);

    // cleanup
    opCB->on_close = NULL;
    opCB->on_readable = NULL;
    opCB->on_writable = NULL;
    opCB->on_error = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    // stop event loop if all flows are closed
    flows_active--;
    fprintf(stderr, "%s - active flows left : %d\n", __func__, flows_active);
    if (flows_active == 0) {
        fprintf(stderr, "%s - stopping event loop\n", __func__);
        neat_stop_event_loop(opCB->ctx);
    }

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    struct neat_flow *flows[config_max_flows];
    struct neat_flow_operations ops[config_max_flows];
    int result = 0;
    int arg = 0;
    uint32_t num_flows = 1;
    uint32_t i = 0;
    result = EXIT_SUCCESS;

    memset(&ops, 0, sizeof(ops));
    memset(flows, 0, sizeof(flows));

    NEAT_OPTARGS_DECLARE(NEAT_OPTARGS_MAX);
    NEAT_OPTARGS_INIT();

    snprintf(request, sizeof(request), "GET %s %s", "/", request_tail);

    while ((arg = getopt(argc, argv, "u:n:")) != -1) {
        switch(arg) {
        case 'u':
            snprintf(request, sizeof(request), "GET %s %s", optarg, request_tail);
            break;
        case 'n':
            num_flows = strtoul (optarg, NULL, 0);
            if (num_flows > config_max_flows) {
                num_flows = config_max_flows;
            }
            fprintf(stderr, "%s - option - number of flows: %d\n", __func__, num_flows);
            break;
        default:
            fprintf(stderr, "usage: client_http_get [OPTIONS] HOST\n");
            goto cleanup;
            break;
        }
    }

    if (optind + 1 != argc) {
        fprintf(stderr, "usage: client_http_get [OPTIONS] HOST\n");
        goto cleanup;
    }

    printf("%d flows - requesting: %s\n", num_flows, request);

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "could not initialize context\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    for (i = 0; i < num_flows; i++) {
        if ((flows[i] = neat_new_flow(ctx)) == NULL) {
            fprintf(stderr, "could not initialize context\n");
            result = EXIT_FAILURE;
            goto cleanup;
        }

        neat_set_property(ctx, flows[i], config_property);

        ops[i].on_connected = on_connected;
        ops[i].on_error = on_error;
        ops[i].on_close = on_close;
        ops[i].userData = &result; // allow on_error to modify the result variable
        neat_set_operations(ctx, flows[i], &(ops[i]));

        NEAT_OPTARG_STRING(NEAT_TAG_LOCAL_NAME, "10.1.1.1,10.1.2.1");
      //NEAT_OPTARG_STRING(NEAT_TAG_LOCAL_NAME, "10.1.1.1");

        // wait for on_connected or on_error to be invoked
        if (neat_open(ctx, flows[i], argv[argc - 1], 80, NEAT_OPTARGS, NEAT_OPTARGS_COUNT) != NEAT_OK) {
            fprintf(stderr, "Could not open flow\n");
            result = EXIT_FAILURE;
        } else {
            fprintf(stderr, "Opened flow %d\n", i);
            flows_active++;
        }
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

cleanup:
    for (i = 0; i < num_flows; i++) {
        flows[i] = NULL;
    }
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
