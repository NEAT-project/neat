#include <neat.h>
#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uv.h>


static uint32_t config_signaling_buffer_size = 8192;
static uint16_t config_log_level = 1;


static char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"TCP\",\
            \"precedence\": 1\
        }\
    ]\
}";

static uint32_t rcv_buffer_level = 0;
//static uint32_t snd_buffer_level = 0;

static unsigned char *signaling_buffer_rcv  = NULL;
static unsigned char *signaling_buffer_snd  = NULL;

static neat_error_code on_all_written(struct neat_flow_operations *opCB);


// Error handler
static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }
    // Placeholder until neat_error handling is implemented
    return 1;
}

// Read data from neat
static neat_error_code
signaling_on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    neat_error_code code;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, signaling_buffer_rcv, config_signaling_buffer_size, &rcv_buffer_level, NULL, 0);
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


    if (config_log_level >= 1) {
        fprintf(stderr, "%s - received %d bytes\n", __func__, rcv_buffer_level);
    }

    fwrite(signaling_buffer_rcv, sizeof(char), rcv_buffer_level, stdout);
    fflush(stdout);

    return NEAT_OK;
}

// Send data from stdin
static neat_error_code
signaling_on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;


    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }


    code = neat_write(opCB->ctx, opCB->flow, signaling_buffer_snd, config_signaling_buffer_size, NULL, 0);
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write - error: %d\n", __func__, (int)code);
        return on_error(opCB);
    }

    // stop writing
    opCB->on_writable = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

static neat_error_code
signaling_on_all_written(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    // data sent completely - continue reading from stdin

    return NEAT_OK;
}

static neat_error_code
signaling_on_connected(struct neat_flow_operations *opCB)
{
    opCB->on_readable = signaling_on_readable;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    return NEAT_OK;
}

static neat_error_code
signaling_on_close(struct neat_flow_operations *opCB)
{
    fprintf(stderr, "%s - flow closed OK!\n", __func__);

    // cleanup
    opCB->on_close      = NULL;
    opCB->on_readable   = NULL;
    opCB->on_writable   = NULL;
    opCB->on_error      = NULL;

    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    neat_stop_event_loop(opCB->ctx);

    return NEAT_OK;
}


int
main(int argc, char *argv[])
{
    int result;
    char *arg_property = NULL;

    struct neat_flow_operations signaling_ops;
    struct neat_ctx *ctx = NULL;
    struct neat_flow *signaling_flow = NULL;

    memset(&signaling_ops, 0, sizeof(signaling_ops));

    result = EXIT_SUCCESS;

    if ((signaling_buffer_rcv = malloc(config_signaling_buffer_size)) == NULL) {
        fprintf(stderr, "%s - error: could not allocate receive buffer\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }
    if ((signaling_buffer_snd = malloc(config_signaling_buffer_size)) == NULL) {
        fprintf(stderr, "%s - error: could not allocate send buffer\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "%s - error: could not initialize context\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // new neat flow
    if ((signaling_flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "%s - error: could not create new neat flow\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set properties
    if (neat_set_property(ctx, signaling_flow, arg_property ? arg_property : config_property)) {
        fprintf(stderr, "%s - error: neat_set_property\n", __func__);
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

    // set callbacks
    signaling_ops.on_connected    = signaling_on_connected;
    signaling_ops.on_error        = on_error;
    signaling_ops.on_close        = signaling_on_close;

    if (neat_set_operations(ctx, signaling_flow, &signaling_ops)) {
        fprintf(stderr, "%s - error: neat_set_operations\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }


    // wait for on_connected or on_error to be invoked
    if (neat_open(ctx, signaling_flow, "localhost", 5000, NULL, 0) == NEAT_OK) {
        neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
    } else {
        fprintf(stderr, "%s - error: neat_open\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

cleanup:
    free(signaling_buffer_rcv);
    free(signaling_buffer_snd);

    if (arg_property) {
        free(arg_property);
    }

    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
