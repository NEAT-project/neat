#include "webrtc_signaling.h"
#include <neat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"TCP\",\
            \"precedence\": 1\
        }\
    ]\
}";

static neat_error_code signaling_on_connected(struct neat_flow_operations *opCB);
static neat_error_code signaling_on_close(struct neat_flow_operations *opCB);
static neat_error_code signaling_on_readable(struct neat_flow_operations *opCB);
static neat_error_code signaling_on_writable(struct neat_flow_operations *opCB);

neat_error_code
neat_signaling_init(struct neat_ctx *ctx, struct neat_signaling_context *sctx) {
    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    memset(sctx, 0, sizeof(struct neat_signaling_context));

    sctx->ctx = ctx;
    if ((sctx->flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
        exit(EXIT_FAILURE);
    }


    sctx->ops.userData          = sctx;
    sctx->ops.on_connected      = signaling_on_connected;
    sctx->ops.on_close          = signaling_on_close;
    sctx->log_level             = 2;

    if (neat_set_operations(ctx, sctx->flow, &(sctx->ops))) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    // set properties
    if (neat_set_property(ctx, sctx->flow, config_property)) {
        fprintf(stderr, "%s - neat_set_property failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    // wait for on_connected or on_error to be invoked
    if (neat_open(ctx, sctx->flow, "neat.nplab.de", 5000, NULL, 0) != NEAT_OK) {
        fprintf(stderr, "Could not open flow\n");
        exit(EXIT_FAILURE);
    }

    return NEAT_OK;
}

neat_error_code
neat_signaling_send(struct neat_signaling_context *sctx, unsigned char* buffer, uint32_t buffer_length) {

    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    if (buffer_length > BUFFER_SIZE) {
        fprintf(stderr, "%s - buffer_length > BUFFER_SIZE\n", __func__);
        return NEAT_ERROR_MESSAGE_TOO_BIG;
    }

    fprintf(stderr, "%s - SIGNALING OUT (%d):\n%s\n", __func__, buffer_length, buffer);

    memcpy(&(sctx->buffer_snd), buffer, buffer_length);
    sctx->buffer_snd_level = buffer_length;

    if (sctx->state == NEAT_SIGNALING_STATE_READY) {
        sctx->ops.on_writable = signaling_on_writable;
        neat_set_operations(sctx->ctx, sctx->flow, &(sctx->ops));
    }

    return NEAT_OK;
}

// Read data from neat
static neat_error_code
signaling_on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    neat_error_code code;
    struct neat_signaling_context *sctx = opCB->userData;
    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    if (sctx->log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, (unsigned char *) &(sctx->buffer_rcv), BUFFER_SIZE, &(sctx->buffer_rcv_level), NULL, 0);
    if (code != NEAT_OK) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            if (sctx->log_level >= 1) {
                fprintf(stderr, "%s - neat_read - NEAT_ERROR_WOULD_BLOCK\n", __func__);
            }
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read - error: %d\n", __func__, (int)code);
            //return on_error(opCB);
            return NEAT_ERROR_IO;
        }
    }

    if (sctx->state == NEAT_SIGNALING_STATE_WAITING &&  sctx->buffer_rcv_level == 8) {
        if (strncmp((const char *) &(sctx->buffer_rcv), "READY###", 8)) {
            fprintf(stderr, "%s - something went wrong\n", __func__);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "%s - Signaling ready\n", __func__);
        sctx->state = NEAT_SIGNALING_STATE_READY;


        if (sctx->buffer_snd_level) {
            sctx->ops.on_writable = signaling_on_writable;
            neat_set_operations(sctx->ctx, sctx->flow, &(sctx->ops));
        }
    }


    if (sctx->log_level >= 1) {
        fprintf(stderr, "%s - received %d bytes\n", __func__, sctx->buffer_rcv_level);
    }

    fwrite(sctx->buffer_rcv, sizeof(char), sctx->buffer_rcv_level, stdout);
    fflush(stdout);

    return NEAT_OK;
}

// Send data from stdin
static neat_error_code
signaling_on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    struct neat_signaling_context *sctx = opCB->userData;
    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    if (sctx->log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }


    code = neat_write(opCB->ctx, opCB->flow, (unsigned char *) &(sctx->buffer_snd), sctx->buffer_snd_level, NULL, 0);
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write - error: %d\n", __func__, (int)code);
        //return on_error(opCB);
        return NEAT_ERROR_IO;
    }

    // stop writing
    opCB->on_writable = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

static neat_error_code
signaling_on_all_written(struct neat_flow_operations *opCB)
{
    struct neat_signaling_context *sctx = opCB->userData;
    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    if (sctx->log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    // data sent completely - continue reading from stdin

    return NEAT_OK;
}

static neat_error_code
signaling_on_connected(struct neat_flow_operations *opCB)
{
    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);
    opCB->on_readable = signaling_on_readable;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    return NEAT_OK;
}

static neat_error_code
signaling_on_close(struct neat_flow_operations *opCB)
{
    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    // cleanup
    opCB->on_close      = NULL;
    opCB->on_readable   = NULL;
    opCB->on_writable   = NULL;
    opCB->on_error      = NULL;

    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    neat_stop_event_loop(opCB->ctx);

    return NEAT_OK;
}
