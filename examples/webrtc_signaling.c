#include "webrtc_signaling.h"
#include <neat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef WEBRTC_SUPPORT
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

struct neat_signaling_context *
neat_signaling_init(struct neat_ctx *ctx, struct neat_flow *flow, uint32_t room) {
    struct neat_signaling_context *sctx = calloc(1, sizeof(struct neat_signaling_context));

    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    sctx->ctx = ctx;

    if ((sctx->flow = neat_new_flow(sctx->ctx)) == NULL) {
        fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    sctx->ops.userData          = sctx;
    sctx->ops.on_connected      = signaling_on_connected;
    sctx->ops.on_close          = signaling_on_close;
    sctx->log_level             = 2;
    sctx->webrtc_flow           = flow;
    sctx->room                  = room;

    if (neat_set_operations(sctx->ctx, sctx->flow, &(sctx->ops))) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    // set properties
    if (neat_set_property(sctx->ctx, sctx->flow, config_property)) {
        fprintf(stderr, "%s - neat_set_property failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    // wait for on_connected or on_error to be invoked
    if (neat_open(sctx->ctx, sctx->flow, "neat.nplab.de", 5001, NULL, 0) != NEAT_OK) {
        fprintf(stderr, "Could not open flow\n");
        exit(EXIT_FAILURE);
    }

    return sctx;
}

neat_error_code
neat_signaling_free(struct neat_signaling_context *sctx) {

    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    neat_close(sctx->ctx, sctx->flow);
    free(sctx);
    return NEAT_OK;
}

neat_error_code
neat_signaling_send(struct neat_signaling_context *sctx, unsigned char* buffer, uint32_t buffer_length) {
    uint32_t *payload_length = (uint32_t *) &(sctx->buffer_snd);

    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    if (sctx->buffer_snd_level > 0) {
        fprintf(stderr, "%s - sctx->buffer_snd_level > 0 - we have unsent data! FIX LOGIC!\n", __func__);
        exit(EXIT_FAILURE);
    }

    if (buffer_length > BUFFER_SIZE) {
        fprintf(stderr, "%s - buffer_length > BUFFER_SIZE\n", __func__);
        exit(EXIT_FAILURE);
    }

    memcpy(sctx->buffer_snd + 4, buffer, buffer_length);
    sctx->buffer_snd_level = buffer_length + 4;
    *payload_length = htonl(buffer_length);

    if (sctx->state == NEAT_SIGNALING_STATE_READY) {
        sctx->ops.on_writable = signaling_on_writable;
        sctx->ops.on_readable = signaling_on_readable;
	neat_set_operations(sctx->ctx, sctx->flow, &(sctx->ops));
    }

    return NEAT_OK;
}

static neat_error_code
signaling_handle_buffer(struct neat_signaling_context *sctx) {
    char *remote = NULL;
    uint32_t payload_length = 0;
    uint32_t *payload_length_network = NULL;

    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    while (sctx->buffer_rcv_level >= 4) {
        payload_length_network = (uint32_t *) &(sctx->buffer_rcv);
        payload_length = ntohl(*payload_length_network);

        fprintf(stderr, "#######################################\n");
        fprintf(stderr, "buffer_rcv_level : %d\n", sctx->buffer_rcv_level);
        fprintf(stderr, "payload_length : %d\n", payload_length);


        if ((payload_length + 4) > (sctx->buffer_rcv_level)) {
            fprintf(stderr, "%s - message not complete yet - %d/%d\n", __func__, payload_length + 4, sctx->buffer_rcv_level);
            return NEAT_ERROR_UNABLE;
        }

        if (sctx->state == NEAT_SIGNALING_STATE_WAITING && payload_length == 8) {
            if (strncmp((const char *) &(sctx->buffer_rcv) + 4, "READY###", 8)) {
                fprintf(stderr, "%s - something went wrong - A\n", __func__);
                exit(EXIT_FAILURE);
            }

            sctx->state = NEAT_SIGNALING_STATE_READY;
            fprintf(stderr, "%s - Signaling ready\n", __func__);

            if (sctx->buffer_snd_level) {
                fprintf(stderr, "%s - send buffer filled, start writing\n", __func__);
		sctx->ops.on_writable = signaling_on_writable;
		sctx->ops.on_readable = signaling_on_readable;
                neat_set_operations(sctx->ctx, sctx->flow, &(sctx->ops));
            }
        } else if (sctx->state == NEAT_SIGNALING_STATE_READY) {
            remote = strdup((char *) &(sctx->buffer_rcv) + 4);


            //fprintf(stderr, "a - %s\n", (char *) (&(sctx->buffer_rcv) + 4));
            fprintf(stderr, "b - %s\n", remote);

            neat_send_remote_parameters(sctx->ctx, sctx->flow, remote);


        }
        sctx->buffer_rcv_level -= payload_length + 4;
        memmove(sctx->buffer_rcv, sctx->buffer_rcv + payload_length + 4, sctx->buffer_rcv_level);

    }
    fprintf(stderr, "%s - >>>>>>>>>>>>>>>>>  return NEAT_OK\n", __func__);
    return NEAT_OK;
}

// Read data from neat
static neat_error_code
signaling_on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    neat_error_code code;
    struct neat_signaling_context *sctx = opCB->userData;

    uint32_t recv_length;

    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);

    if (sctx->log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, (unsigned char *) &(sctx->buffer_rcv) + sctx->buffer_rcv_level, BUFFER_SIZE, &recv_length, NULL, 0);
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

    sctx->buffer_rcv_level += recv_length;

    if (sctx->log_level >= 1) {
        fprintf(stderr, "%s - received %d bytes\n", __func__, sctx->buffer_rcv_level);
    }

    signaling_handle_buffer(sctx);

    //fwrite(sctx->buffer_rcv, sizeof(char), sctx->buffer_rcv_level, stdout);
    //fflush(stdout);

    return NEAT_OK;
}

// Send data from stdin
static neat_error_code
signaling_on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    struct neat_signaling_context *sctx = opCB->userData;
    fprintf(stderr, ">>>>>>>> SIGNALING %s\n", __func__);
    uint32_t room;

    if (sctx->log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (sctx->state == NEAT_SIGNALING_STATE_READY) {
        code = neat_write(opCB->ctx, opCB->flow, (unsigned char *) &(sctx->buffer_snd), sctx->buffer_snd_level, NULL, 0);
    } else {
        room = htonl(sctx->room);
        code = neat_write(opCB->ctx, opCB->flow, (unsigned char *) &room, sizeof(room), NULL, 0);
    }


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
    opCB->on_writable = signaling_on_writable;
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
#endif
