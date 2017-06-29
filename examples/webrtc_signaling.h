#ifndef WEBRTC_SIGNALING_H
#define WEBRTC_SIGNALING_H

#include <neat.h>

#define BUFFER_SIZE 8192

typedef enum {
    NEAT_SIGNALING_STATE_WAITING = 0,
    NEAT_SIGNALING_STATE_READY,
    NEAT_SIGNALING_STATE_DONE
} signaling_state;

struct neat_signaling_context {
    struct neat_ctx *ctx;
    struct neat_flow *flow;
    struct neat_flow_operations ops;
    uint8_t log_level;
    unsigned char buffer_rcv[BUFFER_SIZE];
    unsigned char buffer_snd[BUFFER_SIZE];
    uint32_t buffer_rcv_level;
    uint32_t buffer_snd_level;
    uint8_t state;
};

neat_error_code neat_signaling_init(struct neat_ctx *ctx, struct neat_signaling_context *sctx);
neat_error_code neat_signaling_send(struct neat_signaling_context *sctx, unsigned char* buffer, uint32_t buffer_length);

#endif /* ifndef WEBRTC_SIGNALING_H */
