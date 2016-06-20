#ifndef NEAT_PMI_H
#define NEAT_PMI_H

#include "neat_queue.h"

#define PMI_BUF_SIZE 512//2048

typedef void (*neat_pmi_reply_t)(struct neat_ctx *ctx, struct neat_flow *flow,
				 char *reply);

struct neat_pmi_pipe {
    uv_fs_t req;
    uv_buf_t buf;

    int ready;
};

TAILQ_HEAD(neat_pmi_request_queue, neat_pmi_req);

struct neat_pmi_ctx {
    uv_fs_t req_rd;
    uv_fs_t req_wr;

    char *reply;
    size_t reply_len;

    uv_poll_t poll_in;
    //uv_poll_t poll_out;

    int reading_in;

    struct neat_pmi_request_queue req_queue;

    struct neat_pmi_pipe in;
    struct neat_pmi_pipe out;
};

enum neat_pmi_direction {
    NEAT_PMI_IN,
    NEAT_PMI_OUT
};

struct neat_pmi_req {
    struct neat_ctx *ctx;
    struct neat_flow *flow;
    enum neat_pmi_direction direction;
    neat_pmi_reply_t cb_reply;
    uv_buf_t request;
    uv_buf_t reply;
    uv_fs_t *send_req;
    size_t written;
    size_t read;
    TAILQ_ENTRY(neat_pmi_req) req_queue;
};

neat_error_code neat_pmi_init(struct neat_ctx *ctx);
void neat_pmi_shutdown(struct neat_ctx *ctx);
neat_error_code neat_pmi_send(struct neat_ctx *ctx,
			      struct neat_flow *flow,
			      char *buf,
			      size_t len,
			      neat_pmi_reply_t cb_reply);
#endif // NEAT_PMI_H
