#ifndef NEAT_PM_SOCKET_INCLUDE
#define NEAT_PM_SOCKET_INCLUDE

#include "neat.h"
#include "neat_internal.h"
#include <uv.h>
#include <jansson.h>

enum {
    PM_ERROR_OK = 0,
    PM_ERROR_SOCKET_UNAVAILABLE,
    PM_ERROR_SOCKET,
    PM_ERROR_INVALID_JSON,
    PM_ERROR_OOM,
};

typedef void (*pm_callback)(struct neat_ctx *ctx, struct neat_flow *flow);
typedef void (*pm_reply_callback)(struct neat_ctx *ctx, struct neat_flow *flow, json_t *json);
typedef void (*pm_error_callback)(struct neat_ctx *ctx, struct neat_flow *flow, int error);

struct neat_pm_context {
    uv_pipe_t pm_pipe;
    // uv_stream_t *pm_handle;
    // char *pm_path;
};

struct neat_pm_request {
    uv_handle_t handle;
};

// neat_error_code neat_pm_socket_connect(struct neat_ctx *ctx, struct neat_flow *flow, pm_callback cb);
neat_error_code neat_pm_send(struct neat_ctx *ctx, struct neat_flow *flow, char *buffer, pm_reply_callback cb, pm_error_callback err_cb);

#endif /* ifndef NEAT_PM_SOCKET_INCLUDE */
