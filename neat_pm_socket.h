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

typedef void (*pm_error_callback)(struct neat_ctx *ctx, struct neat_flow *flow, int error);
typedef void (*pm_reply_callback)(struct neat_ctx *ctx, struct neat_flow *flow, json_t *json);

struct neat_pm_context {
    char* output_buffer;
    pm_error_callback on_pm_error;
    pm_reply_callback on_pm_reply;
    struct neat_ipc_context *ipc_context;
    uv_timer_t* timer;
};


// neat_error_code neat_pm_socket_connect(struct neat_ctx *ctx, struct neat_flow *flow, pm_callback cb);
neat_error_code neat_json_send_once(struct neat_ctx *ctx, struct neat_flow *flow, const char *path, json_t *json, pm_reply_callback cb, pm_error_callback err_cb);

#endif /* ifndef NEAT_PM_SOCKET_INCLUDE */
