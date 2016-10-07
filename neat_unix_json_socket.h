#ifndef NEAT_UNIX_JSON_SOCKET_INCLUDE
#define NEAT_UNIX_JSON_SOCKET_INCLUDE

#include "neat.h"
#include "neat_internal.h"
#include <uv.h>
#include <jansson.h>

struct neat_ipc_context;

typedef void (*written_callback)(struct neat_ctx *ctx, struct neat_flow *flow, struct neat_ipc_context *context);
typedef void (*connected_callback)(struct neat_ipc_context *context, void *data);

typedef void (*reply_callback)(struct neat_ctx *ctx, struct neat_flow *flow, json_t *json, void *data);
typedef void (*close_callback)(void *data);
typedef void (*error_callback)(struct neat_ctx *ctx, struct neat_flow *flow, int status, void *data);

struct neat_ipc_context {
    struct neat_ctx *ctx;
    struct neat_flow *flow;
    uv_pipe_t *pipe;
    uv_stream_t *stream;
    char* read_buffer;
    size_t buffer_size;
    void *data;

    written_callback on_written;
    connected_callback on_connected;
    reply_callback on_reply;
    error_callback on_error;
    close_callback on_close;

    size_t json_nesting_count;
};

neat_error_code neat_unix_json_socket_open(struct neat_ctx *ctx, struct neat_flow *flow, struct neat_ipc_context *context, const char *path, connected_callback conn_cb, reply_callback reply_cb, error_callback err_cb, void *data);
neat_error_code neat_unix_json_send(struct neat_ipc_context *context, const char *buffer, written_callback on_written, error_callback on_error);
neat_error_code neat_unix_json_start_read(struct neat_ipc_context *context);
neat_error_code neat_unix_json_shutdown(struct neat_ipc_context *context);
void neat_unix_json_close(struct neat_ipc_context *context, close_callback cb, void *data);


#endif /* ifndef NEAT_UNIX_JSON_SOCKET_INCLUDE */

