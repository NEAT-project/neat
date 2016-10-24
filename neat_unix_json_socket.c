#include "neat.h"
#include "neat_internal.h"
#include "neat_unix_json_socket.h"

#include <stdlib.h>
#include <uv.h>
#include <string.h>
#include <jansson.h>
#include <assert.h>

// TODO: Store a list of buffers and read JSON from them instead, if possible

static void
on_unix_json_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    json_t *json;
    json_error_t error;
    struct neat_ipc_context *context = stream->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (nread == UV_EOF) {
        neat_log(NEAT_LOG_DEBUG, "Reached EOF on UNIX socket");

        if (context->read_buffer == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Reached EOF with no data");
            context->on_error(context->ctx, context->flow, PM_ERROR_SOCKET, context->data);

        } else if ((json = json_loadb(context->read_buffer, context->buffer_size, 0, &error)) == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Failed to read JSON reply from PM");
            neat_log(NEAT_LOG_DEBUG, "Error at position %d:", error.position);
            neat_log(NEAT_LOG_DEBUG, error.text);

            context->on_error(context->ctx, context->flow, PM_ERROR_INVALID_JSON, context->data);
        } else {
            context->on_reply(context->ctx, context->flow, json, context->data);
        }

    } else if (nread == UV_ENOBUFS) {
        neat_log(NEAT_LOG_DEBUG, "Out of memory");
        context->on_error(context->ctx, context->flow, PM_ERROR_OOM, context->data);
    } else if (nread < 0) {
        neat_log(NEAT_LOG_DEBUG, "UNIX socket error: %s", uv_strerror(nread));
        context->on_error(context->ctx, context->flow, PM_ERROR_SOCKET, context->data);
    } else {
        char *new_buffer;

        neat_log(NEAT_LOG_DEBUG, "Received %d bytes", buf->len);

        if ((new_buffer = realloc(context->read_buffer, context->buffer_size + nread)) == NULL) {
            context->on_error(context->ctx, context->flow, PM_ERROR_OOM, context->data);
        } else {
            size_t old_buffer_size = context->buffer_size;
            size_t new_buffer_size = context->buffer_size + nread;
            size_t offset = 0;

            memcpy(new_buffer + old_buffer_size, buf->base, nread);

            for (size_t i = old_buffer_size;
                 i < new_buffer_size;
                 i++)
            {
                const char *ptr = new_buffer + i;
                switch (*ptr) {
                case '{':
                case '[':
                    context->json_nesting_count++;
                    break;
                case '}':
                case ']':
                    context->json_nesting_count--;
                    break;
                case ' ':
                case '\n':
                case '\t':
                    // Skip whitespace at the start and end
                    continue;
                default:
                    break;
                }

                if (context->json_nesting_count == 0) {
                    if ((json = json_loadb(new_buffer + offset, i + 1 - offset, 0, &error)) == NULL) {
                        neat_log(NEAT_LOG_DEBUG, "Failed to read JSON reply from PM");
                        neat_log(NEAT_LOG_DEBUG, "Error at position %d:", error.position);
                        neat_log(NEAT_LOG_DEBUG, error.text);

                        context->on_error(context->ctx, context->flow, PM_ERROR_INVALID_JSON, context->data);
                    } else {
                        context->on_reply(context->ctx, context->flow, json, context->data);
                        neat_log(NEAT_LOG_DEBUG, "new %d old %d i %d", new_buffer_size, old_buffer_size, i);
                    }

                    offset = i;
                }
            }

            if (context->json_nesting_count == 0) {
                // There's no partial JSON object in the buffer, so just free it
                context->buffer_size = 0;
                free(new_buffer);
                context->read_buffer = NULL;

            } else if (offset != 0) {
                // One or more JSON objects have been delivered.
                // Move the remaining, incomplete JSON object to the start of
                // the buffer.

                memcpy(new_buffer, new_buffer + offset, new_buffer_size - offset);
                context->read_buffer = new_buffer;
                neat_log(NEAT_LOG_DEBUG, "\n%s", context->read_buffer);
                context->buffer_size = new_buffer_size - offset;

                context->read_buffer = realloc(context->read_buffer, context->buffer_size);
            } else {
                // Nothing delivered, leave the buffer as-is
                context->read_buffer = new_buffer;
                context->buffer_size = new_buffer_size;
            }
        }
    }

    if (buf->base)
        free(buf->base);
}

static void
on_request_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    neat_log(NEAT_LOG_DEBUG, "on_request_alloc");

    // buf->len == 0 indicates OOM. on_read will be called with nread == UV_ENOBUFS
    buf->base = malloc(4096);
    buf->len  = (buf->base) ? 4096 : 0;
}

static void
on_shutdown(uv_shutdown_t *shutdown, int status)
{
    free(shutdown);

    if (status != 0) {
        neat_log(NEAT_LOG_DEBUG, "PM on_shutdown status %d: %s",
                 status, uv_strerror(status));
    }
}

neat_error_code
neat_unix_json_shutdown(struct neat_ipc_context *context)
{
    int rc;
    uv_shutdown_t *shutdown;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if ((shutdown = malloc(sizeof(*shutdown))) == NULL)
        return NEAT_ERROR_OUT_OF_MEMORY;

    if ((rc = uv_shutdown(shutdown, context->stream, on_shutdown)) != 0) {
        neat_log(NEAT_LOG_DEBUG, "uv_shutdown error: %s", uv_strerror(rc));
        free(shutdown);
        return NEAT_ERROR_INTERNAL;
    }

    return NEAT_OK;
}

neat_error_code
neat_unix_json_start_read(struct neat_ipc_context *context)
{
    int rc;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    context->stream->data = context;

    if ((rc = uv_read_start(context->stream, on_request_alloc, on_unix_json_read)) != 0) {
        neat_log(NEAT_LOG_DEBUG, "uv_read_start error: %s", uv_strerror(rc));
        return NEAT_ERROR_INTERNAL;
    }

    return NEAT_OK;
}

static void
on_unix_json_written(uv_write_t* wr, int status)
{
    struct neat_ipc_context *context = wr->data;

    if (context->on_written) {
        context->on_written(context->flow->ctx, context->flow, context);
    }

    free(wr);
}

static void
on_unix_json_connected(uv_connect_t* connect, int status)
{
    struct neat_ipc_context *context = connect->data;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    context->stream = connect->handle;

    free(connect);

    if (status < 0) {
        neat_log(NEAT_LOG_DEBUG, "Failed to connect to UNIX socket");
        context->on_error(context->ctx, context->flow, PM_ERROR_SOCKET_UNAVAILABLE, context->data);
        return;
    }

    if (uv_stream_set_blocking(context->stream, 0) < 0) {
        neat_log(NEAT_LOG_DEBUG, "Failed to set UNIX socket as non-blocking");
        context->on_error(context->ctx, context->flow, PM_ERROR_SOCKET, context->data);
        return;
    }

    if (context->on_connected) {
        context->on_connected(context, context->data);
    }

    return;
}

neat_error_code
neat_unix_json_send(struct neat_ipc_context *context, const char *buffer,
                    written_callback on_written, error_callback on_error)
{
    int rc;
    uv_write_t *wr;
    uv_buf_t buf;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if ((wr = calloc(sizeof(*wr), 1)) == NULL) {
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    wr->data = context;

    buf.base = (char*)buffer;
    buf.len  = strlen(buf.base);

    context->on_written = on_written;
    context->on_error   = on_error;

    if ((rc = uv_write(wr, context->stream, &buf, 1, on_unix_json_written)) != 0) {
        neat_log(NEAT_LOG_DEBUG, "uv_write error: %s", strerror(rc));
        free(wr);
        return NEAT_ERROR_INTERNAL;
    }

    return NEAT_OK;
}

neat_error_code
neat_unix_json_socket_open(struct neat_ctx *ctx, struct neat_flow *flow,
                           struct neat_ipc_context *context, const char *path,
                           connected_callback conn_cb, reply_callback reply_cb,
                           error_callback err_cb, void *data)
{
    int rc;
    uv_connect_t *connect;
    uv_pipe_t *pipe;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    assert(err_cb);
    if (ctx == NULL || flow == NULL || path == NULL || err_cb == NULL) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    if ((connect = malloc(sizeof(uv_connect_t))) == NULL)
        return NEAT_ERROR_OUT_OF_MEMORY;

    if ((pipe = malloc(sizeof(uv_pipe_t))) == NULL) {
        free(connect);
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    context->pipe         = pipe;
    context->ctx          = ctx;
    context->flow         = flow;
    context->on_error     = err_cb;
    context->on_connected = conn_cb;
    context->on_reply     = reply_cb;
    context->read_buffer  = NULL;
    context->buffer_size  = 0;
    context->data         = data;
    context->json_nesting_count = 0;

    connect->data = context;

    neat_log(NEAT_LOG_DEBUG, "Opening UNIX socket %s", path);

    if ((rc = uv_pipe_init(ctx->loop, pipe, 1 /* 1 => IPC = TRUE */)) != 0) {
        free(connect);
        free(pipe);
        return NEAT_ERROR_INTERNAL;
    }

    uv_pipe_connect(connect, pipe, path, on_unix_json_connected);

    return NEAT_OK;
}

static void
on_pipe_close(uv_handle_t *handle)
{
    struct neat_ipc_context *context = handle->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    free(context->read_buffer);
    free(handle);

    context->on_close(context->data);
}

void
neat_unix_json_close(struct neat_ipc_context *context, close_callback cb, void *data)
{
    context->pipe->data = context;
    context->data = data;
    context->on_close = cb;
    uv_close((uv_handle_t*)context->pipe, on_pipe_close);
}
