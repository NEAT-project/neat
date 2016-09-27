#include "neat.h"
#include "neat_internal.h"
#include "neat_pm_socket.h"

#include <stdlib.h>
#include <uv.h>
#include <string.h>
#include <jansson.h>
#include <assert.h>


// TODO: Store a list of buffers and read JSON from them instead, if possible
// TODO: Allocate as much as possible in one function, free everything in a single function

struct neat_pm_request_data {
    struct neat_ctx *ctx;
    struct neat_flow *flow;
    uv_pipe_t *pipe;
    pm_reply_callback on_pm_reply;
    pm_error_callback on_pm_error;
    char *output_buffer;
    char *read_buffer;
    size_t buffer_size;
    uv_stream_t *stream;
    uv_timer_t *timer;
};

static void
on_pm_socket_close(uv_handle_t *handle)
{
    struct neat_pm_request_data *data = handle->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (data != NULL) {
        if (data->read_buffer)
            free(data->read_buffer);
        if (data->output_buffer)
            free(data->output_buffer);

        free(data);
    }

    free(handle);
}

static inline void
stop(uv_stream_t *stream, int error)
{
    struct neat_pm_request_data *data = stream->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (data) {
        if (error != PM_ERROR_OK && data->on_pm_error)
            data->on_pm_error(data->ctx, data->flow, error);

        if (data->timer)
            uv_timer_stop(data->timer);

    }

    uv_close((uv_handle_t*)stream, on_pm_socket_close);
}

static void
on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    struct neat_pm_request_data *data = stream->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (nread == UV_EOF) {
        json_t *json;
        json_error_t error;

        neat_log(NEAT_LOG_DEBUG, "Done reading", nread);

        if (data->read_buffer == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Reached EOF with no data");

            stop(stream, PM_ERROR_INVALID_JSON);
            goto end;
        }

        json = json_loadb(data->read_buffer, data->buffer_size, 0, &error);
        if (!json) {
            neat_log(NEAT_LOG_DEBUG, "Failed to read JSON reply from PM");
            neat_log(NEAT_LOG_DEBUG, "Error at position %d:", error.position);
            neat_log(NEAT_LOG_DEBUG, error.text);

            stop(stream, PM_ERROR_INVALID_JSON);
            goto end;
        }

        data->on_pm_reply(data->ctx, data->flow, json);

        stop(stream, PM_ERROR_OK);
        goto end;
    }

    if (nread < 0) {
        neat_log(NEAT_LOG_DEBUG, "PM interface error: %s", uv_strerror(nread));

        stop(stream, PM_ERROR_SOCKET);
        goto end;
    }

    neat_log(NEAT_LOG_DEBUG, "Received %d bytes", nread);

    data->read_buffer = realloc(data->read_buffer, data->buffer_size + nread);

    if (data->read_buffer == NULL) {
        stop(stream, PM_ERROR_SOCKET);
        goto end;
    }

    memcpy(data->read_buffer + data->buffer_size, buf->base, nread);
    data->buffer_size += nread;
end:
    if (buf->len && buf->base)
        free(buf->base);
}

static void
on_timeout(uv_timer_t* handle)
{
    struct neat_pm_request_data *data = handle->data;

    neat_log(NEAT_LOG_DEBUG, "PM timeout");

    stop(data->stream, PM_ERROR_SOCKET);
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
on_shutdown(uv_shutdown_t *req, int status)
{
    if (status != 0) {
        neat_log(NEAT_LOG_DEBUG, "PM on_shutdown status %d: %s",
                 status, uv_strerror(status));
    }
    free(req);
}

static void
on_written(uv_write_t* wr, int status)
{
    struct neat_pm_request_data *data = wr->data;
    uv_timer_t *timer;
    uv_shutdown_t *req;

    neat_log(NEAT_LOG_DEBUG, "on_written, status %d", status);

    timer = malloc(sizeof(*timer));
    req   = malloc(sizeof(*req));

    if (timer == NULL || req == NULL) {
        if (timer)
            free(timer);
        if (req)
            free(req);

        if (data->on_pm_error)
            data->on_pm_error(data->ctx, data->flow, PM_ERROR_SOCKET);

        free(data->output_buffer);
        free(data);

        goto error;
    }

    uv_read_start(wr->handle, on_request_alloc, on_read);
    wr->handle->data = data;
    data->stream = (uv_stream_t*)wr->handle;

    uv_shutdown(req, (uv_stream_t*)wr->handle, on_shutdown);

    uv_timer_init(data->ctx->loop, timer);
    timer->data = data;
    data->timer = timer;
    uv_timer_start(timer, on_timeout, 3000, 0);

error:
    free(wr);
}

static void
on_pm_connected(uv_connect_t* req, int status)
{
    uv_write_t *wr;
    uv_buf_t *buf;
    struct neat_pm_request_data *data = req->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (status < 0) {
        neat_log(NEAT_LOG_DEBUG, "Failed to connect to PM socket");

        if (data->on_pm_error)
            data->on_pm_error(data->ctx, data->flow, PM_ERROR_SOCKET_UNAVAILABLE);

        req->handle->data = NULL;
        stop(req->handle, 0);

        free(data->output_buffer);
        free(data);
        free(req);

        return;
    }

    // Set non-blocking
    if (uv_stream_set_blocking(req->handle, 0) < 0) {
        neat_log(NEAT_LOG_DEBUG, "Failed to set PM socket as non-blocking");

        if (data->on_pm_error)
            data->on_pm_error(data->ctx, data->flow, PM_ERROR_SOCKET);

        free(data->output_buffer);
        free(data);
        free(req);

        return;
    }

    wr  = malloc(sizeof(*wr));
    buf = malloc(sizeof(*buf));

    if (wr == NULL || buf == NULL) {
        // TODO: stop()
        data->on_pm_error(data->ctx, data->flow, PM_ERROR_SOCKET);

        if (wr)
            free(wr);
        if (buf)
            free(buf);

        return;
    }

    data->stream = (uv_stream_t*)wr;

    buf->base = data->output_buffer;
    buf->len  = strlen(buf->base);

    wr->data = data;
    uv_write(wr, req->handle, buf, 1, on_written);

    free(buf);
    free(req);
}

neat_error_code
neat_pm_send(struct neat_ctx *ctx, struct neat_flow *flow, char *buffer, pm_reply_callback cb, pm_error_callback err_cb)
{
    const char *home_dir;
    char socket_path_buf[128];
    const char *socket_path;
    struct neat_pm_request_data *data;
    uv_connect_t *connect;
    uv_pipe_t *pipe;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (ctx == NULL || flow == NULL || buffer == NULL) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    pipe    = malloc(sizeof(*pipe));
    connect = malloc(sizeof(*connect));
    data    = malloc(sizeof(*data));

    if (pipe == NULL || data == NULL || data == NULL) {
        if (pipe)
            free(pipe);
        if (connect)
            free(connect);
        if (data)
            free(data);

        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    data->ctx           = ctx;
    data->flow          = flow;
    data->output_buffer = buffer;
    data->on_pm_reply   = cb;
    data->on_pm_error   = err_cb;
    data->read_buffer   = NULL;
    data->buffer_size   = 0;
    data->timer = NULL;

    connect->data = data;

    uv_pipe_init(ctx->loop, pipe, 1 /* 1 => IPC = TRUE */);

    socket_path = getenv("NEAT_PM_SOCKET");
    if (!socket_path) {
        if ((home_dir = getenv("HOME")) == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Unable to locate the $HOME directory");

            goto error;
        }

        if (snprintf(socket_path_buf, 128, "%s/.neat/neat_pm_socket", home_dir) < 0) {
            neat_log(NEAT_LOG_DEBUG, "Unable to construct default path to PM socket");

            goto error;
        }
    }

    uv_pipe_connect(connect, pipe, socket_path_buf, on_pm_connected);

    return NEAT_OK;
error:
    free(pipe);
    free(connect);
    free(data);

    return NEAT_ERROR_INTERNAL;
}
