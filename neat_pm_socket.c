#include "neat.h"
#include "neat_internal.h"
#include "neat_pm_socket.h"

#include <stdlib.h>
#include <uv.h>
#include <string.h>
#include <jansson.h>
#include <assert.h>


// TODO: Store a list of buffers and read JSON from them instead, if possible

static void
on_timer_close(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    free(handle);
}

static void
on_pipe_close(uv_handle_t *handle)
{
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    free(handle);
}

static void
on_pm_timeout(uv_timer_t *timer)
{
    struct neat_pm_context *pm_context = timer->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    uv_close((uv_handle_t*)timer, on_timer_close);
    uv_close((uv_handle_t*)pm_context->pipe, on_pipe_close);

    free(pm_context->output_buffer);

    if (pm_context->read_buffer)
        free(pm_context->read_buffer);

    pm_context->on_pm_error(pm_context->ctx, pm_context->flow, PM_ERROR_SOCKET);
}

static void
on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    int rc = 0;
    json_t *json;
    json_error_t error;
    struct neat_pm_context *pm_context = stream->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (nread == UV_EOF) {

        neat_log(NEAT_LOG_DEBUG, "Done reading", nread);
        uv_timer_stop(pm_context->timer);

        if (pm_context->read_buffer == NULL) {
            neat_log(NEAT_LOG_DEBUG, "Reached EOF with no data");
            rc = PM_ERROR_SOCKET;
            goto end;
        }

        json = json_loadb(pm_context->read_buffer, pm_context->buffer_size, 0, &error);
        if (!json) {
            neat_log(NEAT_LOG_DEBUG, "Failed to read JSON reply from PM");
            neat_log(NEAT_LOG_DEBUG, "Error at position %d:", error.position);
            neat_log(NEAT_LOG_DEBUG, error.text);

            rc = PM_ERROR_INVALID_JSON;
            goto end;
        }

        // rc == 0
        goto end;
    } else if (nread == UV_ENOBUFS) {
        neat_log(NEAT_LOG_DEBUG, "Out of memory");
        rc = PM_ERROR_OOM;
        goto end;
    }

    neat_log(NEAT_LOG_DEBUG, "Received %d bytes", buf->len);

    pm_context->read_buffer = realloc(pm_context->read_buffer, pm_context->buffer_size + nread);

    if (pm_context->read_buffer == NULL) {
        rc = PM_ERROR_OOM;
        goto end;
    }

    memcpy(pm_context->read_buffer + pm_context->buffer_size, buf->base, nread);
    pm_context->buffer_size += nread;

    if (buf->len && buf->base)
        free(buf->base);

    return;
end:
    if (buf->len && buf->base)
        free(buf->base);

    uv_close((uv_handle_t*)pm_context->pipe, on_pipe_close);
    uv_close((uv_handle_t*)pm_context->timer, on_timer_close);
    free(pm_context->read_buffer);
    free(pm_context->output_buffer);

    if (rc)
        pm_context->on_pm_error(pm_context->ctx, pm_context->flow, rc);
    else
        pm_context->on_pm_reply(pm_context->ctx, pm_context->flow, json);
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
    if (status != 0) {
        neat_log(NEAT_LOG_DEBUG, "PM on_shutdown status %d: %s",
                 status, uv_strerror(status));
    }

    free(shutdown);
}

static void
on_written(uv_write_t* wr, int status)
{
    struct neat_pm_context *pm_context = wr->data;
    uv_timer_t *timer;
    uv_stream_t *stream = wr->handle;
    uv_shutdown_t *shutdown;

    neat_log(NEAT_LOG_DEBUG, "%s, status %d", __func__, status);

    free(wr);

    timer = malloc(sizeof(*timer));

    if (timer == NULL) {
        free(pm_context->output_buffer);
        uv_close((uv_handle_t*)pm_context->pipe, on_pipe_close);

        pm_context->on_pm_error(pm_context->ctx, pm_context->flow, PM_ERROR_OOM);
        return;
    }

    shutdown   = malloc(sizeof(*shutdown));
    if (shutdown == NULL) {
        free(timer);
        free(pm_context->output_buffer);
        uv_close((uv_handle_t*)pm_context->pipe, on_pipe_close);

        pm_context->on_pm_error(pm_context->ctx, pm_context->flow, PM_ERROR_OOM);
        return;
    }

    stream->data = pm_context;
    uv_read_start(stream, on_request_alloc, on_read);

    uv_timer_init(pm_context->ctx->loop, timer);
    timer->data = pm_context;
    pm_context->timer = timer;
    uv_timer_start(timer, on_pm_timeout, 1000, 0);

    uv_shutdown(shutdown, stream, on_shutdown);
}

static void
on_pm_connected(uv_connect_t* connect, int status)
{
    int rc;
    uv_write_t *wr;
    uv_buf_t *buf;
    struct neat_pm_context *pm_context = connect->data;
    uv_stream_t* stream = connect->handle;
    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    free(connect);

    if (status < 0) {
        neat_log(NEAT_LOG_DEBUG, "Failed to connect to PM socket");
        rc = PM_ERROR_SOCKET_UNAVAILABLE;
        goto error;
    }

    if (uv_stream_set_blocking(stream, 0) < 0) {
        neat_log(NEAT_LOG_DEBUG, "Failed to set PM socket as non-blocking");
        rc = PM_ERROR_SOCKET;
        goto error;
    }

    wr  = malloc(sizeof(*wr));
    buf = malloc(sizeof(*buf));

    buf->base = pm_context->output_buffer;
    buf->len  = strlen(buf->base);

    wr->data = pm_context;

    uv_write(wr, stream, buf, 1, on_written);

    free(buf);

    return;
error:
    uv_close((uv_handle_t*)pm_context->pipe, on_pipe_close);

    free(pm_context->output_buffer);

    if (pm_context->on_pm_error)
        pm_context->on_pm_error(pm_context->ctx, pm_context->flow, rc);

    return;
}

neat_error_code
neat_pm_send(struct neat_ctx *ctx, struct neat_flow *flow, const char *path, char *buffer, pm_reply_callback cb, pm_error_callback err_cb)
{
    struct neat_pm_context *pm_context = flow->pm_context;
    uv_connect_t *connect;
    uv_pipe_t *pipe;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_log(NEAT_LOG_DEBUG, "Opening UNIX socket %s", path);

    if (ctx == NULL || flow == NULL || path == NULL || buffer == NULL) {
        return NEAT_ERROR_BAD_ARGUMENT;
    }

    if ((connect = malloc(sizeof(uv_connect_t))) == NULL)
        return NEAT_ERROR_OUT_OF_MEMORY;

    if ((pipe = malloc(sizeof(uv_pipe_t))) == NULL) {
        free(connect);
        return NEAT_ERROR_OUT_OF_MEMORY;
    }

    pm_context->pipe = pipe;
    pm_context->ctx           = ctx;
    pm_context->flow          = flow;
    pm_context->on_pm_error   = err_cb;
    pm_context->output_buffer = buffer;
    pm_context->on_pm_reply   = cb;
    pm_context->read_buffer   = NULL;
    pm_context->buffer_size   = 0;

    connect->data = pm_context;

    uv_pipe_init(ctx->loop, pipe, 1 /* 1 => IPC = TRUE */);
    uv_pipe_connect(connect, pipe, path, on_pm_connected);

    return NEAT_OK;
}
