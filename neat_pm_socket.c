#include <stdlib.h>
#include <uv.h>
#include <jansson.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_unix_json_socket.h"
#include "neat_pm_socket.h"

static void
on_pm_written(struct neat_ctx *ctx, struct neat_flow *flow, struct neat_ipc_context *context)
{
    struct neat_pm_context *pm_context = context->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if (neat_unix_json_start_read(context) ||
        neat_unix_json_shutdown(context)) {

        neat_log(NEAT_LOG_DEBUG, "Failed to initiate read/shutdown for PM socket");

        pm_context->on_pm_error(ctx, flow, PM_ERROR_SOCKET);
    }
}

static void
on_timer_close(uv_handle_t* handle)
{
    free(handle);
}

static void
on_pm_close(void* data)
{
    struct neat_pm_context *pm_context = data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    free(pm_context->output_buffer);
    free(pm_context->ipc_context);

    uv_close((uv_handle_t*)pm_context->timer, on_timer_close);

    free(pm_context);
}

static void
on_pm_timeout(uv_timer_t* timer)
{
    struct neat_pm_context *pm_context = timer->data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    pm_context->on_pm_error(pm_context->ipc_context->ctx, pm_context->ipc_context->flow, PM_ERROR_SOCKET);

    neat_unix_json_close(pm_context->ipc_context, on_pm_close, pm_context);
}

static void
on_pm_read(struct neat_ctx *ctx, struct neat_flow *flow, json_t *json, void *data)
{
    struct neat_pm_context *pm_context = data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    pm_context->on_pm_reply(ctx, flow, json);

    neat_unix_json_close(pm_context->ipc_context, on_pm_close, data);
}

static void
on_pm_error(struct neat_ctx *ctx, struct neat_flow *flow, int error, void *data)
{
    struct neat_pm_context *pm_context = data;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    pm_context->on_pm_error(ctx, flow, error);

    neat_unix_json_close(pm_context->ipc_context, on_pm_close, data);
}

static void
on_pm_connected(struct neat_ipc_context *context, void *data)
{
    struct neat_pm_context *pm_context = data;
    if ((neat_unix_json_send(context, pm_context->output_buffer, on_pm_written, context->on_error)) != NEAT_ERROR_OK) {
        pm_context->on_pm_error(pm_context->ipc_context->ctx, pm_context->ipc_context->flow, PM_ERROR_SOCKET);
    }
}

neat_error_code
neat_json_send_once(struct neat_ctx *ctx, struct neat_flow *flow, const char *path, json_t *json, pm_reply_callback cb, pm_error_callback err_cb)
{
    int rc;
    struct neat_ipc_context *context;
    struct neat_pm_context *pm_context;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    if ((context = malloc(sizeof(*context))) == NULL)
        return NEAT_ERROR_OUT_OF_MEMORY;

    if ((pm_context = malloc(sizeof(*pm_context))) == NULL) {
        rc = NEAT_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    pm_context->timer = NULL;

    if ((pm_context->output_buffer = json_dumps(json, JSON_INDENT(2))) == NULL) {
        rc = NEAT_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    if ((pm_context->timer = malloc(sizeof(*pm_context->timer))) == NULL) {
        rc = NEAT_ERROR_OUT_OF_MEMORY;
        goto error;
    }

    if ((rc = uv_timer_init(ctx->loop, pm_context->timer))) {
        neat_log(NEAT_LOG_DEBUG, "uv_timer_init error: %s", uv_strerror(rc));
        rc = NEAT_ERROR_INTERNAL;
        goto error;
    }

    if ((rc = uv_timer_start(pm_context->timer, on_pm_timeout, 3000, 0))) {
        neat_log(NEAT_LOG_DEBUG, "uv_timer_start error: %s", uv_strerror(rc));
        rc = NEAT_ERROR_INTERNAL;
        goto error;
    }

    pm_context->timer->data = pm_context;
    pm_context->on_pm_reply = cb;
    pm_context->on_pm_error = err_cb;
    pm_context->ipc_context = context;

    if ((rc = neat_unix_json_socket_open(ctx, flow, context, path, on_pm_connected, on_pm_read, on_pm_error, pm_context)) == NEAT_OK)
        return NEAT_OK;
error:
    if (pm_context) {
        if (pm_context->output_buffer)
            free(pm_context->output_buffer);
        if (pm_context->timer)
            free(pm_context->timer);
        free(pm_context);
    }
    if (context)
        free(context);
    return rc;
}
