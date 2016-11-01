#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <usrsctp.h>
#include <unistd.h>
#include <stdarg.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_addr.h"
#include "neat_usrsctp.h"
#include "neat_usrsctp_internal.h"

#define MCLBYTES 2048


static void neat_usrsctp_sctp4_readable(uv_poll_t *handle,
                                    int status,
                                    int events)
{
    neat_log(NEAT_LOG_DEBUG, "%s(status=%d, events=%d)", __func__, status, events);
    if (status < 0) {
        neat_log(NEAT_LOG_ERROR, "%s: socket not readable", __func__);
        return;
    }
    usrsctp_recv_function_sctp4();
}

static void neat_usrsctp_udpsctp4_readable(uv_poll_t *handle,
                                    int status,
                                    int events)
{
printf("neat_usrsctp_udpsctp4_readable\n");
    if (status < 0) {
        neat_log(NEAT_LOG_ERROR, "%s: socket not readable", __func__);
        return;
    }
    usrsctp_recv_function_udpsctp4();
}

static void neat_usrsctp_sctp6_readable(uv_poll_t *handle,
                                    int status,
                                    int events)
{
    if (status < 0) {
        neat_log(NEAT_LOG_ERROR, "%s: socket not readable", __func__);
        return;
    }
    usrsctp_recv_function_sctp6();
}

static void neat_usrsctp_udpsctp6_readable(uv_poll_t *handle,
                                    int status,
                                    int events)
{
    if (status < 0) {
        neat_log(NEAT_LOG_ERROR, "%s: socket not readable", __func__);
        return;
    }
    usrsctp_recv_function_udpsctp6();
}

static void neat_usrsctp_cleanup(struct neat_ctx *ctx)
{
    if (ctx->sctp4_fd >= 0) {
        close(ctx->sctp4_fd);
    }
    if (ctx->udpsctp4_fd >= 0) {
        close(ctx->udpsctp4_fd);
    }
    if (ctx->sctp6_fd >= 0) {
        close(ctx->sctp6_fd);
    }
    if (ctx->udpsctp6_fd >= 0) {
        close(ctx->udpsctp6_fd);
    }
}

void neat_handle_usrsctp_timeout(uv_timer_t *handle)
{
    usrsctp_handle_timers(10);
}

struct neat_ctx *neat_usrsctp_init_ctx(struct neat_ctx *ctx)
{
    int ret;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);
    ctx->cleanup = neat_usrsctp_cleanup;

    uv_timer_init(ctx->loop, &(ctx->usrsctp_timer_handle));
    ctx->usrsctp_timer_handle.data = ctx;
    uv_timer_start(&(ctx->usrsctp_timer_handle), neat_handle_usrsctp_timeout, 10, 10);

    usrsctp_init(SCTP_UDP_TUNNELING_PORT, NULL, neat_log_usrsctp);

    ctx->sctp4_fd = usrsctp_open_sctp4_socket();
    neat_log(NEAT_LOG_DEBUG, "sctp4_fd=%d", ctx->sctp4_fd);

    if (ctx->sctp4_fd != -1) {
        if ((ret = uv_poll_init(ctx->loop, &(ctx->uv_sctp4_handle), ctx->sctp4_fd)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't initialize uv_sctp4_handle (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }

        ctx->uv_sctp4_handle.data = ctx;
        if ((ret = uv_poll_start(&(ctx->uv_sctp4_handle),
                                     UV_READABLE,
                                     neat_usrsctp_sctp4_readable)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't start receiving sctp4 readable events (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }
    }

    ctx->udpsctp4_fd = usrsctp_open_udpsctp4_socket();
    neat_log(NEAT_LOG_DEBUG, "udpsctp4_fd=%d", ctx->udpsctp4_fd);
    if (ctx->udpsctp4_fd != -1) {
        if ((ret = uv_poll_init(ctx->loop, &(ctx->uv_udpsctp4_handle), ctx->udpsctp4_fd)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't initialize uv_udpsctp4_handle (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }
        ctx->uv_udpsctp4_handle.data = ctx;
        if ((ret = uv_poll_start(&(ctx->uv_udpsctp4_handle),
                                     UV_READABLE,
                                     neat_usrsctp_udpsctp4_readable)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't start receiving udpsctp4 readable events (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }
    }

    ctx->sctp6_fd = usrsctp_open_sctp6_socket();
    neat_log(NEAT_LOG_DEBUG, "sctp6_fd=%d", ctx->sctp6_fd);
    if (ctx->sctp6_fd != -1) {
        if ((ret = uv_poll_init(ctx->loop, &(ctx->uv_sctp6_handle), ctx->sctp6_fd)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't initialize uv_sctp6_handle (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }
        ctx->uv_sctp6_handle.data = ctx;
        if ((ret = uv_poll_start(&(ctx->uv_sctp6_handle),
                                     UV_READABLE,
                                     neat_usrsctp_sctp6_readable)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't start receiving sctp4 readable events (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }
    }

    ctx->udpsctp6_fd = usrsctp_open_udpsctp6_socket();
    neat_log(NEAT_LOG_DEBUG, "udpsctp6_fd=%d", ctx->udpsctp6_fd);
    if (ctx->udpsctp6_fd != -1) {
        if ((ret = uv_poll_init(ctx->loop, &(ctx->uv_udpsctp6_handle), ctx->udpsctp6_fd)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't initialize uv_udpsctp6_handle (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }
        ctx->uv_udpsctp6_handle.data = ctx;
        if ((ret = uv_poll_start(&(ctx->uv_udpsctp6_handle),
                                     UV_READABLE,
                                     neat_usrsctp_udpsctp6_readable)) < 0) {
            neat_log(NEAT_LOG_ERROR, "%s: can't start receiving udpsctp6 readable events (%s)", __func__, uv_strerror(ret));
            neat_usrsctp_cleanup(ctx);
            return NULL;
        }
    }
    usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
    return ctx;
}
