#include <string.h>
#include <uv.h>
#include <assert.h>

#include "neat.h"
#include "neat_internal.h"
#include "neat_pmi.h"

static neat_error_code pmi_open(struct neat_ctx *ctx, enum neat_pmi_direction dir);
static void pmi_req_process(struct neat_ctx *ctx);
static void pmi_req_finish(struct neat_pmi_req *req, neat_error_code status);
static void pmi_req_fail(struct neat_ctx *ctx, neat_error_code status);

static void pmi_on_read(uv_fs_t *req)
{
    struct neat_pmi_req *pr, *pmi_req;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    pr = (struct neat_pmi_req*)req->data;
    if (pr == NULL) {
	neat_log(NEAT_LOG_ERROR, "PMI read without PMI context");
	return;
    }

    pmi_req = pr->ctx->pmi_ctx.req_queue.tqh_first;

    if (req->result == 0) {
	neat_log(NEAT_LOG_DEBUG, "PMI closed output pipe");
	uv_poll_stop(&pr->ctx->pmi_ctx.poll_in);
	pr->ctx->pmi_ctx.in.ready = 0;

	if (pmi_req != NULL)
	    pmi_req_finish(pmi_req, NEAT_OK);

	return;
    }

    neat_log(NEAT_LOG_DEBUG, "PMI read in dir: %s. Res: %d (%s). Path %s",
	     (pr->direction == NEAT_PMI_IN) ? "in" : "out",
	     req->result,
	     (req->result < 0) ? uv_strerror(req->result) : "OK",
	     req->path);

    if (req->result > 0) {
	if (pmi_req->reply.len <= pmi_req->read + req->result) {
	    pmi_req->reply.base = realloc(pmi_req->reply.base, pmi_req->reply.len + req->result + 1);
	    if (pmi_req->reply.base == NULL) {
		neat_log(NEAT_LOG_ERROR, "Could not extend PMI read buffer.");
		// TODO handle properly
		pmi_req_finish(pmi_req, NEAT_ERROR_INTERNAL);
		return;
	    }

	    pmi_req->reply.len += req->result + 1;
	}
	memcpy(pmi_req->reply.base + pmi_req->read, pr->ctx->pmi_ctx.in.buf.base, req->result);
	pmi_req->read += req->result;
    }

    pr->ctx->pmi_ctx.reading_in = 0;
}

static void pmi_on_readable(uv_poll_t *handle, int status, int events)
{
    struct neat_pmi_req *pr;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    pr = (struct neat_pmi_req*)handle->data;
    if (pr == NULL) {
	neat_log(NEAT_LOG_WARNING, "pmi_readable: no PR!");
	return;
    }

    if (status < 0) {
	neat_log(NEAT_LOG_ERROR, "Error polling PMI output: %s", uv_strerror(status));
	pmi_req_fail(pr->ctx, NEAT_ERROR_IO);
	return;
    }

    neat_log(NEAT_LOG_DEBUG, "PMI readable: pr %p, status %d, event %d.",
	     pr, status, events);

    if (!pr->ctx->pmi_ctx.reading_in) {
	uv_fs_read(pr->ctx->loop, &pr->ctx->pmi_ctx.req_rd, pr->ctx->pmi_ctx.in.req.result,
		   &pr->ctx->pmi_ctx.in.buf, 1, -1, pmi_on_read);
	pr->ctx->pmi_ctx.reading_in = 1;
    }
}

static void pmi_on_open(uv_fs_t *req)
{
    struct neat_pmi_req *pr;
    struct neat_pmi_pipe *pipe;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    pr = (struct neat_pmi_req*)req->data;
    if (req->result >= 0) {
	if (pr->direction == NEAT_PMI_IN) {
	    pipe = &pr->ctx->pmi_ctx.in;
	    pr->ctx->pmi_ctx.req_rd.data = req->data;

	    uv_poll_init(pr->ctx->loop, &pr->ctx->pmi_ctx.poll_in, req->result);
	    pr->ctx->pmi_ctx.poll_in.data = req->data;
	    uv_poll_start(&pr->ctx->pmi_ctx.poll_in, UV_READABLE, pmi_on_readable);
	} else {
	    pipe = &pr->ctx->pmi_ctx.out;
	    pipe->ready = 1;
	    pmi_req_process(pr->ctx);
	}

	pipe->ready = 1;
    } else {
	neat_log(NEAT_LOG_ERROR, "Could not open PMI named pipe! " \
		 "Direction: %s. Error: %d %s. Path: %s\n",
		 (pr->direction == NEAT_PMI_IN) ? "in" : "out",
		 req->result, uv_strerror(req->result),
		 req->path);
	pmi_req_fail(pr->ctx, NEAT_ERROR_IO);
    }
}

static void pmi_on_write(uv_fs_t *req)
{
    struct neat_pmi_req *pr;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    neat_log(NEAT_LOG_DEBUG, "Write result: %d", req->result);

    pr = (struct neat_pmi_req *)req->data;

    if (req->result >= 0) {
	pr->written += req->result;

	if (pr->written >= pr->request.len) {
	    pmi_open(pr->ctx, NEAT_PMI_IN);
	    free(pr->request.base);
	    pr->request.base = NULL;
	    pr->request.len = 0;
	    neat_log(NEAT_LOG_DEBUG, "Finished writing PMI request.");
	} else {
	    // FIXME WRITE MORE
	    neat_log(NEAT_LOG_DEBUG, "Partial write.");
	}
    } else {
	neat_log(NEAT_LOG_ERROR, "Failed to write to PM: %s.",
		 uv_strerror(req->result));
	pmi_req_fail(pr->ctx, NEAT_ERROR_IO);
    }
}

static neat_error_code pmi_open(struct neat_ctx *ctx, enum neat_pmi_direction dir)
{
    struct neat_pmi_req *pr;
    uv_fs_t *req;
    const char *env_home;
    char pipe_path[1024];
    int filemode;
    neat_error_code error = NEAT_OK;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    pr = malloc(sizeof(struct neat_pmi_req));
    if (pr == NULL) {
	neat_log(NEAT_LOG_ERROR, "%s: failed to allocate memory for %s PMI req.",
		 (dir == NEAT_PMI_IN) ? "input" : "output");
	error = NEAT_ERROR_INTERNAL;
	goto error_out;
    }
    pr->ctx = ctx;
    pr->direction = dir;

    if (dir == NEAT_PMI_OUT) {
	req = &ctx->pmi_ctx.out.req;
	filemode = O_WRONLY;
    } else {
	req = &ctx->pmi_ctx.in.req;
	filemode = O_RDONLY;
    }

    req->data = pr;

    env_home = getenv("HOME");
    if (env_home == NULL)
	env_home = "/etc/neat";
    // Our output is the input of the PM...
    snprintf(pipe_path, sizeof(pipe_path), "%s/.neat/policy/pm_json.%s", env_home,
	     (dir == NEAT_PMI_IN) ? "out" : "in");

    pr->direction = dir;
    uv_fs_open(ctx->loop, req, pipe_path,
		    filemode | O_NONBLOCK, 0, pmi_on_open);

    return NEAT_OK;
  error_out:
    pmi_req_fail(ctx, error);
    if (pr != NULL)
	free(pr);

    return error;
}

neat_error_code neat_pmi_init(struct neat_ctx *ctx)
{
    neat_error_code error = NEAT_OK;
    char *buf;
    enum neat_pmi_direction dir;
    struct neat_pmi_pipe *pipe;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    TAILQ_INIT(&ctx->pmi_ctx.req_queue);

    for (dir = NEAT_PMI_IN; dir <= NEAT_PMI_OUT; dir++) {
	switch (dir) {
	case NEAT_PMI_IN:
	    pipe = &ctx->pmi_ctx.in;
	    break;
	case NEAT_PMI_OUT:
	    pipe = &ctx->pmi_ctx.out;
	    break;
	default:
	    assert(0);
	}

	buf = malloc(PMI_BUF_SIZE);
	if (buf == NULL) {
	    neat_log(NEAT_LOG_ERROR, "%s: failed to allocate memory for PMI %s buffer.",
		     (dir == NEAT_PMI_IN) ? "input" : "output");
	    error = NEAT_ERROR_INTERNAL;
	    goto error_out;
	}
	pipe->buf = uv_buf_init(buf, PMI_BUF_SIZE);
    }

    return NEAT_OK;
  error_out:
    if (ctx->pmi_ctx.in.buf.base != NULL)
	free(ctx->pmi_ctx.in.buf.base);
    if (ctx->pmi_ctx.out.buf.base != NULL)
	free(ctx->pmi_ctx.out.buf.base);

    return error;
}

void neat_pmi_shutdown(struct neat_ctx *ctx)
{
    uv_fs_t close_req;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    uv_cancel((uv_req_t*)&ctx->pmi_ctx.in.req);
    uv_cancel((uv_req_t*)&ctx->pmi_ctx.out.req);
    uv_cancel((uv_req_t*)&ctx->pmi_ctx.req_rd);
    uv_cancel((uv_req_t*)&ctx->pmi_ctx.req_wr);
    uv_fs_close(ctx->loop, &close_req, ctx->pmi_ctx.in.req.result, NULL);
    uv_fs_close(ctx->loop, &close_req, ctx->pmi_ctx.out.req.result, NULL);

    if (ctx->pmi_ctx.out.req.data != NULL)
	free(ctx->pmi_ctx.out.req.data);
    if (ctx->pmi_ctx.in.req.data != NULL)
	free(ctx->pmi_ctx.in.req.data);
    if (ctx->pmi_ctx.in.buf.base != NULL)
	free(ctx->pmi_ctx.in.buf.base);
    if (ctx->pmi_ctx.out.buf.base != NULL)
	free(ctx->pmi_ctx.out.buf.base);


    uv_fs_req_cleanup(&ctx->pmi_ctx.in.req);
    uv_fs_req_cleanup(&ctx->pmi_ctx.out.req);
}

// Handle next request in queue
static void pmi_req_process(struct neat_ctx *ctx)
{
    struct neat_pmi_req *curr;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    curr = ctx->pmi_ctx.req_queue.tqh_first;

    if (curr == NULL)
	return;

    if (ctx->pmi_ctx.out.ready)
	uv_fs_write(ctx->loop, curr->send_req, ctx->pmi_ctx.out.req.result,
		    &curr->request, 1, -1, pmi_on_write);
    else
	pmi_open(ctx, NEAT_PMI_OUT);
}

// Convenience function to fail current request if any.
static void pmi_req_fail(struct neat_ctx *ctx, neat_error_code status)
{
    if (ctx->pmi_ctx.req_queue.tqh_first != NULL)
	pmi_req_finish(ctx->pmi_ctx.req_queue.tqh_first, status);
}

// Finish current request and execute callback
static void pmi_req_finish(struct neat_pmi_req *req, neat_error_code status)
{
    struct neat_ctx *ctx;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    ctx = req->ctx;
    TAILQ_REMOVE(&ctx->pmi_ctx.req_queue, ctx->pmi_ctx.req_queue.tqh_first, req_queue);

    if (status == NEAT_OK) {

	neat_log(NEAT_LOG_DEBUG, "Request completed. Read %d bytes from PMI.",
		 req->read);

	req->reply.base[req->read] = '\0';
	req->cb_reply(ctx, req->flow, req->reply.base);
    } else {
	neat_log(NEAT_LOG_ERROR, "PMI request failed. Error code %d.",
		 status);
	req->cb_reply(ctx, req->flow, NULL);
    }

    free(req->reply.base);
    uv_fs_req_cleanup(req->send_req);
    free(req->send_req);
    free(req);

    // Check if there are pending requests
    pmi_req_process(ctx);
}

// Send request for processing to Policy Manager.
// buf must contain the JSON-encoded request properties.
// len is the length of the buf string.
// cb_reply will be called when a reply has been received.
// The request string is copied to an internal buffer.
neat_error_code neat_pmi_send(struct neat_ctx *ctx,
			      struct neat_flow *flow,
			      char *buf,
			      size_t len,
			      neat_pmi_reply_t cb_reply)
{
    uv_fs_t *send_req;
    struct neat_pmi_req *pr;
    size_t rqlen;
    neat_error_code error = NEAT_OK;
    char *requestbuf = NULL;
    char *replybuf = NULL;

    neat_log(NEAT_LOG_DEBUG, "%s", __func__);

    send_req = calloc(1, sizeof(uv_fs_t));
    if (send_req == NULL) {
	neat_log(NEAT_LOG_ERROR, "Could not allocate memory for PMI send req");
	error = NEAT_ERROR_INTERNAL;
	goto error_out;
    }

    neat_log(NEAT_LOG_DEBUG, "Sending '%s' to PM.", buf);

    pr = calloc(1, sizeof(struct neat_pmi_req));
    if (pr == NULL) {
	neat_log(NEAT_LOG_ERROR, "Could not allocate memory for PMI request");
	error = NEAT_ERROR_INTERNAL;
	goto error_out;
    }
    send_req->data = pr;
    pr->send_req = send_req;
    pr->ctx = ctx;
    pr->flow = flow;
    pr->cb_reply = cb_reply;
    pr->read = 0;

    rqlen = len + 2; //newline + NULL
    requestbuf = calloc(1, rqlen);
    if (requestbuf == NULL) {
	neat_log(NEAT_LOG_ERROR, "Could not allocate PMI request buffer.");
	error = NEAT_ERROR_INTERNAL;
	goto error_out;
    }
    snprintf(requestbuf, rqlen, "%s\n", buf);
    pr->request = uv_buf_init(requestbuf, rqlen);

    replybuf = calloc(1, PMI_BUF_SIZE);
    if (replybuf == NULL) {
	neat_log(NEAT_LOG_ERROR, "Could not allocate PMI reply buffer.");
	error = NEAT_ERROR_INTERNAL;
	goto error_out;
    }
    pr->reply = uv_buf_init(replybuf, PMI_BUF_SIZE);

    TAILQ_INSERT_TAIL(&ctx->pmi_ctx.req_queue, pr, req_queue);

    pmi_req_process(ctx);
    return NEAT_OK;
  error_out:
    if (send_req != NULL)
	free(send_req);

    if (requestbuf != NULL)
	free(requestbuf);

    if (replybuf != NULL)
	free(replybuf);

    return error;
}
