#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "../neat.h"

/**********************************************************************
 * Stripped down version of http_client_get used for testing various
 * ways users could free or shut down flows and contexts.
 **********************************************************************/

typedef struct {
    int on_connected;
    int on_readable;
    int on_writable;
    int on_error;
    int on_close;
} close_t;

static int config_rcv_buffer_size = 65536;
static const char *request_tail = "HTTP/1.0\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";
static char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"SCTP\",\
            \"precedence\": 1\
        },\
        {\
            \"value\": \"TCP\",\
            \"precedence\": 1\
        }\
    ]\
}";\

static neat_error_code on_close(struct neat_flow_operations *ops);

#define ON_ERROR_CLOSE_COUNT 2
static neat_error_code
on_error(struct neat_flow_operations *ops)
{
    close_t *cls = ops->userData;

    fprintf(stderr, "%s\n", __func__);

    if (cls->on_error == 1)
        neat_close(ops->ctx, ops->flow);

    neat_stop_event_loop(ops->ctx);

    // TODO: This leads to an abort in libuv after calling neat_set_ops
    // in on_close.
#if 1
    if (cls->on_error == 2)
        neat_close(ops->ctx, ops->flow);
#endif

    return NEAT_OK;
}

#define ON_READABLE_CLOSE_COUNT 2
static neat_error_code
on_readable(struct neat_flow_operations *ops)
{
    close_t *cls = ops->userData;

    unsigned char buffer[config_rcv_buffer_size];
    uint32_t bytes_read = 0;
    neat_error_code code;

    if (cls->on_readable == 1)
        neat_close(ops->ctx, ops->flow);

    fprintf(stderr, "%s - reading from flow\n", __func__);
    code = neat_read(ops->ctx, ops->flow, buffer, config_rcv_buffer_size, &bytes_read, NULL, 0);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    }

    assert(code == NEAT_OK);

    if (!bytes_read) { // eof
        fprintf(stderr, "%s - neat_read() got 0 bytes - connection closed\n", __func__);
        fflush(stdout);
        neat_close(ops->ctx, ops->flow);
    } else if (bytes_read > 0) {
        fprintf(stderr, "%s - received %d bytes\n", __func__, bytes_read);
        fwrite(buffer, sizeof(char), bytes_read, stdout);
    }

    if (cls->on_readable == 2)
        neat_close(ops->ctx, ops->flow);

    return 0;
}

#define ON_WRITABLE_CLOSE_COUNT 3
static neat_error_code
on_writable(struct neat_flow_operations *ops)
{
    close_t *cls = ops->userData;

    neat_error_code code;
    fprintf(stderr, "%s - writing to flow\n", __func__);

    if (cls->on_writable == 1)
        neat_close(ops->ctx, ops->flow);

    code = neat_write(ops->ctx, ops->flow, (const unsigned char *)request_tail, strlen(request_tail), NULL, 0);
    if (code != NEAT_OK) {
        return on_error(ops);
    }

    if (cls->on_writable == 2)
        neat_close(ops->ctx, ops->flow);

    ops->on_writable = NULL;
    neat_set_operations(ops->ctx, ops->flow, ops);

    if (cls->on_writable == 3)
        neat_close(ops->ctx, ops->flow);

    return 0;
}

#define ON_CONNECTED_CLOSE_COUNT 2
static neat_error_code
on_connected(struct neat_flow_operations *ops)
{
    close_t *cls = ops->userData;

    // now we can start writing
    fprintf(stderr, "%s - connection established\n", __func__);

    if (cls->on_connected == 1)
        neat_close(ops->ctx, ops->flow);

    ops->on_readable = on_readable;
    ops->on_writable = on_writable;
    neat_set_operations(ops->ctx, ops->flow, ops);

    if (cls->on_connected == 2)
        neat_close(ops->ctx, ops->flow);

    return 0;
}

#define ON_CLOSE_CLOSE_COUNT 3
static neat_error_code
on_close(struct neat_flow_operations *ops)
{
    close_t *cls = ops->userData;

    fprintf(stderr, "%s - flow closed OK!\n", __func__);

    if (cls->on_close == 1)
        neat_close(ops->ctx, ops->flow);

    // cleanup
    ops->on_close = NULL;
    ops->on_readable = NULL;
    ops->on_writable = NULL;
    ops->on_error = NULL;
    neat_set_operations(ops->ctx, ops->flow, ops);

    if (cls->on_close == 2)
        neat_close(ops->ctx, ops->flow);

    // stop event loop if all flows are closed
    neat_stop_event_loop(ops->ctx);

    if (cls->on_close == 3)
        neat_close(ops->ctx, ops->flow);

    return NEAT_OK;
}

int
run_case(const char* name, close_t *close_spec)
{
    struct neat_ctx *ctx = NULL;
    struct neat_flow *flow = NULL;
    struct neat_flow_operations ops;
    int result = 0;
    result = EXIT_SUCCESS;

    memset(&ops, 0, sizeof(ops));

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "could not initialize context\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if ((flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "could not create new flow\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    neat_set_property(ctx, flow, config_property);

    ops.userData = close_spec;

    ops.on_connected = on_connected;
    ops.on_error = on_error;
    ops.on_close = on_close;

    neat_set_operations(ctx, flow, &ops);

    // wait for on_connected or on_error to be invoked
    if (neat_open(ctx, flow, name, 80, NULL, 0) != NEAT_OK) {
        fprintf(stderr, "Could not open flow\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

cleanup:
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    return result;
}

int
main(int argc, char *argv[])
{
    close_t cls;
    memset(&cls, 0, sizeof(cls));

    for (int i = 1; i <= ON_CONNECTED_CLOSE_COUNT; ++i) {
        cls.on_connected = i;
        run_case("bsd10.fh-muenster.de", &cls);
    }
    cls.on_connected = 0;

    for (int i = 1; i <= ON_READABLE_CLOSE_COUNT; ++i) {
        cls.on_readable = i;
        run_case("bsd10.fh-muenster.de", &cls);
    }
    cls.on_readable = 0;

    for (int i = 1; i <= ON_WRITABLE_CLOSE_COUNT; ++i) {
        cls.on_writable = i;
        run_case("bsd10.fh-muenster.de", &cls);
    }
    cls.on_writable = 0;

    for (int i = 1; i <= ON_CLOSE_CLOSE_COUNT; ++i) {
        cls.on_close = i;
        run_case("bsd10.fh-muenster.de", &cls);
    }
    cls.on_close = 0;

    for (int i = 1; i <= ON_ERROR_CLOSE_COUNT; ++i) {
        cls.on_error = i;
        run_case("not.resolvable.neat", &cls);
    }
    cls.on_error = 0;

    return 0;
}
