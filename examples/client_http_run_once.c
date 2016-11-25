#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include "../neat.h"

/**********************************************************************

    HTTP-GET client in neat
    * connect to HOST and send GET request
    * write response to stdout

    client_http_get [OPTIONS] HOST
    -u : URI
    -n : number of requests/flows

**********************************************************************/

static uint32_t config_rcv_buffer_size = 65536;
static uint32_t config_max_flows = 50;
static char request[512];
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

static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    fprintf(stderr, "%s\n", __func__);
    exit(EXIT_FAILURE);
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    unsigned char buffer[config_rcv_buffer_size];
    uint32_t bytes_read = 0;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer, config_rcv_buffer_size, &bytes_read, NULL, 0);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    } else if (code != NEAT_OK) {
        return on_error(opCB);
    }

    if (!bytes_read) { // eof
        int *numstreams = opCB->userData;
        (*numstreams)--; /* one stream less */
        fflush(stdout);
        opCB->on_readable = NULL; // do not read more
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
        neat_stop_event_loop(opCB->ctx);
    } else if (bytes_read > 0) {
        fwrite(buffer, sizeof(char), bytes_read, stdout);
    }
    return 0;
}

static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    code = neat_write(opCB->ctx, opCB->flow, (const unsigned char *)request, strlen(request), NULL, 0);
    if (code != NEAT_OK) {
        return on_error(opCB);
    }
    opCB->on_writable = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return 0;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    // now we can start writing
    opCB->on_readable = on_readable;
    opCB->on_writable = on_writable;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return 0;
}

int
main(int argc, char *argv[])
{
    struct neat_ctx *ctx = NULL;
    struct neat_flow *flows[config_max_flows];
    struct neat_flow_operations ops[config_max_flows];
    int result = 0;
    int arg = 0;
    uint32_t num_flows = 1;
    uint32_t i = 0;
    int backend_fd;
    int streams_going = 0;
    result = EXIT_SUCCESS;

    memset(&ops, 0, sizeof(ops));
    memset(flows, 0, sizeof(flows));

    snprintf(request, sizeof(request), "GET %s %s", "/", request_tail);

    while ((arg = getopt(argc, argv, "u:n:")) != -1) {
        switch(arg) {
        case 'u':
            snprintf(request, sizeof(request), "GET %s %s", optarg, request_tail);
            break;
        case 'n':
            num_flows = strtoul (optarg, NULL, 0);
            if (num_flows > config_max_flows) {
                num_flows = config_max_flows;
            }
            fprintf(stderr, "%s - option - number of flows: %d\n", __func__, num_flows);
            break;
        default:
            fprintf(stderr, "usage: client_http_get [OPTIONS] HOST\n");
            goto cleanup;
            break;
        }
    }

    if (optind + 1 != argc) {
        fprintf(stderr, "usage: client_http_get [OPTIONS] HOST\n");
        goto cleanup;
    }

    printf("%d flows - requesting: %s\n", num_flows, request);

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "could not initialize context\n");
        result = EXIT_FAILURE;
        goto cleanup;
    }


    for (i = 0; i < num_flows; i++) {
        if ((flows[i] = neat_new_flow(ctx)) == NULL) {
            fprintf(stderr, "could not initialize context\n");
            result = EXIT_FAILURE;
            goto cleanup;
        }

        neat_set_property(ctx, flows[i], config_property);

        ops[i].on_connected = on_connected;
        ops[i].on_error = on_error;
        ops[i].userData = &streams_going;
        streams_going++;
        neat_set_operations(ctx, flows[i], &(ops[i]));

        // wait for on_connected or on_error to be invoked
        if (neat_open(ctx, flows[i], argv[argc - 1], 80, NULL, 0) != NEAT_OK) {
            fprintf(stderr, "Could not open flow\n");
            result = EXIT_FAILURE;
        } else {
            fprintf(stderr, "Opened flow %d\n", i);
        }
    }

    /* Get the underlying single file descriptor from libuv. Wait on this
       descriptor to become readable to know when to ask NEAT to run another
       loop ONCE on everything that it might have to work on. */

    backend_fd = neat_get_backend_fd(ctx);

    /* kick off the event loop first */
    neat_start_event_loop(ctx, NEAT_RUN_ONCE);

    while (streams_going) {
        struct pollfd fds[1] = {
            {
                .fd = backend_fd,
                .events = POLLERR | POLLIN | POLLHUP,
                .revents = 0,
            }
        };
        int rc = poll(fds, 1, neat_get_backend_timeout(ctx));

        if (rc > 0) {
            /* there's stuff to do */
            neat_start_event_loop(ctx, NEAT_RUN_NOWAIT);
        }
        else {
            fprintf(stderr, "Waiting on %d streams...\n", streams_going);
            neat_start_event_loop(ctx, NEAT_RUN_NOWAIT);
        }

    }
cleanup:
    if (ctx != NULL) {
        for (i = 0; i < num_flows; i++) {
            if (flows[i] != NULL) {
                neat_close(ctx, flows[i]);
            }
        }
        neat_free_ctx(ctx);
    }
    exit(result);
}
