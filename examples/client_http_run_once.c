#include <neat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

/**********************************************************************

    Non-blocking HTTP-GET client in neat
    * connect to HOST and send GET request
    * write response to stdout

    client_http_run_once [OPTIONS] HOST
    -u : URI
    -n : number of requests/flows (default: 3)
    -c : number of contexts (default: 1)

 Each new flow will be put on the next context (if more than one context is
 specified) and when reaching the end of the total number of contexts, it
 starts over on the context on index 0 again.

**********************************************************************/

static uint32_t config_rcv_buffer_size = 65536;
static uint32_t config_max_flows = 500;
static uint32_t config_max_ctxs = 50;
static char request[512];
static const char *request_tail = "HTTP/1.0\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";
static char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"SCTP\",\
            \"precedence\": 1\
        },\
        {\
            \"value\": \"SCTP/UDP\",\
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
    struct neat_ctx *ctx[config_max_ctxs];
    struct neat_flow *flows[config_max_flows];
    struct neat_flow_operations ops[config_max_flows];
    struct pollfd fds[config_max_ctxs];
    int result = 0;
    int arg = 0;
    uint32_t num_flows = 3;
    uint32_t i = 0;
    uint32_t c = 0;
    int backend_fds[config_max_ctxs];
    int streams_going = 0;
    uint32_t num_ctxs = 1;
    result = EXIT_SUCCESS;

    memset(&ops, 0, sizeof(ops));
    memset(flows, 0, sizeof(flows));
    memset(ctx, 0, sizeof(ctx));

    snprintf(request, sizeof(request), "GET %s %s", "/", request_tail);

    while ((arg = getopt(argc, argv, "u:n:c:")) != -1) {
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
        case 'c':
            num_ctxs = strtoul (optarg, NULL, 0);
            if (num_ctxs > config_max_ctxs) {
                num_ctxs = config_max_ctxs;
            }
            fprintf(stderr, "%s - option - number of contexts: %d\n", __func__, num_ctxs);
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

    for (i = 0; i < num_ctxs; i++) {
        if ((ctx[i] = neat_init_ctx()) == NULL) {
            fprintf(stderr, "could not initialize context %d\n", i);
            result = EXIT_FAILURE;
            goto cleanup;
        }
    }

    for (i = 0, c = 0; i < num_flows; i++, c++) {
        if (c >= num_ctxs) {
            c = 0;
        }
        if ((flows[i] = neat_new_flow(ctx[c])) == NULL) {
            fprintf(stderr, "could not initialize context\n");
            result = EXIT_FAILURE;
            goto cleanup;
        }
        neat_log_level(ctx[c], NEAT_LOG_OFF);

        neat_set_property(ctx[c], flows[i], config_property);

        ops[i].on_connected = on_connected;
        ops[i].on_error = on_error;
        ops[i].userData = &streams_going;
        streams_going++;
        neat_set_operations(ctx[c], flows[i], &(ops[i]));

        // wait for on_connected or on_error to be invoked
        if (neat_open(ctx[c], flows[i], argv[argc - 1], 80, NULL, 0) != NEAT_OK) {
            fprintf(stderr, "Could not open flow\n");
            result = EXIT_FAILURE;
        } else {
            fprintf(stderr, "Opened flow %d\n", i);
        }
    }

    /* Get the underlying single file descriptors from libuv. Wait on these
       descriptors to become readable to know when to ask NEAT to run another
       loop ONCE on everything that it might have to work on. */

    for (c=0; c<num_ctxs; c++) {
        backend_fds[c] = neat_get_backend_fd(ctx[c]);
        /* kick off the event loop first for each context */
        neat_start_event_loop(ctx[c], NEAT_RUN_ONCE);
    }

    while (streams_going) {
        int timeout = 9999;

        fprintf(stderr, "[%d flows to go]\n", streams_going);
        for (c=0; c<num_ctxs; c++) {
            int t;
            fds[c].fd = backend_fds[c];
            fds[c].events = POLLERR | POLLIN | POLLHUP;
            fds[c].revents = 0;

            t = neat_get_backend_timeout(ctx[c]);
            if (t < timeout) {
                timeout = t;
            }
        }
        /* use the shortest timeout from all contexts used */
        int rc = poll(fds, num_ctxs, timeout);

        if (rc > 0) {
            /* there's stuff to do on one or more contexts, do them all */
            ;
        }
        else {
            fprintf(stderr, "Waiting...\n");
        }
        for (c=0; c<num_ctxs; c++) {
            neat_start_event_loop(ctx[c], NEAT_RUN_NOWAIT);
        }
    }
cleanup:
    for (i = 0, c = 0; i < num_flows; i++, c++) {
      if (c >= num_ctxs) {
        c = 0;
      }
      if (flows[i] != NULL) {
        neat_close(ctx[c], flows[i]);
      }
    }
    for (c = 0; c < num_ctxs; c++) {
      neat_free_ctx(ctx[c]);
    }
    exit(result);
}
