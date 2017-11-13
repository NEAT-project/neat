#include <neat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#define QUOTE(...) #__VA_ARGS__

/**********************************************************************

    Non-blocking HTTP-GET client in neat
    * connect to HOST and send GET request
    * write response to stdout

    client_http_run_once [OPTIONS] HOST
    -u : URI
    -n : number of requests/flows (default: 3)
    -c : number of contexts (default: 1)
    -R : receive buffer size in byte
    -v : log level (0 .. 4)
    -t : use tcp as transport protocol
    -s : use sctp as transport protocol

 Each new flow will be put on the next context (if more than one context is
 specified) and when reaching the end of the total number of contexts, it
 starts over on the context on index 0 again.

**********************************************************************/

#define MAX_FLOWS   500
#define MAX_CTXS    10

static uint32_t config_rcv_buffer_size = 65536;
static char request[512];
static const char *request_tail = "HTTP/1.0\r\nUser-agent: libneat\r\nConnection: close\r\n\r\n";
static char *config_property_sctp_tcp = QUOTE(
    {                                             
    "transport": [
        {
            "value": "SCTP",
            "precedence": 1
        },
        {
            "value": "SCTP/UDP",
            "precedence": 1
        },
        {
            "value": "TCP",
            "precedence": 1
        }
    ]
      });
static char *config_property_tcp = QUOTE({
    "transport": [
        {
            "value": "TCP",
            "precedence": 1
        }
    ]
      });
static char *config_property_sctp = QUOTE({
    "transport": [
        {
            "value": "SCTP",
            "precedence": 1
        },
        {
            "value": "SCTP/UDP",
            "precedence": 1
        }
    ]
      });
static unsigned char *buffer = NULL;
static int streams_going = 0;
static uint32_t ctx_flows[MAX_CTXS];

struct user_flow {
    struct neat_flow *flow;
    uint32_t id;
    uint32_t ctx_id;
};

static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    struct user_flow *f = opCB->userData;
    fprintf(stderr, "%s\n", __func__);
    fprintf(stderr, "[on_error on flow %u]\n", f->id);
    streams_going--;
    return 0;
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    uint32_t bytes_read = 0;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer, config_rcv_buffer_size, &bytes_read, NULL, 0);
    if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
    } else if (code != NEAT_OK) {
        return on_error(opCB);
    }

    if (bytes_read > 0) {
        //fwrite(buffer, sizeof(char), bytes_read, stdout);
    }

    return 0;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB) {
    struct user_flow *f = opCB->userData;
    ctx_flows[f->ctx_id] = ctx_flows[f->ctx_id] - 1;
    streams_going--; /* one stream less */
    fprintf(stderr, "[Flow %u ended, %d to go, %d for ctx %d]\n", f->id, streams_going, ctx_flows[f->ctx_id], f->ctx_id);
    fflush(stdout);
    opCB->on_readable = NULL; // do not read more
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    if (ctx_flows[f->ctx_id] == 0) {
        fprintf(stderr, "%s - no flows left for ctx, stopping event loop\n", __func__);
        //neat_stop_event_loop(opCB->ctx);
    }

    return NEAT_OK;
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
    struct neat_ctx *ctx[MAX_CTXS];
    struct user_flow flows[MAX_FLOWS];
    struct neat_flow_operations ops[MAX_FLOWS];
    struct pollfd fds[MAX_CTXS];
    int result = 0;
    int arg = 0;
    uint32_t num_flows = 3;
    uint32_t i = 0;
    uint32_t c = 0;
    int backend_fds[MAX_CTXS];
    uint32_t num_ctxs = 10;
    int config_log_level = NEAT_LOG_WARNING;
    const char *config_property;

    result = EXIT_SUCCESS;
    memset(&ops,        0, sizeof(ops));
    memset(ctx,         0, sizeof(ctx));
    memset(&flows,      0, sizeof(flows));
    memset(&ctx_flows,  0, sizeof(ctx_flows));

    config_property = config_property_sctp_tcp;

    snprintf(request, sizeof(request), "GET %s %s", "/", request_tail);

    while ((arg = getopt(argc, argv, "u:n:c:sR:tv:")) != -1) {
        switch(arg) {
        case 'u':
            snprintf(request, sizeof(request), "GET %s %s", optarg, request_tail);
            break;
        case 'n':
            num_flows = strtoul (optarg, NULL, 0);
            if (num_flows > MAX_FLOWS) {
                num_flows = MAX_FLOWS;
            }
            fprintf(stderr, "%s - option - number of flows: %d\n", __func__, num_flows);
            break;
        case 'c':
            num_ctxs = strtoul (optarg, NULL, 0);
            if (num_ctxs > MAX_CTXS) {
                num_ctxs = MAX_CTXS;
            }
            fprintf(stderr, "%s - option - number of contexts: %d\n", __func__, num_ctxs);
            break;
        case 'R':
            config_rcv_buffer_size = atoi(optarg);
            fprintf(stderr, "%s - option - receive buffer size: %d\n",
                    __func__, config_rcv_buffer_size);
            break;
        case 'v':
            config_log_level = atoi(optarg);
            fprintf(stderr, "%s - option - log level: %d\n", __func__, config_log_level);
            break;
        case 's':
            config_property = config_property_sctp;
            break;
        case 't':
            config_property = config_property_tcp;
            break;
        default:
            fprintf(stderr, "usage: client_http_run_once [OPTIONS] HOST\n"
                    " -u <path> - to send with GET\n"
                    " -n <num>  - number of requests/flows (default: %d)\n"
                    " -c <num>  - number of contexts (default: %d)\n"
                    " -R <size> - receive buffer size in byte (default: %d\n"
                    " -v <lvl>  - log level, 0 - 4 (default: %d)\n",
                    num_flows, num_ctxs, config_rcv_buffer_size,
                    config_log_level);
            goto cleanup;
            break;
        }
    }

    if (optind + 1 != argc) {
        fprintf(stderr, "usage: client_http_get [OPTIONS] HOST\n");
        goto cleanup;
    }

    printf("%d flows - requesting: %s\n", num_flows, request);

    buffer = malloc(config_rcv_buffer_size);

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
        if ((flows[i].flow = neat_new_flow(ctx[c])) == NULL) {
            fprintf(stderr, "could not initialize context\n");
            result = EXIT_FAILURE;
            goto cleanup;
        }
        neat_log_level(ctx[c], config_log_level);

        neat_set_property(ctx[c], flows[i].flow, config_property);

        ctx_flows[c]++;

        ops[i].on_connected = on_connected;
        ops[i].on_error     = on_error;
        ops[i].on_close     = on_close;

        flows[i].id     = streams_going;
        flows[i].ctx_id = c;
        ops[i].userData = &flows[i];

        streams_going++;
        neat_set_operations(ctx[c], flows[i].flow, &(ops[i]));

        // wait for on_connected or on_error to be invoked
        if (neat_open(ctx[c], flows[i].flow, argv[argc - 1], 80, NULL, 0) != NEAT_OK) {
            fprintf(stderr, "Could not open flow\n");
            result = EXIT_FAILURE;
        } else {
            fprintf(stderr, "Opened flow %d for ctx %d\n", i, c);
        }
    }

    /* Get the underlying single file descriptors from libuv. Wait on these
       descriptors to become readable to know when to ask NEAT to run another
       loop ONCE on everything that it might have to work on. */

    for (c = 0; c < num_ctxs; c++) {
        backend_fds[c] = neat_get_backend_fd(ctx[c]);
        /* kick off the event loop first for each context */
        neat_start_event_loop(ctx[c], NEAT_RUN_ONCE);
    }

    while (streams_going) {
        int timeout = 9999;

        fprintf(stderr, "[%d flows to go]\n", streams_going);
        for (c = 0; c < num_ctxs; c++) {
            int t;
            fds[c].fd       = backend_fds[c];
            fds[c].events   = POLLERR | POLLIN | POLLHUP;
            fds[c].revents  = 0;

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
        } else {
            fprintf(stderr, "Waiting...\n");
        }

        for (c = 0; c < num_ctxs; c++) {
            neat_start_event_loop(ctx[c], NEAT_RUN_NOWAIT);
        }
    }
cleanup:
    fprintf(stderr, "Cleanup!\n");

    for (c = 0; c < num_ctxs; c++) {
        neat_free_ctx(ctx[c]);
    }

    if (buffer) {
        free(buffer);
    }

    exit(result);
}
