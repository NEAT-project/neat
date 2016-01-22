#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../neat.h"
#include <sys/time.h>

#define NO_DEBUG_INFO
#define BUFFERSIZE 1024

#ifdef NO_DEBUG_INFO
#define debug_info(M, ...)
#else
#define debug_info(M, ...) fprintf(stderr, "[INFO][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define debug_error(M, ...) fprintf(stderr, "[ERROR][%s:%d] " M "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

struct stats {
    uint64_t pkts;
    uint64_t bytes;
    struct timeval tv_first;
    struct timeval tv_last;
};

static struct neat_flow_operations ops;
static uint8_t active = 0;
static struct stats rcv_stats;
static struct stats snd_stats;
static uint8_t chargen_offset = 0;
static uint32_t max_runtime = 10;
static char birate_human[10];

static uint64_t on_error(struct neat_flow_operations *opCB) {
    exit(EXIT_FAILURE);
}

char* readable_fs(double bytes, char *buf) {
    int i = 0;
    const char* units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    while (bytes > 1024) {
        bytes /= 1024;
        i++;
    }
    sprintf(buf, "%.*f %s", i, bytes, units[i]);
    return buf;
}

/*
    send BUFFERSIZE chars to peer
*/
static uint64_t on_writable(struct neat_flow_operations *opCB) {
    neat_error_code code;
    unsigned char buffer[BUFFERSIZE];

    memset(buffer, 33+chargen_offset++, BUFFERSIZE);
    chargen_offset = chargen_offset % 72;

    code = neat_write(opCB->ctx, opCB->flow, buffer, BUFFERSIZE);
    if (code) {
        debug_error("neat_write - code: %d", (int)code);
        return on_error(opCB);
    }

    debug_info("neat_write - %d byte", BUFFERSIZE);

    if (snd_stats.pkts == 0) {
        gettimeofday(&snd_stats.tv_first, NULL);
    }

    snd_stats.pkts++;
    snd_stats.bytes += BUFFERSIZE;
    gettimeofday(&snd_stats.tv_last, NULL);

    uint32_t elapsedTime;
    elapsedTime = snd_stats.tv_last.tv_sec - snd_stats.tv_first.tv_sec;

    // stop writing if max_runtime reached
    if (elapsedTime >= max_runtime) {
        opCB->on_writable = NULL;
        neat_stop_event_loop(opCB->ctx);
        return 0;
    }

    return 0;
}

static uint64_t on_readable(struct neat_flow_operations *opCB) {
    unsigned char buffer[BUFFERSIZE];
    uint32_t buffer_filled;
    neat_error_code code;

    code = neat_read(opCB->ctx, opCB->flow, buffer, BUFFERSIZE, &buffer_filled);
    if (code) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            debug_error("NEAT_ERROR_WOULD_BLOCK");
            return 0;
        } else {
            debug_error("neat_read - code: %d", (int)code);
            return on_error(opCB);
        }
    }

    if (!buffer_filled) {
        // client disconnected - print statistics
        double elapsedTime;
        elapsedTime = rcv_stats.tv_last.tv_sec - rcv_stats.tv_first.tv_sec; // sec
        elapsedTime += (rcv_stats.tv_last.tv_usec - rcv_stats.tv_first.tv_usec) / 1000000.0; // us >> sec
        printf("client disconnected - stats\n");
        printf("%ld bytes in %ld packets in %.2f seconds - %.2f bytes/s - %s/s\n", rcv_stats.bytes, rcv_stats.pkts, elapsedTime, rcv_stats.bytes/elapsedTime, readable_fs(rcv_stats.bytes/elapsedTime, birate_human));
        opCB->on_readable = NULL;
    } else if (buffer_filled > 0) {
        // we got data!
        debug_info("got some data - discarding...");

        if (rcv_stats.pkts == 0) {
            gettimeofday(&rcv_stats.tv_first, NULL);
        }
        rcv_stats.pkts++;
        rcv_stats.bytes += buffer_filled;
        gettimeofday(&rcv_stats.tv_last, NULL);
    }
    return 0;
}

static uint64_t on_connected(struct neat_flow_operations *opCB) {
    debug_info();

    // reset stats
    rcv_stats.pkts = 0;
    rcv_stats.bytes = 0;
    snd_stats.pkts = 0;
    snd_stats.bytes = 0;

    opCB->on_readable = on_readable;

    if (active) {
        ops.on_writable = on_writable;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    struct neat_ctx *ctx = neat_init_ctx();
    struct neat_flow *flow;
    uint64_t prop;

    // check for argumets
    if (argc == 3) {
        debug_info("acting active");
        active = 1;
    } else {
        debug_info("acting passive");
    }

    // check for successful context
    if (ctx == NULL) {
        debug_error("could not initialize context");
        exit(EXIT_FAILURE);
    }

    // new neat flow
    if ((flow = neat_new_flow(ctx)) == NULL) {
        debug_error("neat_new_flow");
        exit(EXIT_FAILURE);
    }

    ops.on_connected = on_connected;
    ops.on_error = on_error;


    //ops.on_all_written = on_all_written;
    if (neat_set_operations(ctx, flow, &ops)) {
        debug_error("neat_set_operations");
        exit(EXIT_FAILURE);
    }

    // get properties
    if (neat_get_property(ctx, flow, &prop)) {
        debug_error("neat_get_property");
        exit(EXIT_FAILURE);
    }

    prop |= NEAT_PROPERTY_TCP_REQUIRED;
    prop |= NEAT_PROPERTY_IPV4_REQUIRED;

    // set properties
    if (neat_set_property(ctx, flow, prop)) {
        debug_error("neat_set_property");
        exit(EXIT_FAILURE);
    }

    if (active) {
        // connect to peer
        if (neat_open(ctx, flow, argv[1], argv[2])) {
            debug_error("neat_open");
            exit(EXIT_FAILURE);
        }
    } else {
        // wait for on_connected or on_error to be invoked
        if (neat_accept(ctx, flow, "*", "8080")) {
            debug_error("neat_accept");
            exit(EXIT_FAILURE);
        }
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    debug_info("freeing (flow + ctx) and bye bye!");

    // cleanup
    neat_free_flow(flow);
    neat_free_ctx(ctx);
    exit(EXIT_SUCCESS);
}
