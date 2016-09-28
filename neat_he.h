#ifndef NEAT_HE_H
#define NEAT_HE_H

#include <uv.h>

// Delay in ms between each priority level
#define HE_PRIO_DELAY 10

struct neat_flow;
struct neat_ctx;

struct neat_he_resolver_data
{
    struct neat_ctx *ctx;
    struct neat_flow *flow;
    uv_poll_cb callback_fx;
};

#endif
