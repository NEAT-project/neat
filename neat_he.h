#ifndef NEAT_HE_H
#define NEAT_HE_H

#include <uv.h>

struct neat_flow;
struct neat_ctx;

struct neat_he_resolver_data
{
    struct neat_ctx *ctx;
    struct neat_flow *flow;
    uv_poll_cb callback_fx;
};

#endif
