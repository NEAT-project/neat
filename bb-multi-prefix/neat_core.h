#ifndef NEAT_MULTI_PREFIX_H
#define NEAT_MULTI_PREFIX_H

#include "include/queue.h"

#define RETVAL_SUCCESS  0
#define RETVAL_FAILURE  1
#define RETVAL_IGNORE   2

struct neat_ctx;

//Pass data to all subscribers of event type
void neat_run_event_cb(struct neat_ctx *nc, uint8_t event_type,
        void *data);
#endif
