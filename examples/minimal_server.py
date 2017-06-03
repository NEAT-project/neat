#!/usr/bin/env python3

"""
    This file is a ported version of the C example bundled with NEAT.
    Note that the NEAT bindings currently require Python 3.
"""

import neat
import sys

def on_readable(ops):
    return neat.NEAT_OK

def on_writable(ops):
    message = "Hello, this is NEAT!"
    neat.neat_write(ops.ctx, ops.flow, message, 20, None, 0)
    return neat.NEAT_OK

def on_all_written(ops):
    neat.neat_close(ops.ctx, ops.flow)
    return neat.NEAT_OK

def on_connected(ops):
    ops.on_writable = on_writable
    ops.on_all_written = on_all_written
    neat.neat_set_operations(ops.ctx, ops.flow, ops)
    return neat.NEAT_OK

if __name__ == "__main__":

    ctx  = neat.neat_init_ctx()
    flow = neat.neat_new_flow(ctx)
    ops  = neat.neat_flow_operations()

    ops.on_connected = on_connected
    neat.neat_set_operations(ctx, flow, ops)

    if (neat.neat_accept(ctx, flow, 5000, None, 0)):
        sys.exit("neat_accept failed")

    neat.neat_start_event_loop(ctx, neat.NEAT_RUN_DEFAULT);
