#!/usr/bin/env python3

"""
    This file is a ported version of the C example bundled with NEAT.
    Note that the NEAT bindings currently require Python 2.7 or larger.
    Python 3 will not work.
"""

from neat import *
import sys
import ctypes # TODO: Get rid of this

def on_readable(ops):
    buffer = ctypes.create_string_buffer(32)
    bytes_read = 0
    if (neat_read(ops.ctx, ops.flow, buffer, 31, ctypes.byref(bytes_read), None, 0) == NEAT_OK):
        buffer[bytes_read] = 0
        print("Read {} bytes:\n{}".format(bytes_read, buffer))
    neat_close(ops.ctx, ops.flow)
    return NEAT_OK

def on_close(ops):
    neat_stop_event_loop(ops.ctx)
    return NEAT_OK

def on_writable(ops):
    message = "Hi!"
    neat_write(ops.ctx, ops.flow, message, 3, NULL, 0)
    return NEAT_OK

def on_all_written(ops):
    ops.on_readable = on_readable
    ops.on_writable = None
    neat_set_operations(ops.ctx, ops.flow, ops);
    return NEAT_OK

def on_connected(ops):
    ops.on_writable = on_writable
    ops.on_all_written = on_all_written
    neat_set_operations(ops.ctx, ops.flow, ops)

    return NEAT_OK

properties = """{
    "transport":
        {
            "value": ["SCTP", SCTP],
            "precedence": 1
        }
}"""

if __name__ == "__main__":
    ctx = neat_init_ctx()
    flow = neat_new_flow(ctx)
    ops = neat_flow_operations()

    ops.on_connected = on_connected
    ops.on_close = on_close
    neat_set_operations(ctx, flow, ops)

    neat_set_property(ctx, flow, properties)

    if (neat_open(ctx, flow, "127.0.0.1", 5000, None, 0)):
        sys.exit("neat_open failed")

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT)

    neat_free_ctx(ctx)
