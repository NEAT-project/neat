#!/usr/bin/env python3
# coding=utf-8

"""
    This file is a ported version of the C example bundled with NEAT.
    Note that the NEAT bindings currently require Python 2.7 or larger.
    Python 3 will not work.
"""

from neat import *
import sys


def on_readable(ops):
    buffer = charArr(32)
    bytes_read = new_uint32_tp()
    try:
        neat_read(ops.ctx, ops.flow, buffer, 31, bytes_read, None, 0)
        byte_array = bytearray(uint32_tp_value(bytes_read))
        for i in range(uint32_tp_value(bytes_read)):
            byte_array[i] = buffer[i]

        print("\n\nRead {} bytes: {}\n\n".format(uint32_tp_value(bytes_read), byte_array))
    except:
        print('\033[91m' + "\n\nAn error occurred in the Python callback: {}\n\n".upper() + '\033[0m').format(sys.exc_info()[0])
        neat_abort(ops.ctx, ops.flow)
    return NEAT_OK


def on_writable(ops):
    message = "Hello, this is NEAT!"
    neat_write(ops.ctx, ops.flow, message, 20, None, 0)
    ops.on_writable = None
    neat_set_operations(ops.ctx, ops.flow, ops)
    return NEAT_OK


def on_all_written(ops):
    neat_close(ops.ctx, ops.flow)
    return NEAT_OK


def on_connected(ops):
    ops.on_writable = on_writable
    ops.on_all_written = on_all_written
    neat_set_operations(ops.ctx, ops.flow, ops)
    return NEAT_OK


if __name__ == "__main__":

    ctx = neat_init_ctx()
    flow = neat_new_flow(ctx)
    ops = neat_flow_operations()

    ops.on_readable = on_readable
    ops.on_connected = on_connected
    neat_set_operations(ctx, flow, ops)

    if neat_accept(ctx, flow, 5000, None, 0):
        sys.exit("neat_accept failed")

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT)
