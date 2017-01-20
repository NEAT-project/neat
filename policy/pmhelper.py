import logging
import socket

so_separator = '/'
so_prefix = 'SO'

# for testing
so_str = 'SO/SOL_TCP/SO_KEEPALIVE'


def sock_prop(so_str):
    if not so_str.startswith(so_prefix + so_separator):
        return
    _, level, optname = so_str.split(so_separator)
    try:
        # get socket level
        sol_i = getattr(socket, level)
        so_i = getattr(socket, optname)
    except AttributeError as e:
        logging.debug('Unknown socket option' + e.args[0])
        return

    return so_separator.join(('SO', str(sol_i), str(so_i)))
