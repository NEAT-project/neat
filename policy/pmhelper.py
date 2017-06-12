import logging
import socket

so_separator = '/'
so_prefix = 'SO'


def sock_prop(so_str):
    """
    convert socket option names to system specific integers
    e.g., 'SO/IPPROTO_IP/IP_TOS' --> 'SO/0/1'
    """
    so_str = so_str.upper()
    if not so_str.startswith(so_prefix + so_separator):
        return
    _, level, optname = so_str.split(so_separator)
    try:
        # get socket level
        if level.isdigit():
            sol_i = level
        else:
            sol_i = getattr(socket, level)
        if optname.isdigit():
            so_i = optname
        else:
            so_i = getattr(socket, optname)
    except AttributeError as e:
        logging.debug('Unknown socket option' + e.args[0])
        return -1

    return so_separator.join(('SO', str(sol_i), str(so_i)))
