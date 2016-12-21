#!/usr/bin/env python3.5
import argparse
import asyncio
import logging
import os
import signal
from copy import deepcopy
from operator import attrgetter

import pmconst as PM
import pmrest
import policy
from cib import CIB
from pib import PIB
from policy import PropertyMultiArray

parser = argparse.ArgumentParser(description='NEAT Policy Manager')
parser.add_argument('--cib', type=str, default=PM.CIB_DIR, help='specify directory in which to look for CIB files')
parser.add_argument('--pib', type=str, default=PM.PIB_DIR, help='specify directory in which to look for PIB files')
parser.add_argument('--sock', type=str, default=PM.DOMAIN_SOCK, help='set Unix domain socket')
parser.add_argument('--controller', type=str, default=PM.CONTROLLER_REST, help='set controller REST API')
parser.add_argument('--debug', type=bool, default=PM.DEBUG, help='enable debugging')

parser.add_argument('--rest', type=bool, default=True, help='enable REST API')

parser.add_argument('--bypass', type=bool, default=False, help='enable debugging')

args = parser.parse_args()

try:
    os.makedirs(os.path.dirname(PM.DOMAIN_SOCK), exist_ok=True)
    os.makedirs(os.path.dirname(PM.PIB_SOCK), exist_ok=True)
    os.makedirs(os.path.dirname(PM.CIB_SOCK), exist_ok=True)
except OSError as e:
    print(e)
    raise SystemExit()

# unlink sockets if they already exist
try:
    if os.path.exists(PM.DOMAIN_SOCK):
        os.unlink(PM.DOMAIN_SOCK)
    if os.path.exists(PM.PIB_SOCK):
        os.unlink(PM.PIB_SOCK)
    if os.path.exists(PM.CIB_SOCK):
        os.unlink(PM.CIB_SOCK)
except OSError as e:
    print("here")
    print(e)
    raise SystemExit()


def process_special_properties(r):
    if 'local_endpoint' in r:
        # the local_endpoint property has the format a.b.c.d@eth0 so we need to split it
        local_endpoint = r.get('local_endpoint')
        ip, eth = local_endpoint.value.split('@')

        # create two new NEATProperties for the ip and interfaces
        local_ip = deepcopy(local_endpoint)
        local_ip.key = 'local_ip'
        local_ip.value = ip
        r.add(local_ip)

        interface = deepcopy(local_endpoint)
        interface.key = 'interface'
        interface.value = eth
        r.add(interface)

        del r['local_endpoint']

    # add some default properties
    if 'transport' not in r:
        p = policy.NEATProperty(('transport', 'unknown'), precedence=policy.NEATProperty.OPTIONAL, score=0.0)
        r.add(p)

    # add hook to trigger default policy profile
    p = policy.NEATProperty(('default_profile', True), precedence=policy.NEATProperty.OPTIONAL, score=0.0)
    r.add(p)


def cleanup_special_properties(r):
    if 'default_profile' in r:
        del r['default_profile']
    if 'uid' in r:
        del r['uid']


def process_request(json_str, num_candidates=10):
    """Process JSON requests from NEAT logic"""
    logging.debug(json_str)

    # list which will hold all requests
    requests = []
    try:
        properties_list = policy.json_to_properties(json_str)
    except policy.InvalidPropertyError:
        return

    try:
        for request in properties_list:
            # we create a PropertyMultiArray first and then expand it to get a list of PropertyArrays
            # with all permutations of requested properties
            pma = PropertyMultiArray()
            for p in request:
                pma.add(p)
            requests.extend(pma.expand())


    except policy.NEATPropertyError as e:
        print(e)
        return

    # local_endpoint handling
    # let's try to avoid any other special handling of properties!
    for r in requests:
        process_special_properties(r)

    print('Received %d NEAT requests' % len(requests))
    # for i, request in enumerate(requests):
    #    print("%d: " % i, request)

    candidates = []

    # main lookup sequence
    for i, request in enumerate(requests):
        print(policy.term_separator("processing request %d/%d" % (i + 1, len(requests)), offset=0, line_char='─'))
        logging.info("    %s" % request)

        print('Profile lookup...')
        updated_requests = profiles.lookup(request, tag='(profile)')
        for ur in updated_requests:
            logging.debug("updated request %s" % (ur))

        cib_candidates = []
        print('CIB lookup...')
        for ur in updated_requests:
            for c in cib.lookup(ur):
                if c in cib_candidates: continue
                cib_candidates.append(c)

        cib_candidates.sort(key=attrgetter('score'), reverse=True)
        print('    CIB lookup returned %d candidates:' % len(cib_candidates))
        for c in cib_candidates:
            logging.debug('   %s %.1f %.1f' % (c, *c.score))

        print('PIB lookup...')
        for j, candidate in enumerate(cib_candidates):
            cand_id = 'CIB candidate %s' % (j + 1)
            for c in pib.lookup(candidate, tag=cand_id):
                if c in candidates: continue
                candidates.append(c)
                logging.debug(c)

    candidates.sort(key=attrgetter('score'), reverse=True)
    top_candidates = candidates[:num_candidates]

    for candidate in top_candidates:
        cleanup_special_properties(candidate)

    # print candidates before returning
    logging.info("%d candidates generated in total." % (len(candidates)))
    print(policy.term_separator('Top %d' % num_candidates))
    for candidate in top_candidates:
        print(candidate, candidate.score, candidate.meta.get('cib_uids'))
    # TODO check if candidates contain the minimum src/dst/transport tuple
    print(policy.term_separator())

    return top_candidates


class PIBProtocol(asyncio.Protocol):
    """

    test using
       socat -d -d -d  FILE:test.pib UNIX-CONNECT:$HOME/.neat/neat_pib_socket
    """

    def __init__(self):
        self.slim = ''
        self.transport = None

    def connection_made(self, transport):
        peername = transport.get_extra_info('sockname')
        self.transport = transport

    def data_received(self, data):
        self.slim += data.decode()

    def eof_received(self):
        logging.info("New PIB object received (%dB)." % len(self.slim))
        pib.import_json(self.slim)
        self.transport.close()


class CIBProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.slim = ''

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.slim += data.decode()

    def eof_received(self):
        logging.info("New CIB object received (%dB)" % len(self.slim))
        cib.import_json(self.slim)
        self.transport.close()


class PMProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.request = ''

    def data_received(self, data):
        message = data.decode()
        self.request += message

    def eof_received(self):
        logging.info("New JSON request received (%dB)" % len(self.request))
        # TODO remove for production
        # for debugging neat core skip all calls to CIB/PIB
        if args.bypass:
            data = self.request.strip().encode(encoding='utf-8')
            self.transport.write(data)
            self.transport.close()
            return
        else:
            candidates = process_request(self.request.strip())

        # create JSON string for NEAT logic reply
        try:
            j = [policy.properties_to_json(c) for c in candidates]
            candidates_json = '[' + ', '.join(j) + ']\n'
        except TypeError:
            return

        data = candidates_json.encode(encoding='utf-8')

        self.transport.write(data)
        self.transport.close()


def signal_handler():
    print()
    print(policy.term_separator('ENTERING INTERACTIVE DEBUG MODE', line_char='#'))
    print()
    import code
    code.interact(local=globals(), banner='use Ctrl-D to exit')
    print()
    print(policy.term_separator('EXITING INTERACTIVE DEBUG MODE', line_char='#'))
    print()


def no_loop_test():
    """
    Dummy JSON request for testing
    """
    # test_request_str = '{"remote_ip": {"precedence": 2, "value": "10:54:1.23"}, "transport": [{"value": "TCP", "banned": ["UDP", "UDPLite"]}, {"value": "UDP"}], "MTU": {"value": [1500, 9000]}, "low_latency": {"precedence": 2, "value": true}, "foo": {"banned": ["baz"]}}'

    test_request_str = '{"remote_ip": {"value": "192.168.113.24", "precedence": 2}, "transport": {"value": "reliable", "precedence": 2}}'

    # SDN
    test_request_str = '{"remote_ip": {"value": "203.0.113.23", "precedence": 2}, "transport": {"value": "reliable", "precedence": 2}, "remote_port": {"value": 80}}'
    process_request(test_request_str)

    import code
    code.interact(local=locals(), banner='debug')


if __name__ == "__main__":
    logging.debug("PIB directory is %s" % PM.PIB_DIR)
    logging.debug("CIB directory is %s" % PM.CIB_DIR)

    cib = CIB(PM.CIB_DIR)
    profiles = PIB(PM.PIB_DIR, file_extension='.profile')
    pib = PIB(PM.PIB_DIR, file_extension='.policy')

    loop = asyncio.get_event_loop()

    # Each client connection creates a new protocol instance
    coro = loop.create_unix_server(PMProtocol, PM.DOMAIN_SOCK)
    server = loop.run_until_complete(coro)

    coro_pib = loop.create_unix_server(PIBProtocol, PM.PIB_SOCK)
    pib_server = loop.run_until_complete(coro_pib)

    coro_cib = loop.create_unix_server(CIBProtocol, PM.CIB_SOCK)
    cib_server = loop.run_until_complete(coro_cib)

    # interactive debug mode
    logging.debug('Use Ctrl-\\ to enter interactive debug mode.')
    loop.add_signal_handler(signal.SIGQUIT, signal_handler)

    # try to start the PM REST interface
    pmrest.init_rest_server(loop, profiles, cib, pib, rest_port=PM.REST_PORT)

    print('Waiting for PM requests on {} ...'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nQuitting policy manager.")
        pass
    # TODO implement http://aiohttp.readthedocs.io/en/stable/web.html#graceful-shutdown

    # Close the server
    server.close()
    pib_server.close()
    cib_server.close()
    pmrest.close()

    loop.run_until_complete(server.wait_closed())
    loop.close()
    raise SystemExit(0)
