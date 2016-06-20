#!/usr/bin/env python3

import atexit
import code
import logging
import os
import stat
import time

from operator import attrgetter

from cib import CIB
from policy import PIB, NEATProperty, NEATPolicy, NEATRequest


FIFO_IN = 'pm_json.in'
FIFO_OUT = 'pm_json.out'


def example():
    cib = CIB('cib/example/')
    pib = PIB()

    # ----- example from README.md -----
    property1 = NEATProperty(('remote_ip', '10.1.23.45'), precedence=NEATProperty.IMMUTABLE)

    request = NEATRequest()
    request.properties.insert(property1)
    request.properties.insert(NEATProperty(('MTU', (1500, float('inf')))))
    request.properties.insert(NEATProperty(('transport_TCP', True)))

    request.properties

    policy1 = NEATPolicy(name='Bulk transfer')
    policy1.match.insert(NEATProperty(('remote_ip', '10.1.23.45')))
    policy1.properties.insert(NEATProperty(('capacity', (10000, 100000)), precedence=NEATProperty.IMMUTABLE))
    policy1.properties.insert(NEATProperty(('MTU', 9600)))
    pib.register(policy1)

    policy2 = NEATPolicy(name='TCP options')
    policy2.match.insert(NEATProperty(('MTU', 9600)))
    policy2.match.insert(NEATProperty(('is_wired', True)))
    policy2.properties.insert(NEATProperty(('TCP_window_scale', True)))
    pib.register(policy2)

    # code.interact(local=locals(), banner='start')

    print("CIB lookup:")
    cib.lookup(request)
    request.dump()
    # code.interact(local=locals(), banner='CIB lookup done')

    print("PIB lookup:")
    pib.lookup_all(request.candidates)
    request.dump()

    for candidate in request.candidates:
        print(candidate.properties.json())
    code.interact(local=locals(), banner='PIB lookup done')


@atexit.register
def fifo_cleanup():
    try:
        pass
        # os.unlink(FIFO_IN)
        # os.unlink(FIFO_OUT)
    except Exception as e:
        pass


def process_request(json_str):
    logging.debug(json_str)
    request = NEATRequest()
    request.properties.insert_json(json_str)
    print('received NEAT request: %s' % str(request.properties))

    profiles._lookup(request.properties, remove_matched=True, apply=True)
    cib.lookup(request)
    pib.lookup_all(request.candidates)

    request.candidates.sort(key=attrgetter('score'), reverse=True)
    candidates_json = '[' + ', '.join([candidate.properties.json() for candidate in request.candidates]) + ']'

    print("===== CANDIDATES =====")
    print(candidates_json)
    api_writer(candidates_json.replace('NaN', '"NaN"'))


def api_reader():
    """Read requests from NEAT logic over a named pipe"""

    print("Waiting for JSON input in pipe %s..." % FIFO_IN)
    with open(FIFO_IN) as fifo:
        while True:
            line = fifo.readline()
            if not line:
                # FIXME use callback
                time.sleep(0.1)
                continue
            requests = line.splitlines()
            for r in requests:
                process_request(r)


def api_writer(out_str):
    with open(FIFO_OUT, 'w') as fifo:
        fifo.write(out_str)


def create_pipes():
    try:
        mode = os.stat(FIFO_IN).st_mode
        if not stat.S_ISFIFO(mode):
            print('File %s already exists and is not a named pipe!' % FIFO_IN)
            exit(1)
    except FileNotFoundError:
        os.mkfifo(FIFO_IN)
        logging.info('Creating named pipe %s' % FIFO_IN)

    try:
        mode = os.stat(FIFO_OUT).st_mode
        if not stat.S_ISFIFO(mode):
            print('File %s already exists and is not a named pipe!' % FIFO_OUT)
            exit(1)
    except FileNotFoundError:
        os.mkfifo(FIFO_OUT)
        logging.info('Creating named pipe %s' % FIFO_OUT)


if __name__ == "__main__":
    create_pipes()

    cib = CIB('cib/example/')
    profiles = PIB('pib/profiles/')
    pib = PIB('pib/examples/')

    api_reader()
    # test_request = '{"MTU": {"value": [1500, Infinity]}, "low_latency": {"precedence": 2, "value": true}, "remote_ip": {"precedence": 2, "value": "10.1.23.45"}, "transport_TCP": {"value": true}}'
    # process_request(test_request)
