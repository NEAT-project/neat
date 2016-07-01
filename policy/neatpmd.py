#!/usr/bin/env python3

import atexit
import logging
import os
import stat
import time

from operator import attrgetter

from cib import CIB
from policy import PIB, NEATProperty, NEATPolicy, NEATRequest

FIFO_IN = 'pm_json.in'
FIFO_OUT = 'pm_json.out'


@atexit.register
def fifo_cleanup():
    try:
        pass
        # os.unlink(FIFO_IN)
        # os.unlink(FIFO_OUT)
    except Exception as e:
        pass


def process_request(json_str):
    """Process JSON requests from NEAT logic"""
    logging.debug(json_str)

    request = NEATRequest()
    request.properties.insert_json(json_str)
    print('received NEAT request: %s' % str(request.properties))

    # main lookup sequence
    profiles._lookup(request.properties, remove_matched=True, apply=True)
    cib.lookup(request)
    pib.lookup_all(request.candidates)

    request.candidates.sort(key=attrgetter('score'), reverse=True)
    candidates_json = '[' + ', '.join([candidate.properties.json() for candidate in request.candidates]) + ']'

    request.dump()
    logging.info("JSON candidates piped to %s" % FIFO_OUT)

    api_writer(candidates_json)


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
                logging.info("JSON request received in %s" % FIFO_IN)
                process_request(r)


def api_writer(out_str):
    with open(FIFO_OUT, 'w') as fifo:
        fifo.write(out_str)
        print('written')


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
