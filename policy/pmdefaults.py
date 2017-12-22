import logging
import os
import sys
import uuid

DEBUG = True
UTF = True if sys.stdout.encoding == 'UTF-8' else False

# enable caching of HE CIB entries
CIB_CACHE = True

logging.addLevelName(logging.INFO, 'INF')
logging.addLevelName(logging.ERROR, 'ERR')
logging.addLevelName(logging.DEBUG, 'DBG')
logging.addLevelName(logging.WARN, 'WRN')

logging.basicConfig(format='[%(levelname)s]: %(message)s')

CLIENT_UID = str(uuid.uuid3(uuid.NAMESPACE_OID, str(uuid.getnode())))

# CIB expiration time in seconds
CIB_DEFAULT_TIMEOUT = 10 * 60

SOCK_DIR = os.path.join(os.environ['HOME'], '.neat', '')
PIB_SOCK_NAME = 'neat_pib_socket'
CIB_SOCK_NAME = 'neat_cib_socket'
DOMAIN_SOCK_NAME = 'neat_pm_socket'


def update_log_level(level):
    if level == 0:
        log_level = logging.ERROR
    elif level == 3:
        log_level = logging.DEBUG
    elif level == 2:
        log_level = logging.INFO
    elif level == 1:
        log_level = logging.WARN
    else:
        log_level = logging.ERROR

    logging.getLogger().setLevel(log_level)


def update_sock_files():
    global PIB_SOCK, CIB_SOCK, DOMAIN_SOCK
    PIB_SOCK = os.path.join(SOCK_DIR, PIB_SOCK_NAME)
    CIB_SOCK = os.path.join(SOCK_DIR, CIB_SOCK_NAME)
    DOMAIN_SOCK = os.path.join(SOCK_DIR, DOMAIN_SOCK_NAME)


update_sock_files()

PIB_DIR = 'examples/pib/'
CIB_DIR = 'examples/cib/'

# default policy property attributes
DEFAULT_SCORE = 0.0
DEFAULT_PRECEDENCE = 1
DEFAULT_EVALUATED = False

# Policy Manager REST API
REST_ENABLE = True
REST_IP = '0.0.0.0'
REST_PORT = 45888

# SDN controller northbound API address
# use http://httpbin.org/post for testing
CONTROLLER_REST = ''
CONTROLLER_USER = 'admin'
CONTROLLER_PASS = 'admin'
CONTROLLER_ANNOUNCE = 3 * 60


class STYLES(object):
    DARK_GRAY_START = '\033[90m'
    LIGHT_GRAY_START = '\033[37m'
    BOLD_START = '\033[1m'
    BOLD_END = '\033[21m'
    UNDERLINE_START = '\033[4m'
    UNDERLINE_END = '\033[24m'
    STRIKETHROUGH_START = '\033[9m'
    FORMAT_END = '\033[0m'


class CHARS(object):
    RIGHT_ARROW = '⟶' if UTF else '>>'
    LINE_SEPARATOR = '═' if UTF else '='
    DASH = '─' if UTF else '-'
