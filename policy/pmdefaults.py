import logging
import os
import sys
import uuid

DEBUG = True
UTF = True if sys.stdout.encoding == 'UTF-8' else False

if DEBUG:
    log_level = logging.DEBUG
else:
    log_level = logging.INFO

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=log_level)

CLIENT_UID = str(uuid.uuid3(uuid.NAMESPACE_OID, str(uuid.getnode())))

# CIB expiration time in seconds
CIB_DEFAULT_TIMEOUT = 10 * 60

PIB_SOCK = os.environ['HOME'] + '/.neat/neat_pib_socket'
CIB_SOCK = os.environ['HOME'] + '/.neat/neat_cib_socket'
DOMAIN_SOCK = os.environ['HOME'] + '/.neat/neat_pm_socket'

PIB_DIR = 'pib/example/'
CIB_DIR = 'cib/example/'

# default policy property attributes
DEFAULT_SCORE = 0.0
DEFAULT_PRECEDENCE = 1
DEFAULT_EVALUATED = False

# Policy Manager REST API
REST_ENABLE = True
REST_IP = '0.0.0.0'
REST_PORT = 45888

# SDN controller northbound API address
CONTROLLER_REST = 'http://httpbin.org/post'
CONTROLLER_USER = 'admin'
CONTROLLER_PASS = 'admin'
CONTROLLER_ANNOUNCE = 3 * 60


class STYLES(object):
    DARK_GRAY_START = '\033[90m'
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
