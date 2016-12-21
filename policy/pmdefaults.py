import logging
import os

DEBUG = True

logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.DEBUG)

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
LOCAL_IP = '0.0.0.0'
REST_PORT = 45888

# SDN controller northbound API address
CONTROLLER_REST = 'http://httpbin.org/post'
CONTROLLER_ANNOUNCE = 3 * 60


class STYLE(object):
    DARK_GRAY_START = '\033[90m'
    BOLD_START = '\033[1m'
    BOLD_END = '\033[21m'
    UNDERLINE_START = '\033[4m'
    UNDERLINE_END = '\033[24m'
    STRIKETHROUGH_START = '\033[9m'
    FORMAT_END = '\033[0m'
