#!/usr/bin/env python

import sys
from distutils.core import setup

if sys.version_info < (3, 5):
    sys.exit("Python 3.5 is required")

setup(name='neatpmd',
      version='0.1',
      description='NEAT Policy Manager Daemon',
      author='Zdravko Bozakov',
      author_email='zdravko@bozakov.de',
      url='https://github.com/NEAT-project/neat/tree/master/policy/',
      scripts=['neatpmd'],
      py_modules=['policy', 'cib', 'pib', 'pmdefaults', 'pmhelper', 'resthelper', 'pmrest'],
      )
