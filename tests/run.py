#!/usr/bin/env python3
import subprocess
import sys
import os

# usage: python3.5 run.py [test-set] [prefix]

prefix      = ""
workdir     = "../examples/"
timeout     = 60

# Test syntax ([expected return value], [test status: 0-not executed yet / 1-passed / 2-failed])

# General tests
tests_general = []
tests_general.append([0, 0, workdir + 'client_http_get -u /cgi-bin/he -v 2 bsd10.nplab.de'])
tests_general.append([0, 0, workdir + 'client_http_get -u /cgi-bin/he -v 2 212.201.121.100'])
tests_general.append([0, 0, workdir + 'client_http_get -u /cgi-bin/he -v 2 2a02:c6a0:4015:10::100'])
tests_general.append([1, 0, workdir + 'client_http_get -u /cgi-bin/he -v 2 not.resolvable.neat'])
tests_general.append([1, 0, workdir + 'client_http_get -u /cgi-bin/he -v 2 buildbot.nplab.de'])
#tests_general.append([0, 0, workdir + 'client_http_run_once -u /cgi-bin/he bsd10.nplab.de'])
#tests_general.append([0, 0, 'python3.5 ../../policy/pmtests.py'])

# USRSCTP specific tests
tests_usrsctp = []
tests_usrsctp.append([0, 0, workdir + 'client_http_get -u /cgi-bin/he -v 2 -P ' + workdir + 'prop_sctp.json  bsd10.nplab.de'])

# Default values
tests       = tests_general

# For PM tests
os.environ['PYTHONIOENCODING'] = 'utf-8'

# First argument: chose between tests
if len(sys.argv) > 1 :
    if sys.argv[1] == "general" :
        tests = tests_general
    elif sys.argv[1] == "usrsctp" :
        tests = tests_usrsctp
    else:
        print("WARN: Unknown testsuite, using default")
        tests = tests_general

# Second argument: command prefix (e.g. valgrind)
if len(sys.argv) > 2 :
    prefix = sys.argv[2]

print("prefix : " + prefix)
print("Starting tests...")

result_global = 0

# Iteratre through tests
for test in tests:
    result = 0
    print("\n\n############################### TEST")
    print("Runnning: " + test[2])
    try:
        result = subprocess.call(prefix + test[2], shell=True, timeout=40)
        if result != test[0]:
            print("Test failed: program returned with error")
            test[1] = 2
            break
    except subprocess.TimeoutExpired:
        print("Test failed: timeout")
        test[1] = 2
        break
    except:
        print("Something went wrong")
        test[1] = 2
        break

    # test succeeded
    test[1] = 1

print("\n\n###############################")
print("Tests finished - summary")
for test in tests:
    if test[1] == 1:
        print("PASSED   --  " + test[2])
    elif test[1] == 2:
        print("FAILED   --  " + test[2])
        result_global = 2
    else:
        print("SKIPPED  --  " + test[2])
        result_global = 2

if result_global > 0:
    sys.exit(-1)
else:
    sys.exit(0)
