#!/usr/bin/env python3
import subprocess
import sys

# General tests
tests_general = []
tests_general.append([0, 'client_http_get -u /cgi-bin/he -v 2 bsd10.nplab.de'])
tests_general.append([0, 'client_http_get -u /cgi-bin/he -v 2 212.201.121.100'])
tests_general.append([0, 'client_http_get -u /cgi-bin/he -v 2 2a02:c6a0:4015:10::100'])
tests_general.append([1, 'client_http_get -u /cgi-bin/he -v 2 not.resolvable.neat'])
tests_general.append([1, 'client_http_get -u /cgi-bin/he -v 2 buildbot.nplab.de'])
tests_general.append([1, 'client_http_run_once -u /cgi-bin/he bsd10.nplab.de'])

# USRSCTP specific tests
tests_usrsctp = []
tests_usrsctp.append([0, 'client_http_get -u /cgi-bin/he -v 2 bsd10.nplab.de'])

# Default values
tests       = tests_general
prefix      = ""
workdir     = "../examples/"
timeout     = 60

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

# Iteratre through tests
for test in tests:
    test_return = 0
    print("Runnning: " + test[1])
    try:
        test_return = subprocess.call(workdir + test[1], shell=True, timeout=40)
        if test_return != 0:
            print("Test failed: program returned with error")
            sys.exit(-1)
    except subprocess.TimeoutExpired:
        print("Test failed: timeout")
        sys.exit(-1)
    except:
        print("Something went wrong")
        sys.exit(-1)

    print(test[1] + " >> returned " + str(test_return))


print("Tests finished")
sys.exit(0)
