#!/bin/sh

echo " Running NEAT tests"
echo "########################################"

PREFIX=$1
EXAMPLES_DIR="../examples"
RC_GLOBAL=0
ARG=""

##############

echo ""
echo "########################################"
ARG="$PREFIX$EXAMPLES_DIR/client_http_get -u /cgi-bin/he bsd10.nplab.de"
echo "Running: $ARG"
$ARG
RC=$?
if [ $RC -ne 0 ]; then
    RC_GLOBAL=1
    echo ">> test failed!"
else
    echo ">> test succeeded"
fi

##############

echo ""
echo "########################################"
ARG="$PREFIX$EXAMPLES_DIR/client_http_get -u /cgi-bin/he 212.201.121.100"
echo "Running: $ARG"
$ARG
RC=$?
if [ $RC -ne 0 ]; then
    RC_GLOBAL=1
    echo ">> test failed!"
else
    echo ">> test succeeded"
fi

##############

echo ""
echo "########################################"
ARG="$PREFIX$EXAMPLES_DIR/client_http_get -u /cgi-bin/he 2a02:c6a0:4015:10::100"
echo "Running: $ARG"
$ARG
RC=$?
if [ $RC -ne 0 ]; then
    RC_GLOBAL=1
    echo ">> test failed!"
else
    echo ">> test succeeded"
fi

##############

echo ""
echo "########################################"
ARG="$PREFIX$EXAMPLES_DIR/client_http_get -u /cgi-bin/he not.resolvable.neat"
echo "Running: $ARG"
$ARG
RC=$?
if [ $RC -ne 1 ]; then
    RC_GLOBAL=1
    echo ">> RC $RC - test failed!"
else
    echo ">> RC $RC - test succeeded"
fi

##############

# TODO: Not running with $PREFIX here.
# server_echo should capture a signal and stop the event loop
# to allow for graceful shutdown.
echo ""
echo "########################################"
ARG="$EXAMPLES_DIR/server_echo -P $EXAMPLES_DIR/all.json"
echo "Starting NEAT server..."
$ARG &
SERVER_PID=$!

# wait until server started
sleep 3

# check if the server process is runnning
kill -0 $SERVER_PID
res=$?
if [ $res -ne 0 ]; then
    echo "Server not running - exit"
    # exit 1
else

    # run the tests
    echo "Starting tests..."
    ./test_echo
    RC=$?
    echo "Tests finished"

    # graceful kill for server process and wait for output
    kill -TERM $SERVER_PID
    sleep 3
    # kill it with fire...
    kill -KILL $SERVER_PID

    if [ $RC -ne 0 ]; then
        echo ">> RC $RC - test failed!"
    else
        echo ">> RC $RC - test succeeded"
    fi
fi


##############

if [ ! -n "$PREFIX" ]; then
    echo ""
    echo "########################################"
    export PYTHONIOENCODING=utf-8
    ARG="python3.5 ../../policy/pmtests.py"
    echo "Running: $ARG"
    $ARG
    RC=$?
    if [ $RC -ne 0 ]; then
        RC_GLOBAL=1
        echo ">> RC $RC - test failed!"
    else
        echo ">> RC $RC - test succeeded"
    fi
fi

echo "########################################"
echo "All tests finished - RC $RC_GLOBAL"
echo "########################################"

exit $RC_GLOBAL
