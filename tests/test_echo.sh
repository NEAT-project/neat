#!/bin/sh

# TODO: Not running with $PREFIX here.
# server_echo should capture a signal and stop the event loop
# to allow for graceful shutdown.
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
    exit 1
else

    # run the tests
    echo "Starting tests..."
    ./test_echo
    res=$?
    echo "Tests finished"

    # graceful kill for server process and wait for output
    kill -TERM $SERVER_PID
    sleep 3
    # kill it with fire...
    kill -KILL $SERVER_PID

    if [ $res -ne 0 ]; then
        echo "FAILED"
        exit 1
    else
        echo "SUCCESS"
        exit 0
    fi
fi

