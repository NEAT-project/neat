#! /usr/bin/env bash

if [ -n "$VERBOSE" ]; then
    ( ../examples/server_echo -P "" ) &
    SERVER_PID=$!
else
    ( ../examples/server_echo -P "" 2>/dev/null > /dev/null) &
    SERVER_PID=$!
fi

echo "Starting NEAT server..."

sleep 3

echo "Running tests..."

./test_echo
res=$?

kill -9 $SERVER_PID

if [ $res -ne 0 ]; then
    echo "TEST FAILED"
    exit -1
else
    echo "SUCCESS"
    exit 0
fi

