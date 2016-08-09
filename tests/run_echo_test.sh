#!/bin/sh

( $1 ../examples/server_echo -P "") &
SERVER_PID=$!

echo "Starting NEAT server..."

# wait until server started
sleep 3

# check if the server process is runnning
kill -0 $!
res=$?
if [ $res -ne 0 ]; then
    echo "Server not running - exit"
    exit -1
fi


echo "Running tests..."

./test_echo
res=$?

# wait for valgrind
sleep 2

echo "Tests finished"

# graceful kill for server process
kill -TERM $SERVER_PID

if [ $res -ne 0 ]; then
    echo "TEST FAILED"
    exit -1
else
    echo "SUCCESS"
    exit 0
fi
