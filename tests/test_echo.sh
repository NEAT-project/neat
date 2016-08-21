#!/bin/sh

# determine script directory
DIR=$(dirname "$0")

# run server and use first script argument as prefix - e.g. "valgrind"
($1 $DIR/../examples/server_echo -P "") &
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

# run the tests
echo "Starting tests..."
$1 $DIR/test_echo
res=$?
echo "Tests finished"

# graceful kill for server process and wait for output
kill -TERM $SERVER_PID
sleep 2
# kill it with fire...
kill -KILL $SERVER_PID

if [ $res -ne 0 ]; then
    echo "FAILED"
    exit -1
else
    echo "SUCCESS"
    exit 0
fi
