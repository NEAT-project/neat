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
