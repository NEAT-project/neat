#!/bin/bash

retcode=1
cmdprefix=""

if [ $# -eq 1 ]; then
    cmdprefix=$1
    echo "No arguments supplied"
fi

function runtest {
    $cmdprefix "$@"
    local status=$?
    if [ $status -ne $retcode ]; then
        echo "TEST FAILED!" >&2
        echo "$@" >&2
        exit 0
    fi
    return $status
}

retcode=0
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "2" "bsd10.nplab.de"
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "2" "212.201.121.100"
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "2" "2a02:c6a0:4015:10::100"

retcode=1
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "2" "buildbot.nplab.de"
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "2" "not.resolvable.neat"

unamestr=`uname`
if [ "$unamestr" == "Linux" ] || [ "$unamestr" == "FreeBSD" ]; then
    retcode=0
    runtest "../examples/client_http_get" "-P" "../examples/prop_tcp_security.json" "-p" "443" "-v" "2" "www.fh-muenster.de"
    runtest "../examples/tneat" "-v" "2" "-P" "../examples/prop_sctp_dtls.json" "interop.fh-muenster.de"
    runtest "../examples/tneat" "-v" "2" "-L" "-n" "1024" "-P" "../examples/prop_sctp.json"
fi
