#!/bin/bash

retcode=1
cmdprefix=""

if [ $# -eq 1 ]; then
	cmdprefix=$1
	echo "Running tests with prefix: $cmdprefix"
fi

function runtest {
	echo "##################################"
	echo "$@"
	echo ""
	$cmdprefix "$@"
	local status=$?
	if [ $status -ne $retcode ]; then
		echo "TEST FAILED!" >&2
		echo "$@" >&2
		exit 1
	fi
	echo ""
}

# Tests which should succeed
retcode=0
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "1" "interop.nplab.de"
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "1" "212.201.121.80"
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "1" "2a02:c6a0:4015:11::80"
runtest "../examples/client_http_get" "-u" "/files/32M" "-v" "1" "interop.nplab.de"
runtest "../examples/tneat" "-L"
runtest "../examples/tneat" "-L" "-P" "../examples/prop_tcp_delayed.json"

# Tests which should fail
retcode=1
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "1" "buildbot.nplab.de"
runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "1" "not.resolvable.neat"

# Platform specific tests
unamestr=`uname`

if [ "$unamestr" == "Linux" ] || [ "$unamestr" == "FreeBSD" ]; then
	retcode=0
	runtest "../examples/client_http_get" "-P" "../examples/prop_tcp_security.json" "-p" "443" "-v" "1" "www.fh-muenster.de"
	runtest "../examples/tneat" "-L" "-P" "../examples/prop_sctp_delayed.json"
	runtest "../examples/client_http_get" "-P" "../examples/prop_sctp.json" "-u" "/files/32M" "-v" "1" "interop.nplab.de"
fi

if [ "$unamestr" == "FreeBSD" ]; then
	retcode=0
	runtest "../examples/tneat" "-P" "../examples/prop_sctp_dtls.json" "interop.fh-muenster.de"
fi

if [ "$unamestr" == "Darwin" ]; then
	retcode=0
	#runtest "../examples/client_http_get" "-u" "/cgi-bin/he" "-v" "2" "bsd10.nplab.de"
fi
