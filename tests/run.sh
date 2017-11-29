#!/bin/bash
set -e


declare -a arr=("../examples/client_http_get -u /cgi-bin/he -v 2 bsd10.nplab.de"
                "../examples/client_http_get -u /cgi-bin/he -v 2 212.201.121.100"
                "../examples/client_http_get -u /cgi-bin/he -v 2 2a02:c6a0:4015:10::100"
                "../examples/client_http_get -u /cgi-bin/he -v 2 buildbot.nplab.de"
                "../examples/client_http_get -u /cgi-bin/he -v 2 not.resolvable.neat")

## now loop through the above array
for i in "${arr[@]}"
do
    echo "############################"
    echo "$i"
    echo ""
    $i
    echo ""
    echo ""
done
