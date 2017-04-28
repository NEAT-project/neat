#!/bin/sh -e

rm -f CMakeCache.txt
cmake -DCMAKE_INSTALL_PREFIX=/usr -DUSRSCTP_SUPPORT=1 -DSCTP_MULTISTREAMING=1 -DFLOW_GROUPS=1 .

cores=`getconf _NPROCESSORS_ONLN`
make -j${cores}
