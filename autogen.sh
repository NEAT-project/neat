#!/bin/sh -e

rm -f CMakeCache.txt
cmake -DCMAKE_INSTALL_PREFIX=/usr .

cores=`getconf _NPROCESSORS_ONLN`
make -j${cores}
