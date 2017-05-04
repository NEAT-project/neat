#!/bin/sh
cppcheck --xml-version=2 --force --std=c99 -i build --enable=all --xml . 2> cpp.xml
cppcheck-htmlreport --file=cpp.xml --report-dir=cppcheck --source-dir=.
rm cpp.xml
