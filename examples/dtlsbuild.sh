#!/bin/sh

# Generate keys:
# from: https://gist.github.com/denji/12b3a568f092ab951456
#
# server
# openssl ecparam -genkey -name secp384r1 -out server-key.pem   
# openssl req -new -x509 -sha256 -key server-key.pem -out server-cert.pem -days 3650      
#
# client
# openssl ecparam -genkey -name secp384r1 -out client-key.pem   
# openssl req -new -x509 -sha256 -key client-key.pem -out client-cert.pem -days 3650      

# build
cc -o dtlsecho dtls_udp_echo.c -lssl -lcrypto -lpthread

# run the server
# ./dtlsecho -V

# the client
# ./dtlsecho -V 127.0.0.1
