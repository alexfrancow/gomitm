#!/bin/bash

mkdir cert
cd cert
openssl genrsa -out ca.key 2048
openssl req -new -key ca.key -out my_request.csr
openssl x509 -req -days 3650 -in my_request.csr -signkey ca.key -out cert.crt
openssl pkcs12 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -export -in cert.crt -inkey ca.key -out cert.pfx -name "$1"

