#!/bin/bash -e

rm -rf cert
mkdir -p cert
cd cert

git clone https://github.com/jsha/minica.git
cd minica
go install
cd ..

minica -ca-alg rsa   -domains localhost
# or: minica -ca-alg ecdsa -domains localhost
minica -ca-alg rsa   -domains client-rsa
minica -ca-alg ecdsa -domains client-ec
