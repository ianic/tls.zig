#!/bin/bash -e

rm -rf cert
mkdir -p cert
cd cert

git clone https://github.com/jsha/minica.git
cd minica
go install
cd ..

minica -ca-alg rsa   -domains localhost
mv localhost localhost_rsa
minica -ca-alg ecdsa -domains localhost
mv localhost localhost_ec

minica -ca-alg rsa   -domains client
mv client client_rsa
minica -ca-alg ecdsa -domains client
mv client client_ec


for bits in 2048 3072 4096
do
    echo "create rsa key $bits bits"
    openssl genrsa -out key.pem $bits
    openssl req -new -key key.pem -out cert.csr \
        -subj "/C=HR/ST=Croatia/L=Zagreb/O=home/CN=localhost"
    openssl x509 -req -in cert.csr -out cert.pem -days 365 \
        -CA minica.pem \
        -CAkey minica-key.pem \
        -CAcreateserial 2> /dev/null
    rm cert.csr
    mkdir -p client_rsa_$bits
    mv key.pem cert.pem client_rsa_$bits
done

for alg in prime256v1 secp384r1 secp521r1
do
    echo "create ec $alg "
    openssl ecparam -name $alg -genkey -noout -out key.pem
    openssl req -new -key key.pem -out cert.csr \
        -subj "/C=HR/ST=Croatia/L=Zagreb/O=home/CN=localhost"
    openssl x509 -req -in cert.csr -out cert.pem -days 365 \
        -CA minica.pem \
        -CAkey minica-key.pem \
        -CAcreateserial 2> /dev/null
    rm cert.csr
    mkdir -p client_ec_$alg
    mv key.pem cert.pem client_ec_$alg/
done
