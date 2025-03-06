#!/bin/bash -e

rm -rf cert
mkdir -p cert
cd cert

git clone https://github.com/jsha/minica.git
cd minica
go install
cd ..

# server certificates, rsa and ec
minica -ca-alg rsa   -domains localhost
mv localhost localhost_rsa
minica -ca-alg ecdsa -domains localhost
mv localhost localhost_ec

# client certificates, rsa and ec
minica -ca-alg rsa   -domains client
mv client client_rsa
minica -ca-alg ecdsa -domains client
mv client client_ec

# generate more rsa client certificates
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

# generate more ec client certificates
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

# download war and peace, larger text file used in tests
if [[ -z "${GITHUB_ACTION}" && ! -f pg2600.txt  ]]; then
  wget https://www.gutenberg.org/cache/epub/2600/pg2600.txt
fi

head -c 10M </dev/urandom >random
ls -al
