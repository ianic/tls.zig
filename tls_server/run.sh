#!/bin/bash

# generate certificates
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
  -keyout server.key \
  -out server.crt \
  -days 365 \
  -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost"


# download war and peace from project gutenberg
if [[ ! -f pg2600.txt  ]]; then
  wget https://www.gutenberg.org/cache/epub/2600/pg2600.txt
fi

# start server
go run server.go

# you can test server response with:
# echo "request" | openssl s_client -connect localhost:8443 -ign_eof
