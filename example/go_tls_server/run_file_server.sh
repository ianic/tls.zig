#!/bin/bash

# download war and peace from project gutenberg
if [[ ! -f pg2600.txt  ]]; then
  wget https://www.gutenberg.org/cache/epub/2600/pg2600.txt
fi

# start server
go run file_server.go

# you can test server response with:
# echo "request" | openssl s_client -connect localhost:8443 -ign_eof
