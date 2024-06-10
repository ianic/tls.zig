

### Notes

Decrypt curl TLS messages in Wireshark: https://daniel.haxx.se/blog/2018/01/15/inspect-curls-tls-traffic/

View certificate for the site: 
`openssl s_client -connect google.com:443 -tls1_2`

List supported ciphers: 
`nmap --script ssl-enum-ciphers -p 443 google.com`

reference: https://serverfault.com/questions/638691/how-can-i-verify-if-tls-1-2-is-supported-on-a-remote-web-server-from-the-rhel-ce


top 500 sites JSON: https://github.com/Kikobeats/top-sites/blob/master/top-sites.json

rfc: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3

illustrated examples: https://tls12.xargs.org/#client-key-exchange

code from the book: https://github.com/yhyuan/Implementing-SSL-TLS-Using-Cryptography-and-PKI/blob/74c213606ff391e4f0b06447155259b4a37b632d/after/ch09/tls.c#L1180


Lengthy SO post: https://security.stackexchange.com/questions/20803/how-does-ssl-tls-work

Curl use tls1.2 and specific cipher:
`curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://github.com`

list of ciphers is here:  https://github.com/curl/curl/blob/cf337d851ae0120ec5ed801ad7eb128561bd8cf6/lib/vtls/sectransp.c#L729


ChaCha in tls 1.2 has different iv:
https://datatracker.ietf.org/doc/rfc7905/
