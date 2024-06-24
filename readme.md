# tls.zig

Zig library which implements tls 1.2 and tls 1.3 protocol.

[Here](https://github.com/ianic/tls.zig/blob/main/demo/src/main.zig) is simple example of how to use library.   
To upgrade existing tcp connection to the tls connection:
```zig
    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle, .{});
```
After that you can use `cli` read/write methods as on plain tcp connection.

## Options

Third parameter in calling handshake are [tls.Options](https://github.com/ianic/tls.zig/blob/8e06c80a86aa9b50546e652ed7241608113ac734/src/handshake.zig#L25-L45) they can be used to force subset of implemented ciphers. For example to use just ciphers which are graded secure or recommended on  https://ciphersuite.info:
```zig
    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle, .{.cipher_suites = &tls.CipherSuite.secure})
```
That can be used to force tls 1.3 only or tls 1.2 only ciphers. Or to reorder cipher preferences.

Stats can be used to inspect which cipher suite and other handshake parameters were chosen by the server:
```zig
    var cli = tls.client(tcp);
    var stats: tls.Stats = .{};
    try cli.handshake(host, ca_bundle, .{.stats = &stats})
    // inspect stats
```

### Client authentication

If server requires client authentication set `auth` attribute in options. You need to prepare certificate bundle with client certificates and client private key.

```zig
    // Load client certificate(s) and client private key
    var client_certificates: Certificate.Bundle = .{};
    try client_certificates.addCertsFromFilePath(gpa, dir, "client-rsa/cert.pem");
    const file = try dir.openFile("client-rsa/key.pem", .{});
    defer file.close();
    const client_private_key = try tls.PrivateKey.fromFile(gpa, file);

    // Handshake with client authentication
    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle, .{
        .auth = .{
            .certificates = client_certificates,
            .private_key = client_private_key,
        },
    });
```

When client receives certificate request from server during handshake it will respond with client certificates message build from provided certificate bundle and client certificate verify message where verify data is signed with client private key.

# Examples

## Top sites

Uses [list](https://github.com/Kikobeats/top-sites/blob/master/top-sites.json) of top 500 domains and pages on the web. , based on [Moz Top 500](https://moz.com/top500). Tries to establish https connection to each site. If the connection fails runs curl on the same domain, if curl can't connect it is count as error, if curl connect counts as fail.   

```
$ zig-out/bin/top_sites
stats:
         total: 500
         success: 483
         fail: 0
         error: 14
         skip: 3
```
Domains on which we fail to establish tls connection are also failing when using curl. Errors are: 7 UnknownHostName, 4 ConnectionRefused, 2 CertificateHostMismatch, 1 CertificateIssuerNotFound.
    
### top sites with std lib 

Tls implementation in Zig standard library is currently tls 1.3 only. Trying to connect to all top 500 domains gives:
```
$ zig-out/bin/std_top_sites
stats:
         total: 500
         success: 360
         fail: 120
         error: 12
         skip: 8
```

If we change standard library tls implementation to the one which uses this tls library we can connect to tls 1.2 sites also:
```
$ zig build --zig-lib-dir ../zig/lib 
$ zig-out/bin/std_top_sites
stats:
         total: 500
         success: 480
         fail: 5
         error: 12
         skip: 3
```

## badssl

Uses urls from [badssl.com](https://badssl.com/dashboard/) to test client implementation.

```
$ zig-out/bin/badssl 

Certificate Validation (High Risk)
If your browser connects to one of these sites, it could be very easy for an attacker to see and modify everything on web sites that you visit.
        ✅ expired.badssl.com error.CertificateExpired
        ✅ wrong.host.badssl.com error.CertificateHostMismatch
        ✅ self-signed.badssl.com error.CertificateIssuerNotFound
        ✅ untrusted-root.badssl.com error.CertificateIssuerNotFound

Interception Certificates (High Risk)
If your browser connects to one of these sites, it could be very easy for an attacker to see and modify everything on web sites that you visit. This may be due to interception software installed on your device.
        ✅ superfish.badssl.com error.CertificateIssuerNotFound
        ✅ edellroot.badssl.com error.CertificateIssuerNotFound
        ✅ dsdtestprovider.badssl.com error.CertificateIssuerNotFound
        ✅ preact-cli.badssl.com error.CertificateIssuerNotFound
        ✅ webpack-dev-server.badssl.com error.CertificateIssuerNotFound

Broken Cryptography (Medium Risk)
If your browser connects to one of these sites, an attacker with enough resources may be able to see and/or modify everything on web sites that you visit. This is because your browser supports connections settings that are outdated and known to have significant security flaws.
        ✅ rc4.badssl.com error.TlsAlertHandshakeFailure
        ✅ rc4-md5.badssl.com error.TlsAlertHandshakeFailure
        ✅ dh480.badssl.com error.TlsAlertHandshakeFailure
        ✅ dh512.badssl.com error.TlsAlertHandshakeFailure
        ✅ dh1024.badssl.com error.TlsAlertHandshakeFailure
        ✅ null.badssl.com error.TlsAlertHandshakeFailure

Legacy Cryptography (Moderate Risk)
If your browser connects to one of these sites, your web traffic is probably safe from attackers in the near future. However, your connections to some sites might not be using the strongest possible security. Your browser may use these settings in order to connect to some older sites.
        ✅ tls-v1-0.badssl.com error.TlsBadVersion
        ✅ tls-v1-1.badssl.com error.TlsBadVersion
        🆗 cbc.badssl.com
        ✅ 3des.badssl.com error.TlsAlertHandshakeFailure
        ✅ dh2048.badssl.com error.TlsAlertHandshakeFailure

Domain Security Policies
These are special tests for some specific browsers. These tests may be able to tell whether your browser uses advanced domain security policy mechanisms (HSTS, HPKP, SCT) to detect illegitimate certificates.
        🆗 revoked.badssl.com
        🆗 pinning-test.badssl.com
        ✅ no-sct.badssl.com error.CertificateIssuerNotFound

Secure (Uncommon)
These settings are secure. However, they are less common and even if your browser doesn't support them you probably won't have issues with most sites.
        🆗 1000-sans.badssl.com error.TlsUnsupportedFragmentedHandshakeMessage
        🆗 10000-sans.badssl.com error.TlsUnsupportedFragmentedHandshakeMessage
        🆗 sha384.badssl.com error.CertificateExpired
        🆗 sha512.badssl.com error.CertificateExpired
        🆗 rsa8192.badssl.com error.BufferOverflow
        🆗 no-subject.badssl.com error.CertificateExpired
        🆗 no-common-name.badssl.com error.CertificateExpired
        🆗 incomplete-chain.badssl.com error.CertificateIssuerNotFound

Secure (Common)
These settings are secure and commonly used by sites. Your browser will need to support most of these in order to connect to sites securely.
        ✅ tls-v1-2.badssl.com
        ✅ sha256.badssl.com
        ✅ rsa2048.badssl.com
        ✅ ecc256.badssl.com
        ✅ ecc384.badssl.com
        ✅ mozilla-modern.badssl.com
```



## All ciphers

Tries all supported ciphers on some domain. 
```
$ zig-out/bin/all_ciphers cloudflare.com
✔️ AES_128_GCM_SHA256 cloudflare.com
✔️ AES_256_GCM_SHA384 cloudflare.com
✔️ CHACHA20_POLY1305_SHA256 cloudflare.com
✔️ ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cloudflare.com
✔️ ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cloudflare.com
✔️ ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 cloudflare.com
✔️ ECDHE_RSA_WITH_AES_128_GCM_SHA256 cloudflare.com
✔️ ECDHE_RSA_WITH_AES_256_GCM_SHA384 cloudflare.com
✔️ ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 cloudflare.com
✔️ ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 cloudflare.com
✔️ ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 cloudflare.com
✔️ ECDHE_ECDSA_WITH_AES_128_CBC_SHA cloudflare.com
✔️ ECDHE_RSA_WITH_AES_128_CBC_SHA256 cloudflare.com
✔️ ECDHE_RSA_WITH_AES_256_CBC_SHA384 cloudflare.com
✔️ ECDHE_RSA_WITH_AES_128_CBC_SHA cloudflare.com
✔️ RSA_WITH_AES_128_CBC_SHA256 cloudflare.com
✔️ RSA_WITH_AES_128_CBC_SHA cloudflare.com
```
Using cloudflare.com as example because it supports all implemented ciphers.

## http get

This example will connect to the domain, show response and tls statistic. You
can change tls options to force tls version or specific cipher.

```
$ zig-out/bin/http_get google.com    
HTTP/1.0 301 Moved Permanently

832 bytes read

google.com
         tls version: tls_1_3
         cipher: AES_128_GCM_SHA256
         named group: x25519_kyber768d00
         signature scheme: ecdsa_secp256r1_sha256
```


## Client certificate example

Create local development certificates and keys:
```
$ cd example && ./cert.sh
```
This uses [minica](https://github.com/jsha/minica) tool. Go compiler and go install dir in the path are required.

Start server from go_tls_server folder:
```
 $ cd example/go_tls_server && go run server.go
```
That server requires client authentication.

```
$ zig-out/bin/tls_client
```

Tls client reads certificate from example/cert/client-rsa/cert.pem and key from example/cert/client-rsa/key.pem and uses them to authenticate to the server.

Equivalent curl is:
```sh
curl https://localhost:8443 --cacert example/cert/minica.pem --cert example/cert/client-rsa/cert.pem --key example/cert/client-rsa/key.pem
```

# Usage with standard library http.Client

This library is only tls protocol implementation. Standard library has great
http client. We can replace standard library tls implementation with this one
and get http client with both tls 1.2 and 1.3 capability.
[Here](https://github.com/ziglang/zig/compare/master...ianic:zig:tls23) are
required changes, assuming that this library is available at
`lib/std/crypt/tls23` path.

This script will checkout tls.zig library, an fork of the zig repository and
link tls.zig to the required path. After that we can point to that standard
library copy while building zig project with `--zig-lib-dir` switch.


```
git clone https://github.com/ianic/tls.zig        
git clone -b tls23 https://github.com/ianic/zig
ln -s $(pwd)/tls.zig/src zig/lib/std/crypto/tls23

cd tls.zig
zig build --zig-lib-dir ../zig/lib
zig-out/bin/std_top_sites 
```


# Tests

Tests are created using examples from [The Illustrated TLS 1.2 Connection](https://tls12.xargs.org/) and [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/). Those are really useful in understanding what each byte means. 

# Memory usage

[handshake](https://github.com/ianic/tls.zig/blob/53885147af325852a4c33c5975e99f5298241aa6/src/client.zig#L62) requires stable pointer to Client type. [Client](https://github.com/ianic/tls.zig/blob/53885147af325852a4c33c5975e99f5298241aa6/src/client.zig#L27) is comptime created over Stream type. From Stream type is required to implement classic read/write methods and ReaderError/WriterError error sets.  
Client uses two 16K buffers. One in record reader and another for writing output messages. When created over std.net.Stream it statically allocates 33544 bytes.




<!--
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


Script to rebase branch tls23 to master.

cd ~/Code/zig && zig-merge-upstream.sh && git checkout tls23 && git rebase master && git push -f
-->


