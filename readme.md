# tls.zig

Zig TLS library, characteristics:
* TLS 1.2 and TLS 1.3 client
* TLS 1.3 server
* handles client authentication
* tested with many domains, handles [badssl](https://badssl.com/dashboard/) urls 
* options to select client cipher sites to use, named groups, ...
* can configure Wireshark to show decrypted traffic
* same performance as standard library implementation
* can be used with standard library http client (with modified std lib copy)
<!--
* solved many [issues](https://github.com/ziglang/zig/issues/14172#issuecomment-2181202318) which I found in std 
-->

# Client

[Here](https://github.com/ianic/tls.zig/blob/main/demo/src/main.zig) is simple example of how to use library.   
To upgrade existing tcp connection to the tls connection call `tls.client`:
```zig
    // Establish tcp connection
    var tcp = try std.net.tcpConnectToHost(allocator, host, port);
    defer tcp.close();

    // Load system root certificates
    var root_ca: std.crypto.Certificate.Bundle = .{};
    try root_ca.rescan(allocator);
    defer root_ca.deinit(allocator);

    // Upgrade tcp connection to tls
    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
    });
```
After that you can use `conn` read/write methods as on plain tcp connection.

## Options

Second parameter in calling `tls.client` are [tls.ClientOptions](https://github.com/ianic/tls.zig/blob/main/src/handshake_client.zig#L28-L73) they can be used to force subset of implemented ciphers, set client authentication parameters, allow self insecure signed certificates, collect handshake diagnostics, exchange session keys with Wireshark to view decrypted traffic.

### Select cipher suite

To use just ciphers which are graded secure or recommended on  https://ciphersuite.info:
```zig
    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
        .cipher_suites = tls.cipher_suites.secure,
    });
```
`cipher_suites` can be used to force tls 1.3 only or tls 1.2 only ciphers. Or to reorder cipher preferences.


### Client authentication

If server requires client authentication set `authentication` attribute in options. You need to prepare certificate bundle with client certificates and client private key.

```zig
    // Load client certificate
    var certificates: Certificate.Bundle = .{};
    defer certificates.deinit(allocator);
    try certificates.addCertsFromFilePath(allocator, cert_dir, "cert.pem");
    // Load client private key
    const private_key_file = try cert_dir.openFile("key.pem", .{});
    defer private_key_file.close();
    const private_key = try tls.PrivateKey.fromFile(allocator, private_key_file);

    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
        .authentication = .{
            .certificates = certificates,
            .private_key = private_key,
        },
    });
```

When client receives certificate request from server during handshake it will respond with client certificates message build from provided certificate bundle and client certificate verify message where verify data is signed with client private key.

If authentication is not provided client will respond with empty certificate message when server requests authentication (as specified in RFC). 

### Logging tls session keys

Key logs can be written to file so that external programs can decrypt TLS connections. Wireshark can use these log files to decrypt packets. You can [tell](https://everything.curl.dev/usingcurl/tls/sslkeylogfile.html) Wireshark where to find the key file via Edit→Preferences→Protocols→SSL→(Pre)-Master-Secret log filename.

Key logging is enabled by setting the environment variable SSLKEYLOGFILE to point to a file. And enabling key log callback in client options:

```zig
    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
        .key_log_callback = tls.key_log.callback,
    });
```

# Server

Library has also minimal, tls 1.3 only server implementation. To upgrade tcp to tls connection:

```zig
    // Load server certificate
    var certificates: Certificate.Bundle = .{};
    defer certificates.deinit(allocator);
    try certificates.addCertsFromFilePath(allocator, dir, "localhost_ec/cert.pem");

    // Load server private key
    const private_key_file = try dir.openFile("localhost_ec/key.pem", .{});
    const private_key = try tls.PrivateKey.fromFile(allocator, private_key_file);
    private_key_file.close();
    
    // Tcp listener
    const port = 9443;
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{
        .reuse_address = true,
    });
    
     // Tcp accept
     const tcp = try server.accept();
     defer tcp.stream.close();

     // Upgrade tcp to tls
     var conn = try tls.server(tcp.stream, .{
         .authentication = .{
             .certificates = certificates,
             .private_key = private_key,
         },
     });
     
     // use conn
```


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


## Server and client example

Create local development certificates and keys:
```
$ cd example && ./cert.sh && cd -
```
This uses [minica](https://github.com/jsha/minica) tool. Go compiler and go install dir in the path are required.

Start server and connect to with client to the server.
```
$ zig build && zig-out/bin/server& ; sleep 1 && zig-out/bin/client ; kill %1
```

## Client authentication

After we have certificates created in previous example, here we will start Go tls server which requires client authentication and connect to that server with various different rsa and ec certificates using both tls 1.2 and 1.3. 
```
$ zig build ; cd example/go_tls_server; go run server.go & ; cd - ; sleep 1 && zig-out/bin/client_auth ; kill %1

```

Equivalent `curl` is:
```sh
curl https://localhost:8443 --cacert example/cert/minica.pem --cert example/cert/client_rsa/cert.pem --key example/cert/client_rsa/key.pem
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

# Performance comparison with standard library

Starting local server which will stream a text file (`src/main.zig` in this example) to the connected client:
```sh
$ zig build -Doptimize=ReleaseFast && zig-out/bin/server src/main.zig
```

Running 50 client request to that server by using this library and then by using standard library implementation and comparing them:

```sh
$ zig build -Doptimize=ReleaseFast && sudo ~/.local/bin/poop './zig-out/bin/client --cycles 50' 'zig-out/bin/client --cycles 50 --std'
Benchmark 1 (19 runs): ./zig-out/bin/client --cycles 50
  measurement          mean ± σ            min … max           outliers         delta
  wall_time           265ms ± 12.7ms     251ms …  294ms          0 ( 0%)        0%
  peak_rss            828KB ±  131KB     524KB … 1.05MB          0 ( 0%)        0%
  cpu_cycles          415M  ± 10.2M      376M  …  426M           1 ( 5%)        0%
  instructions       1.62G  ± 38.3M     1.48G  … 1.64G           1 ( 5%)        0%
  cache_references    375K  ±  183K     65.9K  …  563K           0 ( 0%)        0%
  cache_misses       9.55K  ± 2.21K     5.20K  … 14.1K           0 ( 0%)        0%
  branch_misses       187K  ± 38.3K      124K  …  228K           0 ( 0%)        0%
Benchmark 2 (19 runs): zig-out/bin/client --cycles 50 --std
  measurement          mean ± σ            min … max           outliers         delta
  wall_time           265ms ± 14.3ms     247ms …  296ms          0 ( 0%)          +  0.2% ±  3.4%
  peak_rss            786KB ±    0       786KB …  786KB          0 ( 0%)          -  5.0% ±  7.4%
  cpu_cycles          410M  ± 11.7M      364M  …  417M           1 ( 5%)          -  1.1% ±  1.8%
  instructions       1.61G  ± 51.8M     1.40G  … 1.64G           1 ( 5%)          -  1.0% ±  1.9%
  cache_references    340K  ±  150K     49.9K  …  487K           0 ( 0%)          -  9.4% ± 29.5%
  cache_misses       8.77K  ± 1.97K     5.42K  … 12.4K           0 ( 0%)          -  8.2% ± 14.5%
  branch_misses       189K  ± 38.2K      113K  …  232K           0 ( 0%)          +  1.4% ± 13.6%

```

# Tests

Tests are created using examples from [The Illustrated TLS 1.2 Connection](https://tls12.xargs.org/) and [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/). Those are really useful in understanding what each byte means. 

# Credits

 * @jedisct1 for [zig-cbc](https://github.com/jedisct1/zig-cbc) library. Copied to [src/cbc](/src/cbc) with padding changed from pkcs to tls.
 * @clickingbuttons for rsa package. Copied to [src/rsa](/src/rsa) from [branch](
https://github.com/clickingbuttons/zig/blob/f1cea91624fd2deae28bfb2414a4fd9c7e246883/lib/std/crypto/rsa.zig) of this [PR](
https://github.com/ziglang/zig/pull/19771)


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





zig-out/bin/http_get airable.io
airable.io
         tls version: tls_1_2
         cipher: none
         named group: none
         signature scheme: none
error: TlsAlertUnrecognizedName
/usr/local/zig/zig-linux-x86_64-0.14.0-dev.144+a31fe8aa3/lib/std/crypto/tls.zig:201:9: 0x1087d8e in toError (http_get)
        return switch (alert) {
        ^
/home/ianic/Code/tls.zig/src/record.zig:187:17: 0x1087bce in expectContentType (http_get)
                try desc.toError();
                ^
/home/ianic/Code/tls.zig/src/handshake_client.zig:325:17: 0x108d0b7 in readServerFlight1 (http_get)
                try d.expectContentType(.handshake);
                ^
/home/ianic/Code/tls.zig/src/handshake_client.zig:182:13: 0x10ebb3c in handshake (http_get)
            try h.readServerFlight1(opt); // server flight 1
            ^
/home/ianic/Code/tls.zig/src/main.zig:18:19: 0x10ec741 in client__anon_5656 (http_get)
    conn.cipher = try h.handshake(conn.stream, opt);
                  ^
/home/ianic/Code/tls.zig/example/common.zig:238:15: 0x10ed730 in get (http_get)
    var cli = try tls.client(tcp, opt);
              ^
/home/ianic/Code/tls.zig/example/http_get.zig:18:9: 0x10ef76f in main (http_get)
        try cmn.get(allocator, domain, null, true, true, .{
        ^

Ovaj salje warning alert, curl takodjer posalje da je dobio alert ali ide dalje. 
* TLSv1.3 (IN), TLS alert, unrecognized name (368):
-->


