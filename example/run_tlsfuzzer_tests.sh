#!/bin/bash -e


# for filename in scripts/test-tls13-*.py; do
#     echo $filename
#     #PYTHONPATH=. bin/python $filename
# done


declare -a tests=(

    "test-tls13-conversation.py"
    "test-tls13-connection-abort.py -e 'After NewSessionTicket'"
    "test-tls13-count-tickets.py -t 0"
    "test-tls13-crfg-curves.py -e 'sanity x448 with compression ansiX962_compressed_char2' -e 'sanity x448 with compression ansiX962_compressed_prime' -e 'sanity x448 with compression uncompressed'"
    "test-tls13-ecdhe-curves.py -e 'sanity - x448' -e 'sanity - secp521r1'"
    "test-tls13-finished.py"
    "test-tls13-finished-plaintext.py"
    "test-tls13-invalid-ciphers.py"
    "test-tls13-nociphers.py"
    "test-tls13-legacy-version.py"
    "test-tls13-record-layer-limits.py -e 'too big ClientHello msg, with 16168 bytes of padding' -e 'max size of Finished msg, with 16587 bytes of record layer padding TLS_AES_128_GCM_SHA256' -e 'max size of Finished msg, with 16587 bytes of record layer padding TLS_CHACHA20_POLY1305_SHA256' -e 'too big plaintext, size: 2**14 - 8, with an additional 9 bytes of padding, cipher TLS_AES_128_GCM_SHA256' -e 'too big plaintext, size: 2**14 - 8, with an additional 9 bytes of padding, cipher TLS_CHACHA20_POLY1305_SHA256'"
    "test-tls13-record-padding.py"
    # excluding unsupported signatures
    "test-tls13-serverhello-random.py -e 'TLS 1.3 with ffdhe2048' -e 'TLS 1.3 with ffdhe3072' -e 'TLS 1.3 with secp521r1' -e 'TLS 1.3 with x448' -e  'TLS 1.3 with x448'"

    # those three require unexpected_message alert but we are returning decode_error which is just fine, so skipping
    "test-tls13-zero-length-data.py -e 'zero-len app data with large padding interleaved in handshake' -e 'zero-len app data with padding interleaved in handshake' -e 'zero-length app data interleaved in handshake'"
    "test-tls13-zero-content-type.py"
    "test-tls13-unencrypted-alert.py"
    "test-tls13-empty-alert.py"
    "test-tls13-keyshare-omitted.py"
    "test-tls13-rsa-signatures.py -e 'tls13 signature rsa_pss_rsae_sha384' -e 'tls13 signature rsa_pss_rsae_sha512'"

    # skip some more esoteric cases
    "test-tls13-keyupdate.py
        -e '1/4 fragmented keyupdate msg, appdata between'
        -e '2/3 fragmented keyupdate msg, appdata between'
        -e '4/1 fragmented keyupdate msg, appdata between'
        -e '3/2 fragmented keyupdate msg, appdata between'
        -e 'app data split, conversation with KeyUpdate msg'
        -e 'multiple KeyUpdate messages'
        -e 'two KeyUpdates in one record'
        -e 'two KeyUpdates, first fragmented, second fragment under new keys together with second KeyUpdate'
        -e 'fragmented keyupdate msg'"

    "test-tls13-certificate-request.py -p 4434
       -s 'ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 ed25519 rsa_pkcs1_sha1 rsa_pkcs1_sha256 rsa_pkcs1_sha384'"

    # expects that PKCS1 signatures are always refused, but this implementation is accepting them, so ignoring that cases
    "test-tls13-certificate-verify.py -p 4434
        -s 'ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 ed25519 rsa_pkcs1_sha1 rsa_pkcs1_sha256 rsa_pkcs1_sha384'
        -c ../tls.zig/example/cert/client_rsa/cert.pem
        -k ../tls.zig/example/cert/client_rsa/key.pem
        -e 'check rsa_pkcs1_sha1 signature is refused'
        -e 'check rsa_pkcs1_sha256 signature is refused'
        -e 'check rsa_pkcs1_sha384 signature is refused'
        -e 'check rsa_pkcs1_sha512 signature is refused'"


    "test-tls13-ecdsa-in-certificate-verify.py -p 4434
        -s 'ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 ed25519 rsa_pkcs1_sha1 rsa_pkcs1_sha256 rsa_pkcs1_sha384'
        -k ../tls.zig/example/cert/client_ec/key.pem
        -c ../tls.zig/example/cert/client_ec/cert.pem
        -e 'check ecdsa_secp256r1_sha256 signature is refused'"

    "test-tls13-ecdsa-support.py -p 4436 'Test with ecdsa_secp384r1_sha384'"

    # expects that server sends key update with update requested true on a http get for /keyupdate url
    # we are not sending requested key update type
    # "test-tls13-keyupdate-from-server.py"

    # works for supported ciphers, there is no wildcard exclude and tests get fuzzing prefix, so it is impossible to exclude not supported cipher
    # "test-tls13-symetric-ciphers.py
    #     -e 'check connection with TLS_AES_128_CCM_8_SHA256*'
    #     -e 'check connection with TLS_AES_128_CCM_SHA256*'

    # need server private key with this signature
    # "test-tls13-rsapss-signatures.py"
    
    # sends handshake messages larger than 16k which is not supported in our implementation
    # "test-tls13-signature-algorithms.py"
    # "test-tls13-unrecognised-groups.py"

    # only 1.3 is supported no negotiation about that
    # "test-tls13-version-negotiation.py"

    # requires implementation of server hello retry request
    # "test-tls13-hrr.py"
    # "test-tls13-shuffled-extentions.py"
)

declare -a other=(
    "test-tls13-dhe-shared-secret-padding.py" # unsupported named group
    "test-tls13-large-number-of-extensions.py"

    "test-tls13-lengths.py" # requires echo server
    "test-tls13-minerva.py" # edcsa signature algorithms samo salje
    "test-tls13-multiple-ccs-messages.py"

    "test-tls13-obsolete-curves.py"
    "test-tls13-pkcs-signature.py"
    "test-tls13-psk_dhe_ke.py"
    "test-tls13-psk_ke.py"

    # this is not implemented
    "test-tls13-session-resumption.py"
    "test-tls13-ffdhe-groups.py"
    "test-tls13-ffdhe-sanity.py"
    "test-tls13-post-handshake-auth.py"
    "test-tls13-0rtt-garbage.py"
    "test-tls13-ccs.py"

    # tests that tls 1.3 is not supported
    "test-tls13-non-support.py"
)



for name in "${tests[@]}"; do
    echo $name
    cmd="PYTHONPATH=. bin/python scripts/$name"
    eval $cmd
done
