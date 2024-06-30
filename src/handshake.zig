const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const tls = crypto.tls;

const Certificate = crypto.Certificate;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const Kyber768 = crypto.kem.kyber_d00.Kyber768;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const Sha512 = crypto.hash.sha2.Sha512;

const Cipher = @import("cipher.zig").Cipher;
const CipherSuite = @import("cipher.zig").CipherSuite;
const Transcript = @import("transcript.zig").Transcript;
const record = @import("record.zig");
const PrivateKey = @import("PrivateKey.zig");
const rsa = @import("rsa/rsa.zig");

pub const Options = struct {
    // To use just tls 1.3 cipher suites:
    //   .cipher_suites = &tls.CipherSuite.tls13,
    // To select particular cipher suite:
    //   .cipher_suites = &[_]tls.CipherSuite{tls.CipherSuite.CHACHA20_POLY1305_SHA256},
    cipher_suites: []const CipherSuite = &CipherSuite.all,

    // Some sites are not working when sending keyber public key: godaddy.com,
    // secureserver.net (both have "Server: ATS/9.2.3"). That key is making
    // hello message big ~1655 bytes instead of 360
    //
    // In Wireshark I got window update then tcp re-transmissions of 1440 bytes without ack.
    // After 17sec and 6 re-transmissions connection is broken.
    //
    // This flag disables sending long keyber public key making connection
    // possible to those sites.
    disable_keyber: bool = false,

    // Collect stats from handshake.
    stats: ?*Stats = null,

    // Client authentication
    auth: ?Auth = null,

    pub const Auth = struct {
        // Certificate chain to send to the server if server requests client authentication.
        certificates: Certificate.Bundle,
        // Private key of the first certificate in bundle.
        // Used for creating signature in certificate signature message.
        private_key: PrivateKey,
    };

    pub const Stats = struct {
        tls_version: tls.ProtocolVersion = @enumFromInt(0),
        cipher_suite_tag: CipherSuite = @enumFromInt(0),
        named_group: tls.NamedGroup = @enumFromInt(0),
        signature_scheme: tls.SignatureScheme = @enumFromInt(0),
        client_signature_scheme: tls.SignatureScheme = @enumFromInt(0),
    };
};

// tls.HandshakeType is missing server_key_exchange, server_hello_done
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

const CurveType = enum(u8) {
    named_curve = 0x03,
    _,
};

/// Handshake parses tls server message and creates client messages. Collects
/// tls attributes: server random, cipher suite and so on. Client messages are
/// created using provided buffer. Provided record reader is used to get tls
/// record when needed.
pub fn Handshake(comptime Stream: type) type {
    const RecordReaderT = record.Reader(Stream);
    return struct {
        client_random: [32]u8,
        server_random: [32]u8 = undefined,
        master_secret: [48]u8 = undefined,
        key_material: [48 * 4]u8 = undefined, // for sha256 32 * 4 is filled, for sha384 48 * 4

        transcript: Transcript = .{},
        cipher_suite_tag: CipherSuite = @enumFromInt(0),
        named_group: ?tls.NamedGroup = null,
        dh_kp: DhKeyPair,
        rsa_secret: RsaSecret,
        signature_scheme: tls.SignatureScheme = @enumFromInt(0),
        now_sec: i64 = 0,
        tls_version: tls.ProtocolVersion = .tls_1_2,
        cipher: Cipher = undefined,
        write_seq: u64 = 0,

        cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,
        cert_pub_key_buf: [600]u8 = undefined,
        cert_pub_key: []const u8 = undefined,
        // public key len: x25519 = 32, secp256r1 = 65, secp384r1 = 97, x25519_kyber768d00 = 1120
        server_pub_key_buf: [1120]u8 = undefined,
        server_pub_key: []const u8 = undefined,
        signature_buf: [1024]u8 = undefined,
        signature: []const u8 = undefined,
        client_certificate_requested: bool = false,

        rec_rdr: *RecordReaderT, // tls record reader
        buffer: []u8, // scratch buffer used in all messages creation

        const HandshakeT = @This();

        pub fn init(buf: []u8, reader: *RecordReaderT) !HandshakeT {
            var random_buf: [init_random_buf_len]u8 = undefined;
            crypto.random.bytes(&random_buf);
            return try initWithRandom(buf, reader, random_buf);
        }

        const init_random_buf_len = 32 + 64 + 46;

        fn initWithRandom(buf: []u8, rec_rdr: *RecordReaderT, random_buf: [init_random_buf_len]u8) !HandshakeT {
            return .{
                .client_random = random_buf[0..32].*,
                .dh_kp = try DhKeyPair.init(random_buf[32..][0..64].*),
                .rsa_secret = RsaSecret.init(random_buf[32 + 64 ..][0..46].*),
                .now_sec = std.time.timestamp(),
                .buffer = buf,
                .rec_rdr = rec_rdr,
            };
        }

        /// Handshake upgrades stream to tls connection.
        ///
        /// tls 1.2 messages:
        ///   client flight 1: client hello
        ///   server flight 1: server hello, certificate, key exchange, hello done
        ///   client flight 2: client key exchange, change cipher spec, handshake finished
        ///   server flight 2: server change cipher spec, handshake finished
        ///
        /// tls 1.3 messages:
        ///   client flight 1: client hello
        ///   server flight 1: server hello
        ///         encrypted: server change cipher spec, certificate, certificate verify, handshake finished
        ///   client flight 2: client change cipher spec, handshake finished
        ///
        pub fn handshake(
            h: *HandshakeT,
            w: Stream,
            host: []const u8,
            ca_bundle: ?Certificate.Bundle,
            opt: Options,
        ) !Cipher {
            defer h.statsUpdate(opt);

            // Send client flight 1
            try w.writeAll(try h.makeClientHello(host, opt));

            // Parse server flight 1
            try h.readServerFlight1(ca_bundle, host);
            h.transcript.set(h.cipher_suite_tag.hash());

            // tls 1.3 specific handshake part
            if (h.tls_version == .tls_1_3) {
                try h.generateHandshakeCipher();
                try h.readEncryptedServerFlight1(ca_bundle, host);
                const app_cipher = try h.generateApplicationCipher();
                try w.writeAll(try h.makeClientFlight2TLS13(opt.auth));

                return app_cipher;
            }

            // tls 1.2 specific handshake part
            try h.generateCipher();
            try w.writeAll(try h.makeClientFlight2TLS12(opt.auth));
            try h.readServerFlight2();

            return h.cipher;
        }

        // Prepare key material and generate cipher for tls 1.2
        fn generateCipher(h: *HandshakeT) !void {
            try h.verifyCertificateSignatureTLS12();
            try h.generateKeyMaterial();
            h.cipher = try Cipher.initTLS12(h.cipher_suite_tag, &h.key_material, crypto.random);
        }

        /// Generate tls 1.2 pre master secret, master secret and key material.
        fn generateKeyMaterial(h: *HandshakeT) !void {
            const pre_master_secret = if (h.named_group) |named_group|
                try h.dh_kp.preMasterSecret(named_group, h.server_pub_key)
            else
                &h.rsa_secret.secret;

            _ = dupe(
                &h.master_secret,
                h.transcript.masterSecret(pre_master_secret, h.client_random, h.server_random),
            );
            _ = dupe(
                &h.key_material,
                h.transcript.keyMaterial(&h.master_secret, h.client_random, h.server_random),
            );
        }

        fn generateHandshakeCipher(h: *HandshakeT) !void {
            const shared_key = try h.dh_kp.preMasterSecret(h.named_group.?, h.server_pub_key);
            const handshake_secret = h.transcript.handshakeSecret(shared_key);
            h.cipher = try Cipher.initTLS13(h.cipher_suite_tag, handshake_secret);
        }

        // Generate application (client) cipher
        fn generateApplicationCipher(h: *HandshakeT) !Cipher {
            const application_secret = h.transcript.applicationSecret();
            return try Cipher.initTLS13(h.cipher_suite_tag, application_secret);
        }

        fn makeClientHello(h: *HandshakeT, host: []const u8, opt: Options) ![]const u8 {
            const extension = struct {
                pub const status_request = [_]u8{ 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 };
                pub const ec_point_formats = [_]u8{ 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 };
                pub const renegotiation_info = [_]u8{ 0xff, 0x01, 0x00, 0x01, 0x00 };
                pub const sct = [_]u8{ 0x00, 0x12, 0x00, 0x00 };
            };

            const hello = struct {
                pub const no_compression = [_]u8{ 0x01, 0x00 };
                pub const no_session_id = [_]u8{0x00};
                pub const protocol_version = tls.int2(@intFromEnum(tls.ProtocolVersion.tls_1_2));
            };

            // Buffer will have this parts:
            // | header | payload | extensions |
            //
            // Header will be written last because we need to know length of
            // payload and extensions when creating it. Payload has
            // extensions length (u16) as last element.
            //
            var buffer = h.buffer;
            const header_len = 9; // tls record header (5 bytes) and handshake header (4 bytes)
            const tls_versions = try CipherSuite.versions(opt.cipher_suites);
            // Payload writer, preserve header_len bytes for handshake header.
            var payload = BufWriter{ .buf = buffer[header_len..] };
            try payload.write(&hello.protocol_version ++
                h.client_random ++
                hello.no_session_id);
            try payload.writeEnumArray(CipherSuite, opt.cipher_suites);
            try payload.write(&hello.no_compression);

            // Extensions writer starts after payload and preserves 2 more
            // bytes for extension len in payload.
            var ext = BufWriter{ .buf = buffer[header_len + payload.pos + 2 ..] };
            try ext.writeExtension(.supported_versions, switch (tls_versions) {
                .both => &[_]tls.ProtocolVersion{ .tls_1_3, .tls_1_2 },
                .tls_1_3 => &[_]tls.ProtocolVersion{.tls_1_3},
                .tls_1_2 => &[_]tls.ProtocolVersion{.tls_1_2},
            });
            try ext.write(&extension.ec_point_formats ++
                extension.renegotiation_info ++
                extension.sct);
            try ext.writeExtension(.signature_algorithms, &[_]tls.SignatureScheme{
                .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                .rsa_pss_rsae_sha256,
                .rsa_pss_rsae_sha384,
                .rsa_pss_rsae_sha512,
                .ed25519,
                .rsa_pkcs1_sha1,
                .rsa_pkcs1_sha256,
                .rsa_pkcs1_sha384,
            });

            const named_groups = &[_]tls.NamedGroup{ .x25519, .secp256r1, .secp384r1, .x25519_kyber768d00 };
            const named_groups_len = named_groups.len - @as(usize, if (opt.disable_keyber) 1 else 0);
            try ext.writeExtension(.supported_groups, named_groups[0..named_groups_len]);
            if (tls_versions != .tls_1_2) {
                const keys = &[_][]const u8{
                    try h.dh_kp.publicKey(.x25519),
                    try h.dh_kp.publicKey(.secp256r1),
                    try h.dh_kp.publicKey(.secp384r1),
                    try h.dh_kp.publicKey(.x25519_kyber768d00),
                };
                try ext.writeKeyShare(named_groups[0..named_groups_len], keys[0..named_groups_len]);
            }
            try ext.writeServerName(host);

            // Extensions length at the end of the payload.
            try payload.writeInt(@as(u16, @intCast(ext.pos)));

            // Header at the start of the buffer.
            const body_len = payload.pos + ext.pos;
            buffer[0..header_len].* = recordHeader(.handshake, 4 + body_len) ++
                handshakeHeader(.client_hello, body_len);

            const msg = buffer[0 .. header_len + body_len];
            h.transcript.update(msg[tls.record_header_len..]);
            return msg;
        }

        /// Process first flight of the messages from the server.
        /// Read server hello message. If tls 1.3 is chosen in server hello
        /// return. For tls 1.2 continue and read certificate, key_exchange
        /// and hello done messages.
        fn readServerFlight1(h: *HandshakeT, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
            var handshake_state = HandshakeType.server_hello;

            while (true) {
                var d = try h.rec_rdr.nextDecoder();
                try d.expectContentType(.handshake);

                h.transcript.update(d.payload);

                // Multiple handshake messages can be packed in single tls record.
                while (!d.eof()) {
                    const handshake_type = try d.decode(HandshakeType);
                    if (handshake_state == .certificate_request and handshake_type == .server_hello_done)
                        handshake_state = .server_hello_done; // certificate request is optional
                    if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;

                    const length = try d.decode(u24);
                    if (length > tls.max_cipertext_inner_record_len)
                        return error.TlsUnsupportedFragmentedHandshakeMessage;

                    switch (handshake_type) {
                        .server_hello => { // server hello, ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.3
                            try h.parseServerHello(&d, length);
                            if (h.tls_version == .tls_1_3) {
                                if (!d.eof()) return error.TlsIllegalParameter;
                                return; // end of tls 1.3 server flight 1
                            }
                            handshake_state = .certificate;
                        },
                        .certificate => {
                            try h.parseServerCertificate(&d, ca_bundle, host);
                            handshake_state = if (h.cipher_suite_tag.keyExchange() == .rsa)
                                .server_hello_done
                            else
                                .server_key_exchange;
                        },
                        .server_key_exchange => {
                            try h.parseServerKeyExchange(&d);
                            handshake_state = .certificate_request;
                        },
                        .certificate_request => {
                            h.client_certificate_requested = true;
                            try d.skip(length);
                            handshake_state = .server_hello_done;
                        },
                        .server_hello_done => {
                            if (length != 0) return error.TlsIllegalParameter;
                            return;
                        },
                        else => return error.TlsUnexpectedMessage,
                    }
                }
            }
        }

        /// Parse server hello message.
        fn parseServerHello(h: *HandshakeT, d: *record.Decoder, length: u24) !void {
            if (try d.decode(tls.ProtocolVersion) != tls.ProtocolVersion.tls_1_2)
                return error.TlsBadVersion;
            h.server_random = (try d.array(32)).*;
            if (isServerHelloRetryRequest(&h.server_random))
                return error.TlsServerHelloRetryRequest;

            const session_id_len = try d.decode(u8);
            if (session_id_len > 32) return error.TlsIllegalParameter;
            try d.skip(session_id_len);

            h.cipher_suite_tag = try d.decode(CipherSuite);
            try h.cipher_suite_tag.validate();
            try d.skip(1); // skip compression method

            const extensions_present = length > 2 + 32 + session_id_len + 2 + 1;
            if (extensions_present) {
                const exs_len = try d.decode(u16);
                var l: usize = 0;
                while (l < exs_len) {
                    const typ = try d.decode(tls.ExtensionType);
                    const len = try d.decode(u16);
                    defer l += len + 4;

                    switch (typ) {
                        .supported_versions => {
                            switch (try d.decode(tls.ProtocolVersion)) {
                                .tls_1_2, .tls_1_3 => |v| h.tls_version = v,
                                else => return error.TlsIllegalParameter,
                            }
                            if (len != 2) return error.TlsIllegalParameter;
                        },
                        .key_share => {
                            h.named_group = try d.decode(tls.NamedGroup);
                            h.server_pub_key = dupe(&h.server_pub_key_buf, try d.slice(try d.decode(u16)));
                            if (len != h.server_pub_key.len + 4) return error.TlsIllegalParameter;
                        },
                        else => {
                            try d.skip(len);
                        },
                    }
                }
            }
        }

        fn isServerHelloRetryRequest(server_random: []const u8) bool {
            // HelloRetryRequest message uses the same structure as the ServerHello, but
            // with Random set to the special value of the SHA-256 of "HelloRetryRequest"
            // Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
            const hello_retry_request_magic = testu.hexToBytes(
                \\ CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
            );
            return std.mem.eql(u8, server_random, &hello_retry_request_magic);
        }

        /// Parse server certificate message.
        fn parseServerCertificate(h: *HandshakeT, d: *record.Decoder, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
            var trust_chain_established = false;
            var last_cert: ?Certificate.Parsed = null;
            const certs_len = try d.decode(u24);

            const start_idx = d.idx;
            while (d.idx - start_idx < certs_len) {
                const cert_len = try d.decode(u24);
                // std.debug.print("=> {} {} {} {}\n", .{ certs_len, rec.idx, cert_len, rec.payload.len });
                const cert = try d.slice(cert_len);
                if (h.tls_version == .tls_1_3) {
                    // certificate extensions present in tls 1.3
                    try d.skip(try d.decode(u16));
                }
                if (trust_chain_established)
                    continue;

                const subject = try (Certificate{ .buffer = cert, .index = 0 }).parse();
                if (last_cert) |pc| {
                    if (pc.verify(subject, h.now_sec)) {
                        last_cert = subject;
                    } else |err| switch (err) {
                        error.CertificateIssuerMismatch => {
                            // skip certificate which is not part of the chain
                            continue;
                        },
                        else => return err,
                    }
                } else { // first certificate
                    try subject.verifyHostName(host);
                    h.cert_pub_key = dupe(&h.cert_pub_key_buf, subject.pubKey());
                    h.cert_pub_key_algo = subject.pub_key_algo;
                    last_cert = subject;
                }
                if (ca_bundle) |cb| {
                    if (cb.verify(last_cert.?, h.now_sec)) |_| {
                        trust_chain_established = true;
                    } else |err| switch (err) {
                        error.CertificateIssuerNotFound => {},
                        else => return err,
                    }
                }
            }
            if (ca_bundle != null and !trust_chain_established) {
                return error.CertificateIssuerNotFound;
            }
        }

        /// Parse server key exchange message.
        fn parseServerKeyExchange(h: *HandshakeT, d: *record.Decoder) !void {
            const curve_type = try d.decode(CurveType);
            h.named_group = try d.decode(tls.NamedGroup);
            h.server_pub_key = dupe(&h.server_pub_key_buf, try d.slice(try d.decode(u8)));
            h.signature_scheme = try d.decode(tls.SignatureScheme);
            h.signature = dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
            if (curve_type != .named_curve) return error.TlsIllegalParameter;
        }

        /// Read encrypted part (after server hello) of the server first
        /// flight for tls 1.3: change cipher spec, certificate, certificate
        /// verify and handshake finished messages.
        fn readEncryptedServerFlight1(
            h: *HandshakeT,
            ca_bundle: ?Certificate.Bundle,
            host: []const u8,
        ) !void {
            var sequence: u64 = 0;
            var cleartext_buf = h.buffer;
            var cleartext_buf_head: usize = 0;
            var cleartext_buf_tail: usize = 0;
            var handshake_state: HandshakeType = .encrypted_extensions;

            outer: while (true) {
                // wrapped record decoder
                const rec = (try h.rec_rdr.next() orelse return error.EndOfStream);
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                //std.debug.print("serverFlightTLS13 {} {}\n", .{ wrap_rec.content_type, wrap_rec.payload.len });
                switch (rec.content_type) {
                    .change_cipher_spec => {},
                    .application_data => {
                        const content_type, const cleartext = switch (h.cipher) {
                            inline else => |*p| try p.decrypt(
                                cleartext_buf[cleartext_buf_tail..],
                                sequence,
                                rec,
                            ),
                        };
                        if (content_type != .handshake) return error.TlsUnexpectedMessage;
                        sequence += 1;
                        cleartext_buf_tail += cleartext.len;

                        var d = record.Decoder.init(content_type, cleartext_buf[cleartext_buf_head..cleartext_buf_tail]);
                        while (!d.eof()) {
                            const start_idx = d.idx;
                            const handshake_type = try d.decode(HandshakeType);
                            const length = try d.decode(u24);

                            // std.debug.print("handshake loop: {} {} {}\n", .{ handshake_type, length, rec.payload.len });
                            if (length > tls.max_cipertext_inner_record_len)
                                return error.TlsUnsupportedFragmentedHandshakeMessage;
                            if (length > d.payload.len - 4)
                                continue :outer; // fragmented handshake into multiple records

                            defer {
                                const handshake_payload = d.payload[start_idx..d.idx];
                                h.transcript.update(handshake_payload);
                                cleartext_buf_head += handshake_payload.len;
                            }

                            if (handshake_state == .certificate_request and handshake_type == .certificate)
                                handshake_state = .certificate; // certificate request is optional
                            if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;
                            switch (handshake_type) {
                                .encrypted_extensions => {
                                    try d.skip(length);
                                    handshake_state = .certificate_request;
                                },
                                .certificate_request => {
                                    h.client_certificate_requested = true;
                                    try d.skip(length);
                                    handshake_state = .certificate;
                                },
                                .certificate => {
                                    const request_context = try d.decode(u8);
                                    if (request_context != 0) return error.TlsIllegalParameter;
                                    try h.parseServerCertificate(&d, ca_bundle, host);
                                    handshake_state = .certificate_verify;
                                },
                                .certificate_verify => {
                                    h.signature_scheme = try d.decode(tls.SignatureScheme);
                                    h.signature = dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
                                    try h.verifyCertificateSignatureTLS13();
                                    handshake_state = .finished;
                                },
                                .finished => {
                                    const actual = try d.slice(length);
                                    const expected = h.transcript.serverFinishedTLS13();
                                    if (!mem.eql(u8, expected, actual))
                                        return error.TlsDecryptError;
                                    return;
                                },
                                else => return error.TlsUnexpectedMessage,
                            }
                        }
                        cleartext_buf_head = 0;
                        cleartext_buf_tail = 0;
                    },
                    else => return error.TlsUnexpectedMessage,
                }
            }
        }

        fn verifyCertificateSignatureTLS13(h: *HandshakeT) !void {
            try h.verifyCertificateSignature(h.transcript.serverCertificateVerify());
        }

        /// Create verify data and verify server signature for tls 1.2.
        fn verifyCertificateSignatureTLS12(h: *HandshakeT) !void {
            if (h.cipher_suite_tag.keyExchange() != .ecdhe) return;
            const verify_bytes = brk: {
                var w = BufWriter{ .buf = h.buffer };
                try w.write(&h.client_random);
                try w.write(&h.server_random);
                try w.writeEnum(CurveType.named_curve);
                try w.writeEnum(h.named_group.?);
                try w.writeInt(@as(u8, @intCast(h.server_pub_key.len)));
                try w.write(h.server_pub_key);
                break :brk w.getWritten();
            };
            try h.verifyCertificateSignature(verify_bytes);
        }

        /// Verify server certificate signature with server public key.
        fn verifyCertificateSignature(h: *HandshakeT, verify_bytes: []const u8) !void {
            switch (h.signature_scheme) {
                inline .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                => |comptime_scheme| {
                    if (h.cert_pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                    const cert_named_curve = h.cert_pub_key_algo.X9_62_id_ecPublicKey;
                    switch (cert_named_curve) {
                        inline .secp384r1, .X9_62_prime256v1 => |comptime_cert_named_curve| {
                            const Ecdsa = SchemeEcdsaCert(comptime_scheme, comptime_cert_named_curve);
                            const key = try Ecdsa.PublicKey.fromSec1(h.cert_pub_key);
                            const sig = try Ecdsa.Signature.fromDer(h.signature);
                            try sig.verify(verify_bytes, key);
                        },
                        else => return error.TlsUnknownSignatureScheme,
                    }
                },
                .ed25519 => {
                    if (h.cert_pub_key_algo != .curveEd25519) return error.TlsBadSignatureScheme;
                    const Eddsa = crypto.sign.Ed25519;
                    if (h.signature.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                    const sig = Eddsa.Signature.fromBytes(h.signature[0..Eddsa.Signature.encoded_length].*);
                    if (h.cert_pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                    const key = try Eddsa.PublicKey.fromBytes(h.cert_pub_key[0..Eddsa.PublicKey.encoded_length].*);
                    try sig.verify(verify_bytes, key);
                },
                inline .rsa_pss_rsae_sha256,
                .rsa_pss_rsae_sha384,
                .rsa_pss_rsae_sha512,
                => |comptime_scheme| {
                    if (h.cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                    const Hash = SchemeHash(comptime_scheme);
                    const pk = try rsa.PublicKey.fromDer(h.cert_pub_key);
                    const sig = rsa.Pss(Hash).Signature{ .bytes = h.signature };
                    try sig.verify(verify_bytes, pk, null);
                },
                inline .rsa_pkcs1_sha1,
                .rsa_pkcs1_sha256,
                .rsa_pkcs1_sha384,
                .rsa_pkcs1_sha512,
                => |comptime_scheme| {
                    if (h.cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                    const Hash = SchemeHash(comptime_scheme);
                    const pk = try rsa.PublicKey.fromDer(h.cert_pub_key);
                    const sig = rsa.PKCS1v1_5(Hash).Signature{ .bytes = h.signature };
                    try sig.verify(verify_bytes, pk);
                },
                else => return error.TlsUnknownSignatureScheme,
            }
        }

        /// Creates client key exchange, change cipher spec and handshake
        /// finished messages for tls 1.2.
        /// If client certificate is requested also adds client certificate and
        /// certificate verify messages.
        fn makeClientFlight2TLS12(h: *HandshakeT, auth: ?Options.Auth) ![]const u8 {
            var w = BufWriter{ .buf = h.buffer };

            // Client certificate message
            if (h.client_certificate_requested) {
                if (auth) |a| {
                    const client_certificate = try h.makeClientCertificate(w.getPayload(), a);
                    try w.writeRecord(.handshake, client_certificate.len);
                    h.transcript.update(client_certificate);
                } else {
                    const empty_certificate = &handshakeHeader(.certificate, 3) ++ [_]u8{ 0, 0, 0 };
                    try w.writeRecord(.handshake, empty_certificate);
                    h.transcript.update(empty_certificate);
                }
            }

            // Client key exchange message
            {
                const key_exchange = try h.makeClientKeyExchange(w.getPayload());
                try w.writeRecord(.handshake, key_exchange.len);
                h.transcript.update(key_exchange);
            }

            // Client certificate verify message
            if (h.client_certificate_requested and auth != null) {
                const certificate_verify = try h.makeClientCertificateVerify(w.getPayload(), auth.?);
                try w.writeRecord(.handshake, certificate_verify.len);
                h.transcript.update(certificate_verify);
            }

            // Client change cipher spec message
            try w.writeRecord(.change_cipher_spec, &[_]u8{1});

            // Client handshake finished message
            {
                const client_finished = &h.transcript.clientFinishedTLS12(&h.master_secret);
                try h.writeEncrypted(&w, client_finished);
                h.transcript.update(client_finished);
            }

            return w.getWritten();
        }

        /// Create client change cipher spec and handshake finished messages for
        /// tls 1.3.
        /// If the client certificate is requested by the server and client is
        /// configured with certificates and private key then client certificate
        /// and client certificate verify messages are also created. If the
        /// server has requested certificate but the client is not configured
        /// empty certificate message is sent, as is required by rfc.
        fn makeClientFlight2TLS13(h: *HandshakeT, auth: ?Options.Auth) ![]const u8 {
            var w = BufWriter{ .buf = h.buffer };

            // Client change cipher spec message
            try w.writeRecord(.change_cipher_spec, &[_]u8{1});

            if (h.client_certificate_requested) {
                if (auth) |a| {
                    var buffer: [tls.max_cipertext_inner_record_len]u8 = undefined;
                    // Client certificate message
                    const certificate = try h.makeClientCertificate(&buffer, a);
                    try h.writeEncrypted(&w, certificate);
                    h.transcript.update(certificate);
                    // Client certificate verify message
                    const certificate_verify = try h.makeClientCertificateVerify(&buffer, a);
                    try h.writeEncrypted(&w, certificate_verify);
                    h.transcript.update(certificate_verify);
                } else {
                    // Empty certificate message and no certificate verify message
                    const empty_certificate = &handshakeHeader(.certificate, 4) ++ [_]u8{ 0, 0, 0, 0 };
                    try h.writeEncrypted(&w, empty_certificate);
                    h.transcript.update(empty_certificate);
                }
            }

            // Client handshake finished message
            {
                const client_finished = h.transcript.clientFinishedTLS13();
                try h.writeEncrypted(&w, client_finished);
                h.transcript.update(client_finished);
            }

            return w.getWritten();
        }

        fn makeClientKeyExchange(h: *HandshakeT, buffer: []u8) ![]const u8 {
            var w = BufWriter{ .buf = buffer };
            if (h.named_group) |named_group| {
                const key = try h.dh_kp.publicKey(named_group);
                try w.writeHandshakeHeader(.client_key_exchange, 1 + key.len);
                try w.writeInt(@as(u8, @intCast(key.len)));
                try w.write(key);
            } else {
                const key = try h.rsa_secret.encrypted(h.cert_pub_key_algo, h.cert_pub_key);
                try w.writeHandshakeHeader(.client_key_exchange, 2 + key.len);
                try w.writeInt(@as(u16, @intCast(key.len)));
                try w.write(key);
            }
            return w.getWritten();
        }

        /// Create client certificate message.
        /// Handles differences between TLS versions.
        fn makeClientCertificate(h: HandshakeT, buffer: []u8, auth: Options.Auth) ![]const u8 {
            var w = BufWriter{ .buf = buffer };
            const certs = auth.certificates.bytes.items;
            const certs_count = auth.certificates.map.size;

            // Differences between tls 1.3 and 1.2
            // TLS 1.3 has request context in header and extensions for each certificate.
            // Here we use empty length for each field.
            // TLS 1.2 don't have these two fields.
            const request_context, const extensions = if (h.tls_version == .tls_1_3)
                .{ &[_]u8{0}, &[_]u8{ 0, 0 } }
            else
                .{ &[_]u8{}, &[_]u8{} };
            const certs_len = certs.len + 3 * certs_count + extensions.len;

            // Write handshake header
            try w.writeHandshakeHeader(.certificate, certs_len + request_context.len + 3);
            try w.write(request_context);
            try w.writeInt(@as(u24, @intCast(certs_len)));

            // Write each certificate
            var index: u32 = 0;
            while (index < certs.len) {
                const e = try Certificate.der.Element.parse(certs, index);
                const cert = certs[index..e.slice.end];
                try w.writeInt(@as(u24, @intCast(cert.len))); // certificate length
                try w.write(cert); // certificate
                try w.write(extensions); // certificate extensions
                index = e.slice.end;
            }
            return w.getWritten();
        }

        fn makeClientCertificateVerify(h: *HandshakeT, buffer: []u8, auth: Options.Auth) ![]const u8 {
            var w = BufWriter{ .buf = buffer };

            const signature, const signature_scheme = try h.createSignature(auth);
            try w.writeHandshakeHeader(.certificate_verify, signature.len + 4);
            try w.writeEnum(signature_scheme);
            try w.writeInt(@as(u16, @intCast(signature.len)));
            try w.write(signature);

            return w.getWritten();
        }

        /// Creates signature for client certificate signature message.
        /// Returns signature bytes and signature scheme.
        inline fn createSignature(h: *HandshakeT, auth: Options.Auth) !struct { []const u8, tls.SignatureScheme } {
            switch (auth.private_key.signature_scheme) {
                inline .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                => |comptime_scheme| {
                    const Ecdsa = SchemeEcdsa(comptime_scheme);
                    const key = auth.private_key.key.ecdsa;
                    const key_len = Ecdsa.SecretKey.encoded_length;
                    if (key.len < key_len) return error.InvalidEncoding;
                    const secret_key = try Ecdsa.SecretKey.fromBytes(key[0..key_len].*);
                    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
                    var signer = try key_pair.signer(null);
                    h.setSignatureVerifyBytes(&signer);
                    const signature = try signer.finalize();
                    var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                    return .{ signature.toDer(&buf), comptime_scheme };
                },
                inline .rsa_pss_rsae_sha256,
                .rsa_pss_rsae_sha384,
                .rsa_pss_rsae_sha512,
                => |comptime_scheme| {
                    const Hash = SchemeHash(comptime_scheme);
                    var signer = try auth.private_key.key.rsa.signerOaep(Hash, null);
                    h.setSignatureVerifyBytes(&signer);
                    var buf: [512]u8 = undefined;
                    const signature = try signer.finalize(&buf);
                    return .{ signature.bytes, comptime_scheme };
                },
                else => return error.TlsUnknownSignatureScheme,
            }
        }

        fn setSignatureVerifyBytes(h: *HandshakeT, signer: anytype) void {
            if (h.tls_version == .tls_1_2) {
                // tls 1.2 signature uses current transcript hash value.
                // ref: https://datatracker.ietf.org/doc/html/rfc5246.html#section-7.4.8
                const Hash = @TypeOf(signer.h);
                signer.h = h.transcript.hash(Hash);
            } else {
                // tls 1.3 signature is computed over concatenation of 64 spaces,
                // context, separator and content.
                // ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
                signer.update(h.transcript.clientCertificateVerify());
            }
        }

        fn readServerFlight2(h: *HandshakeT) !void {
            // Read server change cipher spec message.
            {
                var d = try h.rec_rdr.nextDecoder();
                try d.expectContentType(.change_cipher_spec);
            }
            // Read encrypted server handshake finished message. Verify that
            // content of the server finished message is based on transcript
            // hash and master secret.
            {
                const content_type, const server_finished =
                    try h.rec_rdr.nextDecrypt(h.cipher, 0) orelse return error.EndOfStream;
                if (content_type != .handshake)
                    return error.TlsUnexpectedMessage;
                const expected_server_finished = h.transcript.serverFinishedTLS12(&h.master_secret);
                if (!mem.eql(u8, server_finished, &expected_server_finished))
                    return error.TlsBadRecordMac;
            }
        }

        /// Write encrypted handshake message into `w`
        fn writeEncrypted(h: *HandshakeT, w: *BufWriter, cleartext: []const u8) !void {
            const ciphertext = try h.cipher.encrypt(w.getFree(), h.write_seq, .handshake, cleartext);
            w.pos += ciphertext.len;
            h.write_seq += 1;
        }

        // Copy handshake parameters to opt.stats
        fn statsUpdate(h: *HandshakeT, opt: Options) void {
            if (opt.stats) |stats| {
                stats.tls_version = h.tls_version;
                stats.cipher_suite_tag = h.cipher_suite_tag;
                stats.named_group = h.named_group orelse @as(tls.NamedGroup, @enumFromInt(0x0000));
                stats.signature_scheme = h.signature_scheme;
                if (opt.auth) |a|
                    stats.client_signature_scheme = a.private_key.signature_scheme;
            }
        }

        fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
            return switch (scheme) {
                .ecdsa_secp256r1_sha256 => EcdsaP256Sha256,
                .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
                else => unreachable,
            };
        }

        fn SchemeEcdsaCert(comptime scheme: tls.SignatureScheme, comptime cert_named_curve: Certificate.NamedCurve) type {
            return switch (scheme) {
                .ecdsa_secp256r1_sha256 => crypto.sign.ecdsa.Ecdsa(cert_named_curve.Curve(), Sha256),
                .ecdsa_secp384r1_sha384 => crypto.sign.ecdsa.Ecdsa(cert_named_curve.Curve(), Sha384),
                else => @compileError("bad scheme"),
            };
        }

        fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
            return switch (scheme) {
                .rsa_pkcs1_sha1 => crypto.hash.Sha1,
                .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => Sha256,
                .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => Sha384,
                .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => Sha512,
                else => @compileError("bad scheme"),
            };
        }
    };
}

const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
    kyber768_kp: Kyber768.KeyPair = undefined,

    const seed_len = 64;

    fn init(seed: [seed_len]u8) !DhKeyPair {
        return .{
            .x25519_kp = try X25519.KeyPair.create(seed[0..X25519.seed_length].*),
            .secp256r1_kp = try EcdsaP256Sha256.KeyPair.create(seed[0..EcdsaP256Sha256.KeyPair.seed_length].*),
            .secp384r1_kp = try EcdsaP384Sha384.KeyPair.create(seed[0..EcdsaP384Sha384.KeyPair.seed_length].*),
            .kyber768_kp = try Kyber768.KeyPair.create(seed),
        };
    }

    inline fn preMasterSecret(self: DhKeyPair, named_group: tls.NamedGroup, server_pub_key: []const u8) ![]const u8 {
        return switch (named_group) {
            .x25519 => brk: {
                if (server_pub_key.len != X25519.public_length)
                    return error.TlsIllegalParameter;
                break :brk &(try X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..X25519.public_length].*,
                ));
            },
            .secp256r1 => brk: {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp256r1_kp.secret_key.bytes, .big);
                break :brk &mul.affineCoordinates().x.toBytes(.big);
            },
            .secp384r1 => brk: {
                const pk = try EcdsaP384Sha384.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp384r1_kp.secret_key.bytes, .big);
                break :brk &mul.affineCoordinates().x.toBytes(.big);
            },
            .x25519_kyber768d00 => brk: {
                const xksl = crypto.dh.X25519.public_length;
                const hksl = xksl + Kyber768.ciphertext_length;
                if (server_pub_key.len != hksl)
                    return error.TlsIllegalParameter;

                break :brk &((crypto.dh.X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..xksl].*,
                ) catch return error.TlsDecryptFailure) ++ (self.kyber768_kp.secret_key.decaps(
                    server_pub_key[xksl..hksl],
                ) catch return error.TlsDecryptFailure));
            },

            else => return error.TlsIllegalParameter,
        };
    }

    // Returns 32, 65 or 97 bytes
    inline fn publicKey(self: DhKeyPair, named_group: tls.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => &self.secp256r1_kp.public_key.toUncompressedSec1(),
            .secp384r1 => &self.secp384r1_kp.public_key.toUncompressedSec1(),
            .x25519_kyber768d00 => &self.x25519_kp.public_key ++ self.kyber768_kp.public_key.toBytes(),
            else => return error.TlsIllegalParameter,
        };
    }
};

const RsaSecret = struct {
    secret: [48]u8,

    fn init(rand: [46]u8) RsaSecret {
        return .{ .secret = [_]u8{ 0x03, 0x03 } ++ rand };
    }

    // Pre master secret encrypted with certificate public key.
    inline fn encrypted(
        self: RsaSecret,
        cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo,
        cert_pub_key: []const u8,
    ) ![]const u8 {
        if (cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
        const pk = try rsa.PublicKey.fromDer(cert_pub_key);
        var out: [512]u8 = undefined;
        return try pk.encryptPkcsv1_5(&self.secret, &out);
    }
};

test "DhKeyPair.x25519" {
    const seed = testu.hexToBytes("4f27a0ea9873d11f3330b88f9443811a5f79c2339dc90dc560b5b49d5e7fe73e496c893a4bbaf26f3288432c747d8b2b00000000000000000000000000000000");
    const server_pub_key = &testu.hexToBytes("3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = &testu.hexToBytes("f8912817eb835341f70960290b550329968fea80445853bb91de2ab13ad91c15");

    const kp = try DhKeyPair.init(seed[0..64].*);
    try testing.expectEqualSlices(u8, expected, try kp.preMasterSecret(.x25519, server_pub_key));
}

fn dupe(buf: []u8, data: []const u8) []u8 {
    const n = @min(data.len, buf.len);
    @memcpy(buf[0..n], data[0..n]);
    return buf[0..n];
}

const BufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn write(self: *BufWriter, data: []const u8) !void {
        defer self.pos += data.len;
        if (self.pos + data.len > self.buf.len) return error.BufferOverflow;
        _ = dupe(self.buf[self.pos..], data);
    }

    pub fn writeEnum(self: *BufWriter, value: anytype) !void {
        try self.writeInt(@intFromEnum(value));
    }

    pub fn writeInt(self: *BufWriter, value: anytype) !void {
        const IntT = @TypeOf(value);
        const bytes = @divExact(@typeInfo(IntT).Int.bits, 8);
        const free = self.buf[self.pos..];
        if (free.len < bytes) return error.BufferOverflow;
        mem.writeInt(IntT, free[0..bytes], value, .big);
        self.pos += bytes;
    }

    pub fn writeHandshakeHeader(self: *BufWriter, handshake_type: HandshakeType, payload_len: usize) !void {
        try self.write(&handshakeHeader(handshake_type, payload_len));
    }

    pub fn writeRecord(self: *BufWriter, content_type: tls.ContentType, payload: anytype) !void {
        if (@TypeOf(payload) == usize) {
            try self.write(&recordHeader(content_type, payload));
            self.pos += payload;
            return;
        }
        try self.write(&recordHeader(content_type, payload.len));
        try self.write(payload);
    }

    pub fn getPayload(self: *BufWriter) []u8 {
        return self.buf[self.pos + tls.record_header_len ..];
    }

    pub fn getWritten(self: *BufWriter) []const u8 {
        return self.buf[0..self.pos];
    }

    pub fn getFree(self: *BufWriter) []u8 {
        return self.buf[self.pos..];
    }

    pub fn writeEnumArray(self: *BufWriter, comptime E: type, tags: []const E) !void {
        assert(@sizeOf(E) == 2);
        try self.writeInt(@as(u16, @intCast(tags.len * 2)));
        for (tags) |t| {
            try self.writeEnum(t);
        }
    }

    pub fn writeExtension(
        self: *BufWriter,
        comptime et: tls.ExtensionType,
        tags: anytype,
    ) !void {
        try self.writeEnum(et);
        if (et == .supported_versions) {
            try self.writeInt(@as(u16, @intCast(tags.len * 2 + 1)));
            try self.writeInt(@as(u8, @intCast(tags.len * 2)));
        } else {
            try self.writeInt(@as(u16, @intCast(tags.len * 2 + 2)));
            try self.writeInt(@as(u16, @intCast(tags.len * 2)));
        }
        for (tags) |t| {
            try self.writeEnum(t);
        }
    }

    pub fn writeKeyShare(
        self: *BufWriter,
        named_groups: []const tls.NamedGroup,
        keys: []const []const u8,
    ) !void {
        assert(named_groups.len == keys.len);
        try self.writeEnum(tls.ExtensionType.key_share);
        var l: usize = 0;
        for (keys) |key| {
            l += key.len + 4;
        }
        try self.writeInt(@as(u16, @intCast(l + 2)));
        try self.writeInt(@as(u16, @intCast(l)));
        for (named_groups, 0..) |ng, i| {
            const key = keys[i];
            try self.writeEnum(ng);
            try self.writeInt(@as(u16, @intCast(key.len)));
            try self.write(key);
        }
    }

    pub fn writeServerName(self: *BufWriter, host: []const u8) !void {
        try self.write(&serverNameExtensionHeader(@intCast(host.len)));
        try self.write(host);
    }
};

fn serverNameExtensionHeader(host_len: u16) [9]u8 {
    const int2 = tls.int2;

    return int2(@intFromEnum(tls.ExtensionType.server_name)) ++
        int2(host_len + 5) ++ // byte length of this extension payload
        int2(host_len + 3) ++ // server_name_list byte count
        [1]u8{0x00} ++ // name_type
        int2(host_len);
}

fn handshakeRecordHeader(handshake_type: HandshakeType, payload_len: usize) [9]u8 {
    return recordHeader(.handshake, 4 + payload_len) ++
        handshakeHeader(handshake_type, payload_len);
}

pub fn handshakeHeader(handshake_type: HandshakeType, payload_len: usize) [4]u8 {
    return [1]u8{@intFromEnum(handshake_type)} ++ tls.int3(@intCast(payload_len));
}

pub fn recordHeader(content_type: tls.ContentType, payload_len: usize) [5]u8 {
    return [1]u8{@intFromEnum(content_type)} ++
        tls.int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        tls.int2(@intCast(payload_len));
}

test "BufWriter" {
    var buf: [16]u8 = undefined;
    var w = BufWriter{ .buf = &buf };

    try w.write("ab");
    try w.writeEnum(CurveType.named_curve);
    try w.writeEnum(tls.NamedGroup.x25519);
    try w.writeInt(@as(u16, 0x1234));
    try testing.expectEqualSlices(u8, &[_]u8{ 'a', 'b', 0x03, 0x00, 0x1d, 0x12, 0x34 }, w.getWritten());
}

const testing = std.testing;
const data12 = @import("testdata/tls12.zig");
const data13 = @import("testdata/tls13.zig");
const testu = @import("testu.zig");

fn testReader(data: []const u8) record.Reader(std.io.FixedBufferStream([]const u8)) {
    return record.reader(std.io.fixedBufferStream(data));
}
const TestHandshake = Handshake(std.io.FixedBufferStream([]const u8));

test "parse tls 1.2 server hello" {
    var h = brk: {
        var buffer: [1024]u8 = undefined;
        var rec_rdr = testReader(&data12.server_hello_responses);
        break :brk try TestHandshake.init(&buffer, &rec_rdr);
    };

    // Set to known instead of random
    h.client_random = data12.client_random;
    h.dh_kp.x25519_kp.secret_key = data12.client_secret;

    // Parse server hello, certificate and key exchange messages.
    // Read cipher suite, named group, signature scheme, server random certificate public key
    // Verify host name, signature
    // Calculate key material
    try h.readServerFlight1(null, "example.ulfheim.net");
    try testing.expectEqual(.ECDHE_RSA_WITH_AES_128_CBC_SHA, h.cipher_suite_tag);
    try testing.expectEqual(.x25519, h.named_group.?);
    try testing.expectEqual(.rsa_pkcs1_sha256, h.signature_scheme);
    try testing.expectEqualSlices(u8, &data12.server_random, &h.server_random);
    try testing.expectEqualSlices(u8, &data12.server_pub_key, h.server_pub_key);
    try testing.expectEqualSlices(u8, &data12.signature, h.signature);
    try testing.expectEqualSlices(u8, &data12.cert_pub_key, h.cert_pub_key);

    try h.verifyCertificateSignatureTLS12();
    try h.generateKeyMaterial();

    try testing.expectEqualSlices(u8, &data12.key_material, h.key_material[0..data12.key_material.len]);
}

test "verify google.com certificate" {
    var h = brk: {
        var buffer: [1024]u8 = undefined;
        var rec_rdr = testReader(@embedFile("testdata/google.com/server_hello"));
        break :brk try TestHandshake.init(&buffer, &rec_rdr);
    };
    h.now_sec = 1714846451;
    h.client_random = @embedFile("testdata/google.com/client_random").*;

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(testing.allocator);
    defer ca_bundle.deinit(testing.allocator);

    try h.readServerFlight1(ca_bundle, "google.com");
    try h.verifyCertificateSignatureTLS12();
}

test "parse tls 1.3 server hello" {
    var rec_rdr = testReader(&data13.server_hello);
    var d = (try rec_rdr.nextDecoder());

    const handshake_type = try d.decode(HandshakeType);
    const length = try d.decode(u24);
    try testing.expectEqual(0x000076, length);
    try testing.expectEqual(.server_hello, handshake_type);

    var h = try TestHandshake.init(undefined, undefined);
    try h.parseServerHello(&d, length);

    try testing.expectEqual(.AES_256_GCM_SHA384, h.cipher_suite_tag);
    try testing.expectEqualSlices(u8, &data13.server_random, &h.server_random);
    try testing.expectEqual(.tls_1_3, h.tls_version);
    try testing.expectEqual(.x25519, h.named_group);
    try testing.expectEqualSlices(u8, &data13.server_pub_key, h.server_pub_key);
}

test "init tls 1.3 handshake cipher" {
    const cipher_suite_tag: CipherSuite = .AES_256_GCM_SHA384;

    var transcript = Transcript{};
    transcript.set(cipher_suite_tag.hash());
    transcript.update(data13.client_hello[tls.record_header_len..]);
    transcript.update(data13.server_hello[tls.record_header_len..]);

    var dh_kp = DhKeyPair{
        .x25519_kp = .{
            .public_key = data13.client_public_key,
            .secret_key = data13.client_private_key,
        },
    };
    const shared_key = try dh_kp.preMasterSecret(.x25519, &data13.server_pub_key);
    try testing.expectEqualSlices(u8, &data13.shared_key, shared_key);

    const cipher = try Cipher.initTLS13(cipher_suite_tag, transcript.handshakeSecret(shared_key));

    const c = &cipher.AES_256_GCM_SHA384;
    try testing.expectEqualSlices(u8, &data13.server_handshake_key, &c.server_key);
    try testing.expectEqualSlices(u8, &data13.client_handshake_key, &c.client_key);
    try testing.expectEqualSlices(u8, &data13.server_handshake_iv, &c.server_iv);
    try testing.expectEqualSlices(u8, &data13.client_handshake_iv, &c.client_iv);
}

fn initExampleHandshake(h: *TestHandshake) !void {
    h.cipher_suite_tag = .AES_256_GCM_SHA384;
    h.transcript.set(h.cipher_suite_tag.hash());
    h.transcript.update(data13.client_hello[tls.record_header_len..]);
    h.transcript.update(data13.server_hello[tls.record_header_len..]);
    h.cipher = try Cipher.initTLS13(h.cipher_suite_tag, h.transcript.handshakeSecret(&data13.shared_key));
    h.tls_version = .tls_1_3;
    h.now_sec = 1714846451;
    h.server_pub_key = &data13.server_pub_key;
}

test "tls 1.3 decrypt wrapped record" {
    var cipher = brk: {
        var h = try TestHandshake.init(undefined, undefined);
        try initExampleHandshake(&h);
        break :brk h.cipher;
    };

    var cleartext_buf: [1024]u8 = undefined;
    {
        const rec = record.Record.init(&data13.server_encrypted_extensions_wrapped);
        const sequence: u64 = 0;

        const content_type, const cleartext = try cipher.decrypt(&cleartext_buf, sequence, rec);
        try testing.expectEqual(.handshake, content_type);
        try testing.expectEqualSlices(u8, &data13.server_encrypted_extensions, cleartext);
    }
    {
        const rec = record.Record.init(&data13.server_certificate_wrapped);
        const sequence: u64 = 1;

        const content_type, const cleartext = try cipher.decrypt(&cleartext_buf, sequence, rec);
        try testing.expectEqual(.handshake, content_type);
        try testing.expectEqualSlices(u8, &data13.server_certificate, cleartext);
    }
}

test "tls 1.3 process server flight" {
    var buffer: [1024]u8 = undefined;
    var h = brk: {
        var rec_rdr = testReader(&data13.server_flight);
        break :brk try TestHandshake.init(&buffer, &rec_rdr);
    };

    try initExampleHandshake(&h);
    try h.readEncryptedServerFlight1(null, "example.ulfheim.net");

    { // application cipher keys calculation
        try testing.expectEqualSlices(u8, &data13.handshake_hash, &h.transcript.sha384.hash.peek());

        const cipher = try Cipher.initTLS13(h.cipher_suite_tag, h.transcript.applicationSecret());
        const c = &cipher.AES_256_GCM_SHA384;
        try testing.expectEqualSlices(u8, &data13.server_application_key, &c.server_key);
        try testing.expectEqualSlices(u8, &data13.client_application_key, &c.client_key);
        try testing.expectEqualSlices(u8, &data13.server_application_iv, &c.server_iv);
        try testing.expectEqualSlices(u8, &data13.client_application_iv, &c.client_iv);

        const encrypted = try cipher.encrypt(&buffer, 0, .application_data, "ping");
        try testing.expectEqualSlices(u8, &data13.client_ping_wrapped, encrypted);
    }
    { // client finished message
        const client_finished = h.transcript.clientFinishedTLS13();
        try testing.expectEqualSlices(u8, &data13.client_finished_verify_data, client_finished[4..]);

        const encrypted = try h.cipher.encrypt(&buffer, 0, .handshake, client_finished);
        try testing.expectEqualSlices(u8, &data13.client_finished_wrapped, encrypted);
    }
}

test "create client hello" {
    var h = brk: {
        // init with predictable random data
        var random_buf: [TestHandshake.init_random_buf_len]u8 = undefined;
        testu.random(0).bytes(&random_buf);
        var buffer: [1024]u8 = undefined;
        break :brk try TestHandshake.initWithRandom(&buffer, undefined, random_buf);
    };

    const actual = try h.makeClientHello("google.com", .{
        .cipher_suites = &[_]CipherSuite{CipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
        .disable_keyber = true,
    });

    const expected = testu.hexToBytes(
        "16 03 03 00 7c " ++ // record header
            "01 00 00 78 " ++ // handshake header
            "03 03 " ++ // protocol version
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f " ++ // client random
            "00 " ++ // no session id
            "00 02 c0 2b " ++ // cipher suites
            "01 00 " ++ // compression methods
            "00 4d " ++ // extensions length
            "00 2b 00 03 02 03 03 " ++ // supported versions extension
            "00 0b 00 02 01 00 " ++ // ec point formats extension
            "ff 01 00 01 00 " ++ // renegotiation info extension
            "00 12 00 00 " ++ // sct extension
            "00 0d 00 14 00 12 04 03 05 03 08 04 08 05 08 06 08 07 02 01 04 01 05 01 " ++ // signature algorithms extension
            "00 0a 00 08 00 06 00 1d 00 17 00 18 " ++ // named groups extension
            "00 00 00 0f 00 0d 00 00 0a 67 6f 6f 67 6c 65 2e 63 6f 6d ", // server name extension
    );
    try testing.expectEqualSlices(u8, &expected, actual);
}

test "handshake verify server finished message" {
    var buffer: [1024]u8 = undefined;
    var rec_rdr = testReader(&data12.server_handshake_finished_msgs);
    var h = try TestHandshake.init(&buffer, &rec_rdr);

    h.cipher_suite_tag = .ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    h.master_secret = data12.master_secret;

    // add handshake messages to the transcript
    for (data12.handshake_messages) |msg| {
        h.transcript.update(msg[tls.record_header_len..]);
    }

    // expect verify data
    const client_finished = h.transcript.clientFinishedTLS12(&h.master_secret);
    try testing.expectEqualSlices(u8, &data12.client_finished, &client_finished);

    // init client with prepared key_material
    h.cipher = try Cipher.initTLS12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &data12.key_material, crypto.random);

    // check that server verify data matches calculates from hashes of all handshake messages
    h.transcript.update(&data12.client_finished);
    try h.readServerFlight2();
}
