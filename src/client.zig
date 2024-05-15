const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const posix = std.posix;
const mem = std.mem;

const tls = crypto.tls;
const tls12 = @import("tls12.zig");
const AppCipher = @import("cipher.zig").AppCipher;
const Transcript = @import("cipher.zig").Transcript;

const Certificate = crypto.Certificate;
const rsa = Certificate.rsa;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;

pub fn client(stream: anytype) ClientT(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .reader = recordReader(stream),
    };
}

pub fn ClientT(comptime StreamType: type) type {
    const RecordReaderType = RecordReader(StreamType);
    return struct {
        stream: StreamType,
        reader: RecordReaderType,

        app_cipher: AppCipher = undefined,
        client_sequence: usize = 0,
        server_sequence: usize = 0,

        const Client = @This();

        pub fn handshake(c: *Client, host: []const u8, ca_bundle: ?Certificate.Bundle) !void {
            var h = try Handshake.init();
            try h.clientHello(host, &c.stream);
            try h.serverHello(&c.reader, ca_bundle, host);

            if (h.cipher_suite_tag.keyExchange() == .ecdhe)
                try h.verifySignature();
            try h.generateKeyMaterial();
            c.app_cipher = try AppCipher.init(h.cipher_suite_tag, &h.key_material, crypto.random);

            try h.clientHandshakeFinished(c);
            try h.serverHandshakeFinished(c);

            // // TODO remove debug
            // std.debug.print(
            //     " chipher: {}, namded_group: {}, signature scheme: {} ",
            //     .{ h.cipher_suite_tag, h.named_group, h.signature_scheme },
            // );
        }

        /// Low level api. Cleartext can't be greater than tls record
        /// (16K). Buffer has to be bigger than cleartext for encryption
        /// overhead (AppCipherT.max_overhead = 52 bytes).
        ///
        /// Cleartext can be part of the buffer but has to start at byte 16 or
        /// later.
        pub fn write(c: *Client, buffer: []u8, cleartext: []const u8) !void {
            try c.write_(buffer, .application_data, cleartext);
        }

        fn write_(c: *Client, buffer: []u8, content_type: tls.ContentType, cleartext: []const u8) !void {
            assert(cleartext.len <= tls.max_cipertext_inner_record_len);
            assert(buffer.len >= c.app_cipher.minEncryptBufferLen(cleartext.len));

            const payload = try c.encrypt(buffer, content_type, cleartext);
            const header = tls12.recordHeader(content_type, payload.len);

            var iovecs = [_]posix.iovec_const{
                .{ .iov_base = &header, .iov_len = header.len },
                .{ .iov_base = payload.ptr, .iov_len = payload.len },
            };
            try c.stream.writevAll(&iovecs);
        }

        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try client.next()) |buf| { ... }
        pub fn next(c: *Client) !?[]const u8 {
            return c.next_(.application_data);
        }

        fn next_(c: *Client, content_type: tls.ContentType) !?[]const u8 {
            const rec = (try c.reader.next()) orelse return null;
            if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

            const cleartext = try c.decrypt(rec.payload, rec.content_type, rec.payload);
            switch (rec.content_type) {
                .handshake, .application_data => {
                    if (rec.content_type != content_type) return error.TlsUnexpectedMessage;
                    return cleartext;
                },
                .alert => {
                    if (cleartext.len < 2) return error.TlsAlertUnknown;
                    const level: tls.AlertLevel = @enumFromInt(cleartext[0]);
                    const desc: tls.AlertDescription = @enumFromInt(cleartext[1]);
                    _ = level;
                    try desc.toError();
                    return null; // (level == .warning and desc == .close_notify)
                },
                else => return error.TlsUnexpectedMessage,
            }
        }

        fn encrypt(c: *Client, buffer: []u8, content_type: tls.ContentType, cleartext: []const u8) ![]const u8 {
            assert(buffer.len >= c.app_cipher.minEncryptBufferLen(cleartext.len));

            const ad = additonalData(c.client_sequence, content_type, cleartext.len);
            c.client_sequence += 1;
            return switch (c.app_cipher) {
                inline else => |*p| p.encrypt(buffer, &ad, cleartext),
            };
        }

        fn decrypt(c: *Client, buffer: []u8, content_type: tls.ContentType, payload: []const u8) ![]const u8 {
            var ad = additonalData(c.server_sequence, content_type, 0);
            c.server_sequence += 1;
            return switch (c.app_cipher) {
                inline else => |*p| p.decrypt(buffer, &ad, payload),
            };
        }

        fn additonalData(sequence: u64, content_type: tls.ContentType, cleartext_len: usize) [13]u8 {
            var sequence_buf: [8]u8 = undefined;
            mem.writeInt(u64, &sequence_buf, sequence, .big);
            return sequence_buf ++ tls12.recordHeader(content_type, cleartext_len);
        }

        pub fn close(c: *Client) !void {
            var buffer: [AppCipher.max_overhead + tls.record_header_len + tls12.close_notify_alert.len]u8 = undefined;
            const payload = try c.encrypt(buffer[tls.record_header_len..], .alert, &tls12.close_notify_alert);
            buffer[0..tls.record_header_len].* = tls12.recordHeader(.alert, payload.len);
            try c.stream.writeAll(buffer[0 .. tls.record_header_len + payload.len]);
        }

        const Handshake = struct {
            const master_secret_len = 48;
            const key_material_len = 32 * 4;

            client_random: [32]u8,
            server_random: [32]u8 = undefined,
            master_secret: [master_secret_len]u8 = undefined,
            key_material: [key_material_len]u8 = undefined,

            transcript: Transcript = .{},

            cipher_suite_tag: tls12.CipherSuite = undefined,
            named_group: ?tls.NamedGroup = null,
            dh_kp: DhKeyPair,
            rsa_kp: RsaKeyPair,
            signature_scheme: tls.SignatureScheme = undefined,

            now_sec: i64 = 0,

            cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,
            cert_pub_key_buf: [600]u8 = undefined,
            cert_pub_key: []const u8 = undefined,

            server_pub_key_buf: [97]u8 = undefined,
            server_pub_key: []const u8 = undefined,
            signature_buf: [1024]u8 = undefined,
            signature: []const u8 = undefined,

            pub fn init() !Handshake {
                var rand_buf: [32 + 48 + 46]u8 = undefined;
                crypto.random.bytes(&rand_buf);

                return .{
                    .client_random = rand_buf[0..32].*,
                    .dh_kp = try DhKeyPair.init(rand_buf[32..][0..48].*),
                    .rsa_kp = RsaKeyPair.init(rand_buf[32 + 48 ..][0..46].*),
                    .now_sec = std.time.timestamp(),
                };
            }

            /// Send client hello message.
            fn clientHello(h: *Handshake, host: []const u8, stream: *StreamType) !void {
                //try std.fs.cwd().writeFile("client_random", &h.client_random);

                const enum_array = tls.enum_array;
                const host_len: u16 = @intCast(host.len);

                const extensions_payload =
                    tls12.extension.ec_point_formats ++
                    tls12.extension.renegotiation_info ++
                    tls12.extension.sct ++
                    tls.extension(.signature_algorithms, enum_array(tls.SignatureScheme, &.{
                    .ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384,

                    .rsa_pss_rsae_sha256,
                    .rsa_pss_rsae_sha384,
                    .rsa_pss_rsae_sha512,
                    //.rsa_pss_pss_sha256,
                    //
                    // .ed25519,
                    .rsa_pkcs1_sha1, // en.wikipedia.org sends alert if this one is not enabled and then choses rsa_pss_rsae_sha256 !?
                    .rsa_pkcs1_sha256,
                    .rsa_pkcs1_sha384, // dailymotion.com somehow requires this one
                })) ++
                    tls.extension(.supported_groups, enum_array(tls.NamedGroup, &.{
                    .x25519,
                    .secp256r1,
                    .secp384r1,
                })) ++
                    tls12.serverNameExtensionHeader(host_len);

                const payload =
                    tls12.hello.protocol_version ++
                    h.client_random ++
                    tls12.hello.no_session_id ++
                    enum_array(tls12.CipherSuite, &tls12.CipherSuite.supported) ++
                    tls12.hello.no_compression ++
                    tls.int2(@intCast(extensions_payload.len + host_len)) ++
                    extensions_payload;

                const record =
                    tls12.handshakeHeader(.client_hello, payload.len + host_len) ++
                    payload;

                h.transcript.update(record[tls.record_header_len..]);
                h.transcript.update(host);

                var iovecs = [_]posix.iovec_const{
                    .{ .iov_base = &record, .iov_len = record.len },
                    .{ .iov_base = host.ptr, .iov_len = host.len },
                };
                try stream.writevAll(&iovecs);
            }

            /// Read server hello, certificate, key_exchange and hello done messages.
            /// Extract server public key and server random.
            fn serverHello(h: *Handshake, reader: *RecordReaderType, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
                var handshake_state = tls12.HandshakeType.server_hello;

                var prev_cert: Certificate.Parsed = undefined;

                while (true) {
                    var rec = (try reader.next()) orelse return error.TlsUnexpectedMessage;
                    if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                    try rec.expectContentType(.handshake);
                    h.transcript.update(rec.payload);

                    // Multiple handshake messages can be packed in single tls record.
                    while (!rec.eof()) {
                        const handshake_type = try rec.decode(tls12.HandshakeType);
                        if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;

                        const length = try rec.decode(u24);
                        if (length > tls.max_cipertext_inner_record_len)
                            return error.TlsUnsupportedFragmentedHandshakeMessage;

                        switch (handshake_type) {
                            .server_hello => { // server hello, ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.3
                                // try std.fs.cwd().writeFile("server_hello", reader.buffer[0..reader.end]);

                                if (try rec.decode(tls.ProtocolVersion) != tls.ProtocolVersion.tls_1_2)
                                    return error.TlsBadVersion;
                                h.server_random = (try rec.array(32)).*;

                                const session_id_len = try rec.decode(u8);
                                if (session_id_len > 32) return error.TlsIllegalParameter;
                                try rec.skip(session_id_len);

                                h.cipher_suite_tag = try rec.decode(tls12.CipherSuite);
                                try h.cipher_suite_tag.validate();
                                try rec.skip(1); // skip compression method

                                const extensions_present = length > 2 + 32 + session_id_len + 2 + 1;
                                if (extensions_present) {
                                    const extensions_size = try rec.decode(u16);
                                    try rec.skip(extensions_size);
                                }

                                handshake_state = .certificate;
                            },
                            .certificate => {
                                var trust_chain_established = false;
                                const certs_len = try rec.decode(u24);

                                var l: usize = 0;
                                while (l < certs_len) {
                                    const cert_len = try rec.decode(u24);
                                    defer l += cert_len + 3;

                                    const cert = try rec.slice(cert_len);
                                    if (trust_chain_established) continue;
                                    const subject_cert: Certificate = .{ .buffer = cert, .index = 0 };
                                    const subject = try subject_cert.parse();

                                    if (l == 0) { // first certificate
                                        try subject.verifyHostName(host);
                                        h.cert_pub_key = try dupe(&h.cert_pub_key_buf, subject.pubKey());
                                        h.cert_pub_key_algo = subject.pub_key_algo;
                                        prev_cert = subject;
                                    } else {
                                        if (prev_cert.verify(subject, h.now_sec)) {
                                            prev_cert = subject;
                                        } else |_| {
                                            // skip certificate which is not part of the chain
                                            continue;
                                        }
                                    }
                                    if (ca_bundle) |cb| {
                                        if (cb.verify(prev_cert, h.now_sec)) |_| {
                                            trust_chain_established = true;
                                        } else |err| switch (err) {
                                            error.CertificateIssuerNotFound => {},
                                            else => |e| return e,
                                        }
                                    }
                                }
                                if (ca_bundle != null and !trust_chain_established) {
                                    return error.CertificateIssuerNotFound;
                                }
                                handshake_state = if (h.cipher_suite_tag.keyExchange() == .rsa)
                                    .server_hello_done
                                else
                                    .server_key_exchange;
                            },
                            .server_key_exchange => {
                                const curve_type = try rec.decode(tls12.CurveType);
                                h.named_group = try rec.decode(tls.NamedGroup);
                                h.server_pub_key = try dupe(&h.server_pub_key_buf, try rec.slice(try rec.decode(u8)));
                                h.signature_scheme = try rec.decode(tls.SignatureScheme);
                                h.signature = try dupe(&h.signature_buf, try rec.slice(try rec.decode(u16)));
                                if (curve_type != .named_curve) return error.TlsIllegalParameter;

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

            fn verifySignature(h: *Handshake) !void {
                const verify_bytes = brk: {
                    // public key len:
                    // x25519 = 32
                    // secp256r1 = 65
                    // secp384r1 = 97
                    var buf: [32 + 32 + 1 + 2 + 1 + 97]u8 = undefined;

                    var w = BufWriter{ .buf = &buf };
                    try w.write(&h.client_random);
                    try w.write(&h.server_random);
                    try w.writeEnum(tls12.CurveType.named_curve);
                    try w.writeEnum(h.named_group.?);
                    try w.writeInt(@as(u8, @intCast(h.server_pub_key.len)));
                    try w.write(h.server_pub_key);
                    break :brk w.getWritten();
                };
                switch (h.signature_scheme) {
                    inline .ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384,
                    => |comptime_scheme| {
                        if (h.cert_pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;

                        const cert_named_curve = h.cert_pub_key_algo.X9_62_id_ecPublicKey;
                        switch (cert_named_curve) {
                            inline else => |comptime_cert_named_curve| {
                                const Ecdsa = SchemeEcdsa(comptime_scheme, comptime_cert_named_curve);
                                const key = try Ecdsa.PublicKey.fromSec1(h.cert_pub_key);
                                const sig = try Ecdsa.Signature.fromDer(h.signature);
                                try sig.verify(verify_bytes, key);
                            },
                        }
                    },

                    inline .rsa_pss_rsae_sha256,
                    .rsa_pss_rsae_sha384,
                    .rsa_pss_rsae_sha512,
                    => |comptime_scheme| {
                        if (h.cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                        const Hash = SchemeHash(comptime_scheme);
                        const pk = try rsa.PublicKey.parseDer(h.cert_pub_key);
                        switch (pk.modulus.len) {
                            inline 128, 256, 512 => |modulus_len| {
                                const key = try rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
                                const sig = rsa.PSSSignature.fromBytes(modulus_len, h.signature);
                                try rsa.PSSSignature.verify(modulus_len, sig, verify_bytes, key, Hash);
                            },
                            else => {
                                return error.TlsBadRsaSignatureBitCount;
                            },
                        }
                    },
                    inline .rsa_pkcs1_sha1,
                    .rsa_pkcs1_sha256,
                    .rsa_pkcs1_sha384,
                    .rsa_pkcs1_sha512,
                    => |comptime_scheme| {
                        if (h.cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                        const Hash = SchemeHash(comptime_scheme);
                        try verifyRsa(Hash, verify_bytes, h.signature, h.cert_pub_key_algo, h.cert_pub_key);
                    },
                    else => return error.TlsUnknownSignatureScheme,
                }
            }

            fn SchemeEcdsa(comptime scheme: tls.SignatureScheme, comptime cert_named_curve: Certificate.NamedCurve) type {
                return switch (scheme) {
                    .ecdsa_secp256r1_sha256 => switch (cert_named_curve) {
                        .secp384r1 => crypto.sign.ecdsa.Ecdsa(crypto.ecc.P384, crypto.hash.sha2.Sha256),
                        else => EcdsaP256Sha256,
                    },
                    .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
                    else => @compileError("bad scheme"),
                };
            }

            fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
                return switch (scheme) {
                    .rsa_pkcs1_sha1 => crypto.hash.Sha1,
                    .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => crypto.hash.sha2.Sha256,
                    .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => crypto.hash.sha2.Sha384,
                    .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => crypto.hash.sha2.Sha512,
                    else => @compileError("bad scheme"),
                };
            }

            fn generateKeyMaterial(h: *Handshake) !void {
                const pre_master_secret = if (h.named_group) |named_group|
                    try h.dh_kp.preMasterSecret(named_group, h.server_pub_key)
                else
                    &h.rsa_kp.pre_master_secret;

                h.master_secret = Transcript.masterSecret(
                    master_secret_len,
                    h.cipher_suite_tag,
                    pre_master_secret,
                    h.client_random,
                    h.server_random,
                );
                h.key_material = Transcript.keyMaterial(
                    key_material_len,
                    h.cipher_suite_tag,
                    &h.master_secret,
                    h.client_random,
                    h.server_random,
                );
            }

            /// Sends client key exchange, client chiper spec and client
            /// handshake finished messages.
            fn clientHandshakeFinished(h: *Handshake, c: *Client) !void {
                const key: []const u8 = if (h.named_group) |named_group|
                    try h.dh_kp.publicKey(named_group)
                else
                    try h.rsa_kp.publicKey(h.cert_pub_key_algo, h.cert_pub_key);

                const key_exchange = if (h.named_group != null)
                    &tls12.handshakeHeader(.client_key_exchange, 1 + key.len) ++
                        tls12.int1(@intCast(key.len))
                else
                    &tls12.handshakeHeader(.client_key_exchange, 2 + key.len) ++
                        tls12.int2(@intCast(key.len));

                h.transcript.update(key_exchange[tls.record_header_len..]);
                h.transcript.update(key);

                const change_cipher_spec =
                    tls12.recordHeader(.change_cipher_spec, 1) ++
                    tls12.int1(1);

                const client_finished = h.transcript.clientFinished(h.cipher_suite_tag, &h.master_secret);
                const handshake_finished = brk: {
                    // encrypt client_finished into handshake_finished record
                    var buffer: [AppCipher.max_overhead + 5 + 16]u8 = undefined;
                    const payload = try c.encrypt(buffer[5..], .handshake, &client_finished);
                    buffer[0..tls.record_header_len].* = tls12.recordHeader(.handshake, payload.len);
                    break :brk buffer[0 .. tls.record_header_len + payload.len];
                };
                h.transcript.update(&client_finished);

                var iovecs = [_]posix.iovec_const{
                    .{ .iov_base = key_exchange.ptr, .iov_len = key_exchange.len },
                    .{ .iov_base = key.ptr, .iov_len = key.len },
                    .{ .iov_base = &change_cipher_spec, .iov_len = change_cipher_spec.len },
                    .{ .iov_base = handshake_finished.ptr, .iov_len = handshake_finished.len },
                };
                try c.stream.writevAll(&iovecs);
            }

            fn serverHandshakeFinished(h: *Handshake, c: *Client) !void {
                { // parse change ciperh spec message
                    var rec = (try c.reader.next()) orelse return error.EndOfStream;
                    if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                    try rec.expectContentType(.change_cipher_spec);
                }
                { // parse server handshake finished
                    const server_finished = try c.next_(.handshake) orelse return error.EndOfStream;
                    const expected_server_finished = h.transcript.serverFinished(h.cipher_suite_tag, &h.master_secret);
                    if (!mem.eql(u8, server_finished, &expected_server_finished))
                        // TODO should we write alert message
                        return error.TlsBadRecordMac;
                }
            }
        };
    };
}

const testing = std.testing;
const example = @import("testdata/example.zig");
const bytesToHex = std.fmt.bytesToHex;
const hexToBytes = std.fmt.hexToBytes;

test "Handshake.serverHello" {
    const stream = TestStream.init(&example.server_hello_responses, "");
    var h = try ClientT(TestStream).Handshake.init();
    var reader = recordReader(stream);
    // Set to known instead of random
    h.client_random = example.client_random;
    h.dh_kp.x25519_kp.secret_key = example.client_secret;

    // Parse server hello, certificate and key exchange messages.
    // Read cipher suite, named group, signature scheme, server random certificate public key
    // Verify host name, signature
    // Calculate key material
    try h.serverHello(&reader, null, "example.ulfheim.net");
    try testing.expectEqual(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, h.cipher_suite_tag);
    try testing.expectEqual(.x25519, h.named_group.?);
    try testing.expectEqual(.rsa_pkcs1_sha256, h.signature_scheme);
    try testing.expectEqualSlices(u8, &example.server_random, &h.server_random);
    try testing.expectEqualSlices(u8, &example.server_pub_key, h.server_pub_key);
    try testing.expectEqualSlices(u8, &example.signature, h.signature);
    try testing.expectEqualSlices(u8, &example.cert_pub_key, h.cert_pub_key);

    try h.verifySignature();
    try h.generateKeyMaterial();

    try testing.expectEqualSlices(u8, &example.key_material, &h.key_material);
}

test "Client encrypt decrypt" {
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);

    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&example.server_pong, &output_buf);
    var c = client(stream);
    c.app_cipher = try AppCipher.init(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, &example.key_material, rnd);

    var encrypt_buffer: [1024]u8 = undefined;
    c.stream.output.reset();
    { // encrypt verify data from example
        c.client_sequence = 0; //
        test_rnd.idx = 0x40; // sets iv to 40, 41, ... 4f
        try c.write_(&encrypt_buffer, .handshake, &example.client_finished);
        try testing.expectEqualSlices(u8, &example.verify_data_encrypted_msg, c.stream.output.getWritten());
    }

    c.stream.output.reset();
    { // encrypt ping
        const cleartext = "ping";
        test_rnd.idx = 0; // sets iv to 00, 01, ... 0f
        c.client_sequence = 1;

        try c.write(&encrypt_buffer, cleartext);
        try testing.expectEqualSlices(u8, &example.encrypted_ping_msg, c.stream.output.getWritten());
    }
    { // descrypt server pong message
        c.server_sequence = 1;
        try testing.expectEqualStrings("pong", (try c.next()).?);
    }
}

test "Handshake.verifyData" {
    var h = try ClientT(TestStream).Handshake.init();
    h.cipher_suite_tag = .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    h.master_secret = example.master_secret;

    // add handshake messages to the transcript
    for (example.handshake_messages) |msg| {
        h.transcript.update(msg[tls.record_header_len..]);
    }

    // expect verify data
    const client_finished = h.transcript.clientFinished(h.cipher_suite_tag, &h.master_secret);
    try testing.expectEqualSlices(u8, &example.client_finished, &client_finished);

    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&example.server_handshake_finished_msgs, &output_buf);
    // init client with prepared key_material
    var c = client(stream);
    c.app_cipher = try AppCipher.init(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, &example.key_material, crypto.random);

    // check that server verify data matches calculates from hashes of all handshake messages
    h.transcript.update(&example.client_finished);
    try h.serverHandshakeFinished(&c);
}

const TestStream = struct {
    output: std.io.FixedBufferStream([]u8) = undefined,
    input: std.io.FixedBufferStream([]const u8) = undefined,

    pub fn init(input: []const u8, output: []u8) TestStream {
        return .{
            .input = std.io.fixedBufferStream(input),
            .output = std.io.fixedBufferStream(output),
        };
    }

    pub fn writevAll(self: *TestStream, iovecs: []posix.iovec_const) !void {
        for (iovecs) |iovec| {
            var buf: []const u8 = undefined;
            buf.ptr = iovec.iov_base;
            buf.len = iovec.iov_len;
            _ = try self.output.write(buf);
        }
    }

    pub fn read(self: *TestStream, buffer: []u8) !usize {
        return self.input.read(buffer);
    }
};

// To have predictable random numbers in tests
const TestRnd = struct {
    idx: u8 = 0,

    // returns 0,1,2..0xff,0,1...
    pub fn fillFn(self: *@This(), buf: []u8) void {
        for (buf) |*v| {
            v.* = self.idx;
            self.idx +%= 1;
        }
    }
};

const Record = struct {
    content_type: tls.ContentType,
    protocol_version: tls.ProtocolVersion,
    payload: []u8,
    idx: usize = 0,

    pub fn decode(r: *Record, comptime T: type) !T {
        switch (@typeInfo(T)) {
            .Int => |info| switch (info.bits) {
                8 => {
                    try skip(r, 1);
                    return r.payload[r.idx - 1];
                },
                16 => {
                    try skip(r, 2);
                    const b0: u16 = r.payload[r.idx - 2];
                    const b1: u16 = r.payload[r.idx - 1];
                    return (b0 << 8) | b1;
                },
                24 => {
                    try skip(r, 3);
                    const b0: u24 = r.payload[r.idx - 3];
                    const b1: u24 = r.payload[r.idx - 2];
                    const b2: u24 = r.payload[r.idx - 1];
                    return (b0 << 16) | (b1 << 8) | b2;
                },
                else => @compileError("unsupported int type: " ++ @typeName(T)),
            },
            .Enum => |info| {
                const int = try r.decode(info.tag_type);
                if (info.is_exhaustive) @compileError("exhaustive enum cannot be used");
                return @as(T, @enumFromInt(int));
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }

    pub fn array(r: *Record, comptime len: usize) !*[len]u8 {
        try r.skip(len);
        return r.payload[r.idx - len ..][0..len];
    }

    pub fn slice(r: *Record, len: usize) ![]u8 {
        try r.skip(len);
        return r.payload[r.idx - len ..][0..len];
    }

    pub fn skip(r: *Record, amt: usize) !void {
        if (r.idx + amt > r.payload.len) return error.TlsDecodeError;
        r.idx += amt;
    }

    pub fn rest(r: Record) []u8 {
        return r.payload[r.idx..];
    }

    pub fn eof(r: Record) bool {
        return r.idx == r.payload.len;
    }

    pub fn expectContentType(rec: *Record, content_type: tls.ContentType) !void {
        if (rec.content_type == content_type) return;

        switch (rec.content_type) {
            .alert => {
                const level = try rec.decode(tls.AlertLevel);
                const desc = try rec.decode(tls.AlertDescription);
                _ = level;
                try desc.toError();
                return error.TlsServerSideClosure;
            },
            else => return error.TlsUnexpectedMessage,
        }
    }
};

fn RecordReader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,

        buffer: [tls.max_ciphertext_record_len]u8 = undefined,
        start: usize = 0,
        end: usize = 0,

        const Self = @This();

        pub fn next(c: *Self) !?Record {
            while (true) {
                const buffer = c.buffer[c.start..c.end];
                // If we have 5 bytes header.
                if (buffer.len >= tls.record_header_len) {
                    const record_header = buffer[0..tls.record_header_len];
                    const content_type: tls.ContentType = @enumFromInt(record_header[0]);
                    const protocol_version: tls.ProtocolVersion = @enumFromInt(mem.readInt(u16, record_header[1..3], .big));
                    const payload_len = mem.readInt(u16, record_header[3..5], .big);
                    if (payload_len > tls.max_ciphertext_len)
                        return error.TlsRecordOverflow;
                    // If we have whole record
                    if (buffer[tls.record_header_len..].len >= payload_len) {
                        const payload = buffer[tls.record_header_len .. tls.record_header_len + payload_len];
                        c.start += tls.record_header_len + payload_len;
                        return .{
                            .content_type = content_type,
                            .protocol_version = protocol_version,
                            .payload = payload,
                        };
                    }
                }
                { // Move dirty part to the start of the buffer.
                    const n = c.end - c.start;
                    if (n > 0 and c.start > 0) {
                        if (c.start > n) {
                            @memcpy(c.buffer[0..n], c.buffer[c.start..][0..n]);
                        } else {
                            mem.copyForwards(u8, c.buffer[0..n], c.buffer[c.start..][0..n]);
                        }
                    }
                    c.start = 0;
                    c.end = n;
                }
                { // Read more from inner_reader.
                    const n = try c.inner_reader.read(c.buffer[c.end..]);
                    if (n == 0) return null;
                    c.end += n;
                }
            }
        }
    };
}

pub fn recordReader(reader: anytype) RecordReader(@TypeOf(reader)) {
    return .{ .inner_reader = reader };
}

test "RecordReader" {
    var fbs = std.io.fixedBufferStream(&example.server_responses);
    var rdr = recordReader(fbs.reader());

    const expected = [_]struct {
        content_type: tls.ContentType,
        payload_len: usize,
    }{
        .{ .content_type = .handshake, .payload_len = 49 },
        .{ .content_type = .handshake, .payload_len = 815 },
        .{ .content_type = .handshake, .payload_len = 300 },
        .{ .content_type = .handshake, .payload_len = 4 },
        .{ .content_type = .change_cipher_spec, .payload_len = 1 },
        .{ .content_type = .handshake, .payload_len = 64 },
    };
    var i: usize = 0;
    while (try rdr.next()) |rec| {
        const e = expected[i];
        i += 1;
        try testing.expectEqual(e.content_type, rec.content_type);
        try testing.expectEqual(e.payload_len, rec.payload.len);
        try testing.expectEqual(.tls_1_2, rec.protocol_version);
    }
}

test "Record decoder" {
    var fbs = std.io.fixedBufferStream(&example.server_responses);
    var rdr = recordReader(fbs.reader());

    var rec = (try rdr.next()).?;
    try testing.expectEqual(.handshake, rec.content_type);

    try testing.expectEqual(.server_hello, try rec.decode(tls12.HandshakeType));
    try testing.expectEqual(45, try rec.decode(u24)); // length
    try testing.expectEqual(.tls_1_2, try rec.decode(tls.ProtocolVersion));
    try testing.expectEqualStrings(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        &bytesToHex(try rec.array(32), .lower),
    ); // server random
    try testing.expectEqual(0, try rec.decode(u8)); // session id len
    try testing.expectEqual(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, try rec.decode(tls12.CipherSuite));
    try testing.expectEqual(0, try rec.decode(u8)); // compression method
    try testing.expectEqual(5, try rec.decode(u16)); // extension length
    try testing.expectEqual(5, rec.rest().len);
    try rec.skip(5);
    try testing.expect(rec.eof());
}

fn bufPrint(var_name: []const u8, buf: []const u8) void {
    std.debug.print("\nconst {s} = [_]u8{{\n", .{var_name});
    for (buf, 1..) |b, i| {
        std.debug.print("0x{x:0>2}, ", .{b});
        if (i % 16 == 0)
            std.debug.print("\n", .{});
    }
    std.debug.print("}};\n", .{});

    // std.debug.print("const {s} = \"", .{var_name});
    // const charset = "0123456789abcdef";
    // for (buf) |b| {
    //     const x = charset[b >> 4];
    //     const y = charset[b & 15];
    //     std.debug.print("\\x{c}{c}", .{ x, y });
    // }
    // std.debug.print("\"\n", .{});
}

test "verify google.com certificate" {
    const stream = TestStream.init(@embedFile("testdata/google.com/server_hello"), "");
    var h = try ClientT(TestStream).Handshake.init();
    h.now_sec = 1714846451;
    h.client_random = @embedFile("testdata/google.com/client_random").*;

    var rdr = recordReader(stream);

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(testing.allocator);
    defer ca_bundle.deinit(testing.allocator);

    try h.serverHello(&rdr, ca_bundle, "google.com");
    try h.verifySignature();
}

fn dupe(buf: []u8, data: []const u8) ![]u8 {
    if (data.len > buf.len) return error.BufferOverflow;
    @memcpy(buf[0..data.len], data);
    return buf[0..data.len];
}

const BufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn write(self: *BufWriter, data: []const u8) !void {
        defer self.pos += data.len;
        _ = try dupe(self.buf[self.pos..], data);
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

    pub fn getWritten(self: *BufWriter) []const u8 {
        return self.buf[0..self.pos];
    }
};

test "BufWriter" {
    var buf: [16]u8 = undefined;
    var w = BufWriter{ .buf = &buf };

    try w.write("ab");
    try w.writeEnum(tls12.CurveType.named_curve);
    try w.writeEnum(tls.NamedGroup.x25519);
    try w.writeInt(@as(u16, 0x1234));
    try testing.expectEqualSlices(u8, &[_]u8{ 'a', 'b', 0x03, 0x00, 0x1d, 0x12, 0x34 }, w.getWritten());
}

const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,

    const seed_len = 48;

    fn init(seed: [seed_len]u8) !DhKeyPair {
        return .{
            .x25519_kp = try X25519.KeyPair.create(seed[0..X25519.seed_length].*),
            .secp256r1_kp = try EcdsaP256Sha256.KeyPair.create(seed[0..EcdsaP256Sha256.KeyPair.seed_length].*),
            .secp384r1_kp = try EcdsaP384Sha384.KeyPair.create(seed[0..EcdsaP384Sha384.KeyPair.seed_length].*),
        };
    }

    // 32
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
            else => return error.TlsIllegalParameter,
        };
    }

    // Returns 32, 65 or 97 bytes
    inline fn publicKey(self: DhKeyPair, named_group: tls.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => &self.secp256r1_kp.public_key.toUncompressedSec1(),
            .secp384r1 => &self.secp384r1_kp.public_key.toUncompressedSec1(),
            else => return error.TlsIllegalParameter,
        };
    }
};

const RsaKeyPair = struct {
    pre_master_secret: [48]u8,

    fn init(rand: [46]u8) RsaKeyPair {
        return .{ .pre_master_secret = tls12.hello.protocol_version ++ rand };
    }

    inline fn publicKey(
        self: RsaKeyPair,
        cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo,
        cert_pub_key: []const u8,
    ) ![]const u8 {
        if (cert_pub_key_algo != .rsaEncryption)
            return error.TlsBadSignatureScheme;

        const pk = try rsa.PublicKey.parseDer(cert_pub_key);
        switch (pk.modulus.len) {
            inline 128, 256, 512 => |modulus_len| {
                const msg_len = self.pre_master_secret.len;
                const pad_len = modulus_len - msg_len - 3;
                const padded_msg: [modulus_len]u8 =
                    [2]u8{ 0, 2 } ++
                    ([1]u8{0xff} ** pad_len) ++
                    [1]u8{0} ++
                    self.pre_master_secret;

                const key = try rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
                return &(try rsaEncrypt(modulus_len, padded_msg, key));
            },
            else => {
                return error.TlsBadRsaSignatureBitCount;
            },
        }
    }
};

test "RsaKeyPair" {
    var buf: [48 + 270 + 256]u8 = undefined;

    const seed = try hexToBytes(&buf, "23bc6aea3bf218e0154835af87536c8078b3cb9ed7be55579b6c55b36a503090584936ee572afeb19fd16ad333e4");
    const cert_pub_key = try hexToBytes(buf[46..], "3082010a0282010100893b748b32b7dee524a8e0add60d84265eb39b0221f99d1a2bf6011707de90bdadccae76b8ed2e7da1d565b573e9aeb3c316a6d5178ce26b2b4085a2e7bdf9f8372935f06407a183dcda00ba28ed9117093c49a306fb2e1ff4798562eb9a08eb7d70557a11c68b446a0e6f4aee9224886e5bdb07c00c02f3e5428d59f8bd2c79ea53e3e60e1331627f294f5185e7344bb27158fa1494c749cce9d9dafc4550189934e839904ef43252acfd670556e513721658b632cef88a05d825ad5aad83989f973cdad7e9362e465c3930a9fbfa9b245fffbdb6c75856b2457854b5848c79b7a4de6022290a56a0890732c12437c3dbed18004ab4754505b1554c254f66410203010001");
    const expected_key = try hexToBytes(buf[46 + 270 ..], "495fd4a3ff7b2bf5eb6c316b488559142c2678d3204df4408e9a6ccb0680a52739fc766136e6da92e17941c35e1e02150bfcf7830fe0a1443772bf88ca22b614e5d4df122a3e615e6d409bf4702d34effb0bba9f801b3a795f1ff88e483eaa2968a8f7d1fbddee0ac0ecb88c615b5787fd5daa2180ad9791df87dd7d589884414ebe02576bc136f1aa0d866951a29161d80a3339c92300f37c822c6d303919dc9776fa91c7de45d7b0092014b2e0f678daa81fae1530c90b1ef15eecb3aba2b285ba725a623b083aa70ada7adfebbfcbf8472a3cdd9337b92770e33c86f6180591a4f26db6822c95bc5cf379c9fcb3895561e60bf5be02845b96a3e3867c168b");

    var rsa_kp = RsaKeyPair.init(seed[0..46].*);
    try testing.expectEqualSlices(
        u8,
        expected_key,
        try rsa_kp.publicKey(.{ .rsaEncryption = {} }, cert_pub_key),
    );
}

test "DhKeyPair.x25519" {
    var buf: [48 + 32 + 32]u8 = undefined;
    const seed = try hexToBytes(&buf, "4f27a0ea9873d11f3330b88f9443811a5f79c2339dc90dc560b5b49d5e7fe73e496c893a4bbaf26f3288432c747d8bb2");
    const server_pub_key = try hexToBytes(buf[48..], "3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = try hexToBytes(buf[48 + 32 ..], "f8912817eb835341f70960290b550329968fea80445853bb91de2ab13ad91c15");

    const kp = try DhKeyPair.init(seed[0..48].*);
    try testing.expectEqualSlices(u8, expected, try kp.preMasterSecret(.x25519, server_pub_key));
}

// This is copy of the private method encrypt from std.crypto.Certificate.rsa
// If that method can be make public this can be removed.
pub fn rsaEncrypt(comptime modulus_len: usize, msg: [modulus_len]u8, public_key: rsa.PublicKey) ![modulus_len]u8 {
    const max_modulus_bits = 4096;
    const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
    const Fe = Modulus.Fe;

    const m = Fe.fromBytes(public_key.n, &msg, .big) catch return error.MessageTooLong;
    const e = public_key.n.powPublic(m, public_key.e) catch unreachable;
    var res: [modulus_len]u8 = undefined;
    e.toBytes(&res, .big) catch unreachable;
    return res;
}

// This is copy of the private method verifyRsa from std.crypto.Certificate
pub fn verifyRsa(
    comptime Hash: type,
    message: []const u8,
    sig: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    pub_key: []const u8,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.CertificateSignatureAlgorithmMismatch;
    const pk_components = try rsa.PublicKey.parseDer(pub_key);
    const exponent = pk_components.exponent;
    const modulus = pk_components.modulus;
    if (exponent.len > modulus.len) return error.CertificatePublicKeyInvalid;
    if (sig.len != modulus.len) return error.CertificateSignatureInvalidLength;

    const hash_der = switch (Hash) {
        crypto.hash.Sha1 => [_]u8{
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        },
        crypto.hash.sha2.Sha224 => [_]u8{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
            0x00, 0x04, 0x1c,
        },
        crypto.hash.sha2.Sha256 => [_]u8{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        crypto.hash.sha2.Sha384 => [_]u8{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        },
        crypto.hash.sha2.Sha512 => [_]u8{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unreachable"),
    };

    var msg_hashed: [Hash.digest_length]u8 = undefined;
    Hash.hash(message, &msg_hashed, .{});

    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const ps_len = modulus_len - (hash_der.len + msg_hashed.len) - 3;
            const em: [modulus_len]u8 =
                [2]u8{ 0, 1 } ++
                ([1]u8{0xff} ** ps_len) ++
                [1]u8{0} ++
                hash_der ++
                msg_hashed;

            const public_key = rsa.PublicKey.fromBytes(exponent, modulus) catch return error.CertificateSignatureInvalid;
            const em_dec = rsaEncrypt(modulus_len, sig[0..modulus_len].*, public_key) catch |err| switch (err) {
                error.MessageTooLong => unreachable,
            };

            if (!mem.eql(u8, &em, &em_dec)) {
                return error.CertificateSignatureInvalid;
            }
        },
        else => {
            return error.CertificateSignatureUnsupportedBitCount;
        },
    }
}
