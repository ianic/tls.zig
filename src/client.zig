const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const posix = std.posix;

const tls = crypto.tls;
const tls12 = @import("tls12.zig");
const AppCipherT = @import("cipher.zig").AppCipherT;

const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;

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

        app_cipher: AppCipherT = undefined,
        client_sequence: usize = 0,
        server_sequence: usize = 0,

        const Client = @This();

        pub fn handshake(c: *Client, host: []const u8) !void {
            var h = try Handshake.init();
            try h.clientHello(host, &c.stream);
            try h.serverHello(&c.reader);
            try h.generateClientKeys();
            c.app_cipher = try AppCipherT.init(h.cipher_suite_tag, &h.key_material, crypto.random);
            try h.clientHandshakeFinished(c);
            try h.serverHandshakeFinished(c);
        }

        /// Low level write interface. Doesn't allocate but requires provided
        /// buffer for encryption. Cleartext can't be greater than tls record
        /// (16K). Buffer has to be bigger than cleartext for encryption
        /// overhead (AppCipherT.max_overhead = 52 bytes).
        ///
        /// Cleartext can be part of the buffer but has to start at byte 16 or
        /// later.
        pub fn write(c: *Client, buffer: []u8, cleartext: []const u8) !void {
            try c.write_(buffer, .application_data, cleartext);
        }

        //var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
        fn write_(c: *Client, buffer: []u8, content_type: tls.ContentType, cleartext: []const u8) !void {
            assert(cleartext.len <= tls.max_cipertext_inner_record_len);
            assert(buffer.len >= c.app_cipher.minEncryptBufferLen(cleartext.len));

            const payload = try c.encrypt(buffer, content_type, cleartext);
            const header = tls12.recordHeader(content_type, payload.len);

            var iovecs = [_]std.posix.iovec_const{
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
            std.mem.writeInt(u64, &sequence_buf, sequence, .big);
            return sequence_buf ++ tls12.recordHeader(content_type, cleartext_len);
        }

        pub fn close(c: *Client) !void {
            var buffer: [AppCipherT.max_overhead + tls.record_header_len + tls12.close_notify_alert.len]u8 = undefined;
            const payload = try c.encrypt(buffer[tls.record_header_len..], .alert, &tls12.close_notify_alert);
            buffer[0..tls.record_header_len].* = tls12.recordHeader(.alert, payload.len);
            try c.stream.writeAll(buffer[0 .. tls.record_header_len + payload.len]);
        }

        const Handshake = struct {
            transcript: Sha256 = Sha256.init(.{}),

            client_random: [32]u8 = undefined,
            server_random: [32]u8 = undefined,
            server_public_key: []u8 = undefined,
            master_secret: [32 + 16]u8 = undefined,
            key_material: [32 * 4]u8 = undefined,

            cipher_suite_tag: tls12.CipherSuite = undefined,

            named_group: tls.NamedGroup = undefined,
            x25519_kp: X25519.KeyPair = undefined,
            secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,

            pub fn init() !Handshake {
                var random_buffer: [96]u8 = undefined;
                crypto.random.bytes(&random_buffer);

                return .{
                    .client_random = random_buffer[0..32].*,
                    .x25519_kp = try X25519.KeyPair.create(random_buffer[32..64].*),
                    .secp256r1_kp = try EcdsaP256Sha256.KeyPair.create(random_buffer[64..96].*),
                };
            }

            /// Send client hello message.
            fn clientHello(h: *Handshake, host: []const u8, stream: *StreamType) !void {
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
                    .ed25519,
                    .rsa_pkcs1_sha1,
                })) ++
                    tls.extension(.supported_groups, enum_array(tls.NamedGroup, &.{
                    .x25519,
                    .secp256r1,
                })) ++
                    tls12.serverNameExtensionHeader(host_len);

                const cipher_suites = enum_array(tls12.CipherSuite, &.{
                    .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,

                    .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                });

                const payload =
                    tls12.hello.protocol_version ++
                    h.client_random ++
                    tls12.hello.no_session_id ++
                    cipher_suites ++
                    tls12.hello.no_compression ++
                    tls.int2(@intCast(extensions_payload.len + host_len)) ++
                    extensions_payload;

                const record =
                    tls12.handshakeHeader(.client_hello, payload.len + host_len) ++
                    payload;

                h.transcript.update(record[tls.record_header_len..]);
                h.transcript.update(host);

                var iovecs = [_]std.posix.iovec_const{
                    .{ .iov_base = &record, .iov_len = record.len },
                    .{ .iov_base = host.ptr, .iov_len = host.len },
                };
                try stream.writevAll(&iovecs);
            }

            /// Read server hello, certificate, key_exchange and hello done messages.
            /// Extract server public key and server random.
            fn serverHello(h: *Handshake, reader: *RecordReaderType) !void {
                var handshake_state = tls12.HandshakeType.server_hello;
                while (true) {
                    var rec = (try reader.next()) orelse return error.TlsUnexpectedMessage;
                    if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

                    switch (rec.content_type) {
                        .alert => {
                            const level = try rec.decode(tls.AlertLevel);
                            const desc = try rec.decode(tls.AlertDescription);
                            _ = level;
                            try desc.toError();
                            return error.TlsServerSideClosure; // TODO
                        },
                        else => return error.TlsUnexpectedMessage,
                        .handshake => {}, // continue
                    }
                    h.transcript.update(rec.payload);

                    const handshake_type = try rec.decode(tls12.HandshakeType);
                    if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;
                    const length = try rec.decode(u24);

                    switch (handshake_type) {
                        .server_hello => { // server hello
                            if (try rec.decode(tls.ProtocolVersion) != tls.ProtocolVersion.tls_1_2) return error.TlsBadVersion;
                            h.server_random = (try rec.array(32)).*;
                            const session_id_len = try rec.decode(u8);
                            if (session_id_len > 32) return error.TlsIllegalParameter;
                            try rec.skip(session_id_len);

                            h.cipher_suite_tag = try rec.decode(tls12.CipherSuite);
                            try h.cipher_suite_tag.validate();
                            try rec.skip(1); // skip compression method

                            if (!rec.eof()) { // TODO is this because we didn't send any extension
                                const extensions_size = try rec.decode(u16);
                                try rec.skip(extensions_size);
                            }
                            handshake_state = .certificate;
                        },
                        .certificate => {
                            const certs_len = try rec.decode(u24);
                            var l: usize = 0;
                            while (l < certs_len) {
                                const cert_len = try rec.decode(u24);
                                const cert = try rec.slice(cert_len);
                                _ = cert; // TODO: check certificate
                                l += cert_len + 3;
                            }
                            handshake_state = .server_key_exchange;
                        },
                        .server_key_exchange => {
                            const named_curve = try rec.decode(u8);
                            if (named_curve != 0x03) return error.TlsIllegalParameter;
                            h.named_group = try rec.decode(tls.NamedGroup);

                            const key_len = try rec.decode(u8);
                            h.server_public_key = try rec.slice(key_len);

                            const rsa_signature = try rec.decode(u16);
                            const signature_len = try rec.decode(u16);
                            _ = rsa_signature; // TODO what to expect here

                            // TODO: how to check signature
                            try rec.skip(signature_len);

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

            fn generateClientKeys(h: *Handshake) !void {
                var pre_master_secret: []const u8 = undefined;

                switch (h.named_group) {
                    .x25519 => {
                        if (h.server_public_key.len != X25519.public_length)
                            return error.TlsIllegalParameter;
                        pre_master_secret = &(try X25519.scalarmult(
                            h.x25519_kp.secret_key,
                            h.server_public_key[0..X25519.public_length].*,
                        ));
                    },
                    .secp256r1 => {
                        const pk = try crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(h.server_public_key);
                        const mul = try pk.p.mulPublic(h.secp256r1_kp.secret_key.bytes, .big);
                        pre_master_secret = &mul.affineCoordinates().x.toBytes(.big);
                    },
                    else => {
                        return error.TlsIllegalParameter;
                    },
                }
                {
                    const seed = "master secret" ++ h.client_random ++ h.server_random;

                    var a1: [32]u8 = undefined;
                    var a2: [32]u8 = undefined;
                    HmacSha256.create(&a1, seed, pre_master_secret);
                    HmacSha256.create(&a2, &a1, pre_master_secret);

                    var p1: [32]u8 = undefined;
                    var p2: [32]u8 = undefined;
                    HmacSha256.create(&p1, a1 ++ seed, pre_master_secret);
                    HmacSha256.create(&p2, a2 ++ seed, pre_master_secret);

                    h.master_secret[0..32].* = p1;
                    h.master_secret[32..].* = p2[0..16].*;
                }
                {
                    const seed = "key expansion" ++ h.server_random ++ h.client_random;
                    const a0 = seed;

                    var a1: [32]u8 = undefined;
                    var a2: [32]u8 = undefined;
                    var a3: [32]u8 = undefined;
                    var a4: [32]u8 = undefined;
                    HmacSha256.create(&a1, a0, &h.master_secret);
                    HmacSha256.create(&a2, &a1, &h.master_secret);
                    HmacSha256.create(&a3, &a2, &h.master_secret);
                    HmacSha256.create(&a4, &a3, &h.master_secret);

                    HmacSha256.create(h.key_material[0..32], a1 ++ seed, &h.master_secret);
                    HmacSha256.create(h.key_material[32..64], a2 ++ seed, &h.master_secret);
                    HmacSha256.create(h.key_material[64..96], a3 ++ seed, &h.master_secret);
                    HmacSha256.create(h.key_material[96..], a4 ++ seed, &h.master_secret);
                }
            }

            /// Sends client key exchange, client chiper spec and client
            /// handshake finished messages.
            fn clientHandshakeFinished(h: *Handshake, c: *Client) !void {
                const key: []const u8 = switch (h.named_group) {
                    .x25519 => &h.x25519_kp.public_key,
                    .secp256r1 => &h.secp256r1_kp.public_key.toUncompressedSec1(),
                    else => unreachable,
                };

                const key_exchange =
                    tls12.handshakeHeader(.client_key_exchange, 1 + key.len) ++
                    tls12.int1(@intCast(key.len));

                h.transcript.update(key_exchange[tls.record_header_len..]);
                h.transcript.update(key);

                const change_cipher_spec =
                    tls12.recordHeader(.change_cipher_spec, 1) ++
                    tls12.int1(1);

                const handshake_finished = brk: {
                    var buffer: [AppCipherT.max_overhead + 5 + 16]u8 = undefined;
                    const payload = try c.encrypt(buffer[5..], .handshake, &h.verifyData());
                    buffer[0..tls.record_header_len].* = tls12.recordHeader(.handshake, payload.len);
                    break :brk buffer[0 .. tls.record_header_len + payload.len];
                };

                var iovecs = [_]std.posix.iovec_const{
                    .{ .iov_base = &key_exchange, .iov_len = key_exchange.len },
                    .{ .iov_base = key.ptr, .iov_len = key.len },
                    .{ .iov_base = &change_cipher_spec, .iov_len = change_cipher_spec.len },
                    .{ .iov_base = handshake_finished.ptr, .iov_len = handshake_finished.len },
                };
                try c.stream.writevAll(&iovecs);
            }

            fn verifyData(h: *Handshake) [16]u8 {
                const seed = "client finished" ++ h.transcript.finalResult();
                var a1: [32]u8 = undefined;
                var p1: [32]u8 = undefined;
                HmacSha256.create(&a1, seed, &h.master_secret);
                HmacSha256.create(&p1, a1 ++ seed, &h.master_secret);
                return [_]u8{ 0x14, 0x00, 0x00, 0x0c } ++ p1[0..12].*;
            }

            fn serverHandshakeFinished(h: *Handshake, c: *Client) !void {
                _ = h;
                { // read change ciperh spec message
                    const rec = (try c.reader.next()) orelse return error.EndOfStream;
                    if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                    if (rec.content_type != .change_cipher_spec) return error.TlsUnexpectedMessage;
                }
                { // read server handshake finished
                    // TODO check content of the handshake finished message
                    _ = try c.next_(.handshake);
                }
            }
        };
    };
}

const testing = std.testing;
const example = @import("example.zig");
const bytesToHex = std.fmt.bytesToHex;
const hexToBytes = std.fmt.hexToBytes;

test "Handshake.clientHello" {
    var output_buf: [1024]u8 = undefined;
    var stream = TestStream.init("", &output_buf);
    var h = try ClientT(TestStream).Handshake.init();
    _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const host = "www.example.com";
    try h.clientHello(host, &stream);
    const hello_buf = stream.output.getWritten();
    //bufPrint(hello_buf);
    try testing.expectEqualSlices(u8, &example.client_hello, hello_buf);
    try testing.expectEqualStrings(host, hello_buf[hello_buf.len - host.len ..]);
}

test "Handshake.serverHello" {
    const stream = TestStream.init(&example.server_hello_responses, "");
    var h = try ClientT(TestStream).Handshake.init();
    var reader = recordReader(stream);

    // read server random and server public key from server hello, certificate
    // and key exchange messages
    try h.serverHello(&reader);
    try testing.expectEqualStrings(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        &bytesToHex(h.server_random, .lower),
    );
    try testing.expectEqualStrings(
        "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615",
        &bytesToHex(h.server_public_key[0..32].*, .lower),
    );
    try testing.expectEqual(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, h.cipher_suite_tag);
}

test "Handshake.generateMasterSecret" {
    var h = try ClientT(TestStream).Handshake.init();

    { // init with known keys
        _ = try hexToBytes(h.x25519_kp.secret_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        _ = try hexToBytes(h.server_random[0..], "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var public_key_buf: [32]u8 = undefined;
        _ = try hexToBytes(&public_key_buf, "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
        h.server_public_key = &public_key_buf;
        h.cipher_suite_tag = .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        h.named_group = .x25519;
    }

    { // generate encryption keys
        try h.generateClientKeys();
        try testing.expectEqualStrings(
            "1b7d117c7d5f690bc263cae8ef60af0f1878acc22ad8bdd8c601a617126f63540eb20906f781fad2f656d037b173ef3e11169f27231a84b6752a18e7a9fcb7cbcdd8f98dd8f769eba0d2550c9238eebfef5c32251abb67d6434528db4937d540d393135e06a11bb80e45eaebe32cac72757438fbb3df645cbda4067cdfa0f848",
            &bytesToHex(h.key_material, .lower),
        );
    }
}

test "Client.init" {
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);

    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&example.server_responses, &output_buf);
    var c = client(stream);
    var h = try ClientT(TestStream).Handshake.init();

    { // init with known keys
        _ = try hexToBytes(h.x25519_kp.secret_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        _ = try hexToBytes(h.x25519_kp.public_key[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        _ = try hexToBytes(h.server_random[0..], "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var public_key_buf: [32]u8 = undefined;
        _ = try hexToBytes(&public_key_buf, "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
        h.server_public_key = &public_key_buf;

        h.cipher_suite_tag = .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        h.named_group = .x25519;
    }

    const host = "www.example.com";
    test_rnd.idx = 0x20;
    {
        try h.clientHello(host, &c.stream);
        try h.serverHello(&c.reader);
        try h.generateClientKeys();
        c.app_cipher = try AppCipherT.init(h.cipher_suite_tag, &h.key_material, rnd);
        try h.clientHandshakeFinished(&c);
        try h.serverHandshakeFinished(&c);
    }
    { // test messages that client sent
        const written = c.stream.output.getWritten();
        var pos: usize = 0;

        try testing.expectEqualSlices(u8, &example.client_hello, written[0..example.client_hello.len]);
        pos += example.client_hello.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_key_exchange,
            written[pos..][0..example.client_key_exchange.len],
        );
        pos += example.client_key_exchange.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_change_cyper_spec,
            written[pos..][0..example.client_change_cyper_spec.len],
        );
        pos += example.client_change_cyper_spec.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_handshake_finished,
            written[pos..][0..example.client_handshake_finished.len],
        );
        pos += example.client_handshake_finished.len;
    }

    var buffer: [1024]u8 = undefined;
    c.stream.output.reset();
    { // encrypt ping
        const cleartext = "ping";
        test_rnd.idx = 0;
        try c.write(&buffer, cleartext);

        const expected = [_]u8{
            0x17, 0x03, 0x03, 0x00, 0x30, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x6c, 0x42, 0x1c, 0x71, 0xc4, 0x2b, 0x18, 0x3b, 0xfa, 0x06, 0x19,
            0x5d, 0x13, 0x3d, 0x0a, 0x09, 0xd0, 0x0f, 0xc7, 0xcb, 0x4e, 0x0f, 0x5d, 0x1c, 0xda, 0x59, 0xd1,
            0x47, 0xec, 0x79, 0x0c, 0x99,
        };
        try testing.expectEqualSlices(u8, &expected, c.stream.output.getWritten());
    }

    c.stream.output.reset();
    { // encrypt verify data from illustrated example
        const data = [_]u8{
            0x14, 0x00, 0x00, 0x0c, 0xcf, 0x91, 0x96, 0x26, 0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a,
        };
        c.client_sequence = 0;
        test_rnd.idx = 0x40;
        try c.write_(&buffer, .handshake, &data);
        const expected = [_]u8{
            0x22, 0x7b, 0xc9, 0xba, 0x81, 0xef, 0x30, 0xf2, 0xa8, 0xa7, 0x8f, 0xf1, 0xdf, 0x50, 0x84, 0x4d,
            0x58, 0x04, 0xb7, 0xee, 0xb2, 0xe2, 0x14, 0xc3, 0x2b, 0x68, 0x92, 0xac, 0xa3, 0xdb, 0x7b, 0x78,
            0x07, 0x7f, 0xdd, 0x90, 0x06, 0x7c, 0x51, 0x6b, 0xac, 0xb3, 0xba, 0x90, 0xde, 0xdf, 0x72, 0x0f,
        };
        const actual = c.stream.output.getWritten()[5 + 16 ..]; // skip header and iv
        try testing.expectEqualSlices(u8, &expected, actual);
    }
}

test "Handshake.verifyData" {
    var h = try ClientT(TestStream).Handshake.init();
    h.master_secret = example.master_secret;

    // add handshake messages to transcript
    for (example.handshake_messages) |msg| {
        h.transcript.update(msg[tls.record_header_len..]);
    }

    // expect verify data
    const verify_data = h.verifyData();
    try testing.expectEqualStrings(
        "1400000ccf919626f1360c536aaad73a",
        &bytesToHex(verify_data, .lower),
    );
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

const TestRnd = struct {
    idx: u8 = 0,

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
};

fn RecordReader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,

        buffer: [tls.max_ciphertext_record_len]u8 = undefined,
        // // Part of the read buffer with decrypted application data.
        // cleartext_start: usize = 0,
        // cleartext_end: usize = 0,
        // Filled from stream but unencrypted part of the buffer.
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
                    const protocol_version: tls.ProtocolVersion = @enumFromInt(std.mem.readInt(u16, record_header[1..3], .big));
                    const payload_len = std.mem.readInt(u16, record_header[3..5], .big);
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
                            std.mem.copyForwards(u8, c.buffer[0..n], c.buffer[c.start..][0..n]);
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

fn bufPrint(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf, 1..) |b, i| {
        std.debug.print("0x{x:0>2}, ", .{b});
        if (i % 16 == 0)
            std.debug.print("\n", .{});
    }
    std.debug.print("\n", .{});
}
