const std = @import("std");
const crypto = std.crypto;
const posix = std.posix;

const tls = crypto.tls;
const tls12 = @import("tls12.zig");
const AppCipherT = @import("cipher.zig").AppCipherT;

const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const X25519 = crypto.dh.X25519;

pub fn client(stream: anytype, host: []const u8) !ClientT(@TypeOf(stream)) {
    const ClientType = ClientT(@TypeOf(stream));
    return try ClientType.init(stream, crypto.random, host);
}

pub fn ClientT(comptime StreamType: type) type {
    return struct {
        stream: StreamType,
        rnd: std.Random = crypto.random,

        app_cipher: AppCipherT = undefined,
        client_sequence: usize = 0,
        server_sequence: usize = 0,

        read_buffer: [tls.max_ciphertext_record_len]u8 = undefined,
        // Part of the read buffer with decrypted application data.
        cleartext_start: usize = 0,
        cleartext_end: usize = 0,
        // Filled from stream but unencrypted part of the buffer.
        ciphertext_start: usize = 0,
        ciphertext_end: usize = 0,

        const Client = @This();

        pub fn init(stream: StreamType, rnd: std.Random, host: []const u8) !Client {
            var h = try Handshake.init(stream, rnd);
            return try h.run(host, rnd);
        }

        pub fn write(c: *Client, buf: []const u8) !usize {
            const len = @min(buf.len, tls.max_cipertext_inner_record_len);
            try c.send(.application_data, buf[0..len]);
            return len;
        }

        fn send(c: *Client, content_type: tls.ContentType, cleartext: []const u8) !void {
            var buffer: [tls.max_ciphertext_record_len]u8 = undefined;

            const ad = additonalData(c.client_sequence, content_type, cleartext.len);
            c.client_sequence += 1;

            const payload = switch (c.app_cipher) {
                inline else => |*p| p.encrypt(&buffer, &ad, cleartext),
            };

            const header = tls12.recordHeader(content_type, payload.len);
            try streamWrite(c.stream, &header, payload);
        }

        fn decrypt(
            c: *Client,
            cleartext_buffer: []u8,
            content_type: tls.ContentType,
            payload: []const u8,
        ) ![]const u8 {
            var ad = additonalData(c.server_sequence, content_type, 0);
            c.server_sequence += 1;

            return switch (c.app_cipher) {
                inline else => |*p| p.decrypt(cleartext_buffer, &ad, payload),
            };
        }

        fn additonalData(sequence: u64, content_type: tls.ContentType, cleartext_len: usize) [13]u8 {
            var ad: [13]u8 = undefined;
            std.mem.writeInt(u64, ad[0..8], sequence, .big);
            ad[8..13].* = tls12.recordHeader(content_type, cleartext_len);
            return ad;
        }

        fn streamWrite(stream: StreamType, header: []const u8, payload: []const u8) !void {
            var iovecs = [_]std.posix.iovec_const{
                .{
                    .iov_base = header.ptr,
                    .iov_len = header.len,
                },
                .{
                    .iov_base = payload.ptr,
                    .iov_len = payload.len,
                },
            };
            try stream.writevAll(&iovecs);
        }

        fn streamWriteHeader(stream: StreamType, header: []const u8) !void {
            var iovecs = [_]std.posix.iovec_const{
                .{
                    .iov_base = header.ptr,
                    .iov_len = header.len,
                },
            };
            try stream.writevAll(&iovecs);
        }

        pub fn read(c: *Client, buf: []u8) !usize {
            while (true) {
                // If we have unread cleartext data, return them to the caller.
                if (c.cleartext_end > c.cleartext_start) {
                    const n = @min(buf.len, c.cleartext_end - c.cleartext_start);
                    @memcpy(buf[0..n], c.read_buffer[c.cleartext_start..][0..n]);
                    c.cleartext_start += n;
                    return n;
                }

                c.fillRecord() catch |err| switch (err) {
                    error.TlsCloseNotify => return 0,
                    error.EndOfStream => return 0,
                    else => return err,
                };
            }
        }

        fn readRecord(c: *Client) ![]const u8 {
            try c.fillRecord();
            defer c.cleartext_end = c.cleartext_start;
            bufPrint(c.read_buffer[c.cleartext_start..c.cleartext_end]);
            return c.read_buffer[c.cleartext_start..c.cleartext_end];
        }

        fn fillRecord(c: *Client) !void {
            while (true) {
                const read_buffer = c.read_buffer[c.ciphertext_start..c.ciphertext_end];
                // If we have 5 bytes header.
                if (read_buffer.len > tls.record_header_len) {
                    const record_header = read_buffer[0..tls.record_header_len];
                    const content_type: tls.ContentType = @enumFromInt(record_header[0]);
                    const payload_len = std.mem.readInt(u16, record_header[3..5], .big);
                    if (payload_len > tls.max_ciphertext_len) return error.TlsRecordOverflow;

                    // If we have whole encrypted record, decrypt it.
                    if (read_buffer[tls.record_header_len..].len >= payload_len) {
                        const payload = read_buffer[tls.record_header_len .. tls.record_header_len + payload_len];
                        c.cleartext_start = c.ciphertext_start;
                        const cleartext = try c.decrypt(c.read_buffer[c.cleartext_start..], content_type, payload);
                        c.cleartext_end = c.cleartext_start + cleartext.len;
                        c.ciphertext_start += tls.record_header_len + payload_len;
                        switch (content_type) {
                            .handshake => return,
                            .application_data => return,
                            .alert => {
                                const level: tls.AlertLevel = @enumFromInt(cleartext[0]);
                                const desc: tls.AlertDescription = @enumFromInt(cleartext[1]);
                                if (level == .warning and desc == .close_notify)
                                    return error.TlsCloseNotify;
                                try desc.toError();
                                return error.TlsUnexpectedMessage;
                            },
                            else => return error.TlsUnexpectedMessage,
                        }
                    }
                }
                { // Move dirty part to the start of the buffer.
                    const n = c.ciphertext_end - c.ciphertext_start;
                    if (n > 0 and c.ciphertext_start > 0) {
                        if (c.ciphertext_start > n) {
                            @memcpy(c.read_buffer[0..n], c.read_buffer[c.ciphertext_start..][0..n]);
                        } else {
                            std.mem.copyForwards(u8, c.read_buffer[0..n], c.read_buffer[c.ciphertext_start..][0..n]);
                        }
                    }
                    c.ciphertext_start = 0;
                    c.ciphertext_end = n;
                }
                { // Read more from stream.
                    const n = try c.stream.read(c.read_buffer[c.ciphertext_end..]);
                    if (n == 0)
                        return error.EndOfStream;
                    std.debug.print("read: {d}\n", .{n});
                    c.ciphertext_end += n;
                }
            }
        }

        const Handshake = struct {
            buffer: [tls.max_ciphertext_record_len]u8 = undefined,

            transcript: Sha256 = Sha256.init(.{}),
            client_public_key: [32]u8 = undefined,
            client_private_key: [32]u8 = undefined,
            client_random: [32]u8 = undefined,
            server_random: [32]u8 = undefined,
            server_public_key: [32]u8 = undefined,
            master_secret: [32 + 16]u8 = undefined,
            key_material: [32 * 4]u8 = undefined,
            cipher_suite_tag: tls12.CipherSuite = undefined,
            stream: StreamType,

            fn init(stream: StreamType, rnd: std.Random) !Handshake {
                const kp = try X25519.KeyPair.create(null);
                var client_random: [32]u8 = undefined;
                rnd.bytes(&client_random);
                return .{
                    .stream = stream,
                    .client_random = client_random,
                    .client_private_key = kp.secret_key,
                    .client_public_key = kp.public_key,
                };
            }

            fn run(h: *Handshake, host: []const u8, rnd: std.Random) !Client {
                try h.hello(host);
                try h.serverHello();
                try h.generateMasterSecret();
                try h.generateEncryptionKeys();

                var cli = Client{
                    .stream = h.stream,
                    .rnd = rnd,
                    .app_cipher = try AppCipherT.init(h.cipher_suite_tag, &h.key_material, rnd),
                };

                try h.keyExchange();
                try h.changeCipherSpec();
                try h.handshakeFinished(&cli);
                try h.serverHandshakeFinished(&cli);
                return cli;
            }

            /// Send client hello message.
            fn hello(h: *Handshake, host: []const u8) !void {
                const enum_array = tls.enum_array;
                const host_len: u16 = @intCast(host.len);

                const cipher_suites = enum_array(tls12.CipherSuite, &.{
                    .AES_128_GCM_SHA256,
                    .AES_128_CBC_SHA,
                });

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
                })) ++
                    tls12.serverNameExtensionHeader(host_len);

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

                try streamWrite(h.stream, &record, host);
                h.transcript.update(record[5..]);
                h.transcript.update(host);
            }

            /// Read server hello, certificate, key_exchange and hello done messages.
            /// Extract server public key and server random.
            fn serverHello(h: *Handshake) !void {
                var rd: tls.Decoder = .{ .buf = &h.buffer }; // record decoder
                var handshake_state = tls12.HandshakeType.server_hello;
                while (true) {
                    try rd.readAtLeastOurAmt(h.stream, tls.record_header_len);
                    const content_type = rd.decode(tls.ContentType);
                    const protocol_version = rd.decode(tls.ProtocolVersion);
                    const record_len = rd.decode(u16);
                    if (protocol_version != tls.ProtocolVersion.tls_1_2) return error.TlsBadVersion;

                    try rd.readAtLeast(h.stream, record_len);
                    var hd = try rd.sub(record_len); // header decoder

                    switch (content_type) {
                        .alert => {
                            try hd.ensure(2);
                            const level = hd.decode(tls.AlertLevel);
                            const desc = hd.decode(tls.AlertDescription);
                            _ = level;
                            try desc.toError();
                            return error.TlsServerSideClosure; // TODO
                        },
                        .handshake => {}, // continue
                        else => return error.TlsUnexpectedMessage,
                    }
                    if (content_type != .handshake) return error.TlsUnexpectedMessage;
                    h.transcript.update(hd.rest());

                    try hd.ensure(4);
                    const handshake_type = hd.decode(tls12.HandshakeType);
                    if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;
                    const length = hd.decode(u24);
                    var hsd = try hd.sub(length); // handshake decoder

                    switch (handshake_type) {
                        .server_hello => { // server hello
                            try hsd.ensure(2 + 32 + 1);
                            if (hsd.decode(tls.ProtocolVersion) != tls.ProtocolVersion.tls_1_2) return error.TlsBadVersion;
                            h.server_random = hsd.array(32).*;
                            const session_id_len = hsd.decode(u8);

                            if (session_id_len > 32) return error.TlsIllegalParameter;
                            try hsd.ensure(session_id_len);
                            hsd.skip(session_id_len);

                            try hsd.ensure(2 + 1);
                            h.cipher_suite_tag = hsd.decode(tls12.CipherSuite);
                            try h.cipher_suite_tag.validate();

                            hsd.skip(1); // skip compression method

                            if (!hsd.eof()) { // TODO is this because we didn't send any extension
                                try hsd.ensure(2);
                                const extensions_size = hsd.decode(u16);
                                try hsd.ensure(extensions_size);
                                hsd.skip(extensions_size);
                            }
                            handshake_state = .certificate;
                        },
                        .certificate => {
                            try hsd.ensure(3);
                            const certs_len = hsd.decode(u24);
                            try hsd.ensure(certs_len);

                            var l: usize = 0;
                            while (l < certs_len) {
                                const cert_len = hsd.decode(u24);
                                try hsd.ensure(cert_len);
                                const cert = hsd.slice(cert_len);
                                _ = cert; // TODO: check certificate
                                l += cert_len + 3;
                            }
                            handshake_state = .server_key_exchange;
                        },
                        .server_key_exchange => {
                            try hsd.ensure(1 + 2 + 1);
                            const named_curve = hsd.decode(u8);
                            const curve = hsd.decode(u16);
                            const key_len = hsd.decode(u8);
                            if (named_curve != 0x03 or curve != 0x001d or key_len != 0x20)
                                return error.TlsIllegalParameter;
                            try hsd.ensure(32 + 2 + 2);
                            h.server_public_key = hsd.array(32).*;

                            const rsa_signature = hsd.decode(u16);
                            const signature_len = hsd.decode(u16);
                            _ = rsa_signature; // TODO what to expect here

                            if (signature_len != 0x0100)
                                return error.TlsIllegalParameter;
                            try hsd.ensure(signature_len);
                            hsd.skip(signature_len);
                            // TODO: how to check signature
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

            fn generateMasterSecret(h: *Handshake) !void {
                const pre_master_secret = try X25519.scalarmult(h.client_private_key, h.server_public_key);
                const seed = "master secret" ++ h.client_random ++ h.server_random;

                var a1: [32]u8 = undefined;
                var a2: [32]u8 = undefined;
                HmacSha256.create(&a1, seed, &pre_master_secret);
                HmacSha256.create(&a2, &a1, &pre_master_secret);

                var p1: [32]u8 = undefined;
                var p2: [32]u8 = undefined;
                HmacSha256.create(&p1, a1 ++ seed, &pre_master_secret);
                HmacSha256.create(&p2, a2 ++ seed, &pre_master_secret);

                h.master_secret[0..32].* = p1;
                h.master_secret[32..].* = p2[0..16].*;
            }

            fn generateEncryptionKeys(h: *Handshake) !void {
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

                // switch (h.cipher_suite_tag) {
                //     inline .AES_128_CBC_SHA,
                //     .AES_128_GCM_SHA256,
                //     => |tag| {
                //         h.cipher_suite_tag = @unionInit(AppCipherT, @tagName(tag), .{});
                //     },
                //     else => return error.TlsIllegalParameter,
                // }

                //h.cipher_suite_tag = @unionInit(AppCipherT, @tagName(h.cipher_suite_tag), .{});
                // switch (h.client.application_cipher) {
                //     inline else => |*ac| {
                //         const P = @TypeOf(ac.*);
                //         ac.* = P.init(p, h.client.rnd);
                //     },
                // }
            }

            fn keyExchange(h: *Handshake) !void {
                const key_len = h.client_public_key.len;
                const header =
                    tls12.handshakeHeader(.client_key_exchange, 1 + key_len) ++
                    tls12.int1(key_len);

                try streamWrite(h.stream, &header, &h.client_public_key);
                h.transcript.update(header[5..]);
                h.transcript.update(&h.client_public_key);
            }

            fn changeCipherSpec(h: *Handshake) !void {
                const header =
                    tls12.recordHeader(.change_cipher_spec, 1) ++
                    tls12.int1(1);
                try streamWriteHeader(h.stream, &header);
            }

            fn verifyData(h: *Handshake) [16]u8 {
                const seed = "client finished" ++ h.transcript.finalResult();
                var a1: [32]u8 = undefined;
                var p1: [32]u8 = undefined;
                HmacSha256.create(&a1, seed, &h.master_secret);
                HmacSha256.create(&p1, a1 ++ seed, &h.master_secret);
                return [_]u8{ 0x14, 0x00, 0x00, 0x0c } ++ p1[0..12].*;
            }

            fn handshakeFinished(h: *Handshake, c: *Client) !void {
                const verify_data = h.verifyData();
                try c.send(.handshake, &verify_data);
            }

            fn serverHandshakeFinished(h: *Handshake, c: *Client) !void {
                var rd: tls.Decoder = .{ .buf = &h.buffer }; // record decoder
                { // server change cipher spec message
                    try rd.readAtLeastOurAmt(h.stream, tls.record_header_len);
                    const content_type = rd.decode(tls.ContentType);
                    const protocol_version = rd.decode(tls.ProtocolVersion);
                    const record_len = rd.decode(u16);
                    if (protocol_version != tls.ProtocolVersion.tls_1_2) return error.TlsBadVersion;
                    if (content_type != tls.ContentType.change_cipher_spec) return error.TlsUnexpectedMessage;

                    try rd.readAtLeast(h.stream, record_len);
                    try rd.ensure(record_len);
                    rd.skip(record_len);
                }
                { // server finished message
                    try rd.readAtLeastOurAmt(h.stream, tls.record_header_len);
                    const content_type = rd.decode(tls.ContentType);
                    const protocol_version = rd.decode(tls.ProtocolVersion);
                    const record_len = rd.decode(u16);
                    if (protocol_version != tls.ProtocolVersion.tls_1_2) return error.TlsBadVersion;
                    if (content_type != tls.ContentType.handshake) return error.TlsUnexpectedMessage;
                    try rd.readAtLeast(h.stream, record_len);
                    // TODO check finished message
                    try rd.ensure(record_len);
                    const data = rd.slice(record_len);
                    _ = try c.decrypt(&h.buffer, content_type, data);
                    //rd.skip(record_len);
                    //_ = try h.client.readRecord();
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
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);
    // test stream
    var stream = TestStream{};
    defer stream.deinit();
    var h = try ClientT(*TestStream).Handshake.init(&stream, rnd);

    { // client random is set to predictable pattern
        try testing.expectEqualStrings(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            &bytesToHex(h.client_random, .lower),
        );
    }

    { // client hello message
        const host = "www.example.com";
        try h.hello(host);
        try testing.expectEqualSlices(u8, &[_]u8{
            0x16, 0x03, 0x03, 0x00, 0x74, 0x01, 0x00, 0x00, 0x70, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x04, 0xc0, 0x2f,
            0xc0, 0x13, 0x01, 0x00, 0x00, 0x43, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0xff, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05, 0x03, 0x08,
            0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00,
            0x1d, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        }, stream.output.items);
        try testing.expectEqualStrings(host, stream.output.items[stream.output.items.len - host.len ..]);
    }
}

test "Handshake.serverHello" {
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);
    // test stream
    var stream = TestStream{ .input = &example.server_hello_responses };
    defer stream.deinit();
    var h = try ClientT(*TestStream).Handshake.init(&stream, rnd);

    // read server random and server public key from server hello, certificate
    // and key exchange messages
    try h.serverHello();
    try testing.expectEqualStrings(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        &bytesToHex(h.server_random, .lower),
    );
    try testing.expectEqualStrings(
        "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615",
        &bytesToHex(h.server_public_key, .lower),
    );
    // unchanged in serverHello
    try testing.expectEqualStrings(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        &bytesToHex(h.client_random, .lower),
    );

    try testing.expectEqual(tls12.CipherSuite.AES_128_CBC_SHA, h.cipher_suite_tag);
}

test "Handshake.generateMasterSecret" {
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);
    // test stream
    var stream = TestStream{ .input = &example.server_hello_responses };
    defer stream.deinit();
    var h = try ClientT(*TestStream).Handshake.init(&stream, rnd);

    // // predictable random number generator
    // var ptr = TestRnd{};
    // const rnd = std.Random.init(&ptr, TestRnd.fillFn);
    // // test stream
    // var stream = TestStream{ .input = &example.server_hello_responses };
    // defer stream.deinit();
    // // client and handshake with test stream and predictable random
    // const ClientType = ClientT(*TestStream);
    // var c = ClientType{ .stream = &stream, .rnd = rnd };
    // var h = try ClientType.Handshake.init(&c);

    h.cipher_suite_tag = tls12.CipherSuite.AES_128_CBC_SHA;

    { // init with known keys
        _ = try hexToBytes(h.client_private_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        _ = try hexToBytes(h.server_random[0..], "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        _ = try hexToBytes(h.server_public_key[0..], "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
    }
    { // generate master secret
        try h.generateMasterSecret();
        try testing.expectEqualSlices(u8, &example.master_secret, &h.master_secret);
    }
    { // generate encryption keys
        try h.generateEncryptionKeys();
        try testing.expectEqualStrings(
            "1b7d117c7d5f690bc263cae8ef60af0f1878acc22ad8bdd8c601a617126f63540eb20906f781fad2f656d037b173ef3e11169f27231a84b6752a18e7a9fcb7cbcdd8f98dd8f769eba0d2550c9238eebfef5c32251abb67d6434528db4937d540d393135e06a11bb80e45eaebe32cac72757438fbb3df645cbda4067cdfa0f848",
            &bytesToHex(h.key_material, .lower),
        );
    }
    // //var buf: [1024]u8 = undefined;
    // { // encrypt ping
    //     const cleartext = "ping";
    //     c.client_sequence = 1;
    //     ptr.idx = 0;
    //     try c.send(.application_data, cleartext);

    //     const expected = [_]u8{
    //         0x17, 0x03, 0x03, 0x00, 0x30, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    //         0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x6c, 0x42, 0x1c, 0x71, 0xc4, 0x2b, 0x18, 0x3b, 0xfa, 0x06, 0x19,
    //         0x5d, 0x13, 0x3d, 0x0a, 0x09, 0xd0, 0x0f, 0xc7, 0xcb, 0x4e, 0x0f, 0x5d, 0x1c, 0xda, 0x59, 0xd1,
    //         0x47, 0xec, 0x79, 0x0c, 0x99,
    //     };
    //     try testing.expectEqualSlices(u8, &expected, stream.output.items);

    //     //try testing.expectEqualStrings(cleartext, try h.cipher.clientDecrypt(&buf, iv, ciphertext[0..32]));
    // }
    // const output_pos = stream.output.items.len;
    // { // encrypt verify data from illustrated example
    //     const data = [_]u8{
    //         0x14, 0x00, 0x00, 0x0c, 0xcf, 0x91, 0x96, 0x26, 0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a,
    //     };
    //     c.client_sequence = 0;
    //     ptr.idx = 0x40;
    //     try c.send(.handshake, &data);
    //     const expected = [_]u8{
    //         0x22, 0x7b, 0xc9, 0xba, 0x81, 0xef, 0x30, 0xf2, 0xa8, 0xa7, 0x8f, 0xf1, 0xdf, 0x50, 0x84, 0x4d,
    //         0x58, 0x04, 0xb7, 0xee, 0xb2, 0xe2, 0x14, 0xc3, 0x2b, 0x68, 0x92, 0xac, 0xa3, 0xdb, 0x7b, 0x78,
    //         0x07, 0x7f, 0xdd, 0x90, 0x06, 0x7c, 0x51, 0x6b, 0xac, 0xb3, 0xba, 0x90, 0xde, 0xdf, 0x72, 0x0f,
    //     };
    //     const actual = stream.output.items[output_pos + 16 + 5 ..]; // skip header and iv
    //     try testing.expectEqualSlices(u8, &expected, actual);
    // }
}

test "Client.init" {
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);
    // test stream
    var stream = TestStream{ .input = &example.server_responses };
    defer stream.deinit();
    var h = try ClientT(*TestStream).Handshake.init(&stream, rnd);
    { // init with known keys
        _ = try hexToBytes(h.client_private_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        _ = try hexToBytes(h.client_public_key[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    }
    const host = "www.example.com";
    var c = try h.run(host, rnd);

    var output_pos: usize = 0;
    { // test messages that client sent
        try testing.expectEqualSlices(u8, &example.client_hello, stream.output.items[0..example.client_hello.len]);
        output_pos += example.client_hello.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_key_exchange,
            stream.output.items[output_pos..][0..example.client_key_exchange.len],
        );
        output_pos += example.client_key_exchange.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_change_cyper_spec,
            stream.output.items[output_pos..][0..example.client_change_cyper_spec.len],
        );
        output_pos += example.client_change_cyper_spec.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_handshake_finished,
            stream.output.items[output_pos..][0..example.client_handshake_finished.len],
        );
        output_pos += example.client_handshake_finished.len;
    }

    { // encrypt ping
        const cleartext = "ping";
        test_rnd.idx = 0;
        try c.send(.application_data, cleartext);

        const expected = [_]u8{
            0x17, 0x03, 0x03, 0x00, 0x30, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x6c, 0x42, 0x1c, 0x71, 0xc4, 0x2b, 0x18, 0x3b, 0xfa, 0x06, 0x19,
            0x5d, 0x13, 0x3d, 0x0a, 0x09, 0xd0, 0x0f, 0xc7, 0xcb, 0x4e, 0x0f, 0x5d, 0x1c, 0xda, 0x59, 0xd1,
            0x47, 0xec, 0x79, 0x0c, 0x99,
        };
        try testing.expectEqualSlices(u8, &expected, stream.output.items[output_pos..]);
    }

    output_pos = stream.output.items.len;
    { // encrypt verify data from illustrated example
        const data = [_]u8{
            0x14, 0x00, 0x00, 0x0c, 0xcf, 0x91, 0x96, 0x26, 0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a,
        };
        c.client_sequence = 0;
        test_rnd.idx = 0x40;
        try c.send(.handshake, &data);
        const expected = [_]u8{
            0x22, 0x7b, 0xc9, 0xba, 0x81, 0xef, 0x30, 0xf2, 0xa8, 0xa7, 0x8f, 0xf1, 0xdf, 0x50, 0x84, 0x4d,
            0x58, 0x04, 0xb7, 0xee, 0xb2, 0xe2, 0x14, 0xc3, 0x2b, 0x68, 0x92, 0xac, 0xa3, 0xdb, 0x7b, 0x78,
            0x07, 0x7f, 0xdd, 0x90, 0x06, 0x7c, 0x51, 0x6b, 0xac, 0xb3, 0xba, 0x90, 0xde, 0xdf, 0x72, 0x0f,
        };
        const actual = stream.output.items[output_pos + 16 + 5 ..]; // skip header and iv
        try testing.expectEqualSlices(u8, &expected, actual);
    }
}

test "Handshake.verifyData" {
    var stream = TestStream{};
    defer stream.deinit();
    var h = try ClientT(*TestStream).Handshake.init(&stream, crypto.random);
    h.master_secret = example.master_secret;

    // add handshake messages to transcript
    h.transcript.update(example.client_hello_for_transcript[5..]);
    h.transcript.update(example.server_hello[5..]);
    h.transcript.update(example.server_certificate[5..]);
    h.transcript.update(example.server_key_exchange[5..]);
    h.transcript.update(example.server_hello_done[5..]);
    h.transcript.update(example.client_key_exchange_for_transcript[5..]);

    // expect verify data
    const verify_data = h.verifyData();
    try testing.expectEqualStrings(
        "1400000ccf919626f1360c536aaad73a",
        &bytesToHex(verify_data, .lower),
    );
}

const TestStream = struct {
    input: []const u8 = undefined,
    input_pos: usize = 0,
    output: std.ArrayList(u8) = std.ArrayList(u8).init(testing.allocator),

    pub fn writevAll(self: *TestStream, iovecs: []posix.iovec_const) !void {
        for (iovecs) |iovec| {
            var buf: []const u8 = undefined;
            buf.ptr = iovec.iov_base;
            buf.len = iovec.iov_len;

            try self.output.appendSlice(buf);
        }
    }

    pub fn readAtLeast(self: *TestStream, buffer: []u8, len: usize) !usize {
        const n: usize = @min(len, self.input.len - self.input_pos);
        @memcpy(buffer[0..n], self.input[self.input_pos..][0..n]);
        self.input_pos += n;
        return n;
    }

    pub fn deinit(self: *TestStream) void {
        self.output.deinit();
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

fn bufPrint(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf, 1..) |b, i| {
        std.debug.print("0x{x:0>2}, ", .{b});
        if (i % 16 == 0)
            std.debug.print("\n", .{});
    }
    std.debug.print("\n", .{});
}
