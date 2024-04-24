const std = @import("std");
const crypto = std.crypto;
const posix = std.posix;

const tls = crypto.tls;
const tls12 = @import("tls12.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

pub fn client(stream: anytype) ClientT(@TypeOf(stream)) {
    return .{ .stream = stream };
}

fn CipherT(comptime AeadType: type, comptime HashType: type) type {
    return struct {
        pub const AEAD = AeadType;
        pub const Hash = HashType;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const explicit_iv_len = 8;

        client_key: [AEAD.key_length]u8,
        server_key: [AEAD.key_length]u8,
        client_iv: [AEAD.nonce_length - explicit_iv_len]u8,
        server_iv: [AEAD.nonce_length - explicit_iv_len]u8,

        const Self = @This();

        fn init(p: [128]u8) Self {
            const kl = AEAD.key_length;
            const il = AEAD.nonce_length - explicit_iv_len;
            return .{
                .client_key = p[0..kl].*,
                .server_key = p[kl..][0..kl].*,
                .client_iv = p[2 * kl ..][0..il].*,
                .server_iv = p[2 * kl + il ..][0..il].*,
            };
        }

        /// Generete iv, encrypt data, put iv and chipertext into buf.
        /// After this buf contains iv and chipertext.
        fn encrypt(
            cipher: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) []const u8 {
            var explicit_iv: [explicit_iv_len]u8 = undefined;
            crypto.random.bytes(&explicit_iv);
            buf[0..explicit_iv_len].* = explicit_iv;

            const iv = cipher.client_iv ++ explicit_iv;
            const ciphertext = buf[explicit_iv.len..][0..cleartext.len];
            const auth_tag = buf[explicit_iv.len + ciphertext.len ..][0..AEAD.tag_length];
            const ad = additonalData(sequence, content_type, cleartext.len);
            AEAD.encrypt(ciphertext, auth_tag, cleartext, &ad, iv, cipher.client_key);
            return buf[0 .. explicit_iv.len + ciphertext.len + auth_tag.len];
        }

        fn decrypt(
            cipher: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            payload: []const u8,
        ) ![]const u8 {
            if (payload.len < AEAD.tag_length + explicit_iv_len)
                return error.TlsDecryptError;

            const iv = cipher.server_iv ++ payload[0..explicit_iv_len].*;
            const cleartext_len = payload.len - AEAD.tag_length - explicit_iv_len;
            const ciphertext = payload[explicit_iv_len..][0..cleartext_len];
            const auth_tag = payload[explicit_iv_len + cleartext_len ..][0..AEAD.tag_length];
            const ad = additonalData(sequence, content_type, cleartext_len);

            const cleartext = buf[0..cleartext_len];
            try AEAD.decrypt(cleartext, ciphertext, auth_tag.*, &ad, iv, cipher.server_key);
            return cleartext;
        }

        fn additonalData(sequence: u64, content_type: tls.ContentType, cleartext_len: usize) [13]u8 {
            var ad: [13]u8 = undefined;
            std.mem.writeInt(u64, ad[0..8], sequence, .big);
            ad[8..13].* = tls12.recordHeader(content_type, cleartext_len);
            return ad;
        }
    };
}

pub fn ClientT(comptime StreamType: type) type {
    const CipherType = CipherT(std.crypto.aead.aes_gcm.Aes128Gcm, std.crypto.hash.sha2.Sha256);
    return struct {
        stream: StreamType,
        client_sequence: usize = 0,
        server_sequence: usize = 0,

        cipher: CipherType = undefined,

        read_buffer: [tls.max_ciphertext_record_len]u8 = undefined,
        // Part of the read buffer with decrypted application data.
        cleartext_start: usize = 0,
        cleartext_end: usize = 0,
        // Filled from stream but unencrypted part of the buffer.
        ciphertext_start: usize = 0,
        ciphertext_end: usize = 0,

        const Client = @This();

        pub fn handshake(c: *Client, host: []const u8) !void {
            var h = try Handshake.init(c.stream);
            try h.hello(host);
            try h.serverHello();
            try h.generateMasterSecret();
            try h.generateEncryptionKeys();
            try h.keyExchange();
            try h.changeCipherSpec();
            try h.handshakeFinished();
            try h.serverHandshakeFinished();
            c.cipher = h.cipher;
        }

        pub fn write(c: *Client, buf: []const u8) !usize {
            const len = @min(buf.len, tls.max_cipertext_inner_record_len);

            var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
            c.client_sequence += 1;
            const ciphertext = c.cipher.encrypt(&buffer, c.client_sequence, .application_data, buf[0..len]);

            const record_header = tls12.recordHeader(.application_data, ciphertext.len);
            {
                var iovecs = [_]std.posix.iovec_const{
                    .{
                        .iov_base = &record_header,
                        .iov_len = record_header.len,
                    },
                    .{
                        .iov_base = ciphertext.ptr,
                        .iov_len = ciphertext.len,
                    },
                };
                try c.stream.writevAll(&iovecs);
            }
            return len;
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

                const read_buffer = c.read_buffer[c.ciphertext_start..c.ciphertext_end];
                // If we have 5 bytes header.
                if (read_buffer.len > tls.record_header_len) {
                    const record_header = read_buffer[0..tls.record_header_len];
                    const content_type: tls.ContentType = @enumFromInt(record_header[0]);
                    const data_len = std.mem.readInt(u16, record_header[3..5], .big);
                    if (data_len > tls.max_ciphertext_len) return error.TlsRecordOverflow;

                    // If we have whole encrypted record, decrypt it.
                    if (read_buffer[tls.record_header_len..].len >= data_len) {
                        const data = read_buffer[tls.record_header_len .. tls.record_header_len + data_len];
                        c.cleartext_start = c.ciphertext_start;
                        c.server_sequence += 1;
                        const cleartext = try c.cipher.decrypt(
                            c.read_buffer[c.cleartext_start..],
                            c.server_sequence,
                            content_type,
                            data,
                        );
                        c.cleartext_end = c.cleartext_start + cleartext.len;
                        c.ciphertext_start += tls.record_header_len + data_len;
                        switch (content_type) {
                            .application_data => {
                                continue;
                            },
                            .alert => {
                                const level: tls.AlertLevel = @enumFromInt(cleartext[0]);
                                const desc: tls.AlertDescription = @enumFromInt(cleartext[1]);
                                if (level == .warning and desc == .close_notify)
                                    return 0;
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
                    if (n == 0) return 0;
                    c.ciphertext_end += n;
                }
            }
        }

        const Handshake = struct {
            stream: StreamType,
            buffer: [tls.max_ciphertext_record_len]u8 = undefined,

            transcript: Sha256 = Sha256.init(.{}),
            client_public_key: [32]u8 = undefined,
            client_private_key: [32]u8 = undefined,
            client_random: [32]u8 = undefined,
            server_random: [32]u8 = undefined,
            server_public_key: [32]u8 = undefined,
            master_secret: [32 + 16]u8 = undefined,
            cipher: CipherType = undefined,

            fn init(stream: StreamType) !Handshake {
                const kp = try X25519.KeyPair.create(null);
                var rnd: [32]u8 = undefined;
                crypto.random.bytes(&rnd);
                return .{
                    .stream = stream,
                    .client_random = rnd,
                    .client_private_key = kp.secret_key,
                    .client_public_key = kp.public_key,
                };
            }

            /// Send client hello message.
            fn hello(h: *Handshake, host: []const u8) !void {
                const enum_array = tls.enum_array;
                const host_len: u16 = @intCast(host.len);

                const cipher_suites = enum_array(tls12.CipherSuite, &.{
                    .AES_128_GCM_SHA256,
                    //.AES_128_CBC_SHA,
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

                try h.send(&record, host);
                h.transcript.update(record[5..]);
                h.transcript.update(host);
            }

            fn send(h: *Handshake, header: []const u8, payload: []const u8) !void {
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
                try h.stream.writevAll(&iovecs);
            }

            fn sendHeader(h: *Handshake, header: []const u8) !void {
                var iovecs = [_]std.posix.iovec_const{
                    .{
                        .iov_base = header.ptr,
                        .iov_len = header.len,
                    },
                };
                try h.stream.writevAll(&iovecs);
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
                            const cipher_suite = hsd.decode(u16);
                            // TODO: stavi ovdje provjeru da je jedan od predlozenih
                            if (cipher_suite != 0xc02f) return error.TlsIllegalParameter; // the only one we support
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

                var p: [32 * 4]u8 = undefined;
                HmacSha256.create(p[0..32], a1 ++ seed, &h.master_secret);
                HmacSha256.create(p[32..64], a2 ++ seed, &h.master_secret);
                HmacSha256.create(p[64..96], a3 ++ seed, &h.master_secret);
                HmacSha256.create(p[96..], a4 ++ seed, &h.master_secret);

                h.cipher = CipherType.init(p);
            }

            fn keyExchange(h: *Handshake) !void {
                const key_len = h.client_public_key.len;
                const header =
                    tls12.handshakeHeader(.client_key_exchange, 1 + key_len) ++
                    tls12.int1(key_len);

                try h.send(&header, &h.client_public_key);
                h.transcript.update(header[5..]);
                h.transcript.update(&h.client_public_key);
            }

            fn changeCipherSpec(h: *Handshake) !void {
                const header =
                    tls12.recordHeader(.change_cipher_spec, 1) ++
                    tls12.int1(1);
                try h.sendHeader(&header);
            }

            fn verifyData(h: *Handshake) [16]u8 {
                const seed = "client finished" ++ h.transcript.finalResult();
                var a1: [32]u8 = undefined;
                var p1: [32]u8 = undefined;
                HmacSha256.create(&a1, seed, &h.master_secret);
                HmacSha256.create(&p1, a1 ++ seed, &h.master_secret);
                return [_]u8{ 0x14, 0x00, 0x00, 0x0c } ++ p1[0..12].*;
            }

            fn handshakeFinished(h: *Handshake) !void {
                const verify_data = h.verifyData();
                const data = h.cipher.encrypt(&h.buffer, 0, .handshake, &verify_data);
                const header = tls12.recordHeader(.handshake, data.len);
                try h.send(&header, data);
            }

            fn serverHandshakeFinished(h: *Handshake) !void {
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
                    _ = try h.cipher.decrypt(&h.buffer, 0, content_type, data);
                    //rd.skip(record_len);
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
    var stream = TestStream{ .input = undefined };
    defer stream.deinit();
    var h: ClientT(*TestStream).Handshake = .{
        .stream = &stream,
        .client_random = [32]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        },
    };
    const host = "www.example.com";
    try h.hello(host);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x16, 0x03, 0x03, 0x00, 0x72, 0x01, 0x00, 0x00, 0x6e, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0xc0, 0x13,
        0x01, 0x00, 0x00, 0x43, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x12, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x08,
        0x05, 0x08, 0x06, 0x08, 0x07, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00,
        0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    }, stream.output.items);
    try testing.expectEqualStrings(host, stream.output.items[stream.output.items.len - host.len ..]);
}

test "Handshake.serverHello" {
    var stream = TestStream{ .input = &example.server_hello_responses };
    defer stream.deinit();
    var h: ClientT(*TestStream).Handshake = .{
        .stream = &stream,
        .client_random = [_]u8{0} ** 32,
        .server_random = [_]u8{0} ** 32,
        .server_public_key = [_]u8{0} ** 32,
    };
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
        "0000000000000000000000000000000000000000000000000000000000000000",
        &bytesToHex(h.client_random, .lower),
    );
}

test "Handshake.generateMasterSecret" {
    const ClientType = ClientT(TestStream);
    var h: ClientType.Handshake = .{ .stream = undefined };
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
        try testing.expectEqualStrings("1b7d117c7d5f690bc263cae8ef60af0f1878acc2", &bytesToHex(h.cipher.client_secret, .lower));
        try testing.expectEqualStrings("2ad8bdd8c601a617126f63540eb20906f781fad2", &bytesToHex(h.cipher.server_secret, .lower));
    }
    var buf: [1024]u8 = undefined;
    { // encrypt ping
        const cleartext = "ping";
        const iv = [_]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        };
        const ciphertext = try h.cipher.encryptIv(&buf, 1, .application_data, iv, cleartext);
        const expected_ciphertext = [_]u8{
            0x6c, 0x42, 0x1c, 0x71, 0xc4, 0x2b, 0x18, 0x3b, 0xfa, 0x06, 0x19, 0x5d, 0x13, 0x3d, 0x0a, 0x09,
            0xd0, 0x0f, 0xc7, 0xcb, 0x4e, 0x0f, 0x5d, 0x1c, 0xda, 0x59, 0xd1, 0x47, 0xec, 0x79, 0x0c, 0x99,
        };
        try testing.expectEqualSlices(u8, &expected_ciphertext, ciphertext);

        try testing.expectEqualStrings(cleartext, try h.cipher.clientDecrypt(&buf, iv, ciphertext[0..32]));
    }
    { // encrypt verify data from illustrated example
        const iv = [_]u8{
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        };
        const data = [_]u8{
            0x14, 0x00, 0x00, 0x0c, 0xcf, 0x91, 0x96, 0x26, 0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a,
        };
        const ciphertext = try h.cipher.encryptIv(&buf, 0, .handshake, iv, &data);
        const expected_ciphertext = [_]u8{
            0x22, 0x7b, 0xc9, 0xba, 0x81, 0xef, 0x30, 0xf2, 0xa8, 0xa7, 0x8f, 0xf1, 0xdf, 0x50, 0x84, 0x4d,
            0x58, 0x04, 0xb7, 0xee, 0xb2, 0xe2, 0x14, 0xc3, 0x2b, 0x68, 0x92, 0xac, 0xa3, 0xdb, 0x7b, 0x78,
            0x07, 0x7f, 0xdd, 0x90, 0x06, 0x7c, 0x51, 0x6b, 0xac, 0xb3, 0xba, 0x90, 0xde, 0xdf, 0x72, 0x0f,
        };
        try testing.expectEqualSlices(u8, &expected_ciphertext, ciphertext);
    }
}

test "Handshake.clientKeyExchange" {
    var stream = TestStream{};
    defer stream.deinit();
    var h: ClientT(*TestStream).Handshake = .{
        .stream = &stream,
        .client_public_key = [32]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        },
    };
    try h.keyExchange();
    try testing.expectEqualSlices(u8, &[_]u8{
        0x16, 0x03, 0x03, 0x00, 0x25, 0x10, 0x00, 0x00, 0x21, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    }, stream.output.items);
}

test "Handshake.verifyData" {
    // init client with master secret known
    var stream = TestStream{};
    defer stream.deinit();
    var h: ClientT(*TestStream).Handshake = .{ .stream = &stream };
    h.master_secret = example.master_secret;

    // add handshake messages to transcript
    h.transcript.update(example.client_hello[5..]);
    h.transcript.update(example.server_hello[5..]);
    h.transcript.update(example.server_certificate[5..]);
    h.transcript.update(example.server_key_exchange[5..]);
    h.transcript.update(example.server_hello_done[5..]);
    h.transcript.update(example.client_key_exchange[5..]);

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

fn bufPrint(buf: []const u8) void {
    std.debug.print("\n", .{});
    for (buf, 1..) |b, i| {
        std.debug.print("0x{x:0>2}, ", .{b});
        if (i % 16 == 0)
            std.debug.print("\n", .{});
    }
    std.debug.print("\n", .{});
}
