const std = @import("std");
const crypto = std.crypto;
const posix = std.posix;

const tls = crypto.tls;
const int2 = tls.int2;
const int3 = tls.int3;
const array = tls.array;
const enum_array = tls.enum_array;

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

const CipherType = std.crypto.tls.ApplicationCipherT(@import("cbc.zig").CBCAes128, std.crypto.hash.Sha1);

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
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

pub fn client(stream: anytype) Client(@TypeOf(stream)) {
    return .{ .stream = stream };
}

pub fn Client(comptime StreamType: type) type {
    return struct {
        stream: StreamType,
        buffer: [tls.max_ciphertext_record_len]u8 = undefined,

        const Self = @This();

        const Handshake = struct {
            stream: StreamType,
            buffer: [tls.max_ciphertext_record_len]u8 = undefined,

            hash: Sha1 = Sha1.init(.{}),
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
                    .client_private_key = kp.private_key,
                    .client_public_key = kp.public_key,
                };
            }

            /// Send client hello message.
            fn clientHello(h: *Handshake, host: []const u8) !void {
                const host_len: u16 = @intCast(host.len);

                const no_compression = [_]u8{ 0x01, 0x00 };
                const no_session_id = [_]u8{0x00};
                const cipher_suites = [_]u8{
                    0x00, 0x02, // 2 bytes of cipher suite data follows
                    0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
                };

                const extensions_payload =
                    tls.extension(.signature_algorithms, enum_array(tls.SignatureScheme, &.{
                    .ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384,
                    .rsa_pss_rsae_sha256,
                    .rsa_pss_rsae_sha384,
                    .rsa_pss_rsae_sha512,
                    .ed25519,
                })) ++ tls.extension(.supported_groups, enum_array(tls.NamedGroup, &.{
                    .x25519,
                })) ++
                    int2(@intFromEnum(tls.ExtensionType.server_name)) ++
                    int2(host_len + 5) ++ // byte length of this extension payload
                    int2(host_len + 3) ++ // server_name_list byte count
                    [1]u8{0x00} ++ // name_type
                    int2(host_len);

                const extensions_header =
                    int2(@intCast(extensions_payload.len + host_len)) ++
                    extensions_payload;

                const client_hello =
                    int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                    h.client_random ++
                    no_session_id ++
                    cipher_suites ++
                    no_compression ++
                    extensions_header;

                const out_handshake =
                    [_]u8{@intFromEnum(tls.HandshakeType.client_hello)} ++
                    int3(@intCast(client_hello.len + host_len)) ++
                    client_hello;

                const plaintext_header = [_]u8{
                    @intFromEnum(tls.ContentType.handshake),
                    0x03, 0x01, // legacy protocol version
                } ++ int2(@intCast(out_handshake.len + host_len)) ++ out_handshake;

                {
                    var iovecs = [_]std.posix.iovec_const{
                        .{
                            .iov_base = &plaintext_header,
                            .iov_len = plaintext_header.len,
                        },
                        .{
                            .iov_base = host.ptr,
                            .iov_len = host.len,
                        },
                    };
                    try h.stream.writevAll(&iovecs);

                    h.hash.update(plaintext_header[5..]);
                    h.hash.update(host);
                }
            }

            /// Read server hello, certificate, key_exchange and hello done messages.
            /// Extract server public key and server random.
            fn serverHello(h: *Handshake) !void {
                var rd: tls.Decoder = .{ .buf = &h.buffer }; // record decoder
                var handshake_state = HandshakeType.server_hello;
                while (true) {
                    try rd.readAtLeastOurAmt(h.stream, tls.record_header_len);
                    const content_type = rd.decode(tls.ContentType);
                    const protocol_version = rd.decode(tls.ProtocolVersion);
                    const record_len = rd.decode(u16);
                    if (protocol_version != tls.ProtocolVersion.tls_1_2) return error.TlsBadVersion;

                    try rd.readAtLeast(h.stream, record_len);
                    var hd = try rd.sub(record_len); // header decoder

                    switch (content_type) {
                        tls.ContentType.handshake => {
                            try hd.ensure(4);
                            const handshake_type = hd.decode(HandshakeType);
                            if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;
                            const length = hd.decode(u24);
                            var hsd = try hd.sub(length); // handshake decoder
                            h.hash.update(hsd.rest());

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
                                    if (cipher_suite != 0xc013) return error.TlsIllegalParameter; // the only one we support
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
                Sha256.create(&a1, seed, &pre_master_secret);
                Sha256.create(&a2, &a1, &pre_master_secret);

                var p1: [32]u8 = undefined;
                var p2: [32]u8 = undefined;
                Sha256.create(&p1, a1 ++ seed, &pre_master_secret);
                Sha256.create(&p2, a2 ++ seed, &pre_master_secret);

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
                Sha256.create(&a1, a0, &h.master_secret);
                Sha256.create(&a2, &a1, &h.master_secret);
                Sha256.create(&a3, &a2, &h.master_secret);
                Sha256.create(&a4, &a3, &h.master_secret);

                var p: [32 * 4]u8 = undefined;
                Sha256.create(p[0..32], a1 ++ seed, &h.master_secret);
                Sha256.create(p[32..64], a2 ++ seed, &h.master_secret);
                Sha256.create(p[64..96], a3 ++ seed, &h.master_secret);
                Sha256.create(p[96..], a4 ++ seed, &h.master_secret);

                h.cipher = .{
                    .client_secret = p[0..20].*,
                    .server_secret = p[20..40].*,
                    .client_key = p[40..56].*,
                    .server_key = p[56..72].*,
                    .client_iv = p[72..88].*,
                    .server_iv = p[88..104].*,
                };
            }
        };
    };
}

const testing = std.testing;
const bytesToHex = std.fmt.bytesToHex;

test "Handshake.clientHello" {
    var stream = TestStream{ .buffer = undefined };
    defer stream.deinit();
    var h: Client(*TestStream).Handshake = .{
        .stream = &stream,
        .client_random = [32]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        },
    };
    try testing.expectEqualStrings(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        &bytesToHex(h.hash.peek(), .lower),
    );
    const host = "www.example.com";
    try h.clientHello(host);
    try testing.expectEqualStrings(
        "addf49808baa2c4b329898b857b903521be9370d",
        &bytesToHex(h.hash.peek(), .lower),
    );

    try testing.expectEqualSlices(u8, &[_]u8{
        0x16, 0x03, 0x01, 0x00, 0x61, 0x01, 0x00, 0x00, 0x5d, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0xc0, 0x13,
        0x01, 0x00, 0x00, 0x32, 0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0c, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04,
        0x08, 0x05, 0x08, 0x06, 0x08, 0x07, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x12, 0x00, 0x00, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
        0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    }, stream.output.items);
    try testing.expectEqualStrings(host, stream.output.items[stream.output.items.len - host.len ..]);
}

test "Handshake.serverHello" {
    var stream = TestStream{ .buffer = @embedFile("testdata/google_server_hello") };
    defer stream.deinit();
    var h: Client(*TestStream).Handshake = .{
        .stream = &stream,
        .client_random = [_]u8{0} ** 32,
        .server_random = [_]u8{0} ** 32,
        .server_public_key = [_]u8{0} ** 32,
    };
    try h.serverHello();
    try testing.expectEqualStrings(
        "6622823581e433946fff2062e69693714c8e65562778f552444f574e47524401",
        &bytesToHex(h.server_random, .lower),
    );
    try testing.expectEqualStrings(
        "4da89f50a309ddbe6761f99e2fa54e3e5c0e097245703d74debd15c9a2ef6d5f",
        &bytesToHex(h.server_public_key, .lower),
    );
    // unchanged in serverHello
    try testing.expectEqualStrings(
        "0000000000000000000000000000000000000000000000000000000000000000",
        &bytesToHex(h.client_random, .lower),
    );
    try testing.expectEqualStrings(
        "ebae7b885ad10b9921d7c3ddc5fe974753c40825",
        &bytesToHex(h.hash.peek(), .lower),
    );
}

test "Handshake.generateMasterSecret" {
    const hexToBytes = std.fmt.hexToBytes;
    var h: Client(TestStream).Handshake = .{ .stream = undefined };
    _ = try hexToBytes(h.client_private_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    _ = try hexToBytes(h.server_random[0..], "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
    _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    _ = try hexToBytes(h.server_public_key[0..], "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
    try h.generateMasterSecret();
    try testing.expectEqualStrings(
        "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c",
        &bytesToHex(h.master_secret, .lower),
    );

    try h.generateEncryptionKeys();
    try testing.expectEqualStrings("1b7d117c7d5f690bc263cae8ef60af0f1878acc2", &bytesToHex(h.cipher.client_secret, .lower));
    try testing.expectEqualStrings("2ad8bdd8c601a617126f63540eb20906f781fad2", &bytesToHex(h.cipher.server_secret, .lower));
    // try testing.expectEqualStrings("f656d037b173ef3e11169f27231a84b6", &bytesToHex(client_key, .lower));
    // try testing.expectEqualStrings("752a18e7a9fcb7cbcdd8f98dd8f769eb", &bytesToHex(server_key, .lower));
    // try testing.expectEqualStrings("a0d2550c9238eebfef5c32251abb67d6", &bytesToHex(client_iv, .lower));
    // try testing.expectEqualStrings("434528db4937d540d393135e06a11bb8", &bytesToHex(server_iv, .lower));
}

// test "Handshake.generateEncryptionKeys" {
//     const hexToBytes = std.fmt.hexToBytes;
//     var h: Client(TestStream).Handshake = .{ .stream = undefined };
//     _ = try hexToBytes(h.client_private_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
//     _ = try hexToBytes(h.server_random[0..], "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
//     _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
//     _ = try hexToBytes(h.server_public_key[0..], "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
//     try h.generateMasterSecret();
//     try testing.expectEqualStrings(
//         "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c",
//         &bytesToHex(h.master_secret, .lower),
//     );
// }

// example from: https://tls12.xargs.org/#server-hello-done
test "illustrated example" {
    var stream = TestStream{ .buffer = &(server_hello ++ server_certificate ++ server_key_exchange ++ server_hello_done) };
    defer stream.deinit();
    var h: Client(*TestStream).Handshake = .{
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
}

const TestStream = struct {
    buffer: []const u8,
    pos: usize = 0,

    output: std.ArrayList(u8) = std.ArrayList(u8).init(testing.allocator),

    const Self = @This();

    pub fn writevAll(self: *Self, iovecs: []posix.iovec_const) !void {
        for (iovecs) |iovec| {
            var buf: []const u8 = undefined;
            buf.ptr = iovec.iov_base;
            buf.len = iovec.iov_len;

            try self.output.appendSlice(buf);
        }
    }

    pub fn readAtLeast(self: *Self, buffer: []u8, len: usize) !usize {
        const n: usize = @min(len, self.buffer.len - self.pos);
        @memcpy(buffer[0..n], self.buffer[self.pos..][0..n]);
        self.pos += n;
        return n;
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit();
    }
};

const server_hello = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0x31, 0x02, 0x00, 0x00, 0x2d, 0x03, 0x03, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x00, 0xc0, 0x13, 0x00, 0x00,
    0x05, 0xff, 0x01, 0x00, 0x01, 0x00,
};
const server_certificate = [_]u8{
    0x16, 0x03, 0x03, 0x03, 0x2f, 0x0b, 0x00, 0x03, 0x2b, 0x00, 0x03, 0x28, 0x00, 0x03, 0x25, 0x30,
    0x82, 0x03, 0x21, 0x30, 0x82, 0x02, 0x09, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x15, 0x5a,
    0x92, 0xad, 0xc2, 0x04, 0x8f, 0x90, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x22, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x45,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31,
    0x30, 0x30, 0x35, 0x30, 0x31, 0x33, 0x38, 0x31, 0x37, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30,
    0x30, 0x35, 0x30, 0x31, 0x33, 0x38, 0x31, 0x37, 0x5a, 0x30, 0x2b, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x13, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65,
    0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
    0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc4, 0x80, 0x36, 0x06, 0xba, 0xe7, 0x47, 0x6b, 0x08,
    0x94, 0x04, 0xec, 0xa7, 0xb6, 0x91, 0x04, 0x3f, 0xf7, 0x92, 0xbc, 0x19, 0xee, 0xfb, 0x7d, 0x74,
    0xd7, 0xa8, 0x0d, 0x00, 0x1e, 0x7b, 0x4b, 0x3a, 0x4a, 0xe6, 0x0f, 0xe8, 0xc0, 0x71, 0xfc, 0x73,
    0xe7, 0x02, 0x4c, 0x0d, 0xbc, 0xf4, 0xbd, 0xd1, 0x1d, 0x39, 0x6b, 0xba, 0x70, 0x46, 0x4a, 0x13,
    0xe9, 0x4a, 0xf8, 0x3d, 0xf3, 0xe1, 0x09, 0x59, 0x54, 0x7b, 0xc9, 0x55, 0xfb, 0x41, 0x2d, 0xa3,
    0x76, 0x52, 0x11, 0xe1, 0xf3, 0xdc, 0x77, 0x6c, 0xaa, 0x53, 0x37, 0x6e, 0xca, 0x3a, 0xec, 0xbe,
    0xc3, 0xaa, 0xb7, 0x3b, 0x31, 0xd5, 0x6c, 0xb6, 0x52, 0x9c, 0x80, 0x98, 0xbc, 0xc9, 0xe0, 0x28,
    0x18, 0xe2, 0x0b, 0xf7, 0xf8, 0xa0, 0x3a, 0xfd, 0x17, 0x04, 0x50, 0x9e, 0xce, 0x79, 0xbd, 0x9f,
    0x39, 0xf1, 0xea, 0x69, 0xec, 0x47, 0x97, 0x2e, 0x83, 0x0f, 0xb5, 0xca, 0x95, 0xde, 0x95, 0xa1,
    0xe6, 0x04, 0x22, 0xd5, 0xee, 0xbe, 0x52, 0x79, 0x54, 0xa1, 0xe7, 0xbf, 0x8a, 0x86, 0xf6, 0x46,
    0x6d, 0x0d, 0x9f, 0x16, 0x95, 0x1a, 0x4c, 0xf7, 0xa0, 0x46, 0x92, 0x59, 0x5c, 0x13, 0x52, 0xf2,
    0x54, 0x9e, 0x5a, 0xfb, 0x4e, 0xbf, 0xd7, 0x7a, 0x37, 0x95, 0x01, 0x44, 0xe4, 0xc0, 0x26, 0x87,
    0x4c, 0x65, 0x3e, 0x40, 0x7d, 0x7d, 0x23, 0x07, 0x44, 0x01, 0xf4, 0x84, 0xff, 0xd0, 0x8f, 0x7a,
    0x1f, 0xa0, 0x52, 0x10, 0xd1, 0xf4, 0xf0, 0xd5, 0xce, 0x79, 0x70, 0x29, 0x32, 0xe2, 0xca, 0xbe,
    0x70, 0x1f, 0xdf, 0xad, 0x6b, 0x4b, 0xb7, 0x11, 0x01, 0xf4, 0x4b, 0xad, 0x66, 0x6a, 0x11, 0x13,
    0x0f, 0xe2, 0xee, 0x82, 0x9e, 0x4d, 0x02, 0x9d, 0xc9, 0x1c, 0xdd, 0x67, 0x16, 0xdb, 0xb9, 0x06,
    0x18, 0x86, 0xed, 0xc1, 0xba, 0x94, 0x21, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x52, 0x30, 0x50,
    0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x89, 0x4f, 0xde, 0x5b,
    0xcc, 0x69, 0xe2, 0x52, 0xcf, 0x3e, 0xa3, 0x00, 0xdf, 0xb1, 0x97, 0xb8, 0x1d, 0xe1, 0xc1, 0x46,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x01, 0x00, 0x59, 0x16, 0x45, 0xa6, 0x9a, 0x2e, 0x37, 0x79, 0xe4, 0xf6, 0xdd, 0x27,
    0x1a, 0xba, 0x1c, 0x0b, 0xfd, 0x6c, 0xd7, 0x55, 0x99, 0xb5, 0xe7, 0xc3, 0x6e, 0x53, 0x3e, 0xff,
    0x36, 0x59, 0x08, 0x43, 0x24, 0xc9, 0xe7, 0xa5, 0x04, 0x07, 0x9d, 0x39, 0xe0, 0xd4, 0x29, 0x87,
    0xff, 0xe3, 0xeb, 0xdd, 0x09, 0xc1, 0xcf, 0x1d, 0x91, 0x44, 0x55, 0x87, 0x0b, 0x57, 0x1d, 0xd1,
    0x9b, 0xdf, 0x1d, 0x24, 0xf8, 0xbb, 0x9a, 0x11, 0xfe, 0x80, 0xfd, 0x59, 0x2b, 0xa0, 0x39, 0x8c,
    0xde, 0x11, 0xe2, 0x65, 0x1e, 0x61, 0x8c, 0xe5, 0x98, 0xfa, 0x96, 0xe5, 0x37, 0x2e, 0xef, 0x3d,
    0x24, 0x8a, 0xfd, 0xe1, 0x74, 0x63, 0xeb, 0xbf, 0xab, 0xb8, 0xe4, 0xd1, 0xab, 0x50, 0x2a, 0x54,
    0xec, 0x00, 0x64, 0xe9, 0x2f, 0x78, 0x19, 0x66, 0x0d, 0x3f, 0x27, 0xcf, 0x20, 0x9e, 0x66, 0x7f,
    0xce, 0x5a, 0xe2, 0xe4, 0xac, 0x99, 0xc7, 0xc9, 0x38, 0x18, 0xf8, 0xb2, 0x51, 0x07, 0x22, 0xdf,
    0xed, 0x97, 0xf3, 0x2e, 0x3e, 0x93, 0x49, 0xd4, 0xc6, 0x6c, 0x9e, 0xa6, 0x39, 0x6d, 0x74, 0x44,
    0x62, 0xa0, 0x6b, 0x42, 0xc6, 0xd5, 0xba, 0x68, 0x8e, 0xac, 0x3a, 0x01, 0x7b, 0xdd, 0xfc, 0x8e,
    0x2c, 0xfc, 0xad, 0x27, 0xcb, 0x69, 0xd3, 0xcc, 0xdc, 0xa2, 0x80, 0x41, 0x44, 0x65, 0xd3, 0xae,
    0x34, 0x8c, 0xe0, 0xf3, 0x4a, 0xb2, 0xfb, 0x9c, 0x61, 0x83, 0x71, 0x31, 0x2b, 0x19, 0x10, 0x41,
    0x64, 0x1c, 0x23, 0x7f, 0x11, 0xa5, 0xd6, 0x5c, 0x84, 0x4f, 0x04, 0x04, 0x84, 0x99, 0x38, 0x71,
    0x2b, 0x95, 0x9e, 0xd6, 0x85, 0xbc, 0x5c, 0x5d, 0xd6, 0x45, 0xed, 0x19, 0x90, 0x94, 0x73, 0x40,
    0x29, 0x26, 0xdc, 0xb4, 0x0e, 0x34, 0x69, 0xa1, 0x59, 0x41, 0xe8, 0xe2, 0xcc, 0xa8, 0x4b, 0xb6,
    0x08, 0x46, 0x36, 0xa0,
};
const server_key_exchange = [_]u8{
    0x16, 0x03, 0x03, 0x01, 0x2c, 0x0c, 0x00, 0x01, 0x28, 0x03, 0x00, 0x1d, 0x20, 0x9f, 0xd7, 0xad,
    0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b,
    0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15, 0x04, 0x01, 0x01,
    0x00, 0x04, 0x02, 0xb6, 0x61, 0xf7, 0xc1, 0x91, 0xee, 0x59, 0xbe, 0x45, 0x37, 0x66, 0x39, 0xbd,
    0xc3, 0xd4, 0xbb, 0x81, 0xe1, 0x15, 0xca, 0x73, 0xc8, 0x34, 0x8b, 0x52, 0x5b, 0x0d, 0x23, 0x38,
    0xaa, 0x14, 0x46, 0x67, 0xed, 0x94, 0x31, 0x02, 0x14, 0x12, 0xcd, 0x9b, 0x84, 0x4c, 0xba, 0x29,
    0x93, 0x4a, 0xaa, 0xcc, 0xe8, 0x73, 0x41, 0x4e, 0xc1, 0x1c, 0xb0, 0x2e, 0x27, 0x2d, 0x0a, 0xd8,
    0x1f, 0x76, 0x7d, 0x33, 0x07, 0x67, 0x21, 0xf1, 0x3b, 0xf3, 0x60, 0x20, 0xcf, 0x0b, 0x1f, 0xd0,
    0xec, 0xb0, 0x78, 0xde, 0x11, 0x28, 0xbe, 0xba, 0x09, 0x49, 0xeb, 0xec, 0xe1, 0xa1, 0xf9, 0x6e,
    0x20, 0x9d, 0xc3, 0x6e, 0x4f, 0xff, 0xd3, 0x6b, 0x67, 0x3a, 0x7d, 0xdc, 0x15, 0x97, 0xad, 0x44,
    0x08, 0xe4, 0x85, 0xc4, 0xad, 0xb2, 0xc8, 0x73, 0x84, 0x12, 0x49, 0x37, 0x25, 0x23, 0x80, 0x9e,
    0x43, 0x12, 0xd0, 0xc7, 0xb3, 0x52, 0x2e, 0xf9, 0x83, 0xca, 0xc1, 0xe0, 0x39, 0x35, 0xff, 0x13,
    0xa8, 0xe9, 0x6b, 0xa6, 0x81, 0xa6, 0x2e, 0x40, 0xd3, 0xe7, 0x0a, 0x7f, 0xf3, 0x58, 0x66, 0xd3,
    0xd9, 0x99, 0x3f, 0x9e, 0x26, 0xa6, 0x34, 0xc8, 0x1b, 0x4e, 0x71, 0x38, 0x0f, 0xcd, 0xd6, 0xf4,
    0xe8, 0x35, 0xf7, 0x5a, 0x64, 0x09, 0xc7, 0xdc, 0x2c, 0x07, 0x41, 0x0e, 0x6f, 0x87, 0x85, 0x8c,
    0x7b, 0x94, 0xc0, 0x1c, 0x2e, 0x32, 0xf2, 0x91, 0x76, 0x9e, 0xac, 0xca, 0x71, 0x64, 0x3b, 0x8b,
    0x98, 0xa9, 0x63, 0xdf, 0x0a, 0x32, 0x9b, 0xea, 0x4e, 0xd6, 0x39, 0x7e, 0x8c, 0xd0, 0x1a, 0x11,
    0x0a, 0xb3, 0x61, 0xac, 0x5b, 0xad, 0x1c, 0xcd, 0x84, 0x0a, 0x6c, 0x8a, 0x6e, 0xaa, 0x00, 0x1a,
    0x9d, 0x7d, 0x87, 0xdc, 0x33, 0x18, 0x64, 0x35, 0x71, 0x22, 0x6c, 0x4d, 0xd2, 0xc2, 0xac, 0x41,
    0xfb,
};
const server_hello_done = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00,
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
