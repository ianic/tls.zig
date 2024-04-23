const std = @import("std");
const crypto = std.crypto;
const posix = std.posix;

const tls = crypto.tls;
const int2 = tls.int2;
const int3 = tls.int3;
const array = tls.array;
const enum_array = tls.enum_array;

const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

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

pub inline fn int1(x: u8) [1]u8 {
    return .{x};
}

// int1 from enum
pub inline fn int1e(x: anytype) [1]u8 {
    return int1(@intFromEnum(x));
}

pub inline fn int2e(x: anytype) [2]u8 {
    return int2(@intFromEnum(x));
}

pub fn client(stream: anytype) ClientT(@TypeOf(stream)) {
    return .{ .stream = stream };
}

inline fn serverNameExtensionHeader(host_len: u16) [9]u8 {
    return int2e(tls.ExtensionType.server_name) ++
        int2(host_len + 5) ++ // byte length of this extension payload
        int2(host_len + 3) ++ // server_name_list byte count
        [1]u8{0x00} ++ // name_type
        int2(host_len);
}

pub fn ClientT(comptime StreamType: type) type {
    const CipherType = std.crypto.tls.ApplicationCipherT(@import("cbc.zig").CBCAes128, std.crypto.hash.Sha1);
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
            const cipher_text = encrypt(c.cipher, &buffer, c.client_sequence, [_]u8{ 0x17, 0x03, 0x03 }, buf[0..len]);

            const record_header =
                int1e(tls.ContentType.application_data) ++
                int2e(tls.ProtocolVersion.tls_1_2) ++
                int2(@intCast(cipher_text.len));
            {
                var iovecs = [_]std.posix.iovec_const{
                    .{
                        .iov_base = &record_header,
                        .iov_len = record_header.len,
                    },
                    .{
                        .iov_base = cipher_text.ptr,
                        .iov_len = cipher_text.len,
                    },
                };
                try c.stream.writevAll(&iovecs);
            }
            return len;
        }

        pub fn read(c: *Client, buf: []u8) !usize {
            while (true) {
                // If we have unread cleartext data, return them to the caller
                if (c.cleartext_end > c.cleartext_start) {
                    const n = @min(buf.len, c.cleartext_end - c.cleartext_start);
                    @memcpy(buf[0..n], c.read_buffer[c.cleartext_start..][0..n]);
                    c.cleartext_start += n;
                    return n;
                }

                const read_buffer = c.read_buffer[c.ciphertext_start..c.ciphertext_end];
                // If we have 5 bytes header
                if (read_buffer.len > tls.record_header_len) {
                    const record_header = read_buffer[0..tls.record_header_len];
                    const content_type: tls.ContentType = @enumFromInt(record_header[0]);
                    if (content_type != .application_data) // TODO: handle other types
                        return error.TlsUnexpectedMessage;
                    const data_len = std.mem.readInt(u16, record_header[3..5], .big);
                    // If we have whole encrypted record, decrypt it.
                    if (read_buffer[tls.record_header_len..].len >= data_len) {
                        const data = read_buffer[tls.record_header_len .. tls.record_header_len + data_len];
                        c.cleartext_start = c.ciphertext_start;
                        const cleartext = try decrypt(c.cipher, c.read_buffer[c.cleartext_start..], data[0..16].*, data[16..]);
                        c.cleartext_end = c.cleartext_start + cleartext.len;
                        c.ciphertext_start += tls.record_header_len + data_len;
                        continue;
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
                { // Read more from stream into read_buffer.
                    const n = try c.stream.read(c.read_buffer[c.ciphertext_end..]);
                    if (n == 0) return 0;
                    c.ciphertext_end += n;
                }
            }
        }

        /// Generete iv, encrypt data, put iv and chipertext into buf.
        /// After this buf contains iv and chipertext.
        fn encrypt(
            cipher: CipherType,
            buf: []u8,
            sequence: u64,
            record_header: [3]u8,
            data: []const u8,
        ) []const u8 {
            var iv: [16]u8 = undefined;
            crypto.random.bytes(&iv);
            buf[0..16].* = iv;
            const chipertext = try encryptIv(cipher, buf[16..], sequence, record_header, iv, data);
            return buf[0 .. 16 + chipertext.len];
        }

        /// Encrypt with provided iv. Encrypted data are put into buf.
        /// Returns part of the buf with ciphertext data.
        fn encryptIv(
            cipher: CipherType,
            buf: []u8,
            sequence: u64,
            record_header: [3]u8,
            iv: [16]u8,
            data: []const u8,
        ) ![]const u8 {
            const mac_length = CipherType.Hash.digest_length;

            std.mem.writeInt(u64, buf[0..8], sequence, .big);
            buf[8..][0..3].* = record_header;
            std.mem.writeInt(u16, buf[11..][0..2], @intCast(data.len), .big);
            @memcpy(buf[13..][0..data.len], data);
            const mac_buf = buf[0 .. 13 + data.len];

            var mac: [mac_length]u8 = undefined;
            CipherType.Hmac.create(&mac, mac_buf, &cipher.client_secret);

            @memcpy(buf[0..data.len], data);
            @memcpy(buf[data.len..][0..mac.len], &mac);

            const unpadded_len = data.len + mac.len;
            const padded_len = CipherType.AEAD.paddedLength(unpadded_len);
            const padding_byte: u8 = @intCast(padded_len - unpadded_len - 1);
            @memset(buf[unpadded_len..padded_len], padding_byte);
            const cleartext = buf[0..padded_len];

            const z = CipherType.AEAD.init(cipher.client_key);
            const ciphertext = buf[0..cleartext.len];
            z.encryptBlocks(ciphertext, cleartext, iv);
            return ciphertext;
        }

        fn decrypt(cipher: CipherType, buf: []u8, iv: [16]u8, ciphertext: []const u8) ![]const u8 {
            const mac_length = CipherType.Hash.digest_length;
            const z = CipherType.AEAD.init(cipher.server_key);
            const decrypted = buf[0..ciphertext.len];
            try z.decryptBlocks(decrypted, ciphertext, iv);
            const padding_len = decrypted[decrypted.len - 1] + 1;
            // TODO check mac
            const cleartext = decrypted[0 .. decrypted.len - padding_len - mac_length];
            return cleartext;
        }

        // decrypt with client key
        fn clientDecrypt(cipher: CipherType, buf: []u8, iv: [16]u8, ciphertext: []const u8) ![]const u8 {
            const mac_length = CipherType.Hash.digest_length;
            const z = CipherType.AEAD.init(cipher.client_key);
            const decrypted = buf[0..ciphertext.len];
            try z.decryptBlocks(decrypted, ciphertext, iv);
            const padding_len = decrypted[decrypted.len - 1] + 1;
            // TODO check mac
            const cleartext = decrypted[0 .. decrypted.len - padding_len - mac_length];
            return cleartext;
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
                const host_len: u16 = @intCast(host.len);

                const no_compression = [_]u8{ 0x01, 0x00 };
                const no_session_id = [_]u8{0x00};
                const cipher_suites = [_]u8{
                    0x00, 0x02, // 2 bytes of cipher suite data follows
                    0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
                };

                const extensions_payload =
                    [_]u8{ 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 } ++ // status request
                    [_]u8{ 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 } ++ // ec point formats
                    [_]u8{ 0xff, 0x01, 0x00, 0x01, 0x00 } ++ // renegotiation info
                    [_]u8{ 0x00, 0x12, 0x00, 0x00 } ++ // sct
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
                    serverNameExtensionHeader(host_len);

                const payload =
                    int2e(tls.ProtocolVersion.tls_1_2) ++
                    h.client_random ++
                    no_session_id ++
                    cipher_suites ++
                    no_compression ++
                    int2(@intCast(extensions_payload.len + host_len)) ++
                    extensions_payload;

                const handshake_header =
                    int1e(tls.HandshakeType.client_hello) ++
                    int3(@intCast(payload.len + host_len));

                const record =
                    int1e(tls.ContentType.handshake) ++
                    int2e(tls.ProtocolVersion.tls_1_2) ++
                    int2(@intCast(handshake_header.len + payload.len + host_len)) ++
                    handshake_header ++
                    payload;

                {
                    var iovecs = [_]std.posix.iovec_const{
                        .{
                            .iov_base = &record,
                            .iov_len = record.len,
                        },
                        .{
                            .iov_base = host.ptr,
                            .iov_len = host.len,
                        },
                    };
                    try h.stream.writevAll(&iovecs);
                }
                h.transcript.update(record[5..]);
                h.transcript.update(host);
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
                    h.transcript.update(hd.rest());

                    switch (content_type) {
                        tls.ContentType.handshake => {
                            try hd.ensure(4);
                            const handshake_type = hd.decode(HandshakeType);
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

                h.cipher = .{
                    .client_secret = p[0..20].*,
                    .server_secret = p[20..40].*,
                    .client_key = p[40..56].*,
                    .server_key = p[56..72].*,
                    .client_iv = p[72..88].*,
                    .server_iv = p[88..104].*,
                };
            }

            fn keyExchange(h: *Handshake) !void {
                const len = h.client_public_key.len;
                const header =
                    int1e(tls.ContentType.handshake) ++
                    int2e(tls.ProtocolVersion.tls_1_2) ++
                    int2(5 + len) ++
                    int1e(HandshakeType.client_key_exchange) ++
                    int3(1 + len) ++
                    int1(len);
                {
                    var iovecs = [_]std.posix.iovec_const{
                        .{
                            .iov_base = &header,
                            .iov_len = header.len,
                        },
                        .{
                            .iov_base = &h.client_public_key,
                            .iov_len = len,
                        },
                    };
                    try h.stream.writevAll(&iovecs);
                }
                h.transcript.update(header[5..]);
                h.transcript.update(&h.client_public_key);
            }

            fn changeCipherSpec(h: *Handshake) !void {
                const header =
                    int1e(tls.ContentType.change_cipher_spec) ++
                    int2e(tls.ProtocolVersion.tls_1_2) ++
                    int2(1) ++
                    int1(1);
                {
                    var iovecs = [_]std.posix.iovec_const{
                        .{
                            .iov_base = &header,
                            .iov_len = header.len,
                        },
                    };
                    try h.stream.writevAll(&iovecs);
                }
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

                const record_header =
                    int1e(tls.ContentType.handshake) ++
                    int2e(tls.ProtocolVersion.tls_1_2);
                const data = Client.encrypt(h.cipher, &h.buffer, 0, record_header, &verify_data);
                const header = record_header ++ int2(@intCast(data.len));

                {
                    var iovecs = [_]std.posix.iovec_const{
                        .{
                            .iov_base = &header,
                            .iov_len = header.len,
                        },
                        .{
                            .iov_base = data.ptr,
                            .iov_len = data.len,
                        },
                    };
                    try h.stream.writevAll(&iovecs);
                }
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
                    rd.skip(record_len);
                }
            }

            // fn encryptIV(
            //     h: *Handshake,
            //     buf: []u8,
            //     sequence: u64,
            //     record_header: [3]u8,
            //     data: []const u8,
            // ) []const u8 {
            //     var iv: [16]u8 = undefined;
            //     crypto.random.bytes(&iv);
            //     buf[0..16].* = iv;
            //     const chipertext = try h.encrypt(buf[16..], sequence, record_header, iv, data);
            //     return buf[0 .. 16 + chipertext.len];
            // }

            // fn encrypt(
            //     h: *Handshake,
            //     buf: []u8,
            //     sequence: u64,
            //     record_header: [3]u8,
            //     iv: [16]u8,
            //     data: []const u8,
            // ) ![]const u8 {
            //     const mac_length = CipherType.Hash.digest_length;

            //     std.mem.writeInt(u64, buf[0..8], sequence, .big);
            //     buf[8..][0..3].* = record_header;
            //     std.mem.writeInt(u16, buf[11..][0..2], @intCast(data.len), .big);
            //     @memcpy(buf[13..][0..data.len], data);
            //     const mac_buf = buf[0 .. 13 + data.len];

            //     var mac: [mac_length]u8 = undefined;
            //     CipherType.Hmac.create(&mac, mac_buf, &h.cipher.client_secret);

            //     @memcpy(buf[0..data.len], data);
            //     @memcpy(buf[data.len..][0..mac.len], &mac);

            //     const unpadded_len = data.len + mac.len;
            //     const padded_len = CipherType.AEAD.paddedLength(unpadded_len);
            //     const padding_byte: u8 = @intCast(padded_len - unpadded_len - 1);
            //     @memset(buf[unpadded_len..padded_len], padding_byte);
            //     const cleartext = buf[0..padded_len];

            //     const z = CipherType.AEAD.init(h.cipher.client_key);
            //     const ciphertext = buf[0..cleartext.len];
            //     z.encryptBlocks(ciphertext, cleartext, iv);
            //     return ciphertext;
            // }

            // fn decrypt(h: *Handshake, buf: []u8, iv: [16]u8, ciphertext: []const u8) ![]const u8 {
            //     const mac_length = CipherType.Hash.digest_length;
            //     const z = CipherType.AEAD.init(h.cipher.client_key);
            //     const decrypted = buf[0..ciphertext.len];
            //     try z.decryptBlocks(decrypted, ciphertext, iv);
            //     const padding_len = decrypted[decrypted.len - 1] + 1;
            //     // TODO check mac
            //     const cleartext = decrypted[0 .. decrypted.len - padding_len - mac_length];
            //     return cleartext;
            // }
        };
    };
}

const testing = std.testing;
const bytesToHex = std.fmt.bytesToHex;
const hexToBytes = std.fmt.hexToBytes;

test "Handshake.clientHello" {
    var stream = TestStream{ .buffer = undefined };
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
        0x16, 0x03, 0x03, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x77, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0xc0, 0x13,
        0x01, 0x00, 0x00, 0x4c, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
        0x02, 0x01, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x10,
        0x00, 0x0e, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07, 0x02, 0x01,
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
        0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    }, stream.output.items);
    try testing.expectEqualStrings(host, stream.output.items[stream.output.items.len - host.len ..]);
}

test "Handshake.serverHello" {
    var stream = TestStream{ .buffer = @embedFile("testdata/google_server_hello") };
    defer stream.deinit();
    var h: ClientT(*TestStream).Handshake = .{
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
        try testing.expectEqualStrings(
            "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c",
            &bytesToHex(h.master_secret, .lower),
        );
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
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        const ciphertext = try ClientType.encryptIv(h.cipher, &buf, 1, [_]u8{ 0x17, 0x03, 0x03 }, iv, cleartext);
        const expected_ciphertext = [_]u8{
            0x6c, 0x42, 0x1c, 0x71, 0xc4, 0x2b, 0x18, 0x3b, 0xfa, 0x06, 0x19, 0x5d, 0x13, 0x3d, 0x0a, 0x09,
            0xd0, 0x0f, 0xc7, 0xcb, 0x4e, 0x0f, 0x5d, 0x1c, 0xda, 0x59, 0xd1, 0x47, 0xec, 0x79, 0x0c, 0x99,
        };
        try testing.expectEqualSlices(u8, &expected_ciphertext, ciphertext);

        try testing.expectEqualStrings(cleartext, try ClientType.clientDecrypt(h.cipher, &buf, iv, ciphertext[0..32]));
    }
    { // encrypt verify data from illustrated example
        const iv = [_]u8{
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        };
        const data = [_]u8{
            0x14, 0x00, 0x00, 0x0c, 0xcf, 0x91, 0x96, 0x26, 0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a,
        };
        const ciphertext = try ClientType.encryptIv(h.cipher, &buf, 0, [_]u8{ 0x16, 0x03, 0x03 }, iv, &data);
        const expected_ciphertext = [_]u8{
            0x22, 0x7b, 0xc9, 0xba, 0x81, 0xef, 0x30, 0xf2, 0xa8, 0xa7, 0x8f, 0xf1, 0xdf, 0x50, 0x84, 0x4d,
            0x58, 0x04, 0xb7, 0xee, 0xb2, 0xe2, 0x14, 0xc3, 0x2b, 0x68, 0x92, 0xac, 0xa3, 0xdb, 0x7b, 0x78,
            0x07, 0x7f, 0xdd, 0x90, 0x06, 0x7c, 0x51, 0x6b, 0xac, 0xb3, 0xba, 0x90, 0xde, 0xdf, 0x72, 0x0f,
        };
        try testing.expectEqualSlices(u8, &expected_ciphertext, ciphertext);
    }
}

test "Handshake.clientKeyExchange" {
    var stream = TestStream{ .buffer = undefined };
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
    // init client with master secret
    var stream = TestStream{ .buffer = undefined };
    defer stream.deinit();
    var h: ClientT(*TestStream).Handshake = .{ .stream = &stream };
    _ = try std.fmt.hexToBytes(
        h.master_secret[0..],
        "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c",
    );

    // and handshake messages to transcript
    h.transcript.update(client_hello_msg[5..]);
    h.transcript.update(server_hello[5..]);
    h.transcript.update(server_certificate[5..]);
    h.transcript.update(server_key_exchange[5..]);
    h.transcript.update(server_hello_done[5..]);
    h.transcript.update(client_key_exchange[5..]);

    // expect verify data
    const verify_data = h.verifyData();
    try testing.expectEqualStrings(
        "1400000ccf919626f1360c536aaad73a",
        &bytesToHex(verify_data, .lower),
    );
}

// example from: https://tls12.xargs.org/#server-hello-done
test "illustrated example" {
    var stream = TestStream{ .buffer = &(server_hello ++ server_certificate ++ server_key_exchange ++ server_hello_done) };
    defer stream.deinit();
    var h: ClientT(*TestStream).Handshake = .{
        .stream = &stream,
        .client_random = [_]u8{0} ** 32,
        .server_random = [_]u8{0} ** 32,
        .server_public_key = [_]u8{0} ** 32,
    };
    { // set masster key
        _ = try std.fmt.hexToBytes(
            h.master_secret[0..],
            "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c",
        );
    }

    h.transcript.update(client_hello_msg[5..]);
    try h.serverHello();
    h.transcript.update(client_key_exchange[5..]);

    { // server random and public key are extracted from server messages
        try testing.expectEqualStrings(
            "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
            &bytesToHex(h.server_random, .lower),
        );
        try testing.expectEqualStrings(
            "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615",
            &bytesToHex(h.server_public_key, .lower),
        );
    }

    { // expect verify data
        const verify_data = h.verifyData();
        try testing.expectEqualStrings(
            "1400000ccf919626f1360c536aaad73a",
            &bytesToHex(verify_data, .lower),
        );
    }
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

const client_hello_msg = [_]u8{
    0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x20, 0xcc, 0xa8,
    0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14,
    0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00,
    0x00, 0x58, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x05,
    0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00,
    0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00,
    0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02,
    0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00,
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
const client_key_exchange = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0x25, 0x10, 0x00, 0x00, 0x21, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58,
    0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e,
    0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,
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

test "client finished verify data calculation" {
    //var hash: Sha1 = Sha1.init(.{});
    var hash = std.crypto.hash.sha2.Sha256.init(.{});

    hash.update(client_hello_msg[5..]);
    hash.update(server_hello[5..]);
    hash.update(server_certificate[5..]);
    hash.update(server_key_exchange[5..]);
    hash.update(server_hello_done[5..]);
    hash.update(client_key_exchange[5..]);

    var v: [32]u8 = undefined;
    hash.final(&v);
    // std.debug.print("\nv: {x}\n", .{v});

    var master_secret: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(master_secret[0..], "916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c");

    const seed = "client finished" ++ v;
    const a0 = seed;
    var a1: [32]u8 = undefined;
    var p1: [32]u8 = undefined;
    HmacSha256.create(&a1, a0, &master_secret);
    HmacSha256.create(&p1, a1 ++ seed, &master_secret);
    const verify_data = [_]u8{ 0x14, 0x00, 0x00, 0x0c } ++ p1[0..12];

    //var v2: [32]u8 = undefined;
    //Sha256.create(&v2, seed, &master_secret);

    //std.debug.print("verify_data: {x}\n", .{verify_data});

    try testing.expectEqualStrings(
        "1400000ccf919626f1360c536aaad73a",
        &bytesToHex(verify_data, .lower),
    );
}
