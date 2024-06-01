const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const hkdfExpandLabel = tls.hkdfExpandLabel;
const Sha1 = crypto.hash.Sha1;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;

const tls12 = @import("tls12.zig");
const Transcript = @import("transcript.zig").Transcript;

const Aes128Cbc = @import("cbc.zig").Aes128Cbc;
const Aes256Cbc = @import("cbc.zig").Aes256Cbc;
// tls 1.2 cbc chipher types
const CbcAes128Sha1 = CipherCbcT(Aes128Cbc, Sha1);
const CbcAes128Sha256 = CipherCbcT(Aes128Cbc, Sha256);
const CbcAes256Sha384 = CipherCbcT(Aes256Cbc, Sha384);
// tls 1.2 gcm chipher types
const Aead12Aes128Gcm = CipherAeadT(crypto.aead.aes_gcm.Aes128Gcm);
const Aead12Aes256Gcm = CipherAeadT(crypto.aead.aes_gcm.Aes256Gcm);
const Aead12ChaCha = CipherAeadT(crypto.aead.chacha_poly.ChaCha20Poly1305);
// tls 1.3 cipher types
const Aead13Aes128Gcm = CipherAead13T(crypto.aead.aes_gcm.Aes128Gcm);
const Aead13Aes256Gcm = CipherAead13T(crypto.aead.aes_gcm.Aes256Gcm);
const Aead13ChaCha = CipherAead13T(crypto.aead.chacha_poly.ChaCha20Poly1305);

fn CipherType(comptime tag: tls12.CipherSuite) type {
    return switch (tag) {
        // tls 1.2
        .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        .TLS_RSA_WITH_AES_128_CBC_SHA,
        => CbcAes128Sha1,

        .TLS_RSA_WITH_AES_128_CBC_SHA256 => CbcAes128Sha256,
        .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => CbcAes256Sha384,

        .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        => Aead12Aes128Gcm,

        .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Aead12Aes256Gcm,

        .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        => Aead12ChaCha,

        // tls 1.3
        .AES_128_GCM_SHA256 => Aead13Aes128Gcm,
        .AES_256_GCM_SHA384 => Aead13Aes256Gcm,
        .CHACHA20_POLY1305_SHA256 => Aead13ChaCha,

        else => unreachable,
    };
}

pub const Cipher = union(tls12.CipherSuite) {
    // tls 1.2
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: CipherType(.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: CipherType(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
    TLS_RSA_WITH_AES_128_CBC_SHA: CipherType(.TLS_RSA_WITH_AES_128_CBC_SHA),
    TLS_RSA_WITH_AES_128_CBC_SHA256: CipherType(.TLS_RSA_WITH_AES_128_CBC_SHA256),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: CipherType(.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),

    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherType(.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherType(.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherType(.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),

    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherType(.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherType(.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    // tls 1.3
    AES_128_GCM_SHA256: CipherType(.AES_128_GCM_SHA256),
    AES_256_GCM_SHA384: CipherType(.AES_256_GCM_SHA384),
    CHACHA20_POLY1305_SHA256: CipherType(.CHACHA20_POLY1305_SHA256),

    pub fn init12(tag: tls12.CipherSuite, key_material: []const u8, rnd: std.Random) !Cipher {
        switch (tag) {
            inline .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            .TLS_RSA_WITH_AES_128_CBC_SHA,
            .TLS_RSA_WITH_AES_128_CBC_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            => |comptime_tag| {
                return @unionInit(Cipher, @tagName(comptime_tag), CipherType(comptime_tag).init(key_material, rnd));
            },
            else => return error.TlsIllegalParameter,
        }
    }

    pub fn initHandshake(tag: tls12.CipherSuite, shared_key: []const u8, transcript: *Transcript) !Cipher {
        return switch (tag) {
            inline .CHACHA20_POLY1305_SHA256,
            .AES_128_GCM_SHA256,
            .AES_256_GCM_SHA384,
            => |comptime_tag| {
                return init13(comptime_tag, transcript.handshakeSecret(comptime_tag, shared_key));
            },
            else => return error.TlsIllegalParameter,
        };
    }

    pub fn initApplication(tag: tls12.CipherSuite, transcript: *Transcript) !Cipher {
        return switch (tag) {
            inline .CHACHA20_POLY1305_SHA256,
            .AES_128_GCM_SHA256,
            .AES_256_GCM_SHA384,
            => |comptime_tag| {
                return init13(comptime_tag, transcript.applicationSecret(comptime_tag));
            },
            else => return error.TlsIllegalParameter,
        };
    }

    fn init13(comptime tag: tls12.CipherSuite, secret: Transcript.Secret) Cipher {
        const Hkdf = Transcript.Hkdf(tag);
        const T = CipherType(tag);
        return @unionInit(Cipher, @tagName(tag), .{
            .client_key = hkdfExpandLabel(Hkdf, secret.client[0..Hkdf.prk_length].*, "key", "", T.key_len),
            .server_key = hkdfExpandLabel(Hkdf, secret.server[0..Hkdf.prk_length].*, "key", "", T.key_len),
            .client_iv = hkdfExpandLabel(Hkdf, secret.client[0..Hkdf.prk_length].*, "iv", "", T.nonce_len),
            .server_iv = hkdfExpandLabel(Hkdf, secret.server[0..Hkdf.prk_length].*, "iv", "", T.nonce_len),
            .rnd = crypto.random,
        });
    }
};

fn CipherAeadT(comptime AeadType: type) type {
    return struct {
        const key_len = AeadType.key_length;
        const auth_tag_len = AeadType.tag_length;
        const nonce_len = AeadType.nonce_length;
        const iv_len = AeadType.nonce_length - tls12.explicit_iv_len;

        client_key: [key_len]u8,
        server_key: [key_len]u8,
        client_iv: [iv_len]u8,
        server_iv: [iv_len]u8,
        rnd: std.Random,

        const Self = @This();

        fn init(key_material: []const u8, rnd: std.Random) Self {
            return .{
                .rnd = rnd,
                .client_key = key_material[0..key_len].*,
                .server_key = key_material[key_len..][0..key_len].*,
                .client_iv = key_material[2 * key_len ..][0..iv_len].*,
                .server_iv = key_material[2 * key_len + iv_len ..][0..iv_len].*,
            };
        }

        // TODO: nije tocno ima ispred jos i header
        /// Encrypt cleartext into provided buffer `buf`.
        /// After this buf contains payload in format:
        ///   explicit iv | ciphertext | auth tag
        pub fn encrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) []const u8 {
            const header = buf[0..tls.record_header_len];
            var explicit_iv: [tls12.explicit_iv_len]u8 = undefined;
            self.rnd.bytes(&explicit_iv);
            buf[header.len..][0..explicit_iv.len].* = explicit_iv;

            const iv = self.client_iv ++ explicit_iv;
            const ciphertext = buf[header.len + explicit_iv.len ..][0..cleartext.len];
            const auth_tag = buf[header.len + explicit_iv.len + ciphertext.len ..][0..auth_tag_len];
            const ad = additionalData(sequence, content_type, cleartext.len);
            AeadType.encrypt(ciphertext, auth_tag, cleartext, &ad, iv, self.client_key);

            header.* = tls12.recordHeader(content_type, explicit_iv.len + ciphertext.len + auth_tag.len);
            return buf[0 .. header.len + explicit_iv.len + ciphertext.len + auth_tag.len];
        }

        pub fn decrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            header: []const u8,
            payload: []const u8,
        ) !struct { tls.ContentType, []u8 } {
            const overhead = tls12.explicit_iv_len + auth_tag_len;
            if (payload.len < overhead) return error.TlsDecryptError;

            const iv = self.server_iv ++ payload[0..tls12.explicit_iv_len].*;
            const cleartext_len = payload.len - overhead;
            const ciphertext = payload[tls12.explicit_iv_len..][0..cleartext_len];
            const auth_tag = payload[tls12.explicit_iv_len + cleartext_len ..][0..auth_tag_len];
            const cleartext = buf[0..cleartext_len];
            const content_type: tls.ContentType = @enumFromInt(header[0]);
            const ad = additionalData(sequence, content_type, cleartext_len);

            try AeadType.decrypt(cleartext, ciphertext, auth_tag.*, &ad, iv, self.server_key);
            return .{ content_type, cleartext };
        }
    };
}

fn CipherAead13T(comptime AeadType: type) type {
    return struct {
        const key_len = AeadType.key_length;
        const auth_tag_len = AeadType.tag_length;
        const nonce_len = AeadType.nonce_length;

        client_key: [key_len]u8,
        server_key: [key_len]u8,
        client_iv: [nonce_len]u8,
        server_iv: [nonce_len]u8,
        rnd: std.Random,

        const Self = @This();

        pub fn encrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) []const u8 {
            // xor iv and sequence
            var iv = self.client_iv;
            const operand = std.mem.readInt(u64, iv[nonce_len - 8 ..], .big);
            std.mem.writeInt(u64, iv[nonce_len - 8 ..], operand ^ sequence, .big);

            const header = buf[0..tls.record_header_len];
            @memcpy(buf[header.len..][0..cleartext.len], cleartext);
            buf[header.len + cleartext.len] = @intFromEnum(content_type);
            const ciphertext = buf[header.len..][0 .. cleartext.len + 1];
            const auth_tag = buf[header.len + ciphertext.len ..][0..auth_tag_len];
            const encrypted_len = ciphertext.len + auth_tag_len;
            header.* = tls12.recordHeader(.application_data, encrypted_len);

            AeadType.encrypt(ciphertext, auth_tag, ciphertext, header, iv, self.client_key);
            return buf[0 .. header.len + encrypted_len];
        }

        pub fn decrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            header: []const u8,
            payload: []const u8,
        ) !struct { tls.ContentType, []u8 } {
            const overhead = auth_tag_len;
            if (payload.len < overhead) return error.TlsDecryptError;

            // xor iv and sequence
            var iv = self.server_iv;
            const operand = std.mem.readInt(u64, iv[nonce_len - 8 ..], .big);
            std.mem.writeInt(u64, iv[nonce_len - 8 ..], operand ^ sequence, .big);

            const cleartext_len = payload.len - overhead;
            const ciphertext = payload[0..cleartext_len];
            const auth_tag = payload[cleartext_len..][0..auth_tag_len];

            const cleartext = buf[0..cleartext_len];
            try AeadType.decrypt(cleartext, ciphertext, auth_tag.*, header, iv, self.server_key);
            return .{
                @enumFromInt(cleartext[cleartext_len - 1]),
                cleartext[0 .. cleartext.len - 1],
            };
        }
    };
}

fn CipherCbcT(comptime CbcType: type, comptime HashType: type) type {
    return struct {
        const mac_length = HashType.digest_length; // 20, 32, 48 bytes for sha1, sha256, sha384
        const key_length = CbcType.key_length; // 16 bytes
        const iv_length = CbcType.nonce_length; // 16 bytes

        pub const CBC = CbcType;
        pub const Hmac = crypto.auth.hmac.Hmac(HashType);

        client_secret: [mac_length]u8,
        server_secret: [mac_length]u8,
        client_key: [key_length]u8,
        server_key: [key_length]u8,
        rnd: std.Random,

        const Self = @This();

        fn init(key_material: []const u8, rnd: std.Random) Self {
            return .{
                .rnd = rnd,
                .client_secret = key_material[0..mac_length].*,
                .server_secret = key_material[mac_length..][0..mac_length].*,
                .client_key = key_material[2 * mac_length ..][0..key_length].*,
                .server_key = key_material[2 * mac_length + key_length ..][0..key_length].*,
            };
        }

        // max encrypt buf overhead = iv + mac + padding (1-16)
        // aes_128_cbc_sha => 16 + 20 + 16
        // aes_128_cbc_sha256 => 16 + 32 + 16
        // aes_256_cbc_sha384 => 16 + 48 + 16
        pub fn encrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) []const u8 {
            const ad = additionalData(sequence, content_type, cleartext.len);
            const cleartext_idx = tls.record_header_len + iv_length;

            // unused | ad | cleartext | mac
            //        | --mac input--  | --mac output--
            const mac_input_buf = buf[cleartext_idx - ad.len ..][0 .. ad.len + cleartext.len + mac_length];
            @memcpy(mac_input_buf[0..ad.len], &ad);
            @memcpy(mac_input_buf[ad.len..][0..cleartext.len], cleartext);
            const mac_output_buf = mac_input_buf[ad.len + cleartext.len ..][0..mac_length];

            Hmac.create(mac_output_buf, mac_input_buf[0 .. ad.len + cleartext.len], &self.client_secret);

            // unused | ad | cleartext | mac | padding
            const unpadded_len = cleartext.len + mac_length;
            const padded_len = CBC.paddedLength(unpadded_len);
            const payload_buf = buf[cleartext_idx..][0..padded_len];
            const padding_byte: u8 = @intCast(padded_len - unpadded_len - 1);
            @memset(payload_buf[unpadded_len..padded_len], padding_byte);

            // iv | cleartext | mac | padding
            // iv | -------   payload -------
            const iv = buf[cleartext_idx - iv_length .. cleartext_idx];
            self.rnd.bytes(iv);

            CBC.init(self.client_key).encrypt(payload_buf, payload_buf, iv[0..iv_length].*);
            buf[0..tls.record_header_len].* = tls12.recordHeader(content_type, iv_length + payload_buf.len);
            return buf[0 .. cleartext_idx + payload_buf.len];
        }

        pub fn decrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            header: []const u8,
            payload: []const u8,
        ) !struct { tls.ContentType, []u8 } {
            const content_type: tls.ContentType = @enumFromInt(header[0]);
            if (payload.len < iv_length + mac_length + 1) return error.TlsDecryptError;
            var ad = additionalData(sequence, content_type, payload.len);

            // --------- payload ------------
            // iv | -------   crypted -------
            // iv | cleartext | mac | padding
            const iv = payload[0..iv_length];
            const crypted = payload[iv_length..];
            // ---------- buf ---------------
            // ad | ------ decrypted --------
            // ad | cleartext | mac | padding
            const decrypted = buf[ad.len..][0..crypted.len];
            // decrypt crypted -> decrypted
            try CBC.init(self.server_key).decrypt(decrypted, crypted, iv[0..iv_length].*);

            // get padding len from last padding byte
            const padding_len = decrypted[decrypted.len - 1] + 1;
            if (decrypted.len < mac_length + padding_len) return error.TlsDecryptError;

            // split decrypted into cleartext and mac
            const cleartext_len = decrypted.len - mac_length - padding_len;
            const cleartext = decrypted[0..cleartext_len];
            const mac = decrypted[cleartext_len..][0..mac_length];

            // write len to the ad
            std.mem.writeInt(u16, ad[ad.len - 2 ..][0..2], @intCast(cleartext_len), .big);
            @memcpy(buf[0..ad.len], &ad);
            // calculate expected mac
            var expected_mac: [mac_length]u8 = undefined;
            Hmac.create(&expected_mac, buf[0 .. ad.len + cleartext_len], &self.server_secret);
            if (!std.mem.eql(u8, &expected_mac, mac))
                return error.TlsBadRecordMac;

            return .{ content_type, cleartext };
        }
    };
}

pub const additional_data_len = tls.record_header_len + @sizeOf(u64);

fn additionalData(sequence: u64, content_type: tls.ContentType, payload_len: usize) [additional_data_len]u8 {
    const header = tls12.recordHeader(content_type, payload_len);
    var sequence_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_buf, sequence, .big);
    return sequence_buf ++ header;
}

const testing = std.testing;

test "encrypt/decrypt gcm 1.2" {
    inline for ([_]type{
        Aead12Aes128Gcm,
        Aead12Aes256Gcm,
        Aead12ChaCha,
    }) |T| {
        var buf: [128]u8 = undefined;
        { // show byte lengths
            const expected_key_len = switch (T) {
                Aead12Aes128Gcm => 16,
                else => 32,
            };
            try testing.expectEqual(expected_key_len, T.key_len);
            try testing.expectEqual(16, T.auth_tag_len);
            try testing.expectEqual(12, T.nonce_len);
            try testing.expectEqual(4, T.iv_len);
        }
        { // init key material with same keys for client and server
            test_rnd.bytes(buf[0..T.key_len]);
            test_rnd.bytes(buf[T.key_len..][0..T.key_len]);
            test_rnd.bytes(buf[T.key_len * 2 ..][0..T.iv_len]);
            test_rnd.bytes(buf[T.key_len * 2 + T.iv_len ..][0..T.iv_len]);
        }
        var cipher: T = T.init(&buf, test_rnd);
        { // test equal server and client keys
            try testing.expectEqualSlices(u8, &cipher.server_key, &cipher.client_key);
            try testing.expectEqualSlices(u8, &cipher.server_iv, &cipher.client_iv);
        }

        const data = "Hello world!";
        // encrypt
        const ciphertext = cipher.encrypt(&buf, 0, .application_data, data);
        try testing.expectEqual(
            tls.record_header_len + tls12.explicit_iv_len + data.len + T.auth_tag_len,
            ciphertext.len,
        );

        // decrypt
        const header = ciphertext[0..tls.record_header_len];
        const payload = ciphertext[tls.record_header_len..];
        const content_type, const decrypted = try cipher.decrypt(&buf, 0, header, payload);
        try testing.expectEqualSlices(u8, data, decrypted);
        try testing.expectEqual(.application_data, content_type);
    }
}

test "encrypt/decrypt cbc 1.2" {
    inline for ([_]type{
        CbcAes128Sha1,
        CbcAes128Sha256,
        CbcAes256Sha384,
    }) |T| {
        var buf: [160]u8 = undefined;
        { // show byte lengths
            switch (T) {
                CbcAes128Sha1 => {
                    try testing.expectEqual(20, T.mac_length);
                    try testing.expectEqual(16, T.key_length);
                },
                CbcAes128Sha256 => {
                    try testing.expectEqual(32, T.mac_length);
                    try testing.expectEqual(16, T.key_length);
                },
                CbcAes256Sha384 => {
                    try testing.expectEqual(48, T.mac_length);
                    try testing.expectEqual(32, T.key_length);
                },
                else => unreachable,
            }
            try testing.expectEqual(16, T.CBC.paddedLength(1)); // cbc block padding
            try testing.expectEqual(16, T.iv_length);
        }
        { // init key material with same keys for client and server
            test_rnd.bytes(buf[0..T.mac_length]);
            test_rnd.bytes(buf[T.mac_length..][0..T.mac_length]);
            test_rnd.bytes(buf[T.mac_length * 2 ..][0..T.key_length]);
            test_rnd.bytes(buf[T.mac_length * 2 + T.key_length ..][0..T.key_length]);
        }
        var cipher: T = T.init(&buf, test_rnd);
        { // test equal server and client keys
            try testing.expectEqualSlices(u8, &cipher.server_secret, &cipher.client_secret);
            try testing.expectEqualSlices(u8, &cipher.server_key, &cipher.client_key);
        }

        const data = "Hello world!";
        // encrypt
        const ciphertext = cipher.encrypt(&buf, 0, .application_data, data);
        try testing.expectEqual(
            tls.record_header_len + T.CBC.paddedLength(T.iv_length + data.len + T.mac_length),
            ciphertext.len,
        );

        // decrypt
        const header = ciphertext[0..tls.record_header_len];
        const payload = ciphertext[tls.record_header_len..];
        const content_type, const decrypted = try cipher.decrypt(&buf, 0, header, payload);
        try testing.expectEqualSlices(u8, data, decrypted);
        try testing.expectEqual(.application_data, content_type);
    }
}

test "encrypt/decrypt 1.3" {
    inline for ([_]type{
        Aead13Aes128Gcm,
        Aead13Aes256Gcm,
        Aead13ChaCha,
    }) |T| {
        var buf: [160]u8 = undefined;
        { // show byte lengths
            const expected_key_len = switch (T) {
                Aead13Aes128Gcm => 16,
                else => 32,
            };
            try testing.expectEqual(expected_key_len, T.key_len);
            try testing.expectEqual(16, T.auth_tag_len);
            try testing.expectEqual(12, T.nonce_len);
        }
        test_rnd.bytes(buf[0..@max(T.key_len, T.auth_tag_len)]);
        var cipher = T{
            .client_key = buf[0..T.key_len].*,
            .server_key = buf[0..T.key_len].*,
            .client_iv = buf[0..T.nonce_len].*,
            .server_iv = buf[0..T.nonce_len].*,
            .rnd = test_rnd,
        };

        const data = "Hello world!";
        // encrypt
        const ciphertext = cipher.encrypt(&buf, 0, .application_data, data);
        try testing.expectEqual(
            tls.record_header_len + data.len + T.auth_tag_len + 1,
            ciphertext.len,
        );

        // decrypt
        const header = ciphertext[0..tls.record_header_len];
        const payload = ciphertext[tls.record_header_len..];
        const content_type, const decrypted = try cipher.decrypt(&buf, 0, header, payload);
        try testing.expectEqualSlices(u8, data, decrypted);
        try testing.expectEqual(.application_data, content_type);
    }
}

const test_rnd = std.Random{ .ptr = undefined, .fillFn = randomFillFn };

// returns 0,1,2..0xff,0,1...
pub fn randomFillFn(_: *anyopaque, buf: []u8) void {
    var idx: u8 = 0;
    for (buf) |*v| {
        v.* = idx;
        idx +%= 1;
    }
}
