const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const hkdfExpandLabel = tls.hkdfExpandLabel;
const Sha1 = crypto.hash.Sha1;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;

const tls12 = @import("tls12.zig");
const Aes128Cbc = @import("cbc.zig").Aes128Cbc;
const Aes256Cbc = @import("cbc.zig").Aes256Cbc;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

const Transcript = @import("transcript.zig").Transcript;

pub const Cipher = union(tls12.CipherSuite.Cipher) {
    // tls 1.2
    aes_128_cbc_sha: CipherCbcT(Aes128Cbc, Sha1),
    aes_128_cbc_sha256: CipherCbcT(Aes128Cbc, Sha256),
    aes_256_cbc_sha384: CipherCbcT(Aes256Cbc, Sha384),
    aes_128_gcm: CipherAeadT(Aes128Gcm),
    aes_256_gcm: CipherAeadT(Aes256Gcm),
    // tls 1.3
    aes_256_gcm_sha384: CipherAead13T(Aes256Gcm),
    aes_128_gcm_sha256: CipherAead13T(Aes128Gcm),
    chacha20_poly1305_sha256: CipherAead13T(ChaCha20Poly1305),

    pub fn init12(tag: tls12.CipherSuite, key_material: []const u8, rnd: std.Random) !Cipher {
        return switch (try tag.cipher()) {
            .aes_128_cbc_sha => .{ .aes_128_cbc_sha = CipherCbcT(Aes128Cbc, Sha1).init(key_material, rnd) },
            .aes_128_cbc_sha256 => .{ .aes_128_cbc_sha256 = CipherCbcT(Aes128Cbc, Sha256).init(key_material, rnd) },
            .aes_256_cbc_sha384 => .{ .aes_256_cbc_sha384 = CipherCbcT(Aes256Cbc, Sha384).init(key_material, rnd) },
            .aes_128_gcm => .{ .aes_128_gcm = CipherAeadT(Aes128Gcm).init(key_material, rnd) },
            .aes_256_gcm => .{ .aes_256_gcm = CipherAeadT(Aes256Gcm).init(key_material, rnd) },
            else => return error.TlsIllegalParameter,
        };
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
        const cipher_tag = switch (tag) {
            .AES_256_GCM_SHA384 => .aes_256_gcm_sha384,
            .AES_128_GCM_SHA256 => .aes_128_gcm_sha256,
            .CHACHA20_POLY1305_SHA256 => .chacha20_poly1305_sha256,
            else => unreachable,
        };
        const Hkdf = Transcript.Hkdf(tag);
        const AEAD = switch (tag) {
            .AES_256_GCM_SHA384 => CipherAead13T(Aes256Gcm),
            .AES_128_GCM_SHA256 => CipherAead13T(Aes128Gcm),
            .CHACHA20_POLY1305_SHA256 => CipherAead13T(ChaCha20Poly1305),
            else => unreachable,
        };
        return @unionInit(Cipher, @tagName(cipher_tag), .{
            .client_key = hkdfExpandLabel(Hkdf, secret.client[0..Hkdf.prk_length].*, "key", "", AEAD.key_len),
            .server_key = hkdfExpandLabel(Hkdf, secret.server[0..Hkdf.prk_length].*, "key", "", AEAD.key_len),
            .client_iv = hkdfExpandLabel(Hkdf, secret.client[0..Hkdf.prk_length].*, "iv", "", AEAD.nonce_len),
            .server_iv = hkdfExpandLabel(Hkdf, secret.server[0..Hkdf.prk_length].*, "iv", "", AEAD.nonce_len),
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
