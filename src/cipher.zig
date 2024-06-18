const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const hkdfExpandLabel = tls.hkdfExpandLabel;

const Sha1 = crypto.hash.Sha1;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;

const Record = @import("record.zig").Record;
const Transcript = @import("transcript.zig").Transcript;
const recordHeader = @import("consts.zig").recordHeader;
const Aes128Cbc = @import("cbc.zig").Aes128Cbc;
const Aes256Cbc = @import("cbc.zig").Aes256Cbc;

// tls 1.2 cbc cipher types
const CbcAes128Sha1 = CbcType(Aes128Cbc, Sha1);
const CbcAes128Sha256 = CbcType(Aes128Cbc, Sha256);
const CbcAes256Sha256 = CbcType(Aes256Cbc, Sha256);
const CbcAes256Sha384 = CbcType(Aes256Cbc, Sha384);
// tls 1.2 gcm cipher types
const Aead12Aes128Gcm = Aead12Type(crypto.aead.aes_gcm.Aes128Gcm);
const Aead12Aes256Gcm = Aead12Type(crypto.aead.aes_gcm.Aes256Gcm);
// tls 1.2 chacha cipher type
const Aead12ChaCha = Aead12ChaChaType(crypto.aead.chacha_poly.ChaCha20Poly1305);
// tls 1.3 cipher types
const Aead13Aes128Gcm = Aead13Type(crypto.aead.aes_gcm.Aes128Gcm);
const Aead13Aes256Gcm = Aead13Type(crypto.aead.aes_gcm.Aes256Gcm);
const Aead13ChaCha = Aead13Type(crypto.aead.chacha_poly.ChaCha20Poly1305);
const Aead13Ageis128 = Aead13Type(crypto.aead.aegis.Aegis128L);

fn CipherType(comptime tag: CipherSuite) type {
    return switch (tag) {
        // tls 1.2 cbc
        .ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        .ECDHE_RSA_WITH_AES_128_CBC_SHA,
        .RSA_WITH_AES_128_CBC_SHA,
        => CbcAes128Sha1,
        .ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        .ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        .RSA_WITH_AES_128_CBC_SHA256,
        => CbcAes128Sha256,
        .ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        .ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        => CbcAes256Sha384,

        // tls 1.2 gcm
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        => Aead12Aes128Gcm,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        => Aead12Aes256Gcm,

        // tls 1.2 chacha
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        => Aead12ChaCha,

        // tls 1.3
        .AES_128_GCM_SHA256 => Aead13Aes128Gcm,
        .AES_256_GCM_SHA384 => Aead13Aes256Gcm,
        .CHACHA20_POLY1305_SHA256 => Aead13ChaCha,
        .AEGIS_128L_SHA256 => Aead13Ageis128,

        else => unreachable,
    };
}

pub const Cipher = union(CipherSuite) {
    // tls 1.2 cbc
    ECDHE_ECDSA_WITH_AES_128_CBC_SHA: CipherType(.ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
    ECDHE_RSA_WITH_AES_128_CBC_SHA: CipherType(.ECDHE_RSA_WITH_AES_128_CBC_SHA),
    RSA_WITH_AES_128_CBC_SHA: CipherType(.RSA_WITH_AES_128_CBC_SHA),

    ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: CipherType(.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
    ECDHE_RSA_WITH_AES_128_CBC_SHA256: CipherType(.ECDHE_RSA_WITH_AES_128_CBC_SHA256),
    RSA_WITH_AES_128_CBC_SHA256: CipherType(.RSA_WITH_AES_128_CBC_SHA256),

    ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: CipherType(.ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
    ECDHE_RSA_WITH_AES_256_CBC_SHA384: CipherType(.ECDHE_RSA_WITH_AES_256_CBC_SHA384),
    // tls 1.2 gcm
    ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherType(.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: CipherType(.ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    ECDHE_RSA_WITH_AES_128_GCM_SHA256: CipherType(.ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    ECDHE_RSA_WITH_AES_256_GCM_SHA384: CipherType(.ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    // tls 1.2 chacha
    ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: CipherType(.ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: CipherType(.ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    // tls 1.3
    AES_128_GCM_SHA256: CipherType(.AES_128_GCM_SHA256),
    AES_256_GCM_SHA384: CipherType(.AES_256_GCM_SHA384),
    CHACHA20_POLY1305_SHA256: CipherType(.CHACHA20_POLY1305_SHA256),
    AEGIS_128L_SHA256: CipherType(.AEGIS_128L_SHA256),

    // tls 1.2 application cipher
    pub fn init12(tag: CipherSuite, key_material: []const u8, rnd: std.Random) !Cipher {
        switch (tag) {
            inline .ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            .ECDHE_RSA_WITH_AES_128_CBC_SHA,
            .RSA_WITH_AES_128_CBC_SHA,
            .ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            .ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            .RSA_WITH_AES_128_CBC_SHA256,
            .ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            .ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            => |comptime_tag| {
                return @unionInit(Cipher, @tagName(comptime_tag), CipherType(comptime_tag).init(key_material, rnd));
            },
            inline .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            => |comptime_tag| {
                return @unionInit(Cipher, @tagName(comptime_tag), CipherType(comptime_tag).init(key_material));
            },
            else => return error.TlsIllegalParameter,
        }
    }

    // tls 1.3 handshake cipher
    pub fn init13Handshake(tag: CipherSuite, shared_key: []const u8, transcript: *Transcript) !Cipher {
        return try init13(tag, transcript.handshakeSecret(tag, shared_key));
    }

    // tls 1.3 application cipher
    pub fn init13Application(tag: CipherSuite, transcript: *Transcript) !Cipher {
        return try init13(tag, transcript.applicationSecret(tag));
    }

    fn init13(tag: CipherSuite, secret: Transcript.Secret) !Cipher {
        return switch (tag) {
            inline .AES_128_GCM_SHA256,
            .AES_256_GCM_SHA384,
            .CHACHA20_POLY1305_SHA256,
            .AEGIS_128L_SHA256,
            => |comptime_tag| {
                const Hkdf = Transcript.Hkdf(comptime_tag);
                const T = CipherType(comptime_tag);
                return @unionInit(Cipher, @tagName(comptime_tag), .{
                    .client_key = hkdfExpandLabel(Hkdf, secret.client[0..Hkdf.prk_length].*, "key", "", T.key_len),
                    .server_key = hkdfExpandLabel(Hkdf, secret.server[0..Hkdf.prk_length].*, "key", "", T.key_len),
                    .client_iv = hkdfExpandLabel(Hkdf, secret.client[0..Hkdf.prk_length].*, "iv", "", T.nonce_len),
                    .server_iv = hkdfExpandLabel(Hkdf, secret.server[0..Hkdf.prk_length].*, "iv", "", T.nonce_len),
                });
            },
            else => return error.TlsIllegalParameter,
        };
    }

    const Self = @This();

    pub fn encrypt(
        self: Self,
        buf: []u8,
        sequence: u64,
        content_type: tls.ContentType,
        cleartext: []const u8,
    ) ![]const u8 {
        return switch (self) {
            inline else => |*cipher| try cipher.encrypt(buf, sequence, content_type, cleartext),
        };
    }

    pub fn decrypt(
        self: Self,
        buf: []u8,
        sequence: u64,
        rec: Record,
    ) !struct { tls.ContentType, []u8 } {
        return switch (self) {
            inline else => |*cipher| try cipher.decrypt(buf, sequence, rec),
        };
    }
};

fn Aead12Type(comptime AeadType: type) type {
    return struct {
        const explicit_iv_len = 8;
        const key_len = AeadType.key_length;
        const auth_tag_len = AeadType.tag_length;
        const nonce_len = AeadType.nonce_length;
        const iv_len = AeadType.nonce_length - explicit_iv_len;

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

        /// Returns encrypted tls record in format:
        ///   ----------------- buf ----------------------
        ///   header | explicit_iv | ciphertext | auth_tag
        ///
        /// tls record header: 5 bytes
        /// explicit_iv: 8 bytes
        /// ciphertext: same length as cleartext
        /// auth_tag: 16 bytes
        pub fn encrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) ![]const u8 {
            const record_len = tls.record_header_len + explicit_iv_len + cleartext.len + auth_tag_len;
            if (buf.len < record_len) return error.BufferOverflow;

            const header = buf[0..tls.record_header_len];
            const explicit_iv = buf[tls.record_header_len..][0..explicit_iv_len];
            const ciphertext = buf[tls.record_header_len + explicit_iv_len ..][0..cleartext.len];
            const auth_tag = buf[tls.record_header_len + explicit_iv_len + cleartext.len ..][0..auth_tag_len];

            header.* = recordHeader(content_type, explicit_iv_len + cleartext.len + auth_tag_len);
            self.rnd.bytes(explicit_iv);
            const iv = self.client_iv ++ explicit_iv.*;
            const ad = additionalData(sequence, content_type, cleartext.len);
            AeadType.encrypt(ciphertext, auth_tag, cleartext, &ad, iv, self.client_key);

            return buf[0..record_len];
        }

        /// Decrypts payload into cleartext. Returns tls record content type and
        /// cleartext.
        /// Accepts tls record header and payload:
        ///   header | ----------- payload ---------------
        ///   header | explicit_iv | ciphertext | auth_tag
        pub fn decrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            rec: Record,
        ) !struct { tls.ContentType, []u8 } {
            const overhead = explicit_iv_len + auth_tag_len;
            if (rec.payload.len < overhead) return error.TlsDecryptError;
            const cleartext_len = rec.payload.len - overhead;
            if (buf.len < cleartext_len) return error.BufferOverflow;

            const explicit_iv = rec.payload[0..explicit_iv_len];
            const ciphertext = rec.payload[explicit_iv_len..][0..cleartext_len];
            const auth_tag = rec.payload[explicit_iv_len + cleartext_len ..][0..auth_tag_len];

            const iv = self.server_iv ++ explicit_iv.*;
            const ad = additionalData(sequence, rec.content_type, cleartext_len);
            const cleartext = buf[0..cleartext_len];
            AeadType.decrypt(cleartext, ciphertext, auth_tag.*, &ad, iv, self.server_key) catch return error.TlsDecryptError;

            return .{ rec.content_type, cleartext };
        }
    };
}

fn Aead12ChaChaType(comptime AeadType: type) type {
    return struct {
        const key_len = AeadType.key_length;
        const auth_tag_len = AeadType.tag_length;
        const nonce_len = AeadType.nonce_length;

        client_key: [key_len]u8,
        server_key: [key_len]u8,
        client_iv: [nonce_len]u8,
        server_iv: [nonce_len]u8,

        const Self = @This();

        fn init(key_material: []const u8) Self {
            return .{
                .client_key = key_material[0..key_len].*,
                .server_key = key_material[key_len..][0..key_len].*,
                .client_iv = key_material[2 * key_len ..][0..nonce_len].*,
                .server_iv = key_material[2 * key_len + nonce_len ..][0..nonce_len].*,
            };
        }

        /// Returns encrypted tls record in format:
        ///   ------------ buf -------------
        ///   header | ciphertext | auth_tag
        ///
        /// tls record header: 5 bytes
        /// ciphertext: same length as cleartext
        /// auth_tag: 16 bytes
        pub fn encrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) ![]const u8 {
            const record_len = tls.record_header_len + cleartext.len + auth_tag_len;
            if (buf.len < record_len) return error.BufferOverflow;

            const ciphertext = buf[tls.record_header_len..][0..cleartext.len];
            const auth_tag = buf[tls.record_header_len + ciphertext.len ..][0..auth_tag_len];

            const ad = additionalData(sequence, content_type, cleartext.len);
            const iv = ivWithSeq(nonce_len, self.client_iv, sequence);
            AeadType.encrypt(ciphertext, auth_tag, cleartext, &ad, iv, self.client_key);

            buf[0..tls.record_header_len].* = recordHeader(content_type, ciphertext.len + auth_tag.len);
            return buf[0..record_len];
        }

        /// Decrypts payload into cleartext. Returns tls record content type and
        /// cleartext.
        /// Accepts tls record header and payload:
        ///   header | ----- payload -------
        ///   header | ciphertext | auth_tag
        pub fn decrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            rec: Record,
        ) !struct { tls.ContentType, []u8 } {
            const overhead = auth_tag_len;
            if (rec.payload.len < overhead) return error.TlsDecryptError;
            const cleartext_len = rec.payload.len - overhead;
            if (buf.len < cleartext_len) return error.BufferOverflow;

            const ciphertext = rec.payload[0..cleartext_len];
            const auth_tag = rec.payload[cleartext_len..][0..auth_tag_len];
            const cleartext = buf[0..cleartext_len];

            const ad = additionalData(sequence, rec.content_type, cleartext_len);
            const iv = ivWithSeq(nonce_len, self.server_iv, sequence);
            AeadType.decrypt(cleartext, ciphertext, auth_tag.*, &ad, iv, self.server_key) catch return error.TlsDecryptError;
            return .{ rec.content_type, cleartext };
        }
    };
}

fn Aead13Type(comptime AeadType: type) type {
    return struct {
        const key_len = AeadType.key_length;
        const auth_tag_len = AeadType.tag_length;
        const nonce_len = AeadType.nonce_length;

        client_key: [key_len]u8,
        server_key: [key_len]u8,
        client_iv: [nonce_len]u8,
        server_iv: [nonce_len]u8,

        const Self = @This();

        /// Returns encrypted tls record in format:
        ///   ------------ buf -------------
        ///   header | ciphertext | auth_tag
        ///
        /// tls record header: 5 bytes
        /// ciphertext: cleartext len + 1 byte content type
        /// auth_tag: 16 bytes
        pub fn encrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) ![]const u8 {
            const payload_len = cleartext.len + 1 + auth_tag_len;
            const record_len = tls.record_header_len + payload_len;
            if (buf.len < record_len) return error.BufferOverflow;

            const header = buf[0..tls.record_header_len];
            header.* = recordHeader(.application_data, payload_len);

            @memcpy(buf[tls.record_header_len..][0..cleartext.len], cleartext);
            buf[tls.record_header_len + cleartext.len] = @intFromEnum(content_type);
            const ciphertext = buf[tls.record_header_len..][0 .. cleartext.len + 1];
            const auth_tag = buf[tls.record_header_len + ciphertext.len ..][0..auth_tag_len];

            const iv = ivWithSeq(nonce_len, self.client_iv, sequence);
            AeadType.encrypt(ciphertext, auth_tag, ciphertext, header, iv, self.client_key);
            return buf[0..record_len];
        }

        /// Decrypts payload into cleartext. Returns tls record content type and
        /// cleartext.
        /// Accepts tls record header and payload:
        ///   header | ------- payload ---------
        ///   header | ciphertext     | auth_tag
        ///   header | cleartext + ct | auth_tag
        /// Ciphertext after decryption contains cleartext and content type (1 byte).
        pub fn decrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            rec: Record,
        ) !struct { tls.ContentType, []u8 } {
            const overhead = auth_tag_len + 1;
            if (rec.payload.len < overhead) return error.TlsDecryptError;
            const ciphertext_len = rec.payload.len - auth_tag_len;
            if (buf.len < ciphertext_len) return error.BufferOverflow;

            const ciphertext = rec.payload[0..ciphertext_len];
            const auth_tag = rec.payload[ciphertext_len..][0..auth_tag_len];

            const iv = ivWithSeq(nonce_len, self.server_iv, sequence);
            AeadType.decrypt(buf[0..ciphertext_len], ciphertext, auth_tag.*, rec.header, iv, self.server_key) catch return error.TlsDecryptError;

            const cleartext = buf[0 .. ciphertext_len - 1];
            const content_type: tls.ContentType = @enumFromInt(buf[ciphertext_len - 1]);
            return .{ content_type, cleartext };
        }
    };
}

fn CbcType(comptime CBC: type, comptime HashType: type) type {
    return struct {
        const mac_len = HashType.digest_length; // 20, 32, 48 bytes for sha1, sha256, sha384
        const key_len = CBC.key_length; // 16 bytes
        const iv_len = CBC.nonce_length; // 16 bytes

        pub const Hmac = crypto.auth.hmac.Hmac(HashType);
        const paddedLength = CBC.paddedLength;
        const max_padding = 16;

        client_secret: [mac_len]u8,
        server_secret: [mac_len]u8,
        client_key: [key_len]u8,
        server_key: [key_len]u8,
        rnd: std.Random,

        const Self = @This();

        fn init(key_material: []const u8, rnd: std.Random) Self {
            return .{
                .rnd = rnd,
                .client_secret = key_material[0..mac_len].*,
                .server_secret = key_material[mac_len..][0..mac_len].*,
                .client_key = key_material[2 * mac_len ..][0..key_len].*,
                .server_key = key_material[2 * mac_len + key_len ..][0..key_len].*,
            };
        }

        /// Returns encrypted tls record in format:
        ///   ----------------- buf -----------------
        ///   header | iv | ------ ciphertext -------
        ///   header | iv | cleartext | mac | padding
        ///
        /// tls record header: 5 bytes
        /// iv: 16 bytes
        /// ciphertext: cleartext length + mac + padding
        /// mac: 20, 32 or 48 (sha1, sha256, sha384)
        /// padding: 1-16 bytes
        ///
        /// Max encrypt buf overhead = iv + mac + padding (1-16)
        /// aes_128_cbc_sha    => 16 + 20 + 16 = 52
        /// aes_128_cbc_sha256 => 16 + 32 + 16 = 64
        /// aes_256_cbc_sha384 => 16 + 48 + 16 = 80
        pub fn encrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            content_type: tls.ContentType,
            cleartext: []const u8,
        ) ![]const u8 {
            const max_record_len = tls.record_header_len + iv_len + cleartext.len + mac_len + max_padding;
            if (buf.len < max_record_len) return error.BufferOverflow;
            const cleartext_idx = tls.record_header_len + iv_len; // position of cleartext in buf
            @memcpy(buf[cleartext_idx..][0..cleartext.len], cleartext);

            { // calculate mac from (ad + cleatext)
                // ...     | ad | cleartext | mac | ...
                //         | -- mac msg --  | mac |
                const ad = additionalData(sequence, content_type, cleartext.len);
                const mac_msg = buf[cleartext_idx - ad.len ..][0 .. ad.len + cleartext.len];
                @memcpy(mac_msg[0..ad.len], &ad);
                const mac = buf[cleartext_idx + cleartext.len ..][0..mac_len];
                Hmac.create(mac, mac_msg, &self.client_secret);
            }

            // ...         | cleartext | mac | ...
            // ...         | cleartext | mac | padding
            // ...         | ------- plaintext -------
            const plaintext = brk: { // add padding
                const unpadded_len = cleartext.len + mac_len;
                const padded_len = paddedLength(unpadded_len);
                const plaintext = buf[cleartext_idx..][0..padded_len];
                const padding_byte: u8 = @intCast(padded_len - unpadded_len - 1);
                @memset(plaintext[unpadded_len..padded_len], padding_byte);
                break :brk plaintext;
            };

            // header | iv | ------- plaintext -------
            buf[0..tls.record_header_len].* = recordHeader(content_type, iv_len + plaintext.len);
            const iv = buf[tls.record_header_len..][0..iv_len];
            self.rnd.bytes(iv);

            // encrypt plaintext into ciphertext
            CBC.init(self.client_key).encrypt(plaintext, plaintext, iv[0..iv_len].*);

            // header | iv | ------ ciphertext -------
            return buf[0 .. tls.record_header_len + iv_len + plaintext.len];
        }

        /// Decrypts payload into cleartext. Returns tls record content type and
        /// cleartext.
        pub fn decrypt(
            self: Self,
            buf: []u8,
            sequence: u64,
            rec: Record,
        ) !struct { tls.ContentType, []u8 } {
            if (rec.payload.len < iv_len + mac_len + 1) return error.TlsDecryptError;

            // --------- payload ------------
            // iv | ------ ciphertext -------
            // iv | cleartext | mac | padding
            const iv = rec.payload[0..iv_len];
            const ciphertext = rec.payload[iv_len..];

            if (buf.len < ciphertext.len + additional_data_len) return error.BufferOverflow;
            // ---------- buf ---------------
            // ad | ------ plaintext --------
            // ad | cleartext | mac | padding
            const plaintext = buf[additional_data_len..][0..ciphertext.len];
            // decrypt ciphertext -> plaintext
            CBC.init(self.server_key).decrypt(plaintext, ciphertext, iv[0..iv_len].*) catch return error.TlsDecryptError;

            // get padding len from last padding byte
            const padding_len = plaintext[plaintext.len - 1] + 1;
            if (plaintext.len < mac_len + padding_len) return error.TlsDecryptError;
            // split plaintext into cleartext and mac
            const cleartext_len = plaintext.len - mac_len - padding_len;
            const cleartext = plaintext[0..cleartext_len];
            const mac = plaintext[cleartext_len..][0..mac_len];

            // write ad to the buf
            var ad = additionalData(sequence, rec.content_type, cleartext_len);
            @memcpy(buf[0..ad.len], &ad);
            const mac_msg = buf[0 .. ad.len + cleartext_len];

            // calculate expected mac and compare with received mac
            var expected_mac: [mac_len]u8 = undefined;
            Hmac.create(&expected_mac, mac_msg, &self.server_secret);
            if (!std.mem.eql(u8, &expected_mac, mac))
                return error.TlsBadRecordMac;

            return .{ rec.content_type, cleartext };
        }
    };
}

// xor lower 8 iv bytes with sequence
fn ivWithSeq(comptime nonce_len: usize, iv: [nonce_len]u8, sequence: u64) [nonce_len]u8 {
    var res = iv;
    const buf = res[nonce_len - 8 ..];
    const operand = std.mem.readInt(u64, buf, .big);
    std.mem.writeInt(u64, buf, operand ^ sequence, .big);
    return res;
}

pub const additional_data_len = tls.record_header_len + @sizeOf(u64);

fn additionalData(sequence: u64, content_type: tls.ContentType, payload_len: usize) [additional_data_len]u8 {
    const header = recordHeader(content_type, payload_len);
    var sequence_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_buf, sequence, .big);
    return sequence_buf ++ header;
}

// Week, secure, recomended grades are from https://ciphersuite.info/page/faq/
pub const CipherSuite = enum(u16) {
    // tls 1.2 cbc sha1
    ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009, // week
    ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013, // week
    RSA_WITH_AES_128_CBC_SHA = 0x002F, // week
    // tls 1.2 cbc sha256
    ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023, // week
    ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027, // week
    RSA_WITH_AES_128_CBC_SHA256 = 0x003c, // week
    // tls 1.2 cbc sha384
    ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024, // week
    ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028, // week
    // tls 1.2 gcm
    ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b, // recomended
    ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c, // recomended
    ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f, // secure
    ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030, // secure
    // tls 1.2 chacha
    ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9, // recomended
    ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8, // secure
    // tls 1.3 (all are recomended)
    AES_128_GCM_SHA256 = 0x1301,
    AES_256_GCM_SHA384 = 0x1302,
    CHACHA20_POLY1305_SHA256 = 0x1303,
    AEGIS_128L_SHA256 = 0x1307,
    // AEGIS_256_SHA512 = 0x1306,
    _,

    // In the order of preference
    pub const tls12_secure = [_]CipherSuite{
        // recomended
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        // secure
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub const tls12_week = [_]CipherSuite{
        // week
        .ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        .ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        .ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        .ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        .ECDHE_RSA_WITH_AES_128_CBC_SHA,

        .RSA_WITH_AES_128_CBC_SHA256,
        .RSA_WITH_AES_128_CBC_SHA,
    };
    pub const tls13 = [_]CipherSuite{
        .AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .CHACHA20_POLY1305_SHA256,
        // Excluded because didn't find server which supports it to test
        // .AEGIS_128L_SHA256
    };
    pub const tls12 = tls12_secure ++ tls12_week;
    pub const secure = tls13 ++ tls12_secure;
    pub const all = tls13 ++ tls12;

    pub fn validate(cs: CipherSuite) !void {
        if (includes(&tls12, cs)) return;
        if (includes(&tls13, cs)) return;
        return error.TlsIllegalParameter;
    }

    fn includes(list: []const CipherSuite, cs: CipherSuite) bool {
        for (list) |s| {
            if (cs == s) return true;
        }
        return false;
    }

    pub const Versions = enum {
        both,
        tls_1_3,
        tls_1_2,
    };

    // get tls versions from list of cipher suites
    pub fn versions(cipher_suites: []const CipherSuite) !Versions {
        var has_12 = false;
        var has_13 = false;
        for (cipher_suites) |cs| {
            if (includes(&tls12, cs)) {
                has_12 = true;
            } else {
                if (includes(&tls13, cs)) has_13 = true;
            }
        }
        if (has_12 and has_13) return .both;
        if (has_12) return .tls_1_2;
        if (has_13) return .tls_1_3;
        return error.TlsIllegalParameter;
    }

    pub const KeyExchangeAlgorithm = enum {
        ecdhe,
        rsa,
    };

    pub fn keyExchange(s: CipherSuite) KeyExchangeAlgorithm {
        return switch (s) {
            // Random premaster secret, encrypted with publich key from certificate.
            // No server key exchange message.
            .RSA_WITH_AES_128_CBC_SHA,
            .RSA_WITH_AES_128_CBC_SHA256,
            => .rsa,
            else => .ecdhe,
        };
    }

    pub const Hash = enum {
        sha256,
        sha384,
    };

    pub inline fn hash(cs: CipherSuite) Hash {
        return switch (cs) {
            .ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .AES_256_GCM_SHA384,
            => .sha384,
            else => .sha256,
        };
    }
};

const testing = std.testing;

test "CipherSuite validate" {
    {
        const cs: CipherSuite = .AES_256_GCM_SHA384;
        try cs.validate();
        try testing.expectEqual(cs.hash(), .sha384);
        try testing.expectEqual(cs.keyExchange(), .ecdhe);
    }
    {
        const cs: CipherSuite = .AES_128_GCM_SHA256;
        try cs.validate();
        try testing.expectEqual(.sha256, cs.hash());
        try testing.expectEqual(.ecdhe, cs.keyExchange());
    }
    for (CipherSuite.tls12) |cs| {
        try cs.validate();
        _ = cs.hash();
        _ = cs.keyExchange();
    }
}

test "CipherSuite versions" {
    try testing.expectEqual(.tls_1_3, CipherSuite.versions(&[_]CipherSuite{.AES_128_GCM_SHA256}));
    try testing.expectEqual(.both, CipherSuite.versions(&[_]CipherSuite{ .AES_128_GCM_SHA256, .ECDHE_ECDSA_WITH_AES_128_CBC_SHA }));
    try testing.expectEqual(.tls_1_2, CipherSuite.versions(&[_]CipherSuite{.RSA_WITH_AES_128_CBC_SHA}));
}

test "encrypt/decrypt gcm 1.2" {
    inline for ([_]type{
        Aead12Aes128Gcm,
        Aead12Aes256Gcm,
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
        const ciphertext = try cipher.encrypt(&buf, 0, .application_data, data);
        try testing.expectEqual(
            tls.record_header_len + T.explicit_iv_len + data.len + T.auth_tag_len,
            ciphertext.len,
        );

        // decrypt
        const header = ciphertext[0..tls.record_header_len];
        const payload = ciphertext[tls.record_header_len..];
        const rec = Record{ .header = header, .payload = payload, .content_type = .application_data };
        const content_type, const decrypted = try cipher.decrypt(&buf, 0, rec);
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
                    try testing.expectEqual(20, T.mac_len);
                    try testing.expectEqual(16, T.key_len);
                },
                CbcAes128Sha256 => {
                    try testing.expectEqual(32, T.mac_len);
                    try testing.expectEqual(16, T.key_len);
                },
                CbcAes256Sha384 => {
                    try testing.expectEqual(48, T.mac_len);
                    try testing.expectEqual(32, T.key_len);
                },
                else => unreachable,
            }
            try testing.expectEqual(16, T.paddedLength(1)); // cbc block padding
            try testing.expectEqual(16, T.iv_len);
        }
        { // init key material with same keys for client and server
            test_rnd.bytes(buf[0..T.mac_len]);
            test_rnd.bytes(buf[T.mac_len..][0..T.mac_len]);
            test_rnd.bytes(buf[T.mac_len * 2 ..][0..T.key_len]);
            test_rnd.bytes(buf[T.mac_len * 2 + T.key_len ..][0..T.key_len]);
        }
        var cipher: T = T.init(&buf, test_rnd);
        { // test equal server and client keys
            try testing.expectEqualSlices(u8, &cipher.server_secret, &cipher.client_secret);
            try testing.expectEqualSlices(u8, &cipher.server_key, &cipher.client_key);
        }

        const data = "Hello world!";
        // encrypt
        const ciphertext = try cipher.encrypt(&buf, 0, .application_data, data);
        try testing.expectEqual(
            tls.record_header_len + T.paddedLength(T.iv_len + data.len + T.mac_len),
            ciphertext.len,
        );

        // decrypt
        const header = ciphertext[0..tls.record_header_len];
        const payload = ciphertext[tls.record_header_len..];
        const rec = Record{ .header = header, .payload = payload, .content_type = .application_data };
        const content_type, const decrypted = try cipher.decrypt(&buf, 0, rec);
        try testing.expectEqualSlices(u8, data, decrypted);
        try testing.expectEqual(.application_data, content_type);
    }
}

test "encrypt/decrypt 1.3 and 1.2 chacha" {
    inline for ([_]type{
        Aead13Aes128Gcm,
        Aead13Aes256Gcm,
        Aead13ChaCha,
        Aead13Ageis128,
        Aead12ChaCha,
    }) |T| {
        var buf: [160]u8 = undefined;
        { // show byte lengths
            const expected_key_len = switch (T) {
                Aead13Aes128Gcm => 16,
                Aead13Ageis128 => 16,
                else => 32,
            };
            try testing.expectEqual(expected_key_len, T.key_len);
            try testing.expectEqual(16, T.auth_tag_len);
            const expected_nonce_len = switch (T) {
                Aead13Ageis128 => 16,
                else => 12,
            };
            try testing.expectEqual(expected_nonce_len, T.nonce_len);
        }
        test_rnd.bytes(buf[0..@max(T.key_len, T.auth_tag_len)]);
        var cipher = T{
            .client_key = buf[0..T.key_len].*,
            .server_key = buf[0..T.key_len].*,
            .client_iv = buf[0..T.nonce_len].*,
            .server_iv = buf[0..T.nonce_len].*,
        };

        const data = "Hello world!";
        // encrypt
        const ciphertext = try cipher.encrypt(&buf, 0, .application_data, data);
        const content_type_len = if (T == Aead12ChaCha) 0 else 1;
        try testing.expectEqual(
            tls.record_header_len + data.len + T.auth_tag_len + content_type_len,
            ciphertext.len,
        );

        // decrypt
        const header = ciphertext[0..tls.record_header_len];
        const payload = ciphertext[tls.record_header_len..];
        const rec = Record{ .header = header, .payload = payload, .content_type = .application_data };
        const content_type, const decrypted = try cipher.decrypt(&buf, 0, rec);
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
