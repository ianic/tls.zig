const std = @import("std");
const crypto = std.crypto;
const tls12 = @import("tls12.zig");
const Aes128Cbc = @import("cbc.zig").Aes128Cbc;

const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;

pub const HandshakeCipher = union(enum) {
    sha256: HandshakeCipherT(Sha256),
    sha384: HandshakeCipherT(Sha384),

    pub fn init(tag: tls12.CipherSuite, transcript256: Sha256, transcript384: Sha384) HandshakeCipher {
        return switch (tag) {
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            => .{ .sha384 = HandshakeCipherT(Sha384).init(transcript384) },
            else => .{ .sha256 = HandshakeCipherT(Sha256).init(transcript256) },
        };
    }
};

pub fn HandshakeCipherT(comptime HashType: type) type {
    return struct {
        pub const Hash = HashType;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        const mac_length = Hmac.mac_length;

        transcript: Hash,

        const Cipher = @This();

        fn init(transcript: Hash) Cipher {
            return .{ .transcript = transcript };
        }

        pub fn masterSecret(
            pre_master_secret: []const u8,
            client_random: [32]u8,
            server_random: [32]u8,
        ) [mac_length * 2]u8 {
            const seed = "master secret" ++ client_random ++ server_random;

            var a1: [mac_length]u8 = undefined;
            var a2: [mac_length]u8 = undefined;
            Hmac.create(&a1, seed, pre_master_secret);
            Hmac.create(&a2, &a1, pre_master_secret);

            var p1: [mac_length]u8 = undefined;
            var p2: [mac_length]u8 = undefined;
            Hmac.create(&p1, a1 ++ seed, pre_master_secret);
            Hmac.create(&p2, a2 ++ seed, pre_master_secret);

            return p1 ++ p2;
        }

        pub fn keyExpansion(
            master_secret: []const u8,
            client_random: [32]u8,
            server_random: [32]u8,
        ) [mac_length * 4]u8 {
            const seed = "key expansion" ++ server_random ++ client_random;

            const a0 = seed;
            var a1: [mac_length]u8 = undefined;
            var a2: [mac_length]u8 = undefined;
            var a3: [mac_length]u8 = undefined;
            var a4: [mac_length]u8 = undefined;
            Hmac.create(&a1, a0, master_secret);
            Hmac.create(&a2, &a1, master_secret);
            Hmac.create(&a3, &a2, master_secret);
            Hmac.create(&a4, &a3, master_secret);

            var key_material: [mac_length * 4]u8 = undefined;
            Hmac.create(key_material[0..mac_length], a1 ++ seed, master_secret);
            Hmac.create(key_material[mac_length .. mac_length * 2], a2 ++ seed, master_secret);
            Hmac.create(key_material[mac_length * 2 .. mac_length * 3], a3 ++ seed, master_secret);
            Hmac.create(key_material[mac_length * 3 ..], a4 ++ seed, master_secret);
            return key_material;
        }

        pub fn verifyData(c: *Cipher, master_secret: []const u8) [16]u8 {
            const seed = "client finished" ++ c.transcript.finalResult();
            var a1: [mac_length]u8 = undefined;
            var p1: [mac_length]u8 = undefined;
            Hmac.create(&a1, seed, master_secret);
            Hmac.create(&p1, a1 ++ seed, master_secret);
            return [_]u8{ 0x14, 0x00, 0x00, 0x0c } ++ p1[0..12].*;
        }
    };
}

pub const AppCipherT = union(enum) {
    AES_128_CBC_SHA: CipherCbcT(Aes128Cbc, crypto.hash.Sha1),
    AES_128_CBC_SHA256: CipherCbcT(Aes128Cbc, crypto.hash.sha2.Sha256),
    AES_128_GCM_SHA256: CipherAeadT(crypto.aead.aes_gcm.Aes128Gcm),
    AES_256_GCM_SHA384: CipherAeadT(crypto.aead.aes_gcm.Aes256Gcm),

    pub fn init(tag: tls12.CipherSuite, key_material: []const u8, rnd: std.Random) !AppCipherT {
        return switch (tag) {
            .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            => .{
                .AES_128_CBC_SHA = CipherCbcT(Aes128Cbc, crypto.hash.Sha1).init(key_material, rnd),
            },
            .TLS_RSA_WITH_AES_128_CBC_SHA256,
            => .{
                .AES_128_CBC_SHA256 = CipherCbcT(Aes128Cbc, crypto.hash.sha2.Sha256).init(key_material, rnd),
            },
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            => .{
                .AES_128_GCM_SHA256 = CipherAeadT(crypto.aead.aes_gcm.Aes128Gcm).init(key_material, rnd),
            },
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => .{
                .AES_256_GCM_SHA384 = CipherAeadT(crypto.aead.aes_gcm.Aes256Gcm).init(key_material, rnd),
            },
            else => return error.TlsIllegalParameter,
        };
    }

    const Self = @This();

    pub fn overhead(self: Self) usize {
        return switch (self) {
            .AES_128_CBC_SHA => 16 + 20 + 16, // iv (16 bytes), mac (20 bytes), padding (1-16 bytes)
            .AES_128_CBC_SHA256 => 16 + 32 + 16, // iv (16 bytes), mac (32 bytes), padding (1-16 bytes)
            .AES_128_GCM_SHA256 => 8 + 16, // explicit_iv (8 bytes) + auth_tag_len (16 bytes)
            .AES_256_GCM_SHA384 => 8 + 16, // explicit_iv (8 bytes) + auth_tag_len (16 bytes)
        };
    }

    pub const max_overhead = 16 + 32 + 16;

    pub fn minEncryptBufferLen(self: Self, cleartext_len: usize) usize {
        return self.overhead() + cleartext_len;
    }
};

fn CipherAeadT(comptime AeadType: type) type {
    const key_len = AeadType.key_length;
    const auth_tag_len = AeadType.tag_length;
    const iv_len = AeadType.nonce_length - tls12.explicit_iv_len;

    return struct {
        client_key: [key_len]u8,
        server_key: [key_len]u8,
        client_iv: [iv_len]u8,
        server_iv: [iv_len]u8,
        rnd: std.Random,

        const Cipher = @This();

        fn init(key_material: []const u8, rnd: std.Random) Cipher {
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
        pub fn encrypt(cipher: Cipher, buf: []u8, ad: []const u8, cleartext: []const u8) []const u8 {
            var explicit_iv: [tls12.explicit_iv_len]u8 = undefined;
            cipher.rnd.bytes(&explicit_iv);
            buf[0..explicit_iv.len].* = explicit_iv;

            const iv = cipher.client_iv ++ explicit_iv;
            const ciphertext = buf[explicit_iv.len..][0..cleartext.len];
            const auth_tag = buf[explicit_iv.len + ciphertext.len ..][0..auth_tag_len];
            AeadType.encrypt(ciphertext, auth_tag, cleartext, ad, iv, cipher.client_key);
            return buf[0 .. explicit_iv.len + ciphertext.len + auth_tag.len];
        }

        pub fn decrypt(cipher: Cipher, buf: []u8, ad: []u8, payload: []const u8) ![]const u8 {
            const overhead = tls12.explicit_iv_len + auth_tag_len;
            if (payload.len < overhead) return error.TlsDecryptError;

            const iv = cipher.server_iv ++ payload[0..tls12.explicit_iv_len].*;
            const cleartext_len = payload.len - overhead;
            const ciphertext = payload[tls12.explicit_iv_len..][0..cleartext_len];
            const auth_tag = payload[tls12.explicit_iv_len + cleartext_len ..][0..auth_tag_len];
            std.mem.writeInt(u16, ad[ad.len - 2 ..][0..2], @intCast(cleartext_len), .big);

            const cleartext = buf[0..cleartext_len];
            try AeadType.decrypt(cleartext, ciphertext, auth_tag.*, ad, iv, cipher.server_key);
            return cleartext;
        }
    };
}

fn CipherCbcT(comptime CbcType: type, comptime HashType: type) type {
    const mac_length = HashType.digest_length; // 20 bytes for sha1
    const key_length = CbcType.key_length; // 16 bytes for CBCAed128
    const iv_length = CbcType.nonce_length; // 16 bytes for CBCAed128

    return struct {
        pub const CBC = CbcType;
        pub const Hmac = crypto.auth.hmac.Hmac(HashType);

        client_secret: [mac_length]u8,
        server_secret: [mac_length]u8,
        client_key: [key_length]u8,
        server_key: [key_length]u8,
        rnd: std.Random,

        const Cipher = @This();

        fn init(key_material: []const u8, rnd: std.Random) Cipher {
            return .{
                .rnd = rnd,
                .client_secret = key_material[0..mac_length].*,
                .server_secret = key_material[mac_length..][0..mac_length].*,
                .client_key = key_material[2 * mac_length ..][0..key_length].*,
                .server_key = key_material[2 * mac_length + key_length ..][0..key_length].*,
            };
        }

        pub fn encrypt(cipher: Cipher, buf: []u8, ad: []const u8, cleartext: []const u8) []const u8 {
            const cleartext_idx = @max(ad.len, iv_length);

            // unused | ad | cleartext | mac
            //        | --mac input--  | --mac output--
            const mac_input_buf = buf[cleartext_idx - ad.len ..][0 .. ad.len + cleartext.len + mac_length];
            @memcpy(mac_input_buf[0..ad.len], ad);
            @memcpy(mac_input_buf[ad.len..][0..cleartext.len], cleartext);
            const mac_output_buf = mac_input_buf[ad.len + cleartext.len ..][0..mac_length];
            Hmac.create(mac_output_buf, mac_input_buf[0 .. ad.len + cleartext.len], &cipher.client_secret);

            // unused | ad | cleartext | mac | padding
            const unpadded_len = cleartext.len + mac_length;
            const padded_len = CBC.paddedLength(unpadded_len);
            const payload_buf = buf[cleartext_idx..][0..padded_len];
            const padding_byte: u8 = @intCast(padded_len - unpadded_len - 1);
            @memset(payload_buf[unpadded_len..padded_len], padding_byte);

            // iv | cleartext | mac | padding
            // iv | -------   payload -------
            const iv = buf[cleartext_idx - iv_length .. cleartext_idx];
            cipher.rnd.bytes(iv);

            CBC.init(cipher.client_key).encrypt(payload_buf, payload_buf, iv[0..iv_length].*);
            return buf[cleartext_idx - iv_length .. cleartext_idx + payload_buf.len];
        }

        pub fn decrypt(cipher: Cipher, buf: []u8, ad: []u8, payload: []const u8) ![]const u8 {
            if (payload.len < iv_length + mac_length + 1) return error.TlsDecryptError;

            const iv = payload[0..iv_length];

            const crypted = payload[iv_length..];
            const decrypted = buf[0..crypted.len];
            try CBC.init(cipher.server_key).decrypt(decrypted, crypted, iv[0..iv_length].*);

            const padding_len = decrypted[decrypted.len - 1] + 1;
            if (decrypted.len < mac_length + padding_len) return error.TlsDecryptError;

            const cleartext_len = decrypted.len - mac_length - padding_len;
            std.mem.writeInt(u16, ad[ad.len - 2 ..][0..2], @intCast(cleartext_len), .big);

            return decrypted[0..cleartext_len];
            // TODO: ostavi mjesta u buf i tamo zaljepi ad nakon decrypt napravi
            // mac od ad + cleartext to je ad_actual i usporedi s ovim koji je
            // poslan (ad expected)
            // Pazi ovaj ad koji ulazi ima unutar i padding... kako njega odbiti
        }
    };
}
