const std = @import("std");
const crypto = std.crypto;
const tls12 = @import("tls12.zig");

pub const AppCipherT = union(enum) {
    AES_128_CBC_SHA: CipherCbcT(@import("cbc.zig").CBCAes128, crypto.hash.Sha1),
    AES_128_GCM_SHA256: CipherAeadT(crypto.aead.aes_gcm.Aes128Gcm),

    pub fn init(tag: tls12.CipherSuite, key_material: []const u8, rnd: std.Random) !AppCipherT {
        return switch (tag) {
            .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            => .{
                .AES_128_CBC_SHA = CipherCbcT(@import("cbc.zig").CBCAes128, crypto.hash.Sha1).init(key_material, rnd),
            },
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            => .{
                .AES_128_GCM_SHA256 = CipherAeadT(crypto.aead.aes_gcm.Aes128Gcm).init(key_material, rnd),
            },
            else => return error.TlsIllegalParameter,
        };
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
    const mac_length = HashType.digest_length;
    const key_length = CbcType.key_length;
    const iv_length = CbcType.nonce_length;

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
