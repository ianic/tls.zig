// This was originally copied from: https://github.com/jedisct1/zig-cbc
const std = @import("std");
const aes = std.crypto.core.aes;
const mem = std.mem;
const debug = std.debug;

pub const Aes128Cbc = CBC(aes.Aes128);
pub const Aes256Cbc = CBC(aes.Aes256);

/// CBC mode with PKCS#7 padding.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// If you need authenticated encryption, use anything from `std.crypto.aead` instead.
/// If you really need to use CBC mode, make sure to use a MAC to authenticate the ciphertext.
pub fn CBC(comptime BlockCipher: anytype) type {
    return struct {
        const EncryptCtx = aes.AesEncryptCtx(BlockCipher);
        const DecryptCtx = aes.AesDecryptCtx(BlockCipher);

        const Self = @This();

        pub const key_length = BlockCipher.key_bits / 8;
        pub const nonce_length = EncryptCtx.block_length; //key_length;

        enc_ctx: EncryptCtx,
        dec_ctx: DecryptCtx,

        /// Initialize the CBC context with the given key.
        pub fn init(key: [key_length]u8) Self {
            const enc_ctx = BlockCipher.initEnc(key);
            const dec_ctx = DecryptCtx.initFromEnc(enc_ctx);

            return Self{ .enc_ctx = enc_ctx, .dec_ctx = dec_ctx };
        }

        /// Return the length of the ciphertext given the length of the plaintext.
        pub fn paddedLength(length: usize) usize {
            return (std.math.divCeil(usize, length + 1, EncryptCtx.block_length) catch unreachable) * EncryptCtx.block_length;
        }

        pub fn unpaddedLength(length: usize) usize {
            return length - EncryptCtx.block_length;
        }

        /// Encrypt the given plaintext for the given IV.
        /// The destination buffer must be large enough to hold the padded plaintext.
        /// Use the `paddedLength()` function to compute the ciphertext size.
        /// IV must be secret and unpredictable.
        pub fn encrypt(self: Self, dst: []u8, src: []const u8, iv: [EncryptCtx.block_length]u8) void {
            const block_length = EncryptCtx.block_length;
            debug.assert(src.len % block_length == 0);
            debug.assert(src.len == dst.len);
            var cv = iv;
            var i: usize = 0;
            while (i + block_length <= src.len) : (i += block_length) {
                const in = src[i..][0..block_length];
                for (cv[0..], in) |*x, y| x.* ^= y;
                self.enc_ctx.encrypt(&cv, &cv);
                @memcpy(dst[i..][0..block_length], &cv);
            }
        }

        pub fn encryptPad(self: Self, dst: []u8, src: []const u8, iv: [EncryptCtx.block_length]u8) void {
            // Note: encryption *could* be parallelized, see https://research.kudelskisecurity.com/2022/11/17/some-aes-cbc-encryption-myth-busting/
            const block_length = EncryptCtx.block_length;
            const padded_length = paddedLength(src.len);
            debug.assert(dst.len == padded_length); // destination buffer must hold the padded plaintext
            var cv = iv;
            var i: usize = 0;
            while (i + block_length <= src.len) : (i += block_length) {
                const in = src[i..][0..block_length];
                for (cv[0..], in) |*x, y| x.* ^= y;
                self.enc_ctx.encrypt(&cv, &cv);
                @memcpy(dst[i..][0..block_length], &cv);
            }
            // Last block
            var in = [_]u8{0} ** block_length;
            const padding_length: u8 = @intCast(padded_length - src.len);
            @memset(&in, padding_length);
            @memcpy(in[0 .. src.len - i], src[i..]);
            for (cv[0..], in) |*x, y| x.* ^= y;
            self.enc_ctx.encrypt(&cv, &cv);
            @memcpy(dst[i..], cv[0 .. dst.len - i]);
        }

        pub fn decryptPad(self: Self, dst: []u8, src: []const u8, iv: [DecryptCtx.block_length]u8) !void {
            const block_length = DecryptCtx.block_length;
            const padded_length = paddedLength(dst.len);
            if (src.len != padded_length) {
                return error.EncodingError;
            }
            debug.assert(src.len % block_length == 0);
            var i: usize = 0;
            var cv = iv;
            var out: [block_length]u8 = undefined;
            // Decryption could be parallelized
            while (i + block_length <= dst.len) : (i += block_length) {
                const in = src[i..][0..block_length];
                self.dec_ctx.decrypt(&out, in);
                for (&out, cv) |*x, y| x.* ^= y;
                cv = in.*;
                @memcpy(dst[i..][0..block_length], &out);
            }
            // Last block - We intentionally don't check the padding to mitigate timing attacks
            if (i < dst.len) {
                const in = src[i..][0..block_length];
                @memset(&out, 0);
                self.dec_ctx.decrypt(&out, in);
                for (&out, cv) |*x, y| x.* ^= y;
                @memcpy(dst[i..], out[0 .. dst.len - i]);
            }
        }

        /// Decrypt the given ciphertext for the given IV.
        /// The destination buffer must be large enough to hold the plaintext.
        /// IV must be secret, unpredictable and match the one used for encryption.
        pub fn decrypt(self: Self, dst: []u8, src: []const u8, iv: [DecryptCtx.block_length]u8) !void {
            const block_length = DecryptCtx.block_length;
            debug.assert(src.len % block_length == 0);
            debug.assert(src.len == dst.len);
            var i: usize = 0;
            var cv = iv;
            var out: [block_length]u8 = undefined;
            // Decryption could be parallelized
            while (i + block_length <= dst.len) : (i += block_length) {
                const in = src[i..][0..block_length];
                self.dec_ctx.decrypt(&out, in);
                for (&out, cv) |*x, y| x.* ^= y;
                cv = in.*;
                @memcpy(dst[i..][0..block_length], &out);
            }
        }
    };
}

test "CBC mode" {
    const M = CBC(aes.Aes128);
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const src_ = "This is a test of AES-CBC that goes on longer than a couple blocks. It is a somewhat long test case to type out!";
    const expected = [_]u8{ 32, 252, 200, 238, 32, 28, 17, 125, 123, 151, 155, 190, 31, 191, 253, 139, 24, 221, 222, 242, 8, 19, 219, 65, 255, 8, 14, 245, 190, 73, 192, 187 };
    var res: [32]u8 = undefined;

    try comptime std.testing.expect(src_.len / M.paddedLength(1) >= 3); // Ensure that we have at least 3 blocks

    const z = M.init(key);

    // Test encryption and decryption with distinct buffers
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (0..src_.len) |len| {
        const src = src_[0..len];
        var dst = [_]u8{0} ** M.paddedLength(src.len);
        z.encryptPad(&dst, src, iv);
        h.update(&dst);

        var decrypted = [_]u8{0} ** src.len;
        try z.decryptPad(&decrypted, &dst, iv);

        try std.testing.expectEqualSlices(u8, src, &decrypted);
    }
    h.final(&res);
    try std.testing.expectEqualSlices(u8, &expected, &res);

    // Test encryption and decryption with the same buffer
    h = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (0..src_.len) |len| {
        var buf = [_]u8{0} ** M.paddedLength(len);
        @memcpy(buf[0..len], src_[0..len]);
        z.encryptPad(&buf, buf[0..len], iv);
        h.update(&buf);

        try z.decryptPad(buf[0..len], &buf, iv);

        try std.testing.expectEqualSlices(u8, src_[0..len], buf[0..len]);
    }
    h.final(&res);
    try std.testing.expectEqualSlices(u8, &expected, &res);
}
