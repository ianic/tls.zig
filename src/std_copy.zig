const std = @import("std");
const crypto = std.crypto;
const Certificate = crypto.Certificate;
const rsa = Certificate.rsa;

// Copied from: https://github.com/ziglang/zig/blob/455899668b620dfda40252501c748c0a983555bd/lib/std/crypto/tls/Client.zig#L1354
/// Abstraction for sending multiple byte buffers to a slice of iovecs.
pub const VecPut = struct {
    iovecs: []const std.posix.iovec,
    idx: usize = 0,
    off: usize = 0,
    total: usize = 0,

    /// Returns the amount actually put which is always equal to bytes.len
    /// unless the vectors ran out of space.
    pub fn put(vp: *VecPut, bytes: []const u8) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var bytes_i: usize = 0;
        while (true) {
            const v = vp.iovecs[vp.idx];
            const dest = v.base[vp.off..v.len];
            const src = bytes[bytes_i..][0..@min(dest.len, bytes.len - bytes_i)];
            @memcpy(dest[0..src.len], src);
            bytes_i += src.len;
            vp.off += src.len;
            if (vp.off >= v.len) {
                vp.off = 0;
                vp.idx += 1;
                if (vp.idx >= vp.iovecs.len) {
                    vp.total += bytes_i;
                    return bytes_i;
                }
            }
            if (bytes_i >= bytes.len) {
                vp.total += bytes_i;
                return bytes_i;
            }
        }
    }

    /// Returns the next buffer that consecutive bytes can go into.
    fn peek(vp: VecPut) []u8 {
        if (vp.idx >= vp.iovecs.len) return &.{};
        const v = vp.iovecs[vp.idx];
        return v.base[vp.off..v.len];
    }

    // After writing to the result of peek(), one can call next() to
    // advance the cursor.
    fn next(vp: *VecPut, len: usize) void {
        vp.total += len;
        vp.off += len;
        if (vp.off >= vp.iovecs[vp.idx].len) {
            vp.off = 0;
            vp.idx += 1;
        }
    }

    fn freeSize(vp: VecPut) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var total: usize = 0;
        total += vp.iovecs[vp.idx].len - vp.off;
        if (vp.idx + 1 >= vp.iovecs.len) return total;
        for (vp.iovecs[vp.idx + 1 ..]) |v| total += v.len;
        return total;
    }
};

// This is copy of the private method encrypt from std.crypto.Certificate.rsa
// If that method can be make public this can be removed.
pub fn rsaEncrypt(comptime modulus_len: usize, msg: [modulus_len]u8, public_key: rsa.PublicKey) ![modulus_len]u8 {
    const max_modulus_bits = 4096;
    const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
    const Fe = Modulus.Fe;

    const m = Fe.fromBytes(public_key.n, &msg, .big) catch return error.MessageTooLong;
    const e = public_key.n.powPublic(m, public_key.e) catch unreachable;
    var res: [modulus_len]u8 = undefined;
    e.toBytes(&res, .big) catch unreachable;
    return res;
}

// This is copy of the private method verifyRsa from std.crypto.Certificate
pub fn verifyRsa(
    comptime Hash: type,
    message: []const u8,
    sig: []const u8,
    pub_key_algo: Certificate.Parsed.PubKeyAlgo,
    pub_key: []const u8,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.CertificateSignatureAlgorithmMismatch;
    const pk_components = try rsa.PublicKey.parseDer(pub_key);
    const exponent = pk_components.exponent;
    const modulus = pk_components.modulus;
    if (exponent.len > modulus.len) return error.CertificatePublicKeyInvalid;
    if (sig.len != modulus.len) return error.CertificateSignatureInvalidLength;

    const hash_der = switch (Hash) {
        crypto.hash.Sha1 => [_]u8{
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        },
        crypto.hash.sha2.Sha224 => [_]u8{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
            0x00, 0x04, 0x1c,
        },
        crypto.hash.sha2.Sha256 => [_]u8{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        crypto.hash.sha2.Sha384 => [_]u8{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        },
        crypto.hash.sha2.Sha512 => [_]u8{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unreachable"),
    };

    var msg_hashed: [Hash.digest_length]u8 = undefined;
    Hash.hash(message, &msg_hashed, .{});

    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const ps_len = modulus_len - (hash_der.len + msg_hashed.len) - 3;
            const em: [modulus_len]u8 =
                [2]u8{ 0, 1 } ++
                ([1]u8{0xff} ** ps_len) ++
                [1]u8{0} ++
                hash_der ++
                msg_hashed;

            const public_key = rsa.PublicKey.fromBytes(exponent, modulus) catch return error.CertificateSignatureInvalid;
            const em_dec = rsaEncrypt(modulus_len, sig[0..modulus_len].*, public_key) catch |err| switch (err) {
                error.MessageTooLong => unreachable,
            };

            if (!std.mem.eql(u8, &em, &em_dec)) {
                return error.CertificateSignatureInvalid;
            }
        },
        else => {
            return error.CertificateSignatureUnsupportedBitCount;
        },
    }
}
