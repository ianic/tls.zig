const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const crypto = std.crypto;
const tls = std.crypto.tls;
const Certificate = crypto.Certificate;

const Transcript = @import("transcript.zig").Transcript;
const PrivateKey = @import("PrivateKey.zig");

const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const Kyber768 = crypto.kem.kyber_d00.Kyber768;

pub const Side = enum {
    client,
    server,
};

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

pub const CurveType = enum(u8) {
    named_curve = 0x03,
    _,
};

pub const Authentication = struct {
    // Chain of one or more certificates, leaf first. Is is sent to the
    // server if server requests client authentication.
    certificates: Certificate.Bundle,
    // Private key of the leaf certificate in bundle.
    // Used for creating signature in certificate signature message.
    private_key: PrivateKey,
};

pub const CertificateBuilder = struct {
    certificates: Certificate.Bundle,
    private_key: PrivateKey,
    transcript: *Transcript,
    tls_version: tls.ProtocolVersion = .tls_1_3,
    side: Side = .client,

    pub fn makeCertificate(h: CertificateBuilder, buf: []u8) ![]const u8 {
        var w = BufWriter{ .buf = buf };
        const certs = h.certificates.bytes.items;
        const certs_count = h.certificates.map.size;

        // Differences between tls 1.3 and 1.2
        // TLS 1.3 has request context in header and extensions for each certificate.
        // Here we use empty length for each field.
        // TLS 1.2 don't have these two fields.
        const request_context, const extensions = if (h.tls_version == .tls_1_3)
            .{ &[_]u8{0}, &[_]u8{ 0, 0 } }
        else
            .{ &[_]u8{}, &[_]u8{} };
        const certs_len = certs.len + (3 + extensions.len) * certs_count;

        // Write handshake header
        try w.writeHandshakeHeader(.certificate, certs_len + request_context.len + 3);
        try w.write(request_context);
        try w.writeInt(@as(u24, @intCast(certs_len)));

        // Write each certificate
        var index: u32 = 0;
        while (index < certs.len) {
            const e = try Certificate.der.Element.parse(certs, index);
            const cert = certs[index..e.slice.end];
            try w.writeInt(@as(u24, @intCast(cert.len))); // certificate length
            try w.write(cert); // certificate
            try w.write(extensions); // certificate extensions
            index = e.slice.end;
        }
        return w.getWritten();
    }

    pub fn makeCertificateVerify(h: CertificateBuilder, buf: []u8) ![]const u8 {
        var w = BufWriter{ .buf = buf };
        const signature, const signature_scheme = try h.createSignature();
        try w.writeHandshakeHeader(.certificate_verify, signature.len + 4);
        try w.writeEnum(signature_scheme);
        try w.writeInt(@as(u16, @intCast(signature.len)));
        try w.write(signature);
        return w.getWritten();
    }

    /// Creates signature for client certificate signature message.
    /// Returns signature bytes and signature scheme.
    inline fn createSignature(h: CertificateBuilder) !struct { []const u8, tls.SignatureScheme } {
        switch (h.private_key.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const key = h.private_key.key.ecdsa;
                const key_len = Ecdsa.SecretKey.encoded_length;
                if (key.len < key_len) return error.InvalidEncoding;
                const secret_key = try Ecdsa.SecretKey.fromBytes(key[0..key_len].*);
                const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
                var signer = try key_pair.signer(null);
                h.setSignatureVerifyBytes(&signer);
                const signature = try signer.finalize();
                var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                return .{ signature.toDer(&buf), comptime_scheme };
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                const Hash = SchemeHash(comptime_scheme);
                var signer = try h.private_key.key.rsa.signerOaep(Hash, null);
                h.setSignatureVerifyBytes(&signer);
                var buf: [512]u8 = undefined;
                const signature = try signer.finalize(&buf);
                return .{ signature.bytes, comptime_scheme };
            },
            else => return error.TlsUnknownSignatureScheme,
        }
    }

    fn setSignatureVerifyBytes(h: CertificateBuilder, signer: anytype) void {
        if (h.tls_version == .tls_1_2) {
            // tls 1.2 signature uses current transcript hash value.
            // ref: https://datatracker.ietf.org/doc/html/rfc5246.html#section-7.4.8
            const Hash = @TypeOf(signer.h);
            signer.h = h.transcript.hash(Hash);
        } else {
            // tls 1.3 signature is computed over concatenation of 64 spaces,
            // context, separator and content.
            // ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
            if (h.side == .server) {
                signer.update(h.transcript.serverCertificateVerify());
            } else {
                signer.update(h.transcript.clientCertificateVerify());
            }
        }
    }

    fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
        return switch (scheme) {
            .ecdsa_secp256r1_sha256 => EcdsaP256Sha256,
            .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
            else => unreachable,
        };
    }
};

pub fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
    const Sha256 = crypto.hash.sha2.Sha256;
    const Sha384 = crypto.hash.sha2.Sha384;
    const Sha512 = crypto.hash.sha2.Sha512;

    return switch (scheme) {
        .rsa_pkcs1_sha1 => crypto.hash.Sha1,
        .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => Sha256,
        .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => Sha384,
        .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => Sha512,
        else => @compileError("bad scheme"),
    };
}

pub fn dupe(buf: []u8, data: []const u8) []u8 {
    const n = @min(data.len, buf.len);
    @memcpy(buf[0..n], data[0..n]);
    return buf[0..n];
}

pub const BufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn write(self: *BufWriter, data: []const u8) !void {
        defer self.pos += data.len;
        if (self.pos + data.len > self.buf.len) return error.BufferOverflow;
        _ = dupe(self.buf[self.pos..], data);
    }

    pub fn writeEnum(self: *BufWriter, value: anytype) !void {
        try self.writeInt(@intFromEnum(value));
    }

    pub fn writeInt(self: *BufWriter, value: anytype) !void {
        const IntT = @TypeOf(value);
        const bytes = @divExact(@typeInfo(IntT).Int.bits, 8);
        const free = self.buf[self.pos..];
        if (free.len < bytes) return error.BufferOverflow;
        mem.writeInt(IntT, free[0..bytes], value, .big);
        self.pos += bytes;
    }

    pub fn writeHandshakeHeader(self: *BufWriter, handshake_type: HandshakeType, payload_len: usize) !void {
        try self.write(&handshakeHeader(handshake_type, payload_len));
    }

    /// Should be used after writing handshake payload in buffer provided by `getHandshakePayload`.
    pub fn advanceHandshake(self: *BufWriter, handshake_type: HandshakeType, payload_len: usize) !void {
        try self.write(&handshakeHeader(handshake_type, payload_len));
        self.pos += payload_len;
    }

    /// Record payload is already written by using buffer space from `getPayload`.
    /// Now when we know payload len we can write record header and advance over payload.
    pub fn advanceRecord(self: *BufWriter, content_type: tls.ContentType, payload_len: usize) !void {
        try self.write(&recordHeader(content_type, payload_len));
        self.pos += payload_len;
    }

    pub fn writeRecord(self: *BufWriter, content_type: tls.ContentType, payload: []const u8) !void {
        try self.write(&recordHeader(content_type, payload.len));
        try self.write(payload);
    }

    /// Preserves space for record header and returns buffer free space.
    pub fn getPayload(self: *BufWriter) []u8 {
        return self.buf[self.pos + tls.record_header_len ..];
    }

    /// Preserves space for handshake header and returns buffer free space.
    pub fn getHandshakePayload(self: *BufWriter) []u8 {
        return self.buf[self.pos + 4 ..];
    }

    pub fn getWritten(self: *BufWriter) []const u8 {
        return self.buf[0..self.pos];
    }

    pub fn getFree(self: *BufWriter) []u8 {
        return self.buf[self.pos..];
    }

    pub fn writeEnumArray(self: *BufWriter, comptime E: type, tags: []const E) !void {
        assert(@sizeOf(E) == 2);
        try self.writeInt(@as(u16, @intCast(tags.len * 2)));
        for (tags) |t| {
            try self.writeEnum(t);
        }
    }

    pub fn writeExtension(
        self: *BufWriter,
        comptime et: tls.ExtensionType,
        tags: anytype,
    ) !void {
        try self.writeEnum(et);
        if (et == .supported_versions) {
            try self.writeInt(@as(u16, @intCast(tags.len * 2 + 1)));
            try self.writeInt(@as(u8, @intCast(tags.len * 2)));
        } else {
            try self.writeInt(@as(u16, @intCast(tags.len * 2 + 2)));
            try self.writeInt(@as(u16, @intCast(tags.len * 2)));
        }
        for (tags) |t| {
            try self.writeEnum(t);
        }
    }

    pub fn writeKeyShare(
        self: *BufWriter,
        named_groups: []const tls.NamedGroup,
        keys: []const []const u8,
    ) !void {
        assert(named_groups.len == keys.len);
        try self.writeEnum(tls.ExtensionType.key_share);
        var l: usize = 0;
        for (keys) |key| {
            l += key.len + 4;
        }
        try self.writeInt(@as(u16, @intCast(l + 2)));
        try self.writeInt(@as(u16, @intCast(l)));
        for (named_groups, 0..) |ng, i| {
            const key = keys[i];
            try self.writeEnum(ng);
            try self.writeInt(@as(u16, @intCast(key.len)));
            try self.write(key);
        }
    }

    pub fn writeServerName(self: *BufWriter, host: []const u8) !void {
        try self.write(&serverNameExtensionHeader(@intCast(host.len)));
        try self.write(host);
    }
};

fn serverNameExtensionHeader(host_len: u16) [9]u8 {
    const int2 = tls.int2;

    return int2(@intFromEnum(tls.ExtensionType.server_name)) ++
        int2(host_len + 5) ++ // byte length of this extension payload
        int2(host_len + 3) ++ // server_name_list byte count
        [1]u8{0x00} ++ // name_type
        int2(host_len);
}

pub fn handshakeHeader(handshake_type: HandshakeType, payload_len: usize) [4]u8 {
    return [1]u8{@intFromEnum(handshake_type)} ++ tls.int3(@intCast(payload_len));
}

pub fn recordHeader(content_type: tls.ContentType, payload_len: usize) [5]u8 {
    return [1]u8{@intFromEnum(content_type)} ++
        tls.int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        tls.int2(@intCast(payload_len));
}

const testing = std.testing;
const testu = @import("testu.zig");

test "BufWriter" {
    var buf: [16]u8 = undefined;
    var w = BufWriter{ .buf = &buf };

    try w.write("ab");
    try w.writeEnum(CurveType.named_curve);
    try w.writeEnum(tls.NamedGroup.x25519);
    try w.writeInt(@as(u16, 0x1234));
    try testing.expectEqualSlices(u8, &[_]u8{ 'a', 'b', 0x03, 0x00, 0x1d, 0x12, 0x34 }, w.getWritten());
}

pub const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
    kyber768_kp: Kyber768.KeyPair = undefined,

    pub const seed_len = 32 + 32 + 48 + 64;

    pub fn init(seed: [seed_len]u8, named_groups: []const tls.NamedGroup) !DhKeyPair {
        var kp: DhKeyPair = .{};
        for (named_groups) |ng|
            switch (ng) {
                .x25519 => kp.x25519_kp = try X25519.KeyPair.create(seed[0..][0..X25519.seed_length].*),
                .secp256r1 => kp.secp256r1_kp = try EcdsaP256Sha256.KeyPair.create(seed[32..][0..EcdsaP256Sha256.KeyPair.seed_length].*),
                .secp384r1 => kp.secp384r1_kp = try EcdsaP384Sha384.KeyPair.create(seed[32 + 32 ..][0..EcdsaP384Sha384.KeyPair.seed_length].*),
                .x25519_kyber768d00 => kp.kyber768_kp = try Kyber768.KeyPair.create(seed[32 + 32 + 48 ..][0..Kyber768.seed_length].*),
                else => return error.TlsIllegalParameter,
            };
        return kp;
    }

    pub inline fn sharedKey(self: DhKeyPair, named_group: tls.NamedGroup, server_pub_key: []const u8) ![]const u8 {
        return switch (named_group) {
            .x25519 => brk: {
                if (server_pub_key.len != X25519.public_length)
                    return error.TlsIllegalParameter;
                break :brk &(try X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..X25519.public_length].*,
                ));
            },
            .secp256r1 => brk: {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp256r1_kp.secret_key.bytes, .big);
                break :brk &mul.affineCoordinates().x.toBytes(.big);
            },
            .secp384r1 => brk: {
                const pk = try EcdsaP384Sha384.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp384r1_kp.secret_key.bytes, .big);
                break :brk &mul.affineCoordinates().x.toBytes(.big);
            },
            .x25519_kyber768d00 => brk: {
                const xksl = crypto.dh.X25519.public_length;
                const hksl = xksl + Kyber768.ciphertext_length;
                if (server_pub_key.len != hksl)
                    return error.TlsIllegalParameter;

                break :brk &((crypto.dh.X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..xksl].*,
                ) catch return error.TlsDecryptFailure) ++ (self.kyber768_kp.secret_key.decaps(
                    server_pub_key[xksl..hksl],
                ) catch return error.TlsDecryptFailure));
            },
            else => return error.TlsIllegalParameter,
        };
    }

    // Returns 32, 65, 97 or 1216 bytes
    pub inline fn publicKey(self: DhKeyPair, named_group: tls.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => &self.secp256r1_kp.public_key.toUncompressedSec1(),
            .secp384r1 => &self.secp384r1_kp.public_key.toUncompressedSec1(),
            .x25519_kyber768d00 => &self.x25519_kp.public_key ++ self.kyber768_kp.public_key.toBytes(),
            else => return error.TlsIllegalParameter,
        };
    }
};

test "DhKeyPair.x25519" {
    var seed: [DhKeyPair.seed_len]u8 = undefined;
    testu.fill(&seed);
    const server_pub_key = &testu.hexToBytes("3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = &testu.hexToBytes(
        \\ F1 67 FB 4A 49 B2 91 77  08 29 45 A1 F7 08 5A 21
        \\ AF FE 9E 78 C2 03 9B 81  92 40 72 73 74 7A 46 1E
    );
    const kp = try DhKeyPair.init(seed, &.{.x25519});
    try testing.expectEqualSlices(u8, expected, try kp.sharedKey(.x25519, server_pub_key));
}
