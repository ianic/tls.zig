const std = @import("std");
const crypto = std.crypto;
const tls = std.crypto.tls;
const Certificate = crypto.Certificate;

const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const Sha512 = crypto.hash.sha2.Sha512;

const Transcript = @import("transcript.zig").Transcript;
const PrivateKey = @import("PrivateKey.zig");
const BufWriter = @import("handshake.zig").BufWriter;

pub const Side = enum {
    client,
    server,
};

pub const CertificateMessages = struct {
    certificates: Certificate.Bundle,
    private_key: PrivateKey,
    transcript: *Transcript,
    tls_version: tls.ProtocolVersion = .tls_1_3,
    side: Side = .client,

    pub fn makeCertificate(h: CertificateMessages, buf: []u8) ![]const u8 {
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
        const certs_len = certs.len + 3 * certs_count + extensions.len;

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

    pub fn makeCertificateVerify(h: CertificateMessages, buf: []u8) ![]const u8 {
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
    inline fn createSignature(h: CertificateMessages) !struct { []const u8, tls.SignatureScheme } {
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

    fn setSignatureVerifyBytes(h: CertificateMessages, signer: anytype) void {
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

    fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
        return switch (scheme) {
            .rsa_pkcs1_sha1 => crypto.hash.Sha1,
            .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => Sha256,
            .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => Sha384,
            .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => Sha512,
            else => @compileError("bad scheme"),
        };
    }
};
