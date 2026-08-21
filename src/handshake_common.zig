const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const crypto = std.crypto;
const Certificate = crypto.Certificate;
const Io = std.Io;

const Transcript = @import("transcript.zig").Transcript;
const PrivateKey = @import("PrivateKey.zig");
const record = @import("record.zig");
const rsa = @import("rsa/rsa.zig");
const proto = @import("protocol.zig");

const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const MLKem768 = crypto.kem.ml_kem.MLKem768;

pub const supported_signature_algorithms = &[_]proto.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .ed25519,
    .rsa_pkcs1_sha1,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
};

pub const CertKeyPair = struct {
    /// A chain of one or more certificates, leaf first.
    ///
    /// Each X.509 certificate contains the public key of a key pair, extra
    /// information (the name of the holder, the name of an issuer of the
    /// certificate, validity time spans) and a signature generated using the
    /// private key of the issuer of the certificate.
    ///
    /// All certificates from the bundle are sent to the other side when creating
    /// Certificate tls message.
    ///
    /// Leaf certificate and private key are used to create signature for
    /// CertifyVerify tls message.
    bundle: Certificate.Bundle,

    /// Private key corresponding to the public key in leaf certificate from the
    /// bundle.
    key: PrivateKey,

    /// Ecdsa key pair derived from key. Computed on init and cached because it
    /// is costly operation. Important for server which is creating many
    /// signatures with the same key to not repeat that operation.
    ecdsa_key_pair: ?EcdsaKeyPair = null,

    pub fn fromFilePath(
        allocator: mem.Allocator,
        io: Io,
        dir: std.Io.Dir,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        const bundle = try cert.fromFilePath(allocator, io, dir, cert_path);
        const key_file = try dir.openFile(io, key_path, .{});
        defer key_file.close(io);
        var rdr = key_file.reader(io, &.{});

        const key = try PrivateKey.fromFile(allocator, &rdr.interface);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn fromFilePathAbsolute(
        allocator: mem.Allocator,
        io: Io,
        cert_path: []const u8,
        key_path: []const u8,
    ) !CertKeyPair {
        const bundle = try cert.fromFilePathAbsolute(allocator, io, cert_path);
        const key_file = try std.Io.Dir.openFileAbsolute(io, key_path, .{});
        defer key_file.close(io);
        var rdr = key_file.reader(io, &.{});

        const key = try PrivateKey.fromFile(allocator, &rdr.interface);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn fromSlice(
        allocator: mem.Allocator,
        io: Io,
        cert_slice: []const u8,
        key_slice: []const u8,
    ) !CertKeyPair {
        const key = try PrivateKey.parsePem(key_slice);
        const bundle = try cert.fromSlice(allocator, io, cert_slice);

        return .{ .bundle = bundle, .key = key, .ecdsa_key_pair = try EcdsaKeyPair.init(key) };
    }

    pub fn deinit(c: *CertKeyPair, allocator: mem.Allocator) void {
        c.bundle.deinit(allocator);
    }

    const EcdsaKeyPair = union(enum) {
        ecdsa_secp256r1_sha256: EcdsaP256Sha256.KeyPair,
        ecdsa_secp384r1_sha384: EcdsaP384Sha384.KeyPair,

        fn init(pk: PrivateKey) !?EcdsaKeyPair {
            switch (pk.signature_scheme) {
                inline .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                => |comptime_scheme| {
                    const Ecdsa = SchemeEcdsa(comptime_scheme);
                    const key = pk.key.ecdsa;
                    const key_len = Ecdsa.SecretKey.encoded_length;
                    if (key.len < key_len) return error.InvalidEncoding;
                    const secret_key = try Ecdsa.SecretKey.fromBytes(key[0..key_len].*);
                    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
                    return switch (comptime_scheme) {
                        .ecdsa_secp256r1_sha256 => .{ .ecdsa_secp256r1_sha256 = key_pair },
                        .ecdsa_secp384r1_sha384 => .{ .ecdsa_secp384r1_sha384 = key_pair },
                        else => unreachable,
                    };
                },
                else => return null,
            }
        }
    };
};

pub const cert = struct {
    // A chain of one or more certificates.
    //
    // They are used to verify that certificate chain sent by the other side
    // forms valid trust chain.
    pub const Bundle = crypto.Certificate.Bundle;

    pub fn fromFilePath(allocator: mem.Allocator, io: Io, dir: std.Io.Dir, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePath(allocator, io, Io.Clock.real.now(io), dir, path);
        return bundle;
    }

    pub fn fromFilePathAbsolute(allocator: mem.Allocator, io: Io, path: []const u8) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.addCertsFromFilePathAbsolute(allocator, io, Io.Clock.real.now(io), path);
        return bundle;
    }

    pub fn fromSystem(allocator: mem.Allocator, io: Io) !Bundle {
        var bundle: Bundle = .empty;
        try bundle.rescan(allocator, io, Io.Clock.real.now(io));
        return bundle;
    }

    pub fn fromSlice(allocator: mem.Allocator, io: Io, slice: []const u8) !Bundle {
        const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const size = slice.len;
        const ts = Io.Clock.real.now(io);

        var bundle: Bundle = .empty;

        //Contains modified code from std.crypto.Certificate.Bundle.addCertsFromFile
        const decoded_size_upper_bound = size / 4 * 3;
        const needed_capacity = std.math.cast(u32, decoded_size_upper_bound + size) orelse
            return Certificate.Bundle.AddCertsFromFileError.CertificateAuthorityBundleTooBig;
        try bundle.bytes.ensureUnusedCapacity(allocator, needed_capacity);
        const end_reserved: u32 = @intCast(bundle.bytes.items.len + decoded_size_upper_bound);
        const buffer = bundle.bytes.allocatedSlice()[end_reserved..];
        @memcpy(buffer[0..size], slice);
        const encoded_bytes = buffer[0..size];

        const begin_marker = "-----BEGIN CERTIFICATE-----";
        const end_marker = "-----END CERTIFICATE-----";

        var start_index: usize = 0;
        while (mem.indexOfPos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
            const cert_start = begin_marker_start + begin_marker.len;
            const cert_end = mem.indexOfPos(u8, encoded_bytes, cert_start, end_marker) orelse
                return Certificate.Bundle.AddCertsFromFileError.MissingEndCertificateMarker;
            start_index = cert_end + end_marker.len;
            const encoded_cert = mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
            const decoded_start: u32 = @intCast(bundle.bytes.items.len);
            const dest_buf = bundle.bytes.allocatedSlice()[decoded_start..];
            bundle.bytes.items.len += try base64.decode(dest_buf, encoded_cert);
            try bundle.parseCert(allocator, decoded_start, ts.toSeconds());
        }
        return bundle;
    }
};

pub const CertificateBuilder = struct {
    cert_key_pair: *CertKeyPair,
    transcript: *Transcript,
    tls_version: proto.Version = .tls_1_3,
    side: proto.Side = .client,
    rng: std.Random,

    pub fn makeCertificate(h: CertificateBuilder, w: *record.Writer) !void {
        const certs = h.cert_key_pair.bundle.bytes.items;
        const certs_count = h.cert_key_pair.bundle.map.size;

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
        try w.handshakeRecordHeader(.certificate, certs_len + request_context.len + 3);
        try w.slice(request_context);
        try w.int(u24, certs_len);

        // Write each certificate
        var index: u32 = 0;
        while (index < certs.len) {
            const e = try Certificate.der.Element.parse(certs, index);
            const crt = certs[index..e.slice.end];
            try w.int(u24, crt.len); // certificate length
            try w.slice(crt); // certificate
            try w.slice(extensions); // certificate extensions
            index = e.slice.end;
        }
    }

    pub fn makeCertificateVerify(h: CertificateBuilder, w: *record.Writer) !void {
        // Creates signature for client certificate signature message.
        // Returns signature bytes and signature scheme.
        //
        // Every branch below returns a slice pointing into this buffer, so it
        // has to outlive the switch. 512 bytes is the largest of the three: an
        // RSA-4096 signature. ECDSA DER and Ed25519 are much smaller.
        var buf: [512]u8 = undefined;
        const signature, const signature_scheme = switch (h.cert_key_pair.key.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| brk: {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const key_pair = switch (comptime_scheme) {
                    .ecdsa_secp256r1_sha256 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384 => h.cert_key_pair.ecdsa_key_pair.?.ecdsa_secp384r1_sha384,
                    else => unreachable,
                };
                var signer = try key_pair.signer(null);
                h.setSignatureVerifyBytes(&signer);
                const signature = try signer.finalize();
                break :brk .{
                    signature.toDer(buf[0..Ecdsa.Signature.der_encoded_length_max]),
                    comptime_scheme,
                };
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| brk: {
                const Hash = SchemeHash(comptime_scheme);
                var signer = try h.cert_key_pair.key.key.rsa.signerOaep(Hash, null);
                h.setSignatureVerifyBytes(&signer);
                const signature = try signer.finalize(&buf, h.rng);
                break :brk .{ signature.bytes, comptime_scheme };
            },
            .ed25519 => brk: {
                // EdDSA signs the whole message in one shot (no incremental
                // hash state), so unlike the branches above this bypasses
                // setSignatureVerifyBytes and builds the TLS 1.3 CertificateVerify
                // content directly. Ed25519 isn't defined for TLS 1.2's
                // CertificateVerify construction, so tls_1_2 isn't handled here.
                const Eddsa = crypto.sign.Ed25519;
                const message = if (h.side == .server)
                    h.transcript.serverCertificateVerify()
                else
                    h.transcript.clientCertificateVerify();
                const signature = try h.cert_key_pair.key.key.ed25519.sign(message, null);
                buf[0..Eddsa.Signature.encoded_length].* = signature.toBytes();
                break :brk .{ buf[0..Eddsa.Signature.encoded_length], .ed25519 };
            },
            else => return error.TlsUnknownSignatureScheme,
        };

        try w.handshakeRecordHeader(.certificate_verify, signature.len + 4);
        try w.enumValue(signature_scheme);
        try w.int(u16, signature.len);
        try w.slice(signature);
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
};

fn SchemeEcdsa(comptime scheme: proto.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
        else => unreachable,
    };
}

pub const CertificateParser = struct {
    pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,
    pub_key_buf: [1038]u8 = undefined,
    pub_key: []const u8 = undefined,

    signature_scheme: proto.SignatureScheme = @fromBackingInt(@intCast(0)),
    signature_buf: [1024]u8 = undefined,
    signature: []const u8 = undefined,

    root_ca: Certificate.Bundle,
    host: []const u8,
    skip_verify: bool = false,
    now_sec: i64,

    pub fn parseCertificate(h: *CertificateParser, d: *record.Decoder, tls_version: proto.Version) !void {
        if (tls_version == .tls_1_3) {
            const request_context = try d.decode(u8);
            if (request_context != 0) return error.TlsIllegalParameter;
        }

        var trust_chain_established = false;
        var last_cert: ?Certificate.Parsed = null;
        const certs_len = try d.decode(u24);
        const start_idx = d.idx;
        while (d.idx - start_idx < certs_len) {
            const crt_len = try d.decode(u24);
            const crt = try d.slice(crt_len);
            if (tls_version == .tls_1_3) {
                // certificate extensions present in tls 1.3
                try d.skip(try d.decode(u16));
            }
            if (trust_chain_established)
                continue;

            const subject = try (Certificate{ .buffer = crt, .index = 0 }).parse();
            if (last_cert) |pc| {
                if (pc.verify(subject, h.now_sec)) {
                    last_cert = subject;
                } else |err| switch (err) {
                    error.CertificateIssuerMismatch => {
                        // skip certificate which is not part of the chain
                        continue;
                    },
                    else => return err,
                }
            } else { // first certificate
                if (!h.skip_verify and h.host.len > 0) {
                    try verifyIdentity(subject, h.host);
                }
                h.pub_key = try dupe(&h.pub_key_buf, subject.pubKey());
                h.pub_key_algo = subject.pub_key_algo;
                last_cert = subject;
            }
            if (!h.skip_verify) {
                if (h.root_ca.verify(last_cert.?, h.now_sec)) |_| {
                    trust_chain_established = true;
                } else |err| switch (err) {
                    error.CertificateIssuerNotFound => {},
                    else => return err,
                }
            }
        }
        if (!h.skip_verify and !trust_chain_established) {
            return error.CertificateIssuerNotFound;
        }
    }

    pub fn parseCertificateVerify(h: *CertificateParser, d: *record.Decoder) !void {
        h.signature_scheme = try d.decode(proto.SignatureScheme);
        h.signature = try dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
    }

    pub fn verifySignature(h: *CertificateParser, verify_bytes: []const u8) !void {
        switch (h.signature_scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                if (h.pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;
                const cert_named_curve = h.pub_key_algo.X9_62_id_ecPublicKey;
                switch (cert_named_curve) {
                    inline .secp384r1, .X9_62_prime256v1 => |comptime_cert_named_curve| {
                        const Ecdsa = SchemeEcdsaCert(comptime_scheme, comptime_cert_named_curve);
                        const key = try Ecdsa.PublicKey.fromSec1(h.pub_key);
                        const sig = try Ecdsa.Signature.fromDer(h.signature);
                        try sig.verify(verify_bytes, key);
                    },
                    else => return error.TlsUnknownSignatureScheme,
                }
            },
            .ed25519 => {
                if (h.pub_key_algo != .curveEd25519) return error.TlsBadSignatureScheme;
                const Eddsa = crypto.sign.Ed25519;
                if (h.signature.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                const sig = Eddsa.Signature.fromBytes(h.signature[0..Eddsa.Signature.encoded_length].*);
                if (h.pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                const key = try Eddsa.PublicKey.fromBytes(h.pub_key[0..Eddsa.PublicKey.encoded_length].*);
                try sig.verify(verify_bytes, key);
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.Pss(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk, null);
            },
            inline .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            => |comptime_scheme| {
                if (h.pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const pk = try rsa.PublicKey.fromDer(h.pub_key);
                const sig = rsa.PKCS1v1_5(Hash).Signature{ .bytes = h.signature };
                try sig.verify(verify_bytes, pk);
            },
            else => return error.TlsUnknownSignatureScheme,
        }
    }

    fn SchemeEcdsaCert(comptime scheme: proto.SignatureScheme, comptime cert_named_curve: Certificate.NamedCurve) type {
        const Sha256 = crypto.hash.sha2.Sha256;
        const Sha384 = crypto.hash.sha2.Sha384;
        const Ecdsa = crypto.sign.ecdsa.Ecdsa;

        return switch (scheme) {
            .ecdsa_secp256r1_sha256 => Ecdsa(cert_named_curve.Curve(), Sha256),
            .ecdsa_secp384r1_sha384 => Ecdsa(cert_named_curve.Curve(), Sha384),
            else => @compileError("bad scheme"),
        };
    }
};

/// Verifies that `subject` names `host`, where `host` may be an IP literal.
///
/// `Certificate.verifyHostName` matches only `dNSName` SANs. RFC 6125
/// section 6.4 requires IP reference identities to match `iPAddress` SANs
/// instead, so dispatch based on the form of `host` rather than trying both.
pub fn verifyIdentity(
    subject: Certificate.Parsed,
    host: []const u8,
) Certificate.Parsed.VerifyHostNameError!void {
    const address = parseIpLiteral(host) orelse return subject.verifyHostName(host);
    return verifyIpAddress(subject, address);
}

const IpLiteral = struct {
    bytes: [16]u8,
    len: u5,

    fn slice(self: *const IpLiteral) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Parses `text` as an IP literal. A zone suffix is local routing
/// information, so it is excluded from the certificate identity.
fn parseIpLiteral(text: []const u8) ?IpLiteral {
    if (text.len == 0) return null;

    const bare = if (mem.indexOfScalar(u8, text, '%')) |zone| text[0..zone] else text;
    if (bare.len == 0) return null;

    var result: IpLiteral = .{ .bytes = undefined, .len = 0 };
    if (Io.net.Ip4Address.parse(bare, 0)) |ip4| {
        @memcpy(result.bytes[0..4], &ip4.bytes);
        result.len = 4;
        return result;
    } else |_| {}

    if (Io.net.Ip6Address.parse(bare, 0)) |ip6| {
        @memcpy(result.bytes[0..16], &ip6.bytes);
        result.len = 16;
        return result;
    } else |_| {}

    return null;
}

fn verifyIpAddress(
    subject: Certificate.Parsed,
    address: IpLiteral,
) Certificate.Parsed.VerifyHostNameError!void {
    const subject_alt_name = subject.subjectAltName();
    if (subject_alt_name.len == 0) return error.CertificateHostMismatch;

    const general_names = try Certificate.der.Element.parse(subject_alt_name, 0);
    var name_i = general_names.slice.start;
    while (name_i < general_names.slice.end) {
        const general_name = try Certificate.der.Element.parse(subject_alt_name, name_i);
        name_i = general_name.slice.end;

        const tag: Certificate.GeneralNameTag =
            @fromBackingInt(@intCast(@backingInt(general_name.identifier.tag)));
        if (tag != .iPAddress) continue;

        const encoded = subject_alt_name[general_name.slice.start..general_name.slice.end];
        // RFC 5280 section 4.2.1.6 defines only 4-byte and 16-byte encodings.
        if (encoded.len != 4 and encoded.len != 16) continue;
        if (mem.eql(u8, encoded, address.slice())) return;
    }

    return error.CertificateHostMismatch;
}

fn SchemeHash(comptime scheme: proto.SignatureScheme) type {
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

pub fn dupe(buf: []u8, data: []const u8) ![]u8 {
    if (buf.len < data.len) {
        return error.BufferUndersize;
    }
    @memcpy(buf[0..data.len], data);
    return buf[0..data.len];
}

pub fn dupeMin(buf: []u8, data: []const u8) []u8 {
    const n = @min(data.len, buf.len);
    @memcpy(buf[0..n], data[0..n]);
    return buf[0..n];
}

pub const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
    ml_kem768: MLKem768.KeyPair = undefined,

    secp256r1_pk_buf: [EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //65 bytes
    secp384r1_pk_buf: [EcdsaP384Sha384.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined, //97
    ml_kem768_pk_buf: [MLKem768.PublicKey.encoded_length + X25519.public_length]u8 = undefined, // 1216
    shared_key_buf: [64]u8 = undefined,

    pub const seed_len = 32 + 32 + 48 + 64 + 64;

    pub fn init(seed: [seed_len]u8, named_groups: []const proto.NamedGroup) !DhKeyPair {
        var kp: DhKeyPair = .{};
        for (named_groups) |ng|
            switch (ng) {
                .x25519 => kp.x25519_kp = try X25519.KeyPair.generateDeterministic(seed[0..][0..X25519.seed_length].*),
                .secp256r1 => kp.secp256r1_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed[32..][0..EcdsaP256Sha256.KeyPair.seed_length].*),
                .secp384r1 => kp.secp384r1_kp = try EcdsaP384Sha384.KeyPair.generateDeterministic(seed[32 + 32 ..][0..EcdsaP384Sha384.KeyPair.seed_length].*),
                .x25519_ml_kem768 => kp.ml_kem768 = try MLKem768.KeyPair.generateDeterministic(seed[32 + 32 + 48 + 64 ..][0..MLKem768.seed_length].*),
                else => return error.TlsIllegalParameter,
            };
        return kp;
    }

    // x25519: 32,  secp256r1: 32, secp384r1: 48, x25519_ml_kem768: 64
    pub fn sharedKey(self: *DhKeyPair, named_group: proto.NamedGroup, server_pub_key: []const u8) ![]const u8 {
        return switch (named_group) {
            .x25519 => {
                if (server_pub_key.len != X25519.public_length)
                    return error.TlsIllegalParameter;
                self.shared_key_buf[0..32].* = try X25519.scalarmult(
                    self.x25519_kp.secret_key,
                    server_pub_key[0..X25519.public_length].*,
                );
                return self.shared_key_buf[0..32];
            },
            .secp256r1 => {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp256r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..32].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..32];
            },
            .secp384r1 => {
                const pk = try EcdsaP384Sha384.PublicKey.fromSec1(server_pub_key);
                const mul = try pk.p.mulPublic(self.secp384r1_kp.secret_key.bytes, .big);
                self.shared_key_buf[0..48].* = mul.affineCoordinates().x.toBytes(.big);
                return self.shared_key_buf[0..48];
            },
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = self.ml_kem768.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(self.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                self.shared_key_buf = (hsk ++ xsk);
                return &self.shared_key_buf;
            },
            else => return error.TlsIllegalParameter,
        };
    }

    // Returns 32, 65, 97 or 1216 bytes ml_kem
    pub fn publicKey(self: *DhKeyPair, named_group: proto.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => {
                self.secp256r1_pk_buf = self.secp256r1_kp.public_key.toUncompressedSec1();
                return &self.secp256r1_pk_buf;
            },
            .secp384r1 => {
                self.secp384r1_pk_buf = self.secp384r1_kp.public_key.toUncompressedSec1();
                return &self.secp384r1_pk_buf;
            },
            .x25519_ml_kem768 => {
                self.ml_kem768_pk_buf = self.ml_kem768.public_key.toBytes() ++ self.x25519_kp.public_key;
                return &self.ml_kem768_pk_buf;
            },
            else => return error.TlsIllegalParameter,
        };
    }
};

const testing = std.testing;
const testu = @import("testu.zig");

test "DhKeyPair.x25519" {
    var seed: [DhKeyPair.seed_len]u8 = undefined;
    testu.fill(&seed);
    const server_pub_key = &testu.hexToBytes("3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = &testu.hexToBytes(
        \\ F1 67 FB 4A 49 B2 91 77  08 29 45 A1 F7 08 5A 21
        \\ AF FE 9E 78 C2 03 9B 81  92 40 72 73 74 7A 46 1E
    );
    var kp = try DhKeyPair.init(seed, &.{.x25519});
    try testing.expectEqualSlices(u8, expected, try kp.sharedKey(.x25519, server_pub_key));
}

test "CertificateBuilder.makeCertificateVerify ed25519" {
    // Bundle is unused by makeCertificateVerify (it only signs the
    // transcript with cert_key_pair.key), so an empty one is fine here.
    var cert_key_pair = CertKeyPair{
        .bundle = .{ .map = .{}, .bytes = .{ .items = &.{}, .capacity = 0 } },
        .key = try PrivateKey.parsePem(@embedFile("testdata/ed25519_private_key.pem")),
    };
    var transcript = Transcript{};
    var prng = std.Random.DefaultPrng.init(0);
    const cb = CertificateBuilder{
        .cert_key_pair = &cert_key_pair,
        .transcript = &transcript,
        .side = .server,
        .rng = prng.random(),
    };

    var buf: [256]u8 = undefined;
    var w = record.Writer.init(&buf);
    try cb.makeCertificateVerify(&w);

    // Decode the message as a peer would off the wire and check the
    // signature verifies against the key's own public key.
    var d = record.Decoder.init(.handshake, w.buffered()[4..]); // skip 1-byte type + u24 length header
    const signature_scheme = try d.decode(proto.SignatureScheme);
    try testing.expectEqual(.ed25519, signature_scheme);
    const signature = try d.slice(try d.decode(u16));

    const Eddsa = crypto.sign.Ed25519;
    const sig = Eddsa.Signature.fromBytes(signature[0..Eddsa.Signature.encoded_length].*);
    try sig.verify(transcript.serverCertificateVerify(), cert_key_pair.key.key.ed25519.public_key);
}

/// Signs an empty server transcript with `key_pem` and returns the decoded
/// CertificateVerify body, so a test can check the signature the peer sees.
fn testCertificateVerify(
    key_pem: []const u8,
    buf: []u8,
    transcript: *Transcript,
) !struct { proto.SignatureScheme, []const u8 } {
    // Bundle is unused by makeCertificateVerify (it only signs the
    // transcript with cert_key_pair.key), so an empty one is fine here.
    const key = try PrivateKey.parsePem(key_pem);
    var cert_key_pair = CertKeyPair{
        .bundle = .{ .map = .{}, .bytes = .{ .items = &.{}, .capacity = 0 } },
        .key = key,
        // The ecdsa branch signs with this cached pair, not with `key`.
        .ecdsa_key_pair = try CertKeyPair.EcdsaKeyPair.init(key),
    };
    var prng = std.Random.DefaultPrng.init(0);
    const cb = CertificateBuilder{
        .cert_key_pair = &cert_key_pair,
        .transcript = transcript,
        .side = .server,
        .rng = prng.random(),
    };

    var w = record.Writer.init(buf);
    try cb.makeCertificateVerify(&w);

    // Decode as a peer would off the wire; skip 1-byte type + u24 length.
    var d = record.Decoder.init(.handshake, w.buffered()[4..]);
    const scheme = try d.decode(proto.SignatureScheme);
    return .{ scheme, try d.slice(try d.decode(u16)) };
}

test "CertificateBuilder.makeCertificateVerify ecdsa" {
    var transcript = Transcript{};
    var buf: [256]u8 = undefined;
    const scheme, const signature = try testCertificateVerify(
        @embedFile("testdata/ec_prime256v1_private_key.pem"),
        &buf,
        &transcript,
    );
    try testing.expectEqual(.ecdsa_secp256r1_sha256, scheme);

    const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;
    const pk = try PrivateKey.parsePem(@embedFile("testdata/ec_prime256v1_private_key.pem"));
    const secret_key = try Ecdsa.SecretKey.fromBytes(
        pk.key.ecdsa[0..Ecdsa.SecretKey.encoded_length].*,
    );
    const key_pair = try Ecdsa.KeyPair.fromSecretKey(secret_key);
    const sig = try Ecdsa.Signature.fromDer(signature);
    try sig.verify(transcript.serverCertificateVerify(), key_pair.public_key);
}

test "CertificateBuilder.makeCertificateVerify rsa" {
    var transcript = Transcript{};
    var buf: [1024]u8 = undefined;
    const scheme, const signature = try testCertificateVerify(
        @embedFile("testdata/rsa_private_key.pem"),
        &buf,
        &transcript,
    );
    try testing.expectEqual(.rsa_pss_rsae_sha256, scheme);

    const pk = try PrivateKey.parsePem(@embedFile("testdata/rsa_private_key.pem"));
    const Pss = rsa.Pss(crypto.hash.sha2.Sha256);
    const sig = Pss.Signature{ .bytes = signature };
    try sig.verify(transcript.serverCertificateVerify(), pk.key.rsa.public, null);
}

test "IP literals are parsed without confusing host names" {
    try testing.expectEqual(@as(u5, 4), parseIpLiteral("192.168.31.132").?.len);
    try testing.expectEqual(@as(u5, 16), parseIpLiteral("2001:db8::1").?.len);
    try testing.expectEqual(@as(u5, 16), parseIpLiteral("::1").?.len);

    try testing.expect(parseIpLiteral("bmc.example") == null);
    try testing.expect(parseIpLiteral("192.168.31.132.example.com") == null);
    try testing.expect(parseIpLiteral("") == null);
    try testing.expect(parseIpLiteral("999.999.999.999") == null);
}

test "IPv6 zone suffixes are excluded from certificate identity" {
    const zoned = parseIpLiteral("fe80::1%eth0").?;
    const bare = parseIpLiteral("fe80::1").?;
    try testing.expectEqualSlices(u8, bare.slice(), zoned.slice());
}

test "IPv4 literals use the octets encoded in an IP SAN" {
    const parsed = parseIpLiteral("192.168.31.132").?;
    try testing.expectEqualSlices(u8, &.{ 192, 168, 31, 132 }, parsed.slice());
}

/// Self-signed certificate with SANs for `bmc.example`, `192.168.31.132`,
/// and `2001:db8::1`.
const multi_san_der = testu.hexToBytes(
    \\3082034130820229a00302010202142d695dd0357926093f6bd5a060771b756c
    \\49cd34300d06092a864886f70d01010b050030163114301206035504030c0b62
    \\6d632e6578616d706c653020170d3236303831393033303330345a180f323132
    \\36303732363033303330345a30163114301206035504030c0b626d632e657861
    \\6d706c6530820122300d06092a864886f70d01010105000382010f003082010a
    \\0282010100c31291dc34d0848fbd6041da3115c6e3bc784f09761547b588ddb6
    \\38f543046505b3f978cc7f3ae1d22277df2979c3b3a9e91b92f178b6425ecb41
    \\f92609f77d1e19bff4c36c6a966d3ac590f46fd2db7b44f3c3af6d4216285623
    \\ad2b0cbf61b4df4e3bf37d4945172ddb076ae48983f377675466305cb600a764
    \\4b5761e823ad3184157735fa3bde0fa1248925eaf49ad7481fdf714af74c8484
    \\3ca9403b7819aac51a7f93ced273853c287d6d0f7b45fd8865ed1756d66b8a1e
    \\09a1265dd5f67071d37e5acb4fd7fcfa64d0c0fa06d1c2d2a91f70bd82a5e091
    \\8d1cd388d6f54e50c8315eaf989c1046009edf91bfc30eca8cb94a01028e5fe3
    \\f98dfbf0750203010001a38184308181301d0603551d0e04160414ecf4982bf8
    \\7029856e4b37e19eb59277281f792b301f0603551d23041830168014ecf4982b
    \\f87029856e4b37e19eb59277281f792b300f0603551d130101ff040530030101
    \\ff302e0603551d1104273025820b626d632e6578616d706c658704c0a81f8487
    \\1020010db8000000000000000000000001300d06092a864886f70d01010b0500
    \\03820101007f92d4bc4d616cd29a3e2e6036896b63e6ebfd042df730ea2646a9
    \\6ce8db30d49d1e74b88062b8be1379523068226548efcb516395ddf72cc4e892
    \\61a0f1f93b57d8db2b1d7a3e4f669dd5fcd03155cd0a6718db1662e8fcf599ac
    \\b6a9fe808d799dbec47565fe9a68eaae4084b7d1f44ccfc727911d41b8b21777
    \\5b64a852e3f443f0c87ae5d85fbb8e77b7ea77d96bcafad4047779fc40527865
    \\40a6eb30207e983988c09e10be529416fbf4c953360a4f32d551f9e2b3a235a9
    \\43aad1b2a82b8dbc85cfd4b7c33c6d29b3611a8f78ee505ced12ab2ef4f6467d
    \\d3765f0bd8d391b257affdc5177238de982eb93107a3de2994973709a5e72cbd
    \\4e26b576b1
);

fn multiSan() !Certificate.Parsed {
    const cert_bytes: Certificate = .{ .buffer = &multi_san_der, .index = 0 };
    return cert_bytes.parse();
}

test "IP SANs match equivalent IPv4 and IPv6 reference identities" {
    const parsed = try multiSan();
    try verifyIdentity(parsed, "192.168.31.132");
    try verifyIdentity(parsed, "2001:db8::1");
    try verifyIdentity(parsed, "2001:0db8:0000:0000:0000:0000:0000:0001");
}

test "different IP addresses are refused" {
    const parsed = try multiSan();
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyIdentity(parsed, "192.168.31.133"),
    );
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyIdentity(parsed, "2001:db8::2"),
    );
}

test "DNS identity verification remains unchanged" {
    const parsed = try multiSan();
    try verifyIdentity(parsed, "bmc.example");
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyIdentity(parsed, "other.example"),
    );
}

test "IP reference identities do not match DNS SANs" {
    const parsed = try multiSan();
    try testing.expectError(
        error.CertificateHostMismatch,
        verifyIdentity(parsed, "10.0.0.1"),
    );
}
