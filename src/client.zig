const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const posix = std.posix;
const mem = std.mem;
const tls = crypto.tls;

const Certificate = crypto.Certificate;
const rsa = Certificate.rsa;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const EcdsaP384Sha256 = crypto.sign.ecdsa.Ecdsa(crypto.ecc.P384, crypto.hash.sha2.Sha256);
const Kyber768 = crypto.kem.kyber_d00.Kyber768;

const consts = @import("consts.zig");
const Cipher = @import("cipher.zig").Cipher;
pub const CipherSuite = @import("cipher.zig").CipherSuite;
const Transcript = @import("transcript.zig").Transcript;

pub fn client(stream: anytype) ClientT(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .reader = recordReader(stream),
    };
}

pub const ProtocolVersion = tls.ProtocolVersion;

pub const Options = struct {
    // To use just tls 1.2 cipher suites:
    //   .cipher_suites = &tls.CipherSuite.tls12,
    // To select particular cipher suite:
    //   .cipher_suites = &[_]CipherSuite{CipherSuite.CHACHA20_POLY1305_SHA256},
    cipher_suites: []const CipherSuite = &CipherSuite.tls12 ++ CipherSuite.tls13,

    // Some sites are not working when sending keyber public key: godaddy.com, secureserver.net
    // That key is making hello message big ~1655 bytes instead of 360
    // Both have header "Server: ATS/9.2.3"
    // In Wireshark I got window update then tcp retransmissions of 1440 bytes without ack.
    // After 17sec and 6 retransmissions connection is broken.
    disable_keyber: bool = false,

    // Collect stats from handshake.
    stats: ?*Stats = null,
};

pub const Stats = struct {
    tls_version: ProtocolVersion = undefined,
    cipher_suite_tag: CipherSuite = undefined,
    named_group: tls.NamedGroup = undefined,
    signature_scheme: tls.SignatureScheme = undefined,
};

var random = crypto.random;

pub fn ClientT(comptime StreamType: type) type {
    const RecordReaderType = RecordReader(StreamType);
    return struct {
        stream: StreamType,
        reader: RecordReaderType,

        cipher: Cipher = undefined,
        client_sequence: usize = 0,
        server_sequence: usize = 0,
        write_buf: [tls.max_ciphertext_record_len]u8 = undefined,

        const Client = @This();

        pub fn handshake(
            c: *Client,
            host: []const u8,
            ca_bundle: ?Certificate.Bundle,
            opt: Options,
        ) !void {
            var h = try Handshake.init(&c.write_buf);

            defer if (opt.stats) |s| {
                s.tls_version = h.tls_version;
                s.cipher_suite_tag = h.cipher_suite_tag;
                s.named_group = h.named_group orelse @as(tls.NamedGroup, @enumFromInt(0x0000));
                s.signature_scheme = h.signature_scheme;
            };

            errdefer std.debug.print(
                "{s}\n\ttls version: {}\n\tchipher: {}\n\tnamded_group: {}\n\tsignature scheme: {}\n",
                .{
                    host,
                    h.tls_version,
                    h.cipher_suite_tag,
                    h.named_group orelse @as(tls.NamedGroup, @enumFromInt(0x0000)),
                    h.signature_scheme,
                },
            );

            try h.clientHello(host, &c.stream, opt);
            try h.serverFlight1(&c.reader, ca_bundle, host);
            if (h.tls_version == .tls_1_3) {
                const shared_key = try h.dh_kp.preMasterSecret(h.named_group.?, h.server_pub_key);
                h.cipher = try Cipher.initHandshake(h.cipher_suite_tag, shared_key, &h.transcript);
                try h.serverFlightTls13(&c.reader, ca_bundle, host);
                c.cipher = try Cipher.initApplication(h.cipher_suite_tag, &h.transcript);
                try h.clientFlight2Tls13(c);
                return;
            }

            // continue with tls 1.2
            if (h.cipher_suite_tag.keyExchange() == .ecdhe)
                try h.verifySignature12();
            try h.generateKeyMaterial();
            c.cipher = try Cipher.init12(h.cipher_suite_tag, h.key_material, random);

            try h.clientFlight2(c);
            try h.serverFlight2(c);
        }

        pub fn write(c: *Client, cleartext: []const u8) !void {
            var pos: usize = 0;
            while (pos < cleartext.len) {
                const data = cleartext[pos..];
                const n = @min(data.len, tls.max_cipertext_inner_record_len);
                try c.write_(.application_data, data[0..n]);
                pos += n;
            }
        }

        fn write_(c: *Client, content_type: tls.ContentType, cleartext: []const u8) !void {
            assert(cleartext.len <= tls.max_cipertext_inner_record_len);

            const payload = c.encrypt(&c.write_buf, content_type, cleartext);
            try c.stream.writeAll(payload);
        }

        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try client.next()) |buf| { ... }
        pub fn next(c: *Client) !?[]const u8 {
            const content_type, const data = try c.next_() orelse return null;
            if (content_type != .application_data) return error.TlsUnexpectedMessage;
            return data;
        }

        fn next_(c: *Client) !?struct { tls.ContentType, []const u8 } {
            while (true) {
                const rec = (try c.reader.next()) orelse return null;
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

                const content_type, const cleartext = try c.cipher.decrypt(
                    rec.payload,
                    c.server_sequence,
                    rec.header,
                    rec.payload,
                );
                c.server_sequence += 1;

                switch (content_type) {
                    .application_data => {},
                    .handshake => {
                        const handshake_type: consts.HandshakeType = @enumFromInt(cleartext[0]);
                        if (handshake_type == .new_session_ticket)
                            continue;
                    },
                    .alert => {
                        if (cleartext.len < 2) return error.TlsAlertUnknown;
                        const level: tls.AlertLevel = @enumFromInt(cleartext[0]);
                        const desc: tls.AlertDescription = @enumFromInt(cleartext[1]);
                        _ = level;
                        try desc.toError();
                        return null; // (level == .warning and desc == .close_notify)
                    },
                    else => return error.TlsUnexpectedMessage,
                }
                return .{ content_type, cleartext };
            }
        }

        fn encrypt(c: *Client, buffer: []u8, content_type: tls.ContentType, cleartext: []const u8) []const u8 {
            defer c.client_sequence += 1;
            return c.cipher.encrypt(buffer, c.client_sequence, content_type, cleartext);
        }

        pub fn close(c: *Client) !void {
            const msg = c.encrypt(&c.write_buf, .alert, &consts.close_notify_alert);
            try c.stream.writeAll(msg);
        }

        const Handshake = struct {
            client_random: [32]u8,
            server_random: [32]u8 = undefined,
            master_secret: [48]u8 = undefined,
            key_material_buf: [48 * 4]u8 = undefined,
            key_material: []u8 = undefined,

            transcript: Transcript = .{},
            cipher_suite_tag: CipherSuite = undefined,
            named_group: ?tls.NamedGroup = null,
            dh_kp: DhKeyPair,
            rsa_kp: RsaKeyPair,
            signature_scheme: tls.SignatureScheme = undefined,
            now_sec: i64 = 0,
            tls_version: tls.ProtocolVersion = .tls_1_2,
            cipher: Cipher = undefined,

            cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,
            cert_pub_key_buf: [600]u8 = undefined,
            cert_pub_key: []const u8 = undefined,
            // public key len: x25519 = 32, secp256r1 = 65, secp384r1 = 97, x25519_kyber768d00 = 1120
            server_pub_key_buf: [1120]u8 = undefined,
            server_pub_key: []const u8 = undefined,
            signature_buf: [1024]u8 = undefined,
            signature: []const u8 = undefined,

            buffer: []u8, // scratch buffer

            pub fn init(buf: []u8) !Handshake {
                var rand_buf: [32 + 64 + 46]u8 = undefined;
                random.bytes(&rand_buf);

                return .{
                    .client_random = rand_buf[0..32].*,
                    .dh_kp = try DhKeyPair.init(rand_buf[32..][0..64].*),
                    .rsa_kp = RsaKeyPair.init(rand_buf[32 + 64 ..][0..46].*),
                    .now_sec = std.time.timestamp(),
                    .buffer = buf,
                };
            }

            /// Send client hello message.
            fn clientHello(h: *Handshake, host: []const u8, stream: *StreamType, opt: Options) !void {
                const msg = try h.clientHelloMessage(host, opt);
                h.transcript.update(msg[tls.record_header_len..]);
                try stream.writeAll(msg);
            }

            fn clientHelloMessage(h: *Handshake, host: []const u8, opt: Options) ![]const u8 {
                // Buffer will have this parts:
                // | header | payload | extensions |
                //
                // Header will be written last because we need to know length of
                // payload and extensions when creating it. Payload has
                // extensions lenght (u16) as last element.
                //
                var buffer = h.buffer;
                const header_len = 9; // tls record header (5 bytes) and handsheke header (4 bytes)
                const tls_versions = try CipherSuite.versions(opt.cipher_suites);
                // Payload writer, preserve header_len bytes for handshake header.
                var payload = BufWriter{ .buf = buffer[header_len..] };
                try payload.write(&consts.hello.protocol_version ++
                    h.client_random ++
                    consts.hello.no_session_id);
                try payload.writeEnumArray(CipherSuite, opt.cipher_suites);
                try payload.write(&consts.hello.no_compression);

                // Extensions writer starts after payload and preserves 2 more
                // bytes for extension len in payload.
                var ext = BufWriter{ .buf = buffer[header_len + payload.pos + 2 ..] };
                try ext.writeExtension(.supported_versions, switch (tls_versions) {
                    .both => &[_]tls.ProtocolVersion{ .tls_1_3, .tls_1_2 },
                    .tls_1_3 => &[_]tls.ProtocolVersion{.tls_1_3},
                    .tls_1_2 => &[_]tls.ProtocolVersion{.tls_1_2},
                });
                try ext.write(&consts.extension.ec_point_formats ++
                    consts.extension.renegotiation_info ++
                    consts.extension.sct);
                try ext.writeExtension(.signature_algorithms, &[_]tls.SignatureScheme{
                    .ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384,
                    .rsa_pss_rsae_sha256,
                    .rsa_pss_rsae_sha384,
                    .rsa_pss_rsae_sha512,
                    .ed25519,
                    .rsa_pkcs1_sha1,
                    .rsa_pkcs1_sha256,
                    .rsa_pkcs1_sha384,
                });

                const named_groups = &[_]tls.NamedGroup{ .x25519, .secp256r1, .secp384r1, .x25519_kyber768d00 };
                const named_groups_len = named_groups.len - @as(usize, if (opt.disable_keyber) 1 else 0);
                try ext.writeExtension(.supported_groups, named_groups[0..named_groups_len]);
                if (tls_versions != .tls_1_2) {
                    const keys = &[_][]const u8{
                        try h.dh_kp.publicKey(.x25519),
                        try h.dh_kp.publicKey(.secp256r1),
                        try h.dh_kp.publicKey(.secp384r1),
                        try h.dh_kp.publicKey(.x25519_kyber768d00),
                    };
                    try ext.writeKeyShare(named_groups[0..named_groups_len], keys[0..named_groups_len]);
                }
                try ext.writeServerName(host);

                // Extensions length at the end of the payload.
                try payload.writeInt(@as(u16, @intCast(ext.pos)));
                // Header at the start of the buffer.
                buffer[0..header_len].* = consts.handshakeHeader(.client_hello, payload.pos + ext.pos);
                return buffer[0 .. header_len + payload.pos + ext.pos];
            }

            fn serverHello(h: *Handshake, rec: *Record, length: u24) !void {
                if (try rec.decode(tls.ProtocolVersion) != tls.ProtocolVersion.tls_1_2)
                    return error.TlsBadVersion;
                h.server_random = (try rec.array(32)).*;
                if (consts.isServerHelloRetryRequest(&h.server_random))
                    return error.TlsServerHelloRetryRequest;

                const session_id_len = try rec.decode(u8);
                if (session_id_len > 32) return error.TlsIllegalParameter;
                try rec.skip(session_id_len);

                h.cipher_suite_tag = try rec.decode(CipherSuite);
                try h.cipher_suite_tag.validate();
                try rec.skip(1); // skip compression method

                const extensions_present = length > 2 + 32 + session_id_len + 2 + 1;
                if (extensions_present) {
                    const exs_len = try rec.decode(u16);
                    var l: usize = 0;
                    while (l < exs_len) {
                        const typ = try rec.decode(tls.ExtensionType);
                        const len = try rec.decode(u16);
                        defer l += len + 4;

                        switch (typ) {
                            .supported_versions => {
                                switch (try rec.decode(tls.ProtocolVersion)) {
                                    .tls_1_2, .tls_1_3 => |v| h.tls_version = v,
                                    else => return error.TlsIllegalParameter,
                                }
                                if (len != 2) return error.TlsIllegalParameter;
                            },
                            .key_share => {
                                h.named_group = try rec.decode(tls.NamedGroup);
                                h.server_pub_key = try dupe(&h.server_pub_key_buf, try rec.slice(try rec.decode(u16)));
                                if (len != h.server_pub_key.len + 4) return error.TlsIllegalParameter;
                            },
                            else => {
                                try rec.skip(len);
                            },
                        }
                    }
                }
            }

            fn serverCertificate(h: *Handshake, rec: *Record, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
                var trust_chain_established = false;
                var last_cert: ?Certificate.Parsed = null;
                const certs_len = try rec.decode(u24);

                const start_idx = rec.idx;
                while (rec.idx - start_idx < certs_len) {
                    const cert_len = try rec.decode(u24);
                    // std.debug.print("=> {} {} {} {}\n", .{ certs_len, rec.idx, cert_len, rec.payload.len });
                    const cert = try rec.slice(cert_len);
                    if (h.tls_version == .tls_1_3) {
                        // certificate extensions present in tls 1.3
                        try rec.skip(try rec.decode(u16));
                    }
                    if (trust_chain_established)
                        continue;

                    const subject = try (Certificate{ .buffer = cert, .index = 0 }).parse();
                    if (last_cert) |pc| {
                        if (pc.verify(subject, h.now_sec)) {
                            last_cert = subject;
                        } else |_| {
                            // skip certificate which is not part of the chain
                            continue;
                        }
                    } else { // first certificate
                        try subject.verifyHostName(host);
                        h.cert_pub_key = try dupe(&h.cert_pub_key_buf, subject.pubKey());
                        h.cert_pub_key_algo = subject.pub_key_algo;
                        last_cert = subject;
                    }
                    if (ca_bundle) |cb| {
                        if (cb.verify(last_cert.?, h.now_sec)) |_| {
                            trust_chain_established = true;
                        } else |err| switch (err) {
                            error.CertificateIssuerNotFound => {},
                            else => |e| return e,
                        }
                    }
                }
                if (ca_bundle != null and !trust_chain_established) {
                    return error.CertificateIssuerNotFound;
                }
            }

            fn serverKeyExchange(h: *Handshake, rec: *Record) !void {
                const curve_type = try rec.decode(consts.CurveType);
                h.named_group = try rec.decode(tls.NamedGroup);
                h.server_pub_key = try dupe(&h.server_pub_key_buf, try rec.slice(try rec.decode(u8)));
                h.signature_scheme = try rec.decode(tls.SignatureScheme);
                h.signature = try dupe(&h.signature_buf, try rec.slice(try rec.decode(u16)));
                if (curve_type != .named_curve) return error.TlsIllegalParameter;
            }

            /// Read server hello, certificate, key_exchange and hello done messages.
            /// Extract server public key and server random.
            fn serverFlight1(h: *Handshake, reader: *RecordReaderType, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
                var handshake_state = consts.HandshakeType.server_hello;

                while (true) {
                    var rec = (try reader.next()) orelse return error.EndOfStream;
                    try rec.expectContentType(.handshake);
                    if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

                    h.transcript.update(rec.payload);

                    // Multiple handshake messages can be packed in single tls record.
                    while (!rec.eof()) {
                        const handshake_type = try rec.decode(consts.HandshakeType);
                        if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;

                        const length = try rec.decode(u24);
                        if (length > tls.max_cipertext_inner_record_len)
                            return error.TlsUnsupportedFragmentedHandshakeMessage;

                        switch (handshake_type) {
                            .server_hello => { // server hello, ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.3
                                try h.serverHello(&rec, length);
                                if (h.tls_version == .tls_1_3) {
                                    if (!rec.eof()) return error.TlsIllegalParameter;
                                    return;
                                }
                                handshake_state = .certificate;
                            },
                            .certificate => {
                                try h.serverCertificate(&rec, ca_bundle, host);
                                handshake_state = if (h.cipher_suite_tag.keyExchange() == .rsa)
                                    .server_hello_done
                                else
                                    .server_key_exchange;
                            },
                            .server_key_exchange => {
                                try h.serverKeyExchange(&rec);
                                handshake_state = .server_hello_done;
                            },
                            .server_hello_done => {
                                if (length != 0) return error.TlsIllegalParameter;
                                return;
                            },
                            else => return error.TlsUnexpectedMessage,
                        }
                    }
                }
            }

            fn serverFlightTls13(
                h: *Handshake,
                reader: *RecordReaderType,
                ca_bundle: ?Certificate.Bundle,
                host: []const u8,
            ) !void {
                var sequence: u64 = 0;
                var cleartext_buf = h.buffer;
                var cleartext_buf_head: usize = 0;
                var cleartext_buf_tail: usize = 0;
                var handshake_state: tls.HandshakeType = .encrypted_extensions;

                outer: while (true) {
                    var wrap_rec = (try reader.next()) orelse return error.TlsUnexpectedMessage;
                    if (wrap_rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                    //std.debug.print("serverFlightTls13 {} {}\n", .{ wrap_rec.content_type, wrap_rec.payload.len });
                    switch (wrap_rec.content_type) {
                        .change_cipher_spec => {
                            try wrap_rec.skip(wrap_rec.payload.len);
                        },
                        .application_data => {
                            const content_type, const cleartext = switch (h.cipher) {
                                inline else => |*p| try p.decrypt(cleartext_buf[cleartext_buf_tail..], sequence, wrap_rec.header, wrap_rec.payload),
                            };
                            if (content_type != .handshake) return error.TlsUnexpectedMessage;
                            sequence += 1;
                            cleartext_buf_tail += cleartext.len;

                            var rec = Record{
                                .content_type = content_type,
                                .payload = cleartext_buf[cleartext_buf_head..cleartext_buf_tail],
                            };
                            while (!rec.eof()) {
                                const start_idx = rec.idx;
                                const handshake_type = try rec.decode(tls.HandshakeType);
                                const length = try rec.decode(u24);

                                // std.debug.print("handshake loop: {} {} {}\n", .{ handshake_type, length, rec.payload.len });
                                if (length > tls.max_cipertext_inner_record_len)
                                    return error.TlsUnsupportedFragmentedHandshakeMessage;
                                if (length > rec.payload.len - 4)
                                    continue :outer; // fragmented handshake into multiple records

                                defer {
                                    const handshake_payload = rec.payload[start_idx..rec.idx];
                                    h.transcript.update(handshake_payload);
                                    cleartext_buf_head += handshake_payload.len;
                                }

                                if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;
                                switch (handshake_type) {
                                    .encrypted_extensions => {
                                        try rec.skip(length);
                                        handshake_state = .certificate;
                                    },
                                    .certificate => {
                                        const request_context = try rec.decode(u8);
                                        if (request_context != 0) return error.TlsIllegalParameter;
                                        try h.serverCertificate(&rec, ca_bundle, host);
                                        handshake_state = .certificate_verify;
                                    },
                                    .certificate_verify => {
                                        h.signature_scheme = try rec.decode(tls.SignatureScheme);
                                        h.signature = try dupe(&h.signature_buf, try rec.slice(try rec.decode(u16)));
                                        try h.verifySignature(h.transcript.verifyBytes13(h.cipher_suite_tag));
                                        handshake_state = .finished;
                                    },
                                    .finished => {
                                        const actual = try rec.slice(length);
                                        const expected = h.transcript.serverFinished13(h.cipher_suite_tag);
                                        if (!mem.eql(u8, expected, actual))
                                            return error.TlsDecryptError;
                                        return;
                                    },
                                    else => return error.TlsUnexpectedMessage,
                                }
                            }
                            cleartext_buf_head = 0;
                            cleartext_buf_tail = 0;
                        },
                        else => return error.TlsUnexpectedMessage,
                    }
                }
            }

            fn verifySignature12(h: *Handshake) !void {
                const verify_bytes = brk: {
                    var w = BufWriter{ .buf = h.buffer };
                    try w.write(&h.client_random);
                    try w.write(&h.server_random);
                    try w.writeEnum(consts.CurveType.named_curve);
                    try w.writeEnum(h.named_group.?);
                    try w.writeInt(@as(u8, @intCast(h.server_pub_key.len)));
                    try w.write(h.server_pub_key);
                    break :brk w.getWritten();
                };
                try h.verifySignature(verify_bytes);
            }

            fn verifySignature(h: *Handshake, verify_bytes: []const u8) !void {
                switch (h.signature_scheme) {
                    inline .ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384,
                    => |comptime_scheme| {
                        if (h.cert_pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;

                        const cert_named_curve = h.cert_pub_key_algo.X9_62_id_ecPublicKey;
                        switch (cert_named_curve) {
                            inline else => |comptime_cert_named_curve| {
                                const Ecdsa = SchemeEcdsa(comptime_scheme, comptime_cert_named_curve);
                                const key = try Ecdsa.PublicKey.fromSec1(h.cert_pub_key);
                                const sig = try Ecdsa.Signature.fromDer(h.signature);
                                try sig.verify(verify_bytes, key);
                            },
                        }
                    },

                    inline .ed25519 => {
                        std.debug.print("evo ga netko koristi .ed25519 !!!!\n", .{});
                        if (h.cert_pub_key_algo != .curveEd25519) return error.TlsBadSignatureScheme;
                        const Eddsa = crypto.sign.Ed25519;
                        if (h.signature.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                        const sig = Eddsa.Signature.fromBytes(h.signature[0..Eddsa.Signature.encoded_length].*);
                        if (h.cert_pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                        const key = try Eddsa.PublicKey.fromBytes(h.cert_pub_key[0..Eddsa.PublicKey.encoded_length].*);
                        try sig.verify(verify_bytes, key);
                    },

                    inline .rsa_pss_rsae_sha256,
                    .rsa_pss_rsae_sha384,
                    .rsa_pss_rsae_sha512,
                    => |comptime_scheme| {
                        if (h.cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                        const Hash = SchemeHash(comptime_scheme);
                        const pk = try rsa.PublicKey.parseDer(h.cert_pub_key);
                        switch (pk.modulus.len) {
                            inline 128, 256, 512 => |modulus_len| {
                                const key = try rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
                                const sig = rsa.PSSSignature.fromBytes(modulus_len, h.signature);
                                try rsa.PSSSignature.verify(modulus_len, sig, verify_bytes, key, Hash);
                            },
                            else => {
                                return error.TlsBadRsaSignatureBitCount;
                            },
                        }
                    },
                    inline .rsa_pkcs1_sha1,
                    .rsa_pkcs1_sha256,
                    .rsa_pkcs1_sha384,
                    .rsa_pkcs1_sha512,
                    => |comptime_scheme| {
                        if (h.cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                        const Hash = SchemeHash(comptime_scheme);
                        try verifyRsa(Hash, verify_bytes, h.signature, h.cert_pub_key_algo, h.cert_pub_key);
                    },
                    else => return error.TlsUnknownSignatureScheme,
                }
            }

            fn SchemeEcdsa(comptime scheme: tls.SignatureScheme, comptime cert_named_curve: Certificate.NamedCurve) type {
                return switch (scheme) {
                    .ecdsa_secp256r1_sha256 => switch (cert_named_curve) {
                        .secp384r1 => EcdsaP384Sha256,
                        else => EcdsaP256Sha256,
                    },
                    .ecdsa_secp384r1_sha384 => EcdsaP384Sha384,
                    else => @compileError("bad scheme"),
                };
            }

            fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
                return switch (scheme) {
                    .rsa_pkcs1_sha1 => crypto.hash.Sha1,
                    .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => crypto.hash.sha2.Sha256,
                    .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => crypto.hash.sha2.Sha384,
                    .rsa_pss_rsae_sha512, .rsa_pkcs1_sha512 => crypto.hash.sha2.Sha512,
                    else => @compileError("bad scheme"),
                };
            }

            fn generateKeyMaterial(h: *Handshake) !void {
                const pre_master_secret = if (h.named_group) |named_group|
                    try h.dh_kp.preMasterSecret(named_group, h.server_pub_key)
                else
                    &h.rsa_kp.pre_master_secret;

                h.master_secret = Transcript.masterSecret(
                    h.cipher_suite_tag,
                    pre_master_secret,
                    h.client_random,
                    h.server_random,
                )[0..h.master_secret.len].*;
                h.key_material = try dupe(&h.key_material_buf, Transcript.keyMaterial(
                    h.cipher_suite_tag,
                    &h.master_secret,
                    h.client_random,
                    h.server_random,
                ));
            }

            /// Sends client key exchange, client chiper spec and client
            /// handshake finished messages.
            fn clientFlight2(h: *Handshake, c: *Client) !void {
                var fbs = std.io.fixedBufferStream(h.buffer);

                // client key exchange message
                {
                    const key: []const u8 = if (h.named_group) |named_group|
                        try h.dh_kp.publicKey(named_group)
                    else
                        try h.rsa_kp.publicKey(h.cert_pub_key_algo, h.cert_pub_key);

                    const header = if (h.named_group != null)
                        &consts.handshakeHeader(.client_key_exchange, 1 + key.len) ++
                            consts.int1(@intCast(key.len))
                    else
                        &consts.handshakeHeader(.client_key_exchange, 2 + key.len) ++
                            consts.int2(@intCast(key.len));

                    _ = try fbs.write(header);
                    _ = try fbs.write(key);

                    h.transcript.update(fbs.getWritten()[tls.record_header_len..]);
                }

                // client change cipher spec message
                {
                    const change_cipher_spec = consts.recordHeader(.change_cipher_spec, 1) ++ consts.int1(1);
                    _ = try fbs.write(&change_cipher_spec);
                }

                // client handshake finished message
                {
                    // verify data + handshake header
                    const client_finished = h.transcript.clientFinished(h.cipher_suite_tag, &h.master_secret);
                    h.transcript.update(&client_finished);
                    // encrypt client_finished into handshake_finished tls record
                    const handshake_finished = c.encrypt(fbs.buffer[fbs.pos..], .handshake, &client_finished);
                    fbs.pos += handshake_finished.len;
                }

                try c.stream.writeAll(fbs.getWritten());
            }

            fn serverFlight2(h: *Handshake, c: *Client) !void {
                try h.serverChangeCipherSpec(c);
                try h.serverHandshakeFinished(c);
            }

            fn serverChangeCipherSpec(h: *Handshake, c: *Client) !void {
                _ = h;
                var rec = (try c.reader.next()) orelse return error.EndOfStream;
                try rec.expectContentType(.change_cipher_spec);
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
            }

            fn serverHandshakeFinished(h: *Handshake, c: *Client) !void {
                const content_type, const server_finished = try c.next_() orelse return error.EndOfStream;
                if (content_type != .handshake) return error.TlsUnexpectedMessage;

                const expected_server_finished = h.transcript.serverFinished(h.cipher_suite_tag, &h.master_secret);
                if (!mem.eql(u8, server_finished, &expected_server_finished))
                    // TODO should we write alert message
                    return error.TlsBadRecordMac;
            }

            // client change cipher spec and client handshake finished
            fn clientFlight2Tls13(h: *Handshake, c: *Client) !void {
                var buffer = h.buffer;
                const client_finished = h.transcript.clientFinished13Msg(h.cipher_suite_tag);
                const msg = h.cipher.encrypt(buffer[6..], 0, .handshake, client_finished);
                buffer[0..6].* = consts.recordHeader(.change_cipher_spec, 1) ++ [1]u8{0x01};
                try c.stream.writeAll(buffer[0 .. 6 + msg.len]);
            }
        };
    };
}

const testing = std.testing;
const example = @import("testdata/example.zig");
const bytesToHex = std.fmt.bytesToHex;
const hexToBytes = std.fmt.hexToBytes;

test "Handshake.serverHello" {
    const stream = TestStream.init(&example.server_hello_responses, "");
    var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
    var h = try ClientT(TestStream).Handshake.init(&buffer);
    var reader = recordReader(stream);
    // Set to known instead of random
    h.client_random = example.client_random;
    h.dh_kp.x25519_kp.secret_key = example.client_secret;

    // Parse server hello, certificate and key exchange messages.
    // Read cipher suite, named group, signature scheme, server random certificate public key
    // Verify host name, signature
    // Calculate key material
    try h.serverFlight1(&reader, null, "example.ulfheim.net");
    try testing.expectEqual(.ECDHE_RSA_WITH_AES_128_CBC_SHA, h.cipher_suite_tag);
    try testing.expectEqual(.x25519, h.named_group.?);
    try testing.expectEqual(.rsa_pkcs1_sha256, h.signature_scheme);
    try testing.expectEqualSlices(u8, &example.server_random, &h.server_random);
    try testing.expectEqualSlices(u8, &example.server_pub_key, h.server_pub_key);
    try testing.expectEqualSlices(u8, &example.signature, h.signature);
    try testing.expectEqualSlices(u8, &example.cert_pub_key, h.cert_pub_key);

    try h.verifySignature12();
    try h.generateKeyMaterial();

    try testing.expectEqualSlices(u8, &example.key_material, h.key_material);
}

test "Client encrypt decrypt" {
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);

    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&example.server_pong, &output_buf);
    var c = client(stream);
    c.cipher = try Cipher.init12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &example.key_material, rnd);

    c.stream.output.reset();
    { // encrypt verify data from example
        c.client_sequence = 0; //
        test_rnd.idx = 0x40; // sets iv to 40, 41, ... 4f
        try c.write_(.handshake, &example.client_finished);
        try testing.expectEqualSlices(u8, &example.verify_data_encrypted_msg, c.stream.output.getWritten());
    }

    c.stream.output.reset();
    { // encrypt ping
        const cleartext = "ping";
        test_rnd.idx = 0; // sets iv to 00, 01, ... 0f
        c.client_sequence = 1;

        try c.write(cleartext);
        try testing.expectEqualSlices(u8, &example.encrypted_ping_msg, c.stream.output.getWritten());
    }
    { // descrypt server pong message
        c.server_sequence = 1;
        try testing.expectEqualStrings("pong", (try c.next()).?);
    }
}

test "Handshake.verifyData" {
    var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
    var h = try ClientT(TestStream).Handshake.init(&buffer);
    h.cipher_suite_tag = .ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    h.master_secret = example.master_secret;

    // add handshake messages to the transcript
    for (example.handshake_messages) |msg| {
        h.transcript.update(msg[tls.record_header_len..]);
    }

    // expect verify data
    const client_finished = h.transcript.clientFinished(h.cipher_suite_tag, &h.master_secret);
    try testing.expectEqualSlices(u8, &example.client_finished, &client_finished);

    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&example.server_handshake_finished_msgs, &output_buf);
    // init client with prepared key_material
    var c = client(stream);
    c.cipher = try Cipher.init12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &example.key_material, random);

    // check that server verify data matches calculates from hashes of all handshake messages
    h.transcript.update(&example.client_finished);
    try h.serverFlight2(&c);
}

const TestStream = struct {
    output: std.io.FixedBufferStream([]u8) = undefined,
    input: std.io.FixedBufferStream([]const u8) = undefined,

    pub fn init(input: []const u8, output: []u8) TestStream {
        return .{
            .input = std.io.fixedBufferStream(input),
            .output = std.io.fixedBufferStream(output),
        };
    }

    pub fn writeAll(self: *TestStream, buf: []const u8) !void {
        try self.output.writer().writeAll(buf);
    }

    pub fn read(self: *TestStream, buffer: []u8) !usize {
        return self.input.read(buffer);
    }
};

// To have predictable random numbers in tests
const TestRnd = struct {
    idx: u8 = 0,

    // returns 0,1,2..0xff,0,1...
    pub fn fillFn(self: *@This(), buf: []u8) void {
        for (buf) |*v| {
            v.* = self.idx;
            self.idx +%= 1;
        }
    }
};

const Record = struct {
    content_type: tls.ContentType,
    protocol_version: tls.ProtocolVersion = @enumFromInt(0x0000),
    header: []u8 = "",
    payload: []u8,
    idx: usize = 0,

    pub fn decode(r: *Record, comptime T: type) !T {
        switch (@typeInfo(T)) {
            .Int => |info| switch (info.bits) {
                8 => {
                    try skip(r, 1);
                    return r.payload[r.idx - 1];
                },
                16 => {
                    try skip(r, 2);
                    const b0: u16 = r.payload[r.idx - 2];
                    const b1: u16 = r.payload[r.idx - 1];
                    return (b0 << 8) | b1;
                },
                24 => {
                    try skip(r, 3);
                    const b0: u24 = r.payload[r.idx - 3];
                    const b1: u24 = r.payload[r.idx - 2];
                    const b2: u24 = r.payload[r.idx - 1];
                    return (b0 << 16) | (b1 << 8) | b2;
                },
                else => @compileError("unsupported int type: " ++ @typeName(T)),
            },
            .Enum => |info| {
                const int = try r.decode(info.tag_type);
                if (info.is_exhaustive) @compileError("exhaustive enum cannot be used");
                return @as(T, @enumFromInt(int));
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }

    pub fn array(r: *Record, comptime len: usize) !*[len]u8 {
        try r.skip(len);
        return r.payload[r.idx - len ..][0..len];
    }

    pub fn slice(r: *Record, len: usize) ![]u8 {
        try r.skip(len);
        return r.payload[r.idx - len ..][0..len];
    }

    pub fn skip(r: *Record, amt: usize) !void {
        if (r.idx + amt > r.payload.len) return error.TlsDecodeError;
        r.idx += amt;
    }

    pub fn rest(r: Record) []u8 {
        return r.payload[r.idx..];
    }

    pub fn eof(r: Record) bool {
        return r.idx == r.payload.len;
    }

    pub fn expectContentType(rec: *Record, content_type: tls.ContentType) !void {
        if (rec.content_type == content_type) return;

        switch (rec.content_type) {
            .alert => {
                const level = try rec.decode(tls.AlertLevel);
                const desc = try rec.decode(tls.AlertDescription);
                _ = level;
                try desc.toError();
                return error.TlsServerSideClosure;
            },
            else => return error.TlsUnexpectedMessage,
        }
    }
};

fn RecordReader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,

        buffer: [tls.max_ciphertext_record_len]u8 = undefined,
        start: usize = 0,
        end: usize = 0,

        const Self = @This();

        pub fn next(c: *Self) !?Record {
            while (true) {
                const buffer = c.buffer[c.start..c.end];
                // If we have 5 bytes header.
                if (buffer.len >= tls.record_header_len) {
                    const record_header = buffer[0..tls.record_header_len];
                    const content_type: tls.ContentType = @enumFromInt(record_header[0]);
                    const protocol_version: tls.ProtocolVersion = @enumFromInt(mem.readInt(u16, record_header[1..3], .big));
                    const payload_len = mem.readInt(u16, record_header[3..5], .big);
                    if (payload_len > tls.max_ciphertext_len)
                        return error.TlsRecordOverflow;
                    // If we have whole record
                    if (buffer[tls.record_header_len..].len >= payload_len) {
                        const payload = buffer[tls.record_header_len .. tls.record_header_len + payload_len];
                        c.start += tls.record_header_len + payload_len;
                        return .{
                            .header = record_header,
                            .content_type = content_type,
                            .protocol_version = protocol_version,
                            .payload = payload,
                        };
                    }
                }
                { // Move dirty part to the start of the buffer.
                    const n = c.end - c.start;
                    if (n > 0 and c.start > 0) {
                        if (c.start > n) {
                            @memcpy(c.buffer[0..n], c.buffer[c.start..][0..n]);
                        } else {
                            mem.copyForwards(u8, c.buffer[0..n], c.buffer[c.start..][0..n]);
                        }
                    }
                    c.start = 0;
                    c.end = n;
                }
                { // Read more from inner_reader.
                    const n = try c.inner_reader.read(c.buffer[c.end..]);
                    if (n == 0) return null;
                    c.end += n;
                }
            }
        }
    };
}

pub fn recordReader(reader: anytype) RecordReader(@TypeOf(reader)) {
    return .{ .inner_reader = reader };
}

test "RecordReader" {
    var fbs = std.io.fixedBufferStream(&example.server_responses);
    var rdr = recordReader(fbs.reader());

    const expected = [_]struct {
        content_type: tls.ContentType,
        payload_len: usize,
    }{
        .{ .content_type = .handshake, .payload_len = 49 },
        .{ .content_type = .handshake, .payload_len = 815 },
        .{ .content_type = .handshake, .payload_len = 300 },
        .{ .content_type = .handshake, .payload_len = 4 },
        .{ .content_type = .change_cipher_spec, .payload_len = 1 },
        .{ .content_type = .handshake, .payload_len = 64 },
    };
    var i: usize = 0;
    while (try rdr.next()) |rec| {
        const e = expected[i];
        i += 1;
        try testing.expectEqual(e.content_type, rec.content_type);
        try testing.expectEqual(e.payload_len, rec.payload.len);
        try testing.expectEqual(.tls_1_2, rec.protocol_version);
    }
}

test "Record decoder" {
    var fbs = std.io.fixedBufferStream(&example.server_responses);
    var rdr = recordReader(fbs.reader());

    var rec = (try rdr.next()).?;
    try testing.expectEqual(.handshake, rec.content_type);

    try testing.expectEqual(.server_hello, try rec.decode(consts.HandshakeType));
    try testing.expectEqual(45, try rec.decode(u24)); // length
    try testing.expectEqual(.tls_1_2, try rec.decode(tls.ProtocolVersion));
    try testing.expectEqualStrings(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        &bytesToHex(try rec.array(32), .lower),
    ); // server random
    try testing.expectEqual(0, try rec.decode(u8)); // session id len
    try testing.expectEqual(.ECDHE_RSA_WITH_AES_128_CBC_SHA, try rec.decode(CipherSuite));
    try testing.expectEqual(0, try rec.decode(u8)); // compression method
    try testing.expectEqual(5, try rec.decode(u16)); // extension length
    try testing.expectEqual(5, rec.rest().len);
    try rec.skip(5);
    try testing.expect(rec.eof());
}

fn bufPrint(var_name: []const u8, buf: []const u8) void {
    std.debug.print("\nconst {s} = [_]u8{{\n", .{var_name});
    for (buf, 1..) |b, i| {
        std.debug.print("0x{x:0>2}, ", .{b});
        if (i % 16 == 0)
            std.debug.print("\n", .{});
    }
    std.debug.print("}};\n", .{});

    // std.debug.print("const {s} = \"", .{var_name});
    // const charset = "0123456789abcdef";
    // for (buf) |b| {
    //     const x = charset[b >> 4];
    //     const y = charset[b & 15];
    //     std.debug.print("\\x{c}{c}", .{ x, y });
    // }
    // std.debug.print("\"\n", .{});
}

test "verify google.com certificate" {
    const stream = TestStream.init(@embedFile("testdata/google.com/server_hello"), "");
    var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
    var h = try ClientT(TestStream).Handshake.init(&buffer);
    h.now_sec = 1714846451;
    h.client_random = @embedFile("testdata/google.com/client_random").*;

    var rdr = recordReader(stream);

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(testing.allocator);
    defer ca_bundle.deinit(testing.allocator);

    try h.serverFlight1(&rdr, ca_bundle, "google.com");
    try h.verifySignature12();
}

fn dupe(buf: []u8, data: []const u8) ![]u8 {
    if (data.len > buf.len) return error.BufferOverflow;
    @memcpy(buf[0..data.len], data);
    return buf[0..data.len];
}

const BufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn write(self: *BufWriter, data: []const u8) !void {
        defer self.pos += data.len;
        _ = try dupe(self.buf[self.pos..], data);
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

    pub fn getWritten(self: *BufWriter) []const u8 {
        return self.buf[0..self.pos];
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
        try self.write(&consts.serverNameExtensionHeader(@intCast(host.len)));
        try self.write(host);
    }
};

test "BufWriter" {
    var buf: [16]u8 = undefined;
    var w = BufWriter{ .buf = &buf };

    try w.write("ab");
    try w.writeEnum(consts.CurveType.named_curve);
    try w.writeEnum(tls.NamedGroup.x25519);
    try w.writeInt(@as(u16, 0x1234));
    try testing.expectEqualSlices(u8, &[_]u8{ 'a', 'b', 0x03, 0x00, 0x1d, 0x12, 0x34 }, w.getWritten());
}

const DhKeyPair = struct {
    x25519_kp: X25519.KeyPair = undefined,
    secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
    secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
    kyber768_kp: Kyber768.KeyPair = undefined,

    const seed_len = 64;

    fn init(seed: [seed_len]u8) !DhKeyPair {
        return .{
            .x25519_kp = try X25519.KeyPair.create(seed[0..X25519.seed_length].*),
            .secp256r1_kp = try EcdsaP256Sha256.KeyPair.create(seed[0..EcdsaP256Sha256.KeyPair.seed_length].*),
            .secp384r1_kp = try EcdsaP384Sha384.KeyPair.create(seed[0..EcdsaP384Sha384.KeyPair.seed_length].*),
            .kyber768_kp = try Kyber768.KeyPair.create(seed),
        };
    }

    inline fn preMasterSecret(self: DhKeyPair, named_group: tls.NamedGroup, server_pub_key: []const u8) ![]const u8 {
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

    // Returns 32, 65 or 97 bytes
    inline fn publicKey(self: DhKeyPair, named_group: tls.NamedGroup) ![]const u8 {
        return switch (named_group) {
            .x25519 => &self.x25519_kp.public_key,
            .secp256r1 => &self.secp256r1_kp.public_key.toUncompressedSec1(),
            .secp384r1 => &self.secp384r1_kp.public_key.toUncompressedSec1(),
            .x25519_kyber768d00 => &self.x25519_kp.public_key ++ self.kyber768_kp.public_key.toBytes(),
            else => return error.TlsIllegalParameter,
        };
    }
};

const RsaKeyPair = struct {
    pre_master_secret: [48]u8,

    fn init(rand: [46]u8) RsaKeyPair {
        return .{ .pre_master_secret = consts.hello.protocol_version ++ rand };
    }

    inline fn publicKey(
        self: RsaKeyPair,
        cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo,
        cert_pub_key: []const u8,
    ) ![]const u8 {
        if (cert_pub_key_algo != .rsaEncryption)
            return error.TlsBadSignatureScheme;

        const pk = try rsa.PublicKey.parseDer(cert_pub_key);
        switch (pk.modulus.len) {
            inline 128, 256, 512 => |modulus_len| {
                const msg_len = self.pre_master_secret.len;
                const pad_len = modulus_len - msg_len - 3;
                const padded_msg: [modulus_len]u8 =
                    [2]u8{ 0, 2 } ++
                    ([1]u8{0xff} ** pad_len) ++
                    [1]u8{0} ++
                    self.pre_master_secret;

                const key = try rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
                return &(try rsaEncrypt(modulus_len, padded_msg, key));
            },
            else => {
                return error.TlsBadRsaSignatureBitCount;
            },
        }
    }
};

test "RsaKeyPair" {
    var buf: [48 + 270 + 256]u8 = undefined;

    const seed = try hexToBytes(&buf, "23bc6aea3bf218e0154835af87536c8078b3cb9ed7be55579b6c55b36a503090584936ee572afeb19fd16ad333e4");
    const cert_pub_key = try hexToBytes(buf[46..], "3082010a0282010100893b748b32b7dee524a8e0add60d84265eb39b0221f99d1a2bf6011707de90bdadccae76b8ed2e7da1d565b573e9aeb3c316a6d5178ce26b2b4085a2e7bdf9f8372935f06407a183dcda00ba28ed9117093c49a306fb2e1ff4798562eb9a08eb7d70557a11c68b446a0e6f4aee9224886e5bdb07c00c02f3e5428d59f8bd2c79ea53e3e60e1331627f294f5185e7344bb27158fa1494c749cce9d9dafc4550189934e839904ef43252acfd670556e513721658b632cef88a05d825ad5aad83989f973cdad7e9362e465c3930a9fbfa9b245fffbdb6c75856b2457854b5848c79b7a4de6022290a56a0890732c12437c3dbed18004ab4754505b1554c254f66410203010001");
    const expected_key = try hexToBytes(buf[46 + 270 ..], "495fd4a3ff7b2bf5eb6c316b488559142c2678d3204df4408e9a6ccb0680a52739fc766136e6da92e17941c35e1e02150bfcf7830fe0a1443772bf88ca22b614e5d4df122a3e615e6d409bf4702d34effb0bba9f801b3a795f1ff88e483eaa2968a8f7d1fbddee0ac0ecb88c615b5787fd5daa2180ad9791df87dd7d589884414ebe02576bc136f1aa0d866951a29161d80a3339c92300f37c822c6d303919dc9776fa91c7de45d7b0092014b2e0f678daa81fae1530c90b1ef15eecb3aba2b285ba725a623b083aa70ada7adfebbfcbf8472a3cdd9337b92770e33c86f6180591a4f26db6822c95bc5cf379c9fcb3895561e60bf5be02845b96a3e3867c168b");

    var rsa_kp = RsaKeyPair.init(seed[0..46].*);
    try testing.expectEqualSlices(
        u8,
        expected_key,
        try rsa_kp.publicKey(.{ .rsaEncryption = {} }, cert_pub_key),
    );
}

test "DhKeyPair.x25519" {
    var buf: [48 + 32 + 32]u8 = undefined;
    const seed = try hexToBytes(&buf, "4f27a0ea9873d11f3330b88f9443811a5f79c2339dc90dc560b5b49d5e7fe73e496c893a4bbaf26f3288432c747d8b2b00000000000000000000000000000000");
    const server_pub_key = try hexToBytes(buf[48..], "3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = try hexToBytes(buf[48 + 32 ..], "f8912817eb835341f70960290b550329968fea80445853bb91de2ab13ad91c15");

    const kp = try DhKeyPair.init(seed[0..64].*);
    try testing.expectEqualSlices(u8, expected, try kp.preMasterSecret(.x25519, server_pub_key));
}

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

            if (!mem.eql(u8, &em, &em_dec)) {
                return error.CertificateSignatureInvalid;
            }
        },
        else => {
            return error.CertificateSignatureUnsupportedBitCount;
        },
    }
}

const example13 = @import("testdata/example13.zig");

test "tls13 server hello" {
    var fbs = std.io.fixedBufferStream(&example13.server_hello);
    var rdr = recordReader(fbs.reader());
    var rec = (try rdr.next()).?;

    const handshake_type = try rec.decode(consts.HandshakeType);
    const length = try rec.decode(u24);
    try testing.expectEqual(0x000076, length);
    try testing.expectEqual(.server_hello, handshake_type);

    var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
    var h = try ClientT(TestStream).Handshake.init(&buffer);
    try h.serverHello(&rec, length);

    try testing.expectEqual(.AES_256_GCM_SHA384, h.cipher_suite_tag);
    try testing.expectEqualSlices(u8, &example13.server_random, &h.server_random);
    try testing.expectEqual(.tls_1_3, h.tls_version);
    try testing.expectEqual(.x25519, h.named_group);
    try testing.expectEqualSlices(u8, &example13.server_pub_key, h.server_pub_key);
}

test "tls13 handshake cipher" {
    const cipher_suite_tag: CipherSuite = .AES_256_GCM_SHA384;

    var transcript = Transcript{};
    transcript.update(example13.client_hello[tls.record_header_len..]);
    transcript.update(example13.server_hello[tls.record_header_len..]);

    var dh_kp = DhKeyPair{
        .x25519_kp = .{
            .public_key = example13.client_public_key,
            .secret_key = example13.client_private_key,
        },
    };
    const shared_key = try dh_kp.preMasterSecret(.x25519, &example13.server_pub_key);
    try testing.expectEqualSlices(u8, &example13.shared_key, shared_key);

    const cipher = try Cipher.initHandshake(cipher_suite_tag, shared_key, &transcript);

    const c = &cipher.AES_256_GCM_SHA384;
    try testing.expectEqualSlices(u8, &example13.server_handshake_key, &c.server_key);
    try testing.expectEqualSlices(u8, &example13.client_handshake_key, &c.client_key);
    try testing.expectEqualSlices(u8, &example13.server_handshake_iv, &c.server_iv);
    try testing.expectEqualSlices(u8, &example13.client_handshake_iv, &c.client_iv);
}

fn exampleHandshakeCipher() !Cipher {
    const cipher_suite_tag: CipherSuite = .AES_256_GCM_SHA384;
    var transcript = Transcript{};
    transcript.update(example13.client_hello[tls.record_header_len..]);
    transcript.update(example13.server_hello[tls.record_header_len..]);
    return try Cipher.initHandshake(cipher_suite_tag, &example13.shared_key, &transcript);
}

fn initExampleHandshake(h: *ClientT(TestStream).Handshake) !void {
    h.cipher_suite_tag = .AES_256_GCM_SHA384;
    h.transcript.update(example13.client_hello[tls.record_header_len..]);
    h.transcript.update(example13.server_hello[tls.record_header_len..]);
    h.cipher = try Cipher.initHandshake(h.cipher_suite_tag, &example13.shared_key, &h.transcript);
    h.tls_version = .tls_1_3;
    h.now_sec = 1714846451;
    h.server_pub_key = &example13.server_pub_key;
}

test "tls13 decrypt wrapped record" {
    var cipher = brk: {
        var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
        var h = try ClientT(TestStream).Handshake.init(&buffer);
        try initExampleHandshake(&h);
        break :brk h.cipher;
    };

    var buffer: [1024]u8 = undefined;
    {
        const record_header = example13.server_encrypted_extensions_wrapped[0..tls.record_header_len];
        const payload = example13.server_encrypted_extensions_wrapped[tls.record_header_len..];
        const sequence: u64 = 0;

        const content_type, const cleartext = try cipher.decrypt(&buffer, sequence, record_header, payload);
        try testing.expectEqual(.handshake, content_type);
        try testing.expectEqualSlices(u8, &example13.server_encrypted_extensions, cleartext);
    }
    {
        const record_header = example13.server_certificate_wrapped[0..tls.record_header_len];
        const payload = example13.server_certificate_wrapped[tls.record_header_len..];
        const sequence: u64 = 1;
        const content_type, const cleartext = try cipher.decrypt(&buffer, sequence, record_header, payload);
        try testing.expectEqual(.handshake, content_type);
        try testing.expectEqualSlices(u8, &example13.server_certificate, cleartext);
    }
}

test "tls13 process server flight" {
    const stream = TestStream.init(&example13.server_flight, "");
    var reader = recordReader(stream);
    var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
    var h = try ClientT(TestStream).Handshake.init(&buffer);
    try initExampleHandshake(&h);
    try h.serverFlightTls13(&reader, null, "example.ulfheim.net");

    { // application cipher keys calculation
        try testing.expectEqualSlices(u8, &example13.handshake_hash, &h.transcript.sha384.hash.peek());

        const cipher = try Cipher.initApplication(h.cipher_suite_tag, &h.transcript);
        const c = &cipher.AES_256_GCM_SHA384;
        try testing.expectEqualSlices(u8, &example13.server_application_key, &c.server_key);
        try testing.expectEqualSlices(u8, &example13.client_application_key, &c.client_key);
        try testing.expectEqualSlices(u8, &example13.server_application_iv, &c.server_iv);
        try testing.expectEqualSlices(u8, &example13.client_application_iv, &c.client_iv);

        const encrypted = cipher.encrypt(&buffer, 0, .application_data, "ping");
        try testing.expectEqualSlices(u8, &example13.client_ping_wrapped, encrypted);
    }
    { // client finished message
        const client_finished = h.transcript.clientFinished13Msg(.AES_256_GCM_SHA384);
        try testing.expectEqualSlices(u8, &example13.client_finished_verify_data, client_finished[4..]);

        const encrypted = h.cipher.encrypt(&buffer, 0, .handshake, client_finished);
        try testing.expectEqualSlices(u8, &example13.client_finished_wrapped, encrypted);
    }
}

const test_random = std.Random{ .ptr = undefined, .fillFn = randomFillFn };
pub fn randomFillFn(_: *anyopaque, buf: []u8) void {
    var idx: u8 = 0;
    for (buf) |*v| {
        v.* = idx;
        idx +%= 1;
    }
}

test "client hello" {
    random = test_random;

    var output: [2048]u8 = undefined;
    var stream = TestStream.init("", &output);
    var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
    var h = try ClientT(TestStream).Handshake.init(&buffer);
    try h.clientHello("google.com", &stream, .{
        //.cipher_suites = &[_]CipherSuite{CipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
        //.disable_keyber = true,
    });

    //bufPrint("expected_hello", stream.output.getWritten());
    try testing.expectEqualSlices(u8, &expected_hello_all, stream.output.getWritten());
}

const expected_hello = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0x7e, 0x01, 0x00, 0x00, 0x7a, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0xc0, 0x2b,
    0x01, 0x00, 0x00, 0x4f, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03, 0x00, 0x0b, 0x00, 0x02, 0x01,
    0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
    0x04, 0x03, 0x05, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07, 0x02, 0x01, 0x04, 0x01,
    0x05, 0x01, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x63, 0x99,
    0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d,
};

const expected_hello_all = [_]u8{
    0x16, 0x03, 0x03, 0x06, 0x30, 0x01, 0x00, 0x06, 0x2c, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x1a, 0xc0, 0x2f,
    0xc0, 0x2b, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x28, 0x00, 0x2f,
    0x00, 0x3c, 0x13, 0x03, 0x13, 0x02, 0x13, 0x01, 0x01, 0x00, 0x05, 0xe9, 0x00, 0x2b, 0x00, 0x05,
    0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x12, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x05, 0x03, 0x08, 0x04,
    0x08, 0x05, 0x08, 0x06, 0x08, 0x07, 0x02, 0x01, 0x04, 0x01, 0x05, 0x01, 0x00, 0x0a, 0x00, 0x0a,
    0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x63, 0x99, 0x00, 0x33, 0x05, 0x94, 0x05, 0x92,
    0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a,
    0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2,
    0xcd, 0x16, 0x62, 0x54, 0x00, 0x17, 0x00, 0x41, 0x04, 0xfc, 0xff, 0x6a, 0xfb, 0x6f, 0x70, 0xb1,
    0x67, 0x20, 0x77, 0x46, 0x66, 0x5b, 0x2f, 0x28, 0x56, 0x56, 0x28, 0x30, 0x7b, 0xc8, 0x5c, 0xfa,
    0x3a, 0x49, 0x26, 0x3b, 0xa2, 0x09, 0x5a, 0xf8, 0xb5, 0x9d, 0x57, 0xbc, 0x15, 0x35, 0x25, 0x00,
    0xb9, 0x65, 0x7e, 0xe7, 0x5d, 0xce, 0xcc, 0xfa, 0xc3, 0xc4, 0x31, 0x8c, 0xe7, 0xee, 0x82, 0xdf,
    0x9e, 0x2f, 0x64, 0xfc, 0xa3, 0x53, 0x17, 0x16, 0xc0, 0x00, 0x18, 0x00, 0x61, 0x04, 0x5f, 0x29,
    0x27, 0x3c, 0x96, 0x2c, 0x3d, 0x9b, 0x37, 0x33, 0x2b, 0xd9, 0xe8, 0xba, 0xbe, 0x86, 0x42, 0x14,
    0xb4, 0x13, 0x85, 0x31, 0x29, 0xc1, 0xe9, 0x23, 0x46, 0x22, 0x68, 0xac, 0xf4, 0x7c, 0xb3, 0x39,
    0x77, 0x13, 0x59, 0xdf, 0x14, 0xab, 0x8f, 0x53, 0xef, 0x41, 0x9f, 0x99, 0x2c, 0x1c, 0xd9, 0xdd,
    0x09, 0xc3, 0xcc, 0x8f, 0x0d, 0x6f, 0x54, 0x23, 0xcd, 0x4f, 0xf4, 0xe2, 0x37, 0xb9, 0x11, 0x6f,
    0xb0, 0x84, 0xac, 0x5b, 0xfd, 0xdf, 0x1b, 0xc0, 0x40, 0xa0, 0xe3, 0xcb, 0x2b, 0x89, 0x8b, 0x71,
    0xa9, 0x4e, 0x54, 0x2c, 0x55, 0x09, 0xf9, 0x00, 0xe7, 0xca, 0x1f, 0xcf, 0x6a, 0xc6, 0x63, 0x99,
    0x04, 0xc0, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
    0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
    0x62, 0x54, 0xdd, 0x92, 0x73, 0xce, 0xab, 0x25, 0xac, 0x31, 0x33, 0x35, 0x63, 0x48, 0xe8, 0x43,
    0x88, 0x9d, 0xcc, 0xc5, 0x90, 0x72, 0xa5, 0xec, 0x88, 0x49, 0x7c, 0xb7, 0x00, 0x9c, 0x72, 0x84,
    0xe9, 0x22, 0x6b, 0x71, 0x95, 0x29, 0xf3, 0x07, 0x0c, 0x5e, 0x06, 0xc7, 0xfe, 0x12, 0x6f, 0x41,
    0x94, 0x63, 0x5a, 0x0a, 0x29, 0x54, 0x17, 0x42, 0xd9, 0x43, 0xc3, 0x09, 0xe2, 0x7f, 0xe5, 0xfa,
    0x3c, 0xa4, 0x44, 0x23, 0x2e, 0xeb, 0xa1, 0x32, 0xf3, 0x9b, 0x86, 0x05, 0x1d, 0x46, 0x33, 0x7f,
    0x09, 0x08, 0x57, 0x40, 0xf5, 0x58, 0x1a, 0x56, 0x41, 0x2c, 0x68, 0x92, 0x9b, 0x0b, 0x2d, 0x39,
    0xb3, 0xc7, 0x90, 0x0a, 0x99, 0x78, 0x67, 0x29, 0x21, 0x34, 0x32, 0x50, 0x24, 0x01, 0x9e, 0x20,
    0x62, 0x61, 0x00, 0x60, 0x6c, 0x02, 0xc4, 0xb6, 0xeb, 0x11, 0x62, 0x10, 0x15, 0x08, 0xeb, 0x69,
    0x80, 0x87, 0x46, 0x38, 0xbc, 0x8e, 0xd9, 0x4a, 0x73, 0x35, 0xb0, 0x50, 0xbb, 0xb1, 0x79, 0xc1,
    0xe6, 0x3c, 0x38, 0x70, 0x48, 0x14, 0x64, 0x5a, 0x5c, 0x7c, 0xb8, 0xc4, 0x50, 0xa9, 0xe2, 0x12,
    0x9a, 0x20, 0xba, 0x30, 0x30, 0x68, 0x33, 0xc6, 0xb5, 0x28, 0xff, 0x84, 0x0e, 0x41, 0xfb, 0x7b,
    0x24, 0xfc, 0x3f, 0xc0, 0xb1, 0xa9, 0x70, 0x40, 0x53, 0x9e, 0x8c, 0x5d, 0x39, 0xc0, 0x22, 0x1b,
    0xa1, 0x3c, 0x20, 0x1c, 0x2e, 0x06, 0x88, 0xaa, 0xdd, 0x75, 0x46, 0xbc, 0x92, 0x42, 0xf6, 0x05,
    0x07, 0xbe, 0x84, 0xca, 0xc7, 0x52, 0x12, 0x1f, 0x0b, 0x23, 0x08, 0x03, 0x85, 0x03, 0x94, 0x4d,
    0xa9, 0x44, 0xbb, 0x63, 0xcb, 0x10, 0xc3, 0x43, 0xb7, 0x87, 0x45, 0x62, 0x6f, 0x34, 0x02, 0xf1,
    0x33, 0x60, 0x6f, 0x98, 0xbd, 0xcf, 0x4a, 0x54, 0x72, 0xd6, 0xcc, 0xa8, 0xe9, 0x56, 0x2b, 0x22,
    0x5f, 0x37, 0xc6, 0x33, 0x83, 0x6c, 0x50, 0x59, 0x8b, 0x65, 0x82, 0x65, 0xa5, 0xa6, 0xe5, 0xaa,
    0x1e, 0x55, 0x89, 0x15, 0xac, 0x50, 0x19, 0x16, 0x3e, 0x82, 0x85, 0x1a, 0xdb, 0xa0, 0xba, 0x48,
    0x98, 0x54, 0xbd, 0x66, 0xb3, 0xe6, 0x06, 0x5f, 0x47, 0x19, 0x60, 0xd3, 0x9c, 0xcd, 0x8a, 0x45,
    0x69, 0xb8, 0x96, 0xa9, 0x1f, 0xd0, 0x7a, 0x84, 0x19, 0xcb, 0x9a, 0x80, 0xb4, 0xf3, 0x91, 0xb2,
    0x38, 0xac, 0xae, 0x07, 0xbc, 0x79, 0x71, 0x43, 0xb9, 0x15, 0xe9, 0x32, 0xf1, 0x83, 0xc8, 0xb1,
    0x4b, 0x43, 0xe2, 0x06, 0x3e, 0x7c, 0x12, 0x8d, 0xa3, 0x72, 0x5a, 0xe5, 0xe6, 0x10, 0xad, 0xb3,
    0xa3, 0x6b, 0xea, 0x43, 0xd6, 0x26, 0x55, 0x5c, 0x80, 0xb4, 0xeb, 0x20, 0x8e, 0x27, 0x49, 0x36,
    0x4c, 0x65, 0xc9, 0x6a, 0x53, 0x28, 0x6e, 0xc7, 0x43, 0x60, 0x55, 0x2e, 0xcd, 0xaa, 0x57, 0x03,
    0xe5, 0x76, 0x8c, 0xc5, 0x16, 0x76, 0xb3, 0x5a, 0x30, 0x79, 0x96, 0x8c, 0xe5, 0xad, 0x2a, 0x04,
    0x20, 0x54, 0x9a, 0x5f, 0xa5, 0x9a, 0xae, 0xba, 0x58, 0xc5, 0x68, 0x57, 0x8c, 0xda, 0x48, 0x60,
    0x09, 0xcc, 0x58, 0x43, 0x21, 0xaf, 0xe0, 0xb9, 0x69, 0x33, 0x71, 0xcd, 0x13, 0xe1, 0xa9, 0x77,
    0xe3, 0xc2, 0xf7, 0xd1, 0x15, 0x80, 0x39, 0x21, 0xa1, 0x35, 0x67, 0xa9, 0xd8, 0x69, 0xc7, 0xb4,
    0x16, 0x52, 0xb2, 0x0f, 0x58, 0x1c, 0x6e, 0x33, 0x77, 0x7f, 0x26, 0xc0, 0xac, 0xaa, 0x9b, 0x65,
    0x44, 0x75, 0x63, 0xa9, 0x38, 0x24, 0x08, 0xe2, 0xa1, 0xda, 0x64, 0x4a, 0x7b, 0x74, 0x3c, 0xcc,
    0x38, 0x82, 0x2f, 0xf3, 0x30, 0x9c, 0x3c, 0x65, 0x95, 0xd2, 0x4f, 0x06, 0x83, 0x62, 0xca, 0x34,
    0x0e, 0x9d, 0x12, 0xa4, 0xd6, 0xd2, 0x94, 0x91, 0x3c, 0x51, 0x92, 0xea, 0x3c, 0xef, 0x69, 0x7c,
    0xee, 0x73, 0xaa, 0x29, 0xc3, 0x44, 0xc3, 0x87, 0xc9, 0xd9, 0x29, 0x8b, 0x8d, 0xe2, 0xb4, 0xf8,
    0x55, 0x6f, 0x24, 0xbc, 0x34, 0xee, 0x29, 0x2e, 0xcf, 0x92, 0x63, 0xf6, 0x6c, 0xa7, 0x10, 0x86,
    0x7a, 0x1d, 0x20, 0x39, 0xec, 0xc8, 0xcb, 0xa2, 0x98, 0x57, 0x6a, 0x01, 0x6c, 0x4c, 0xd4, 0xae,
    0xd6, 0x0b, 0xa3, 0x14, 0x02, 0xbf, 0xb5, 0x12, 0xc8, 0x15, 0x61, 0xc6, 0x43, 0xf3, 0xa3, 0x79,
    0x46, 0xa7, 0x31, 0x00, 0x3c, 0xb0, 0xb5, 0x65, 0xe6, 0xf1, 0x25, 0xbd, 0x8c, 0x94, 0xe9, 0xe5,
    0xb8, 0xa5, 0x69, 0xc8, 0x27, 0x7b, 0x17, 0x5e, 0x35, 0x08, 0xd7, 0xe7, 0x1c, 0x1a, 0x6b, 0x9f,
    0xdc, 0x80, 0x87, 0xae, 0xf8, 0x83, 0x05, 0x6c, 0xa9, 0x08, 0xf1, 0x80, 0x14, 0xd6, 0x73, 0xc0,
    0xb0, 0x24, 0xfc, 0x3a, 0x43, 0xab, 0x67, 0x5e, 0x59, 0xc1, 0x22, 0xbf, 0xd0, 0x4a, 0x4f, 0x85,
    0x4a, 0x89, 0x43, 0xad, 0xb2, 0x71, 0x30, 0xc4, 0x66, 0x17, 0x2e, 0x42, 0x47, 0xfe, 0x1a, 0xc9,
    0xb6, 0xc6, 0x92, 0xcd, 0x69, 0x9d, 0xb8, 0x4a, 0x9a, 0xad, 0xdc, 0xb4, 0x5b, 0xcb, 0x8e, 0xf3,
    0xd9, 0x28, 0xcb, 0x28, 0x3d, 0xe8, 0x73, 0xc7, 0x24, 0x67, 0x2e, 0x31, 0x7c, 0x11, 0x60, 0x6c,
    0xa6, 0x83, 0xdc, 0xc8, 0x57, 0x7a, 0x7d, 0x5d, 0x64, 0x5b, 0x30, 0x92, 0xa6, 0xe3, 0x97, 0x22,
    0x5c, 0x83, 0x93, 0x3b, 0xd5, 0x45, 0x1c, 0xf4, 0x2a, 0x4a, 0xc3, 0xa5, 0xa0, 0x59, 0x8e, 0x50,
    0x63, 0x80, 0x54, 0x7c, 0x75, 0x83, 0xe7, 0xb4, 0x89, 0xe9, 0x56, 0xc3, 0xe4, 0x13, 0xb7, 0xb2,
    0xb7, 0xca, 0x59, 0x4a, 0x4b, 0x76, 0x88, 0xf2, 0xf9, 0x6c, 0x2b, 0xe3, 0x33, 0x7e, 0x30, 0x28,
    0x09, 0xe8, 0x50, 0x15, 0xb0, 0xc6, 0xfb, 0xb0, 0x9a, 0xec, 0xc2, 0x60, 0xb3, 0x4a, 0xab, 0x1f,
    0x23, 0x52, 0xb3, 0x92, 0x1c, 0x2c, 0x17, 0x4c, 0xf9, 0x86, 0x71, 0xfb, 0xf4, 0x9c, 0x26, 0x06,
    0xc9, 0xe4, 0x50, 0x43, 0x9c, 0x04, 0x68, 0xa3, 0xf7, 0x2b, 0x93, 0x39, 0x4a, 0x9f, 0xd5, 0xc4,
    0xd5, 0xe1, 0xc1, 0xa6, 0xb8, 0x5d, 0x61, 0x04, 0x8f, 0x60, 0x20, 0x9e, 0x7f, 0xe0, 0x56, 0x7c,
    0xe6, 0xcc, 0x20, 0x91, 0x56, 0x8a, 0x2c, 0x36, 0x41, 0x90, 0x6a, 0x0a, 0x63, 0x8c, 0xcd, 0x10,
    0x64, 0x74, 0x32, 0x31, 0x4e, 0x00, 0x60, 0x53, 0x65, 0x89, 0x74, 0xaa, 0x10, 0x34, 0xa6, 0xb4,
    0x17, 0x10, 0x91, 0xaf, 0x16, 0x34, 0x9a, 0x08, 0xa4, 0x51, 0x0c, 0xbe, 0x8e, 0x56, 0x99, 0xe1,
    0x46, 0xc5, 0xa4, 0x0c, 0xcb, 0x9c, 0x15, 0x66, 0xb8, 0x61, 0x74, 0x4c, 0x92, 0xab, 0x0f, 0x53,
    0xba, 0x5e, 0x2b, 0xb4, 0x01, 0xa8, 0xba, 0x06, 0x45, 0x26, 0xa4, 0x7a, 0xc1, 0x78, 0x29, 0x19,
    0x0a, 0x66, 0x18, 0xf9, 0x02, 0x14, 0x4e, 0xca, 0xa6, 0x36, 0x7b, 0x09, 0xa6, 0x63, 0x1e, 0xa6,
    0xd6, 0x19, 0x49, 0x83, 0x92, 0xb2, 0x65, 0x40, 0xb3, 0x06, 0xb6, 0x1b, 0x75, 0x16, 0xec, 0x5b,
    0x11, 0x1d, 0xca, 0xa3, 0x41, 0x27, 0xb4, 0x13, 0x5c, 0x77, 0x7d, 0x81, 0xac, 0x0d, 0x02, 0x48,
    0x33, 0x28, 0x8e, 0xac, 0x5b, 0x99, 0x60, 0xa0, 0x26, 0x07, 0x79, 0x70, 0xe1, 0x73, 0x4b, 0xc9,
    0x77, 0x67, 0xab, 0x3a, 0x53, 0x0b, 0x0c, 0xb0, 0xdf, 0x9a, 0x11, 0x73, 0x2a, 0xc2, 0xe0, 0x89,
    0x8f, 0xfd, 0x97, 0x9f, 0x05, 0x60, 0x17, 0x20, 0x02, 0x5d, 0x16, 0xe7, 0x0e, 0x90, 0xe8, 0xa6,
    0x8c, 0x20, 0x40, 0xbf, 0xa2, 0x0b, 0xe9, 0xd4, 0xb5, 0x67, 0xa4, 0x99, 0xf1, 0xe0, 0xca, 0x3c,
    0xb0, 0xc0, 0x37, 0x2a, 0x0c, 0x9c, 0x69, 0x49, 0xd8, 0xec, 0x7a, 0x6d, 0x66, 0x83, 0xa6, 0x70,
    0x88, 0x4d, 0x01, 0x8b, 0x33, 0x61, 0x25, 0x95, 0x3a, 0xcc, 0x2c, 0x35, 0x35, 0x56, 0x3b, 0x75,
    0xfd, 0x8a, 0x75, 0x56, 0x22, 0x6e, 0x23, 0x00, 0x50, 0x2f, 0xea, 0xb0, 0xd3, 0x7b, 0xc4, 0xec,
    0x16, 0x26, 0xee, 0xfa, 0x4c, 0xc5, 0x8a, 0x7c, 0xf4, 0x60, 0x5c, 0xe1, 0x10, 0x9c, 0xc6, 0xe4,
    0xb1, 0x55, 0xb9, 0x6b, 0x4b, 0x4c, 0x48, 0x48, 0x96, 0x31, 0x0c, 0x54, 0x8c, 0x96, 0x93, 0x0e,
    0xdf, 0x37, 0x6b, 0xbd, 0xa3, 0x76, 0x72, 0xc7, 0x45, 0xaa, 0x68, 0x8f, 0x24, 0xf7, 0x54, 0x18,
    0x90, 0x7e, 0x1e, 0x15, 0xc8, 0x50, 0x22, 0x3c, 0x3f, 0xfc, 0x2d, 0x40, 0xd8, 0x90, 0xba, 0x06,
    0x1e, 0x99, 0x15, 0x6c, 0x51, 0x65, 0xa0, 0x57, 0xe9, 0x0b, 0xee, 0x5b, 0x9b, 0x22, 0x69, 0x80,
    0xae, 0x52, 0xc0, 0xb5, 0xea, 0x37, 0xe7, 0xea, 0xb3, 0xe9, 0x79, 0xa7, 0xf4, 0x95, 0x83, 0xc9,
    0xa0, 0x60, 0x38, 0x8b, 0x6c, 0x2e, 0x28, 0x95, 0x48, 0xde, 0xc8, 0x61, 0xdc, 0xf2, 0x83, 0x7a,
    0xab, 0x95, 0xff, 0xdd, 0xcc, 0xa4, 0x34, 0xd9, 0x64, 0x4a, 0x1e, 0x56, 0x18, 0x40, 0xfd, 0xc8,
    0xe1, 0x1a, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
    0x65, 0x2e, 0x63, 0x6f, 0x6d,
};
