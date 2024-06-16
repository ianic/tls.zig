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
const EcdsaP256Sha384 = crypto.sign.ecdsa.Ecdsa(crypto.ecc.P256, crypto.hash.sha2.Sha384);
const Kyber768 = crypto.kem.kyber_d00.Kyber768;

const consts = @import("consts.zig");
const Cipher = @import("cipher.zig").Cipher;
pub const CipherSuite = @import("cipher.zig").CipherSuite;
const Transcript = @import("transcript.zig").Transcript;
const record = @import("record.zig");

pub fn client(stream: anytype) Client(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .reader = record.reader(stream),
    };
}

pub const ProtocolVersion = tls.ProtocolVersion;

pub const Options = struct {
    // To use just tls 1.2 cipher suites:
    //   .cipher_suites = &tls.CipherSuite.tls12,
    // To select particular cipher suite:
    //   .cipher_suites = &[_]CipherSuite{CipherSuite.CHACHA20_POLY1305_SHA256},
    cipher_suites: []const CipherSuite = &CipherSuite.all,

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
    tls_version: ProtocolVersion = @enumFromInt(0),
    cipher_suite_tag: CipherSuite = @enumFromInt(0),
    named_group: tls.NamedGroup = @enumFromInt(0),
    signature_scheme: tls.SignatureScheme = @enumFromInt(0),
};

var random = crypto.random;

pub fn Client(comptime Stream: type) type {
    const RecordReaderT = record.Reader(Stream);
    const HandshakeT = Handshake(Stream);
    return struct {
        stream: Stream,
        reader: RecordReaderT,

        cipher: Cipher = undefined,
        client_sequence: usize = 0,
        server_sequence: usize = 0,
        write_buf: [tls.max_ciphertext_record_len]u8 = undefined,

        const ClientT = @This();

        fn initHandshake(self: *ClientT) !HandshakeT {
            return try HandshakeT.init(&self.write_buf, &self.reader);
        }

        pub fn handshake(
            c: *ClientT,
            host: []const u8,
            ca_bundle: ?Certificate.Bundle,
            opt: Options,
        ) !void {
            var h = try HandshakeT.init(&c.write_buf, &c.reader);
            defer if (opt.stats) |stats| {
                // collect stats
                stats.tls_version = h.tls_version;
                stats.cipher_suite_tag = h.cipher_suite_tag;
                stats.named_group = h.named_group orelse @as(tls.NamedGroup, @enumFromInt(0x0000));
                stats.signature_scheme = h.signature_scheme;
            };

            try c.send(try h.clientHello(host, opt));
            try h.serverFlight1(ca_bundle, host);
            if (h.tls_version == .tls_1_3) { // tls 1.3 specific handshake part
                const shared_key = try h.dh_kp.preMasterSecret(h.named_group.?, h.server_pub_key);
                h.cipher = try Cipher.init13Handshake(h.cipher_suite_tag, shared_key, &h.transcript);
                try h.serverEncryptedFlight1(ca_bundle, host);
                c.cipher = try Cipher.init13Application(h.cipher_suite_tag, &h.transcript);
                try c.send(try h.clientFlight2Tls13());
            } else { // tls 1.2 specific handshake part
                try h.verifySignature12();
                try h.generateKeyMaterial();
                {
                    h.cipher = try Cipher.init12(h.cipher_suite_tag, h.key_material, random);
                    c.cipher = h.cipher;
                    c.client_sequence = 1;
                }
                try c.send(try h.clientFlight2Tls12());
                { // parse server flight 2
                    try h.serverChangeCipherSpec();
                    // Read encrypted server hadndshake finished message.
                    const content_type, const cleartext = try c.nextRecord() orelse return error.EndOfStream;
                    try h.verifyServerHandshakeFinished(content_type, cleartext);
                }
            }
        }

        /// Encrypts cleartext and writes it to the underlaying stream as single
        /// tls record. Max single tls record payload length is 1<<14 (16K)
        /// bytes.
        pub fn write(c: *ClientT, cleartext: []const u8) !usize {
            const n = @min(cleartext.len, tls.max_cipertext_inner_record_len);
            try c.writeRecord(.application_data, cleartext[0..n]);
            return n;
        }

        /// Encrypts cleartext and writes it to the underlaying stream. If needed
        /// splits cleartext into multiple tls record.
        pub fn writeAll(c: *ClientT, cleartext: []const u8) !void {
            var index: usize = 0;
            while (index < cleartext.len) {
                index += try c.write(cleartext[index..]);
            }
        }

        /// Encrypts and writes single tls record to the stream.
        fn writeRecord(c: *ClientT, content_type: tls.ContentType, cleartext: []const u8) !void {
            assert(cleartext.len <= tls.max_cipertext_inner_record_len);
            const rec = try c.encrypt(&c.write_buf, content_type, cleartext);
            try c.send(rec);
        }

        /// Writes buffer to the underlying stream.
        fn send(c: *ClientT, buffer: []const u8) !void {
            var n: usize = 0;
            while (n < buffer.len) {
                n += try c.stream.write(buffer[n..]);
            }
        }

        /// Returns next record of cleartext data.
        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try client.next()) |buf| { ... }
        pub fn next(c: *ClientT) !?[]const u8 {
            const content_type, const data = try c.nextRecord() orelse return null;
            if (content_type != .application_data) return error.TlsUnexpectedMessage;
            return data;
        }

        fn nextRecord(c: *ClientT) !?struct { tls.ContentType, []const u8 } {
            while (true) {
                const rec = (try c.reader.next()) orelse return null;
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

                const content_type, const cleartext = try c.cipher.decrypt(
                    rec.payload,
                    c.server_sequence,
                    .{
                        .header = rec.header,
                        .payload = rec.payload,
                        .content_type = rec.content_type,
                    },
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

        fn encrypt(c: *ClientT, buffer: []u8, content_type: tls.ContentType, cleartext: []const u8) ![]const u8 {
            defer c.client_sequence += 1;
            return try c.cipher.encrypt(buffer, c.client_sequence, content_type, cleartext);
        }

        pub fn close(c: *ClientT) !void {
            const msg = try c.encrypt(&c.write_buf, .alert, &consts.close_notify_alert);
            try c.send(msg);
        }
    };
}

fn Handshake(comptime Stream: type) type {
    const RecordReaderT = record.Reader(Stream);
    return struct {
        client_random: [32]u8,
        server_random: [32]u8 = undefined,
        master_secret: [48]u8 = undefined,
        key_material_buf: [48 * 4]u8 = undefined,
        key_material: []u8 = undefined,

        transcript: Transcript = .{},
        cipher_suite_tag: CipherSuite = @enumFromInt(0),
        named_group: ?tls.NamedGroup = null,
        dh_kp: DhKeyPair,
        rsa_kp: RsaKeyPair,
        signature_scheme: tls.SignatureScheme = @enumFromInt(0),
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

        reader: *RecordReaderT, // tls record reader
        buffer: []u8, // scratch buffer used in all messages creation

        const HandshakeT = @This();

        pub fn init(buf: []u8, reader: *RecordReaderT) !HandshakeT {
            var rand_buf: [32 + 64 + 46]u8 = undefined;
            random.bytes(&rand_buf);

            return .{
                .client_random = rand_buf[0..32].*,
                .dh_kp = try DhKeyPair.init(rand_buf[32..][0..64].*),
                .rsa_kp = RsaKeyPair.init(rand_buf[32 + 64 ..][0..46].*),
                .now_sec = std.time.timestamp(),
                .buffer = buf,
                .reader = reader,
            };
        }

        /// Create client hello message.
        fn clientHello(h: *HandshakeT, host: []const u8, opt: Options) ![]const u8 {
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

            const msg = buffer[0 .. header_len + payload.pos + ext.pos];
            h.transcript.update(msg[tls.record_header_len..]);
            return msg;
        }

        /// Parse server hello message.
        fn serverHello(h: *HandshakeT, d: *record.Decoder, length: u24) !void {
            if (try d.decode(tls.ProtocolVersion) != tls.ProtocolVersion.tls_1_2)
                return error.TlsBadVersion;
            h.server_random = (try d.array(32)).*;
            if (consts.isServerHelloRetryRequest(&h.server_random))
                return error.TlsServerHelloRetryRequest;

            const session_id_len = try d.decode(u8);
            if (session_id_len > 32) return error.TlsIllegalParameter;
            try d.skip(session_id_len);

            h.cipher_suite_tag = try d.decode(CipherSuite);
            try h.cipher_suite_tag.validate();
            try d.skip(1); // skip compression method

            const extensions_present = length > 2 + 32 + session_id_len + 2 + 1;
            if (extensions_present) {
                const exs_len = try d.decode(u16);
                var l: usize = 0;
                while (l < exs_len) {
                    const typ = try d.decode(tls.ExtensionType);
                    const len = try d.decode(u16);
                    defer l += len + 4;

                    switch (typ) {
                        .supported_versions => {
                            switch (try d.decode(tls.ProtocolVersion)) {
                                .tls_1_2, .tls_1_3 => |v| h.tls_version = v,
                                else => return error.TlsIllegalParameter,
                            }
                            if (len != 2) return error.TlsIllegalParameter;
                        },
                        .key_share => {
                            h.named_group = try d.decode(tls.NamedGroup);
                            h.server_pub_key = try dupe(&h.server_pub_key_buf, try d.slice(try d.decode(u16)));
                            if (len != h.server_pub_key.len + 4) return error.TlsIllegalParameter;
                        },
                        else => {
                            try d.skip(len);
                        },
                    }
                }
            }
        }

        /// Parse server certificate message.
        fn serverCertificate(h: *HandshakeT, d: *record.Decoder, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
            var trust_chain_established = false;
            var last_cert: ?Certificate.Parsed = null;
            const certs_len = try d.decode(u24);

            const start_idx = d.idx;
            while (d.idx - start_idx < certs_len) {
                const cert_len = try d.decode(u24);
                // std.debug.print("=> {} {} {} {}\n", .{ certs_len, rec.idx, cert_len, rec.payload.len });
                const cert = try d.slice(cert_len);
                if (h.tls_version == .tls_1_3) {
                    // certificate extensions present in tls 1.3
                    try d.skip(try d.decode(u16));
                }
                if (trust_chain_established)
                    continue;

                const subject = try (Certificate{ .buffer = cert, .index = 0 }).parse();
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
                        else => return err,
                    }
                }
            }
            if (ca_bundle != null and !trust_chain_established) {
                return error.CertificateIssuerNotFound;
            }
        }

        /// Parse server key exchange message.
        fn serverKeyExchange(h: *HandshakeT, d: *record.Decoder) !void {
            const curve_type = try d.decode(consts.CurveType);
            h.named_group = try d.decode(tls.NamedGroup);
            h.server_pub_key = try dupe(&h.server_pub_key_buf, try d.slice(try d.decode(u8)));
            h.signature_scheme = try d.decode(tls.SignatureScheme);
            h.signature = try dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
            if (curve_type != .named_curve) return error.TlsIllegalParameter;
        }

        /// Process first flight of the messages from the server.
        /// Read server hello message. If tls 1.3 is choosen in server hello
        /// return. For tls 1.2 continue and read certificate, key_exchange
        /// and hello done messages.
        fn serverFlight1(h: *HandshakeT, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
            var handshake_state = consts.HandshakeType.server_hello;

            while (true) {
                var d = try h.reader.nextDecoder();
                try d.expectContentType(.handshake);

                h.transcript.update(d.payload);

                // Multiple handshake messages can be packed in single tls record.
                while (!d.eof()) {
                    const handshake_type = try d.decode(consts.HandshakeType);
                    if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;

                    const length = try d.decode(u24);
                    if (length > tls.max_cipertext_inner_record_len)
                        return error.TlsUnsupportedFragmentedHandshakeMessage;

                    switch (handshake_type) {
                        .server_hello => { // server hello, ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.3
                            try h.serverHello(&d, length);
                            if (h.tls_version == .tls_1_3) {
                                if (!d.eof()) return error.TlsIllegalParameter;
                                return;
                            }
                            handshake_state = .certificate;
                        },
                        .certificate => {
                            try h.serverCertificate(&d, ca_bundle, host);
                            handshake_state = if (h.cipher_suite_tag.keyExchange() == .rsa)
                                .server_hello_done
                            else
                                .server_key_exchange;
                        },
                        .server_key_exchange => {
                            try h.serverKeyExchange(&d);
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

        /// Read encrypted part (after server hello) of the server first
        /// flight for tls 1.3: change cipher spec, certificate, certificate
        /// verify and handshake finished messages.
        fn serverEncryptedFlight1(
            h: *HandshakeT,
            ca_bundle: ?Certificate.Bundle,
            host: []const u8,
        ) !void {
            var sequence: u64 = 0;
            var cleartext_buf = h.buffer;
            var cleartext_buf_head: usize = 0;
            var cleartext_buf_tail: usize = 0;
            var handshake_state: tls.HandshakeType = .encrypted_extensions;

            outer: while (true) {
                // wrapped record decoder
                const rec = (try h.reader.next() orelse return error.EndOfStream);
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                //std.debug.print("serverFlightTls13 {} {}\n", .{ wrap_rec.content_type, wrap_rec.payload.len });
                switch (rec.content_type) {
                    .change_cipher_spec => {},
                    .application_data => {
                        const content_type, const cleartext = switch (h.cipher) {
                            inline else => |*p| try p.decrypt(
                                cleartext_buf[cleartext_buf_tail..],
                                sequence,
                                .{
                                    .header = rec.header,
                                    .payload = rec.payload,
                                    .content_type = rec.content_type,
                                },
                            ),
                        };
                        if (content_type != .handshake) return error.TlsUnexpectedMessage;
                        sequence += 1;
                        cleartext_buf_tail += cleartext.len;

                        var d = record.Decoder.init(content_type, cleartext_buf[cleartext_buf_head..cleartext_buf_tail]);
                        while (!d.eof()) {
                            const start_idx = d.idx;
                            const handshake_type = try d.decode(tls.HandshakeType);
                            const length = try d.decode(u24);

                            // std.debug.print("handshake loop: {} {} {}\n", .{ handshake_type, length, rec.payload.len });
                            if (length > tls.max_cipertext_inner_record_len)
                                return error.TlsUnsupportedFragmentedHandshakeMessage;
                            if (length > d.payload.len - 4)
                                continue :outer; // fragmented handshake into multiple records

                            defer {
                                const handshake_payload = d.payload[start_idx..d.idx];
                                h.transcript.update(handshake_payload);
                                cleartext_buf_head += handshake_payload.len;
                            }

                            if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;
                            switch (handshake_type) {
                                .encrypted_extensions => {
                                    try d.skip(length);
                                    handshake_state = .certificate;
                                },
                                .certificate => {
                                    const request_context = try d.decode(u8);
                                    if (request_context != 0) return error.TlsIllegalParameter;
                                    try h.serverCertificate(&d, ca_bundle, host);
                                    handshake_state = .certificate_verify;
                                },
                                .certificate_verify => {
                                    h.signature_scheme = try d.decode(tls.SignatureScheme);
                                    h.signature = try dupe(&h.signature_buf, try d.slice(try d.decode(u16)));
                                    try h.verifySignature(h.transcript.verifyBytes13(h.cipher_suite_tag));
                                    handshake_state = .finished;
                                },
                                .finished => {
                                    const actual = try d.slice(length);
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

        /// Create verify data and verify server singature for tls 1.2.
        fn verifySignature12(h: *HandshakeT) !void {
            if (h.cipher_suite_tag.keyExchange() != .ecdhe) return;
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

        /// Verify server signature with server public key.
        fn verifySignature(h: *HandshakeT, verify_bytes: []const u8) !void {
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
                .ecdsa_secp384r1_sha384 => switch (cert_named_curve) {
                    .X9_62_prime256v1 => EcdsaP256Sha384,
                    else => EcdsaP384Sha384,
                },
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

        /// Genereate tls 1.2 pre master secret, master secret and key material.
        fn generateKeyMaterial(h: *HandshakeT) !void {
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

        /// Creates client key exchange, change chiper spec and handshake
        /// finished messages for tls 1.2.
        fn clientFlight2Tls12(h: *HandshakeT) ![]u8 {
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
                const handshake_finished = try h.cipher.encrypt(fbs.buffer[fbs.pos..], 0, .handshake, &client_finished);
                fbs.pos += handshake_finished.len;
            }

            return fbs.getWritten();
        }

        /// Read server change cipher spec message.
        fn serverChangeCipherSpec(h: *HandshakeT) !void {
            var d = try h.reader.nextDecoder();
            try d.expectContentType(.change_cipher_spec);
        }

        /// Verify that body of server handshake finished is built from a
        /// hash of all handshake messages.
        fn verifyServerHandshakeFinished(h: *HandshakeT, content_type: tls.ContentType, cleartext: []const u8) !void {
            if (content_type != .handshake) return error.TlsUnexpectedMessage;
            const expected_server_finished = h.transcript.serverFinished(h.cipher_suite_tag, &h.master_secret);
            if (!mem.eql(u8, cleartext, &expected_server_finished))
                return error.TlsBadRecordMac;
        }

        // Create client change cipher spec and handshake finished messages
        // for tls 1.3.
        fn clientFlight2Tls13(h: *HandshakeT) ![]u8 {
            var buffer = h.buffer;
            const client_finished = h.transcript.clientFinished13Msg(h.cipher_suite_tag);
            const msg = try h.cipher.encrypt(buffer[6..], 0, .handshake, client_finished);
            buffer[0..6].* = consts.recordHeader(.change_cipher_spec, 1) ++ [1]u8{0x01};
            return buffer[0 .. 6 + msg.len];
        }
    };
}

const testing = std.testing;
const data12 = @import("testdata/tls12.zig");
const data13 = @import("testdata/tls13.zig");
const testu = @import("testu.zig");

test "Handshake.serverHello" {
    const stream = TestStream.init(&data12.server_hello_responses, "");
    var c = client(stream);
    var h = try c.initHandshake();

    // Set to known instead of random
    h.client_random = data12.client_random;
    h.dh_kp.x25519_kp.secret_key = data12.client_secret;

    // Parse server hello, certificate and key exchange messages.
    // Read cipher suite, named group, signature scheme, server random certificate public key
    // Verify host name, signature
    // Calculate key material
    try h.serverFlight1(null, "example.ulfheim.net");
    try testing.expectEqual(.ECDHE_RSA_WITH_AES_128_CBC_SHA, h.cipher_suite_tag);
    try testing.expectEqual(.x25519, h.named_group.?);
    try testing.expectEqual(.rsa_pkcs1_sha256, h.signature_scheme);
    try testing.expectEqualSlices(u8, &data12.server_random, &h.server_random);
    try testing.expectEqualSlices(u8, &data12.server_pub_key, h.server_pub_key);
    try testing.expectEqualSlices(u8, &data12.signature, h.signature);
    try testing.expectEqualSlices(u8, &data12.cert_pub_key, h.cert_pub_key);

    try h.verifySignature12();
    try h.generateKeyMaterial();

    try testing.expectEqualSlices(u8, &data12.key_material, h.key_material);
}

test "Client encrypt decrypt" {
    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&data12.server_pong, &output_buf);
    var c = client(stream);
    c.cipher = try Cipher.init12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &data12.key_material, testu.random(0));

    c.stream.output.reset();
    { // encrypt verify data from example
        c.client_sequence = 0; //
        _ = testu.random(0x40); // sets iv to 40, 41, ... 4f
        try c.writeRecord(.handshake, &data12.client_finished);
        try testing.expectEqualSlices(u8, &data12.verify_data_encrypted_msg, c.stream.output.getWritten());
    }

    c.stream.output.reset();
    { // encrypt ping
        const cleartext = "ping";
        _ = testu.random(0); // sets iv to 00, 01, ... 0f
        c.client_sequence = 1;

        try c.writeAll(cleartext);
        try testing.expectEqualSlices(u8, &data12.encrypted_ping_msg, c.stream.output.getWritten());
    }
    { // descrypt server pong message
        c.server_sequence = 1;
        try testing.expectEqualStrings("pong", (try c.next()).?);
    }
}

test "Handshake.verifyData" {
    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&data12.server_handshake_finished_msgs, &output_buf);
    var c = client(stream);
    var h = try c.initHandshake();

    h.cipher_suite_tag = .ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    h.master_secret = data12.master_secret;

    // add handshake messages to the transcript
    for (data12.handshake_messages) |msg| {
        h.transcript.update(msg[tls.record_header_len..]);
    }

    // expect verify data
    const client_finished = h.transcript.clientFinished(h.cipher_suite_tag, &h.master_secret);
    try testing.expectEqualSlices(u8, &data12.client_finished, &client_finished);

    // init client with prepared key_material
    c.cipher = try Cipher.init12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &data12.key_material, random);

    // check that server verify data matches calculates from hashes of all handshake messages
    h.transcript.update(&data12.client_finished);
    try h.serverChangeCipherSpec();
    const content_type, const cleartext = try c.nextRecord() orelse return error.EndOfStream;
    try h.verifyServerHandshakeFinished(content_type, cleartext);
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

    pub fn write(self: *TestStream, buf: []const u8) !usize {
        return try self.output.writer().write(buf);
    }

    pub fn read(self: *TestStream, buffer: []u8) !usize {
        return self.input.read(buffer);
    }
};

test "verify google.com certificate" {
    const stream = TestStream.init(@embedFile("testdata/google.com/server_hello"), "");
    var reader = record.reader(stream);

    var buffer: [1024]u8 = undefined;
    var h = try Handshake(TestStream).init(&buffer, &reader);
    h.now_sec = 1714846451;
    h.client_random = @embedFile("testdata/google.com/client_random").*;

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(testing.allocator);
    defer ca_bundle.deinit(testing.allocator);

    try h.serverFlight1(ca_bundle, "google.com");
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
    const seed = testu.hexStr2("23bc6aea3bf218e0154835af87536c8078b3cb9ed7be55579b6c55b36a503090584936ee572afeb19fd16ad333e4");
    const cert_pub_key = &testu.hexStr2("3082010a0282010100893b748b32b7dee524a8e0add60d84265eb39b0221f99d1a2bf6011707de90bdadccae76b8ed2e7da1d565b573e9aeb3c316a6d5178ce26b2b4085a2e7bdf9f8372935f06407a183dcda00ba28ed9117093c49a306fb2e1ff4798562eb9a08eb7d70557a11c68b446a0e6f4aee9224886e5bdb07c00c02f3e5428d59f8bd2c79ea53e3e60e1331627f294f5185e7344bb27158fa1494c749cce9d9dafc4550189934e839904ef43252acfd670556e513721658b632cef88a05d825ad5aad83989f973cdad7e9362e465c3930a9fbfa9b245fffbdb6c75856b2457854b5848c79b7a4de6022290a56a0890732c12437c3dbed18004ab4754505b1554c254f66410203010001");
    const expected_key = &testu.hexStr2("495fd4a3ff7b2bf5eb6c316b488559142c2678d3204df4408e9a6ccb0680a52739fc766136e6da92e17941c35e1e02150bfcf7830fe0a1443772bf88ca22b614e5d4df122a3e615e6d409bf4702d34effb0bba9f801b3a795f1ff88e483eaa2968a8f7d1fbddee0ac0ecb88c615b5787fd5daa2180ad9791df87dd7d589884414ebe02576bc136f1aa0d866951a29161d80a3339c92300f37c822c6d303919dc9776fa91c7de45d7b0092014b2e0f678daa81fae1530c90b1ef15eecb3aba2b285ba725a623b083aa70ada7adfebbfcbf8472a3cdd9337b92770e33c86f6180591a4f26db6822c95bc5cf379c9fcb3895561e60bf5be02845b96a3e3867c168b");

    var rsa_kp = RsaKeyPair.init(seed[0..46].*);
    try testing.expectEqualSlices(
        u8,
        expected_key,
        try rsa_kp.publicKey(.{ .rsaEncryption = {} }, cert_pub_key),
    );
}

test "DhKeyPair.x25519" {
    const seed = testu.hexStr2("4f27a0ea9873d11f3330b88f9443811a5f79c2339dc90dc560b5b49d5e7fe73e496c893a4bbaf26f3288432c747d8b2b00000000000000000000000000000000");
    const server_pub_key = &testu.hexStr2("3303486548531f08d91e675caf666c2dc924ac16f47a861a7f4d05919d143637");
    const expected = &testu.hexStr2("f8912817eb835341f70960290b550329968fea80445853bb91de2ab13ad91c15");

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

test "tls13 server hello" {
    var fbs = std.io.fixedBufferStream(&data13.server_hello);
    var rdr = record.reader(fbs.reader());
    var d = (try rdr.nextDecoder());

    const handshake_type = try d.decode(consts.HandshakeType);
    const length = try d.decode(u24);
    try testing.expectEqual(0x000076, length);
    try testing.expectEqual(.server_hello, handshake_type);

    var h = try Handshake(TestStream).init(undefined, undefined);
    try h.serverHello(&d, length);

    try testing.expectEqual(.AES_256_GCM_SHA384, h.cipher_suite_tag);
    try testing.expectEqualSlices(u8, &data13.server_random, &h.server_random);
    try testing.expectEqual(.tls_1_3, h.tls_version);
    try testing.expectEqual(.x25519, h.named_group);
    try testing.expectEqualSlices(u8, &data13.server_pub_key, h.server_pub_key);
}

test "tls13 handshake cipher" {
    const cipher_suite_tag: CipherSuite = .AES_256_GCM_SHA384;

    var transcript = Transcript{};
    transcript.update(data13.client_hello[tls.record_header_len..]);
    transcript.update(data13.server_hello[tls.record_header_len..]);

    var dh_kp = DhKeyPair{
        .x25519_kp = .{
            .public_key = data13.client_public_key,
            .secret_key = data13.client_private_key,
        },
    };
    const shared_key = try dh_kp.preMasterSecret(.x25519, &data13.server_pub_key);
    try testing.expectEqualSlices(u8, &data13.shared_key, shared_key);

    const cipher = try Cipher.init13Handshake(cipher_suite_tag, shared_key, &transcript);

    const c = &cipher.AES_256_GCM_SHA384;
    try testing.expectEqualSlices(u8, &data13.server_handshake_key, &c.server_key);
    try testing.expectEqualSlices(u8, &data13.client_handshake_key, &c.client_key);
    try testing.expectEqualSlices(u8, &data13.server_handshake_iv, &c.server_iv);
    try testing.expectEqualSlices(u8, &data13.client_handshake_iv, &c.client_iv);
}

fn exampleHandshakeCipher() !Cipher {
    const cipher_suite_tag: CipherSuite = .AES_256_GCM_SHA384;
    var transcript = Transcript{};
    transcript.update(data13.client_hello[tls.record_header_len..]);
    transcript.update(data13.server_hello[tls.record_header_len..]);
    return try Cipher.init13Handshake(cipher_suite_tag, &data13.shared_key, &transcript);
}

fn initExampleHandshake(h: *Handshake(TestStream)) !void {
    h.cipher_suite_tag = .AES_256_GCM_SHA384;
    h.transcript.update(data13.client_hello[tls.record_header_len..]);
    h.transcript.update(data13.server_hello[tls.record_header_len..]);
    h.cipher = try Cipher.init13Handshake(h.cipher_suite_tag, &data13.shared_key, &h.transcript);
    h.tls_version = .tls_1_3;
    h.now_sec = 1714846451;
    h.server_pub_key = &data13.server_pub_key;
}

test "tls13 decrypt wrapped record" {
    var cipher = brk: {
        var h = try Handshake(TestStream).init(undefined, undefined);
        try initExampleHandshake(&h);
        break :brk h.cipher;
    };

    var buffer: [1024]u8 = undefined;
    {
        const record_header = data13.server_encrypted_extensions_wrapped[0..tls.record_header_len];
        const payload = data13.server_encrypted_extensions_wrapped[tls.record_header_len..];
        const sequence: u64 = 0;

        const content_type, const cleartext = try cipher.decrypt(
            &buffer,
            sequence,
            .{ .header = record_header, .payload = payload, .content_type = .application_data },
        );
        try testing.expectEqual(.handshake, content_type);
        try testing.expectEqualSlices(u8, &data13.server_encrypted_extensions, cleartext);
    }
    {
        const record_header = data13.server_certificate_wrapped[0..tls.record_header_len];
        const payload = data13.server_certificate_wrapped[tls.record_header_len..];
        const sequence: u64 = 1;
        const content_type, const cleartext = try cipher.decrypt(
            &buffer,
            sequence,
            .{ .header = record_header, .payload = payload, .content_type = .application_data },
        );
        try testing.expectEqual(.handshake, content_type);
        try testing.expectEqualSlices(u8, &data13.server_certificate, cleartext);
    }
}

test "tls13 process server flight" {
    const stream = TestStream.init(&data13.server_flight, "");
    var reader = record.reader(stream);
    var buffer: [1024]u8 = undefined;
    var h = try Handshake(TestStream).init(&buffer, &reader);
    try initExampleHandshake(&h);
    try h.serverEncryptedFlight1(null, "example.ulfheim.net");

    { // application cipher keys calculation
        try testing.expectEqualSlices(u8, &data13.handshake_hash, &h.transcript.sha384.hash.peek());

        const cipher = try Cipher.init13Application(h.cipher_suite_tag, &h.transcript);
        const c = &cipher.AES_256_GCM_SHA384;
        try testing.expectEqualSlices(u8, &data13.server_application_key, &c.server_key);
        try testing.expectEqualSlices(u8, &data13.client_application_key, &c.client_key);
        try testing.expectEqualSlices(u8, &data13.server_application_iv, &c.server_iv);
        try testing.expectEqualSlices(u8, &data13.client_application_iv, &c.client_iv);

        const encrypted = try cipher.encrypt(&buffer, 0, .application_data, "ping");
        try testing.expectEqualSlices(u8, &data13.client_ping_wrapped, encrypted);
    }
    { // client finished message
        const client_finished = h.transcript.clientFinished13Msg(.AES_256_GCM_SHA384);
        try testing.expectEqualSlices(u8, &data13.client_finished_verify_data, client_finished[4..]);

        const encrypted = try h.cipher.encrypt(&buffer, 0, .handshake, client_finished);
        try testing.expectEqualSlices(u8, &data13.client_finished_wrapped, encrypted);
    }
}

test "Handshake client hello" {
    random = testu.random(0);

    var buffer: [1024]u8 = undefined;
    var h = try Handshake(TestStream).init(&buffer, undefined);
    const actual = try h.clientHello("google.com", .{
        .cipher_suites = &[_]CipherSuite{CipherSuite.ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
        .disable_keyber = true,
    });

    const expected = testu.hexStr3(
        "16 03 03 00 7c " ++ // record header
            "01 00 00 78 " ++ // handshake header
            "03 03 " ++ // protocol version
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f " ++ // client random
            "00 " ++ // no session id
            "00 02 c0 2b " ++ // cipher suites
            "01 00 " ++ // compression methods
            "00 4d " ++ // extensions length
            "00 2b 00 03 02 03 03 " ++ // supported versions extension
            "00 0b 00 02 01 00 " ++ // ec point formats extension
            "ff 01 00 01 00 " ++ // renegotiation info extension
            "00 12 00 00 " ++ // sct extension
            "00 0d 00 14 00 12 04 03 05 03 08 04 08 05 08 06 08 07 02 01 04 01 05 01 " ++ // signature algorithms extension
            "00 0a 00 08 00 06 00 1d 00 17 00 18 " ++ // named groups extension
            "00 00 00 0f 00 0d 00 00 0a 67 6f 6f 67 6c 65 2e 63 6f 6d ", // server name extension
    );
    try testing.expectEqualSlices(u8, &expected, actual);
}
