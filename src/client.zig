const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const posix = std.posix;

const tls = crypto.tls;
const tls12 = @import("tls12.zig");
const AppCipher = @import("cipher.zig").AppCipher;
const Transcript = @import("cipher.zig").Transcript;

const Certificate = crypto.Certificate;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = crypto.sign.ecdsa.EcdsaP384Sha384;

pub fn client(stream: anytype) ClientT(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .reader = recordReader(stream),
    };
}

pub fn ClientT(comptime StreamType: type) type {
    const RecordReaderType = RecordReader(StreamType);
    return struct {
        stream: StreamType,
        reader: RecordReaderType,

        app_cipher: AppCipher = undefined,
        client_sequence: usize = 0,
        server_sequence: usize = 0,

        const Client = @This();

        pub fn handshake(c: *Client, host: []const u8, ca_bundle: ?Certificate.Bundle) !void {
            var h = try Handshake.init();
            try h.clientHello(host, &c.stream);
            try h.serverHello(&c.reader, ca_bundle, host);
            c.app_cipher = try AppCipher.init(h.cipher_suite_tag, &h.key_material, crypto.random);
            try h.clientHandshakeFinished(c);
            try h.serverHandshakeFinished(c);

            // // TODO remove debug
            // std.debug.print(
            //     " chipher: {}, namded_group: {}, signature scheme: {} ",
            //     .{ h.cipher_suite_tag, h.named_group, h.signature_scheme },
            // );
        }

        /// Low level write interface. Doesn't allocate but requires provided
        /// buffer for encryption. Cleartext can't be greater than tls record
        /// (16K). Buffer has to be bigger than cleartext for encryption
        /// overhead (AppCipherT.max_overhead = 52 bytes).
        ///
        /// Cleartext can be part of the buffer but has to start at byte 16 or
        /// later.
        pub fn write(c: *Client, buffer: []u8, cleartext: []const u8) !void {
            try c.write_(buffer, .application_data, cleartext);
        }

        //var buffer: [tls.max_ciphertext_record_len]u8 = undefined;
        fn write_(c: *Client, buffer: []u8, content_type: tls.ContentType, cleartext: []const u8) !void {
            assert(cleartext.len <= tls.max_cipertext_inner_record_len);
            assert(buffer.len >= c.app_cipher.minEncryptBufferLen(cleartext.len));

            const payload = try c.encrypt(buffer, content_type, cleartext);
            const header = tls12.recordHeader(content_type, payload.len);

            var iovecs = [_]posix.iovec_const{
                .{ .iov_base = &header, .iov_len = header.len },
                .{ .iov_base = payload.ptr, .iov_len = payload.len },
            };
            try c.stream.writevAll(&iovecs);
        }

        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try client.next()) |buf| { ... }
        pub fn next(c: *Client) !?[]const u8 {
            return c.next_(.application_data);
        }

        fn next_(c: *Client, content_type: tls.ContentType) !?[]const u8 {
            const rec = (try c.reader.next()) orelse return null;
            if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

            const cleartext = try c.decrypt(rec.payload, rec.content_type, rec.payload);
            switch (rec.content_type) {
                .handshake, .application_data => {
                    if (rec.content_type != content_type) return error.TlsUnexpectedMessage;
                    return cleartext;
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
        }

        fn encrypt(c: *Client, buffer: []u8, content_type: tls.ContentType, cleartext: []const u8) ![]const u8 {
            assert(buffer.len >= c.app_cipher.minEncryptBufferLen(cleartext.len));

            const ad = additonalData(c.client_sequence, content_type, cleartext.len);
            c.client_sequence += 1;
            return switch (c.app_cipher) {
                inline else => |*p| p.encrypt(buffer, &ad, cleartext),
            };
        }

        fn decrypt(c: *Client, buffer: []u8, content_type: tls.ContentType, payload: []const u8) ![]const u8 {
            var ad = additonalData(c.server_sequence, content_type, 0);
            c.server_sequence += 1;
            return switch (c.app_cipher) {
                inline else => |*p| p.decrypt(buffer, &ad, payload),
            };
        }

        fn additonalData(sequence: u64, content_type: tls.ContentType, cleartext_len: usize) [13]u8 {
            var sequence_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &sequence_buf, sequence, .big);
            return sequence_buf ++ tls12.recordHeader(content_type, cleartext_len);
        }

        pub fn close(c: *Client) !void {
            var buffer: [AppCipher.max_overhead + tls.record_header_len + tls12.close_notify_alert.len]u8 = undefined;
            const payload = try c.encrypt(buffer[tls.record_header_len..], .alert, &tls12.close_notify_alert);
            buffer[0..tls.record_header_len].* = tls12.recordHeader(.alert, payload.len);
            try c.stream.writeAll(buffer[0 .. tls.record_header_len + payload.len]);
        }

        const Handshake = struct {
            const client_random_len = 32;
            const master_secret_len = 48;
            const key_material_len = 32 * 4;

            client_random: [client_random_len]u8 = undefined,
            server_random: [client_random_len]u8 = undefined,
            master_secret: [master_secret_len]u8 = undefined,
            key_material: [key_material_len]u8 = undefined,

            transcript: Transcript = .{},

            cipher_suite_tag: tls12.CipherSuite = undefined,
            named_group: ?tls.NamedGroup = null,
            signature_scheme: tls.SignatureScheme = undefined,

            x25519_kp: X25519.KeyPair = undefined,
            secp256r1_kp: EcdsaP256Sha256.KeyPair = undefined,
            secp384r1_kp: EcdsaP384Sha384.KeyPair = undefined,
            rsa_pre_master_secret: [master_secret_len]u8 = undefined,
            now_sec: i64 = 0,

            cert_pub_key_buf: [600]u8 = undefined,
            cert_pub_key: []const u8 = undefined,
            cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo = undefined,

            pub fn init() !Handshake {
                var random_buffer: [32 * 3 + 48 * 2]u8 = undefined;
                crypto.random.bytes(&random_buffer);

                return .{
                    .client_random = random_buffer[0..32].*,
                    .x25519_kp = try X25519.KeyPair.create(random_buffer[32..][0..32].*),
                    .secp256r1_kp = try EcdsaP256Sha256.KeyPair.create(random_buffer[64..][0..32].*),
                    .secp384r1_kp = try EcdsaP384Sha384.KeyPair.create(random_buffer[96..][0..48].*),
                    .rsa_pre_master_secret = tls12.hello.protocol_version ++ random_buffer[144..][0..46].*,
                    .now_sec = std.time.timestamp(),
                };
            }

            /// Send client hello message.
            fn clientHello(h: *Handshake, host: []const u8, stream: *StreamType) !void {
                //try std.fs.cwd().writeFile("client_random", &h.client_random);

                const enum_array = tls.enum_array;
                const host_len: u16 = @intCast(host.len);

                const extensions_payload =
                    tls12.extension.ec_point_formats ++
                    tls12.extension.renegotiation_info ++
                    tls12.extension.sct ++
                    tls.extension(.signature_algorithms, enum_array(tls.SignatureScheme, &.{
                    .ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384,

                    .rsa_pss_rsae_sha256,
                    .rsa_pss_rsae_sha384,
                    .rsa_pss_rsae_sha512,
                    //.rsa_pss_pss_sha256,
                    //
                    // .ed25519,
                    .rsa_pkcs1_sha1, // en.wikipedia.org sends alert if this one is not enabled and then choses rsa_pss_rsae_sha256 !?
                    .rsa_pkcs1_sha256,
                    .rsa_pkcs1_sha384, // dailymotion.com somehow requires this one
                })) ++
                    tls.extension(.supported_groups, enum_array(tls.NamedGroup, &.{
                    .x25519,
                    .secp256r1,
                    .secp384r1,
                })) ++
                    tls12.serverNameExtensionHeader(host_len);

                const payload =
                    tls12.hello.protocol_version ++
                    h.client_random ++
                    tls12.hello.no_session_id ++
                    enum_array(tls12.CipherSuite, &tls12.CipherSuite.supported) ++
                    tls12.hello.no_compression ++
                    tls.int2(@intCast(extensions_payload.len + host_len)) ++
                    extensions_payload;

                const record =
                    tls12.handshakeHeader(.client_hello, payload.len + host_len) ++
                    payload;

                h.transcript.update(record[tls.record_header_len..]);
                h.transcript.update(host);

                var iovecs = [_]posix.iovec_const{
                    .{ .iov_base = &record, .iov_len = record.len },
                    .{ .iov_base = host.ptr, .iov_len = host.len },
                };
                try stream.writevAll(&iovecs);
            }

            /// Read server hello, certificate, key_exchange and hello done messages.
            /// Extract server public key and server random.
            fn serverHello(h: *Handshake, reader: *RecordReaderType, ca_bundle: ?Certificate.Bundle, host: []const u8) !void {
                var handshake_state = tls12.HandshakeType.server_hello;

                var prev_cert: Certificate.Parsed = undefined;

                while (true) {
                    var rec = (try reader.next()) orelse return error.TlsUnexpectedMessage;
                    if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                    try rec.expectContentType(.handshake);
                    h.transcript.update(rec.payload);

                    // Multiple handshake messages can be packed in single tls record.
                    while (!rec.eof()) {
                        const handshake_type = try rec.decode(tls12.HandshakeType);
                        if (handshake_state != handshake_type) return error.TlsUnexpectedMessage;

                        const length = try rec.decode(u24);
                        if (length > tls.max_cipertext_inner_record_len)
                            return error.TlsUnsupportedFragmentedHandshakeMessage;

                        switch (handshake_type) {
                            .server_hello => { // server hello, ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.3
                                // try std.fs.cwd().writeFile("server_hello", reader.buffer[0..reader.end]);

                                if (try rec.decode(tls.ProtocolVersion) != tls.ProtocolVersion.tls_1_2)
                                    return error.TlsBadVersion;
                                h.server_random = (try rec.array(32)).*;

                                const session_id_len = try rec.decode(u8);
                                if (session_id_len > 32) return error.TlsIllegalParameter;
                                try rec.skip(session_id_len);

                                h.cipher_suite_tag = try rec.decode(tls12.CipherSuite);
                                try h.cipher_suite_tag.validate();
                                try rec.skip(1); // skip compression method

                                const extensions_present = length > 2 + 32 + session_id_len + 2 + 1;
                                if (extensions_present) {
                                    const extensions_size = try rec.decode(u16);
                                    try rec.skip(extensions_size);
                                }

                                if (h.cipher_suite_tag.rsaKeyExchange())
                                    try h.generateKeyMaterial("");
                                handshake_state = .certificate;
                            },
                            .certificate => {
                                var trust_chain_established = false;
                                const certs_len = try rec.decode(u24);

                                var l: usize = 0;
                                while (l < certs_len) {
                                    const cert_len = try rec.decode(u24);
                                    defer l += cert_len + 3;

                                    const cert = try rec.slice(cert_len);
                                    if (trust_chain_established) continue;
                                    const subject_cert: Certificate = .{ .buffer = cert, .index = 0 };
                                    const subject = try subject_cert.parse();

                                    if (l == 0) { // first certificate
                                        try subject.verifyHostName(host);
                                        const pub_key = subject.pubKey();
                                        if (pub_key.len > h.cert_pub_key_buf.len)
                                            return error.CertificatePublicKeyInvalid;
                                        @memcpy(h.cert_pub_key_buf[0..pub_key.len], pub_key);
                                        h.cert_pub_key = h.cert_pub_key_buf[0..pub_key.len];
                                        h.cert_pub_key_algo = subject.pub_key_algo;
                                        prev_cert = subject;
                                    } else {
                                        if (prev_cert.verify(subject, h.now_sec)) {
                                            prev_cert = subject;
                                        } else |_| {
                                            // skip certificate which is not part of the chain
                                        }
                                    }
                                    if (ca_bundle) |cb| {
                                        if (cb.verify(prev_cert, h.now_sec)) |_| {
                                            trust_chain_established = true;
                                        } else |err| switch (err) {
                                            error.CertificateIssuerNotFound => {},
                                            else => |e| return e,
                                        }
                                    }
                                    prev_cert = subject;
                                }
                                if (ca_bundle != null and !trust_chain_established) {
                                    return error.CertificateIssuerNotFound;
                                }
                                handshake_state = if (h.cipher_suite_tag.rsaKeyExchange())
                                    .server_hello_done
                                else
                                    .server_key_exchange;
                            },
                            .server_key_exchange => {
                                const idx_start = rec.idx;
                                const named_curve = try rec.decode(u8);
                                if (named_curve != 0x03) return error.TlsIllegalParameter;
                                h.named_group = try rec.decode(tls.NamedGroup);
                                const server_pub_key_len = try rec.decode(u8);
                                const server_pub_key = try rec.slice(server_pub_key_len);
                                const idx_end = rec.idx;

                                h.signature_scheme = try rec.decode(tls.SignatureScheme);
                                const signature_len = try rec.decode(u16);
                                const signature = try rec.slice(signature_len);
                                const verify_bytes = brk: {
                                    // public key len
                                    // x25519 = 32
                                    // secp256r1 = 65
                                    // secp384r1 = 97
                                    const max_public_key_len = 97;
                                    var verify_buf: [64 + 3 + 1 + max_public_key_len]u8 = undefined;
                                    verify_buf[0..64].* = h.client_random ++ h.server_random;
                                    const payload_part = rec.payload[idx_start..idx_end];
                                    @memcpy(verify_buf[64..][0..payload_part.len], payload_part);
                                    break :brk verify_buf[0 .. 64 + payload_part.len];
                                };
                                try verifySignature(h.signature_scheme, h.cert_pub_key, h.cert_pub_key_algo, signature, verify_bytes);
                                try h.generateKeyMaterial(server_pub_key);

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

            fn verifySignature(
                signature_scheme: tls.SignatureScheme,
                cert_pub_key: []const u8,
                cert_pub_key_algo: Certificate.Parsed.PubKeyAlgo,
                signature: []const u8,
                verify_bytes: []const u8,
            ) !void {
                const rsa = Certificate.rsa;

                switch (signature_scheme) {
                    inline .ecdsa_secp256r1_sha256,
                    .ecdsa_secp384r1_sha384,
                    => |comptime_scheme| {
                        if (cert_pub_key_algo != .X9_62_id_ecPublicKey) return error.TlsBadSignatureScheme;

                        const cert_named_curve = cert_pub_key_algo.X9_62_id_ecPublicKey;
                        switch (cert_named_curve) {
                            inline else => |comptime_cert_named_curve| {
                                const Ecdsa = SchemeEcdsa(comptime_scheme, comptime_cert_named_curve);
                                const key = try Ecdsa.PublicKey.fromSec1(cert_pub_key);
                                const sig = try Ecdsa.Signature.fromDer(signature);
                                try sig.verify(verify_bytes, key);
                            },
                        }
                    },

                    inline .rsa_pss_rsae_sha256,
                    .rsa_pss_rsae_sha384,
                    .rsa_pss_rsae_sha512,
                    => |comptime_scheme| {
                        if (cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                        const Hash = SchemeHash(comptime_scheme);
                        const pk = try rsa.PublicKey.parseDer(cert_pub_key);
                        switch (pk.modulus.len) {
                            inline 128, 256, 512 => |modulus_len| {
                                const key = try rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
                                const sig = rsa.PSSSignature.fromBytes(modulus_len, signature);
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
                        if (cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                        const Hash = SchemeHash(comptime_scheme);
                        // TODO: calling private method
                        try Certificate.verifyRsa(Hash, verify_bytes, signature, cert_pub_key_algo, cert_pub_key);
                    },
                    else => return error.TlsUnknownSignatureScheme,
                }
            }

            fn SchemeEcdsa(comptime scheme: tls.SignatureScheme, comptime cert_named_curve: Certificate.NamedCurve) type {
                return switch (scheme) {
                    .ecdsa_secp256r1_sha256 => switch (cert_named_curve) {
                        .secp384r1 => crypto.sign.ecdsa.Ecdsa(crypto.ecc.P384, crypto.hash.sha2.Sha256),
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

            fn generateKeyMaterial(h: *Handshake, server_pub_key: []const u8) !void {
                const pre_master_secret = if (h.named_group) |named_group|
                    switch (named_group) {
                        .x25519 => brk: {
                            if (server_pub_key.len != X25519.public_length)
                                return error.TlsIllegalParameter;
                            break :brk &(try X25519.scalarmult(
                                h.x25519_kp.secret_key,
                                server_pub_key[0..X25519.public_length].*,
                            ));
                        },
                        .secp256r1 => brk: {
                            const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_pub_key);
                            const mul = try pk.p.mulPublic(h.secp256r1_kp.secret_key.bytes, .big);
                            break :brk &mul.affineCoordinates().x.toBytes(.big);
                        },
                        .secp384r1 => brk: {
                            const pk = try EcdsaP384Sha384.PublicKey.fromSec1(server_pub_key);
                            const mul = try pk.p.mulPublic(h.secp384r1_kp.secret_key.bytes, .big);
                            break :brk &mul.affineCoordinates().x.toBytes(.big);
                        },
                        else => return error.TlsIllegalParameter,
                    }
                else
                    &h.rsa_pre_master_secret;

                h.master_secret = Transcript.masterSecret(
                    master_secret_len,
                    h.cipher_suite_tag,
                    pre_master_secret,
                    h.client_random,
                    h.server_random,
                );
                h.key_material = Transcript.keyMaterial(
                    key_material_len,
                    h.cipher_suite_tag,
                    &h.master_secret,
                    h.client_random,
                    h.server_random,
                );
            }

            /// Sends client key exchange, client chiper spec and client
            /// handshake finished messages.
            fn clientHandshakeFinished(h: *Handshake, c: *Client) !void {
                const key: []const u8 = if (h.named_group) |named_group|
                    switch (named_group) {
                        .x25519 => &h.x25519_kp.public_key,
                        .secp256r1 => &h.secp256r1_kp.public_key.toUncompressedSec1(),
                        .secp384r1 => &h.secp384r1_kp.public_key.toUncompressedSec1(),
                        else => unreachable,
                    }
                else brk: {
                    if (h.cert_pub_key_algo != .rsaEncryption)
                        return error.TlsBadSignatureScheme;

                    const rsa = Certificate.rsa;
                    const pk = try rsa.PublicKey.parseDer(h.cert_pub_key);
                    switch (pk.modulus.len) {
                        inline 128, 256, 512 => |modulus_len| {
                            const msg_len = h.rsa_pre_master_secret.len;
                            const pad_len = modulus_len - msg_len - 3;
                            const padded_msg: [modulus_len]u8 =
                                [2]u8{ 0, 2 } ++
                                ([1]u8{0xff} ** pad_len) ++
                                [1]u8{0} ++
                                h.rsa_pre_master_secret;

                            const key = try rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
                            // TODO calling private method here
                            break :brk &(try rsa.encrypt(modulus_len, padded_msg, key));
                        },
                        else => {
                            return error.TlsBadRsaSignatureBitCount;
                        },
                    }
                };

                const key_exchange = if (h.named_group != null)
                    &tls12.handshakeHeader(.client_key_exchange, 1 + key.len) ++
                        tls12.int1(@intCast(key.len))
                else
                    &tls12.handshakeHeader(.client_key_exchange, 2 + key.len) ++
                        tls12.int2(@intCast(key.len));

                h.transcript.update(key_exchange[tls.record_header_len..]);
                h.transcript.update(key);

                const change_cipher_spec =
                    tls12.recordHeader(.change_cipher_spec, 1) ++
                    tls12.int1(1);

                const handshake_finished = brk: {
                    var buffer: [AppCipher.max_overhead + 5 + 16]u8 = undefined;
                    const verify_data = h.transcript.verifyData(h.cipher_suite_tag, &h.master_secret);
                    const payload = try c.encrypt(buffer[5..], .handshake, &verify_data);
                    buffer[0..tls.record_header_len].* = tls12.recordHeader(.handshake, payload.len);
                    break :brk buffer[0 .. tls.record_header_len + payload.len];
                };

                var iovecs = [_]posix.iovec_const{
                    .{ .iov_base = key_exchange.ptr, .iov_len = key_exchange.len },
                    .{ .iov_base = key.ptr, .iov_len = key.len },
                    .{ .iov_base = &change_cipher_spec, .iov_len = change_cipher_spec.len },
                    .{ .iov_base = handshake_finished.ptr, .iov_len = handshake_finished.len },
                };
                try c.stream.writevAll(&iovecs);
            }

            fn serverHandshakeFinished(h: *Handshake, c: *Client) !void {
                _ = h;
                { // read change ciperh spec message
                    var rec = (try c.reader.next()) orelse return error.EndOfStream;
                    if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                    try rec.expectContentType(.change_cipher_spec);
                }
                { // read server handshake finished
                    // TODO check content of the handshake finished message
                    _ = try c.next_(.handshake);
                }
            }
        };
    };
}

const testing = std.testing;
const example = @import("example.zig");
const bytesToHex = std.fmt.bytesToHex;
const hexToBytes = std.fmt.hexToBytes;

test "Handshake.clientHello" {
    var output_buf: [1024]u8 = undefined;
    var stream = TestStream.init("", &output_buf);
    var h = try ClientT(TestStream).Handshake.init();
    _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const host = "www.example.com";
    try h.clientHello(host, &stream);
    const hello_buf = stream.output.getWritten();
    //bufPrint(hello_buf);
    try testing.expectEqualSlices(u8, &example.client_hello, hello_buf);
    try testing.expectEqualStrings(host, hello_buf[hello_buf.len - host.len ..]);
}

test "Handshake.serverHello" {
    const stream = TestStream.init(&example.server_hello_responses, "");
    var h = try ClientT(TestStream).Handshake.init();
    var reader = recordReader(stream);

    // read server random and server public key from server hello, certificate
    // and key exchange messages
    try h.serverHello(&reader, null);
    try testing.expectEqualStrings(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        &bytesToHex(h.server_random, .lower),
    );
    try testing.expectEqualStrings(
        "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615",
        &bytesToHex(h.server_public_key[0..32].*, .lower),
    );
    try testing.expectEqual(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, h.cipher_suite_tag);
}

test "Handshake.generateMasterSecret" {
    var h = try ClientT(TestStream).Handshake.init();

    { // init with known keys
        _ = try hexToBytes(h.x25519_kp.secret_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        _ = try hexToBytes(h.server_random[0..], "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        h.cipher_suite_tag = .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        h.named_group = .x25519;
    }
    var server_pub_key: [32]u8 = undefined;
    _ = try hexToBytes(&server_pub_key, "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
    { // generate encryptionserver_pub_key
        try h.generateKeyMaterial(&server_pub_key);
        try testing.expectEqualStrings(
            "1b7d117c7d5f690bc263cae8ef60af0f1878acc22ad8bdd8c601a617126f63540eb20906f781fad2f656d037b173ef3e11169f27231a84b6752a18e7a9fcb7cbcdd8f98dd8f769eba0d2550c9238eebfef5c32251abb67d6434528db4937d540d393135e06a11bb80e45eaebe32cac72757438fbb3df645cbda4067cdfa0f848",
            &bytesToHex(h.key_material, .lower),
        );
    }
}

test "Client.init" {
    var test_rnd = TestRnd{};
    const rnd = std.Random.init(&test_rnd, TestRnd.fillFn);

    var output_buf: [1024]u8 = undefined;
    const stream = TestStream.init(&example.server_responses, &output_buf);
    var c = client(stream);
    var h = try ClientT(TestStream).Handshake.init();

    { // init with known keys
        _ = try hexToBytes(h.x25519_kp.secret_key[0..], "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        _ = try hexToBytes(h.x25519_kp.public_key[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        _ = try hexToBytes(h.server_random[0..], "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        _ = try hexToBytes(h.client_random[0..], "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var public_key_buf: [32]u8 = undefined;
        _ = try hexToBytes(&public_key_buf, "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
        h.server_public_key = &public_key_buf;

        h.cipher_suite_tag = .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        h.named_group = .x25519;
    }

    const host = "www.example.com";
    test_rnd.idx = 0x20;
    {
        try h.clientHello(host, &c.stream);
        try h.serverHello(&c.reader, null);
        try h.generateClientKeys();
        c.app_cipher = try AppCipher.init(h.cipher_suite_tag, &h.key_material, rnd);
        try h.clientHandshakeFinished(&c);
        try h.serverHandshakeFinished(&c);
    }
    { // test messages that client sent
        const written = c.stream.output.getWritten();
        var pos: usize = 0;

        try testing.expectEqualSlices(u8, &example.client_hello, written[0..example.client_hello.len]);
        pos += example.client_hello.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_key_exchange,
            written[pos..][0..example.client_key_exchange.len],
        );
        pos += example.client_key_exchange.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_change_cyper_spec,
            written[pos..][0..example.client_change_cyper_spec.len],
        );
        pos += example.client_change_cyper_spec.len;
        try testing.expectEqualSlices(
            u8,
            &example.client_handshake_finished,
            written[pos..][0..example.client_handshake_finished.len],
        );
        pos += example.client_handshake_finished.len;
    }

    var buffer: [1024]u8 = undefined;
    c.stream.output.reset();
    { // encrypt ping
        const cleartext = "ping";
        test_rnd.idx = 0;
        try c.write(&buffer, cleartext);

        const expected = [_]u8{
            0x17, 0x03, 0x03, 0x00, 0x30, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x6c, 0x42, 0x1c, 0x71, 0xc4, 0x2b, 0x18, 0x3b, 0xfa, 0x06, 0x19,
            0x5d, 0x13, 0x3d, 0x0a, 0x09, 0xd0, 0x0f, 0xc7, 0xcb, 0x4e, 0x0f, 0x5d, 0x1c, 0xda, 0x59, 0xd1,
            0x47, 0xec, 0x79, 0x0c, 0x99,
        };
        try testing.expectEqualSlices(u8, &expected, c.stream.output.getWritten());
    }

    c.stream.output.reset();
    { // encrypt verify data from illustrated example
        const data = [_]u8{
            0x14, 0x00, 0x00, 0x0c, 0xcf, 0x91, 0x96, 0x26, 0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a,
        };
        c.client_sequence = 0;
        test_rnd.idx = 0x40;
        try c.write_(&buffer, .handshake, &data);
        const expected = [_]u8{
            0x22, 0x7b, 0xc9, 0xba, 0x81, 0xef, 0x30, 0xf2, 0xa8, 0xa7, 0x8f, 0xf1, 0xdf, 0x50, 0x84, 0x4d,
            0x58, 0x04, 0xb7, 0xee, 0xb2, 0xe2, 0x14, 0xc3, 0x2b, 0x68, 0x92, 0xac, 0xa3, 0xdb, 0x7b, 0x78,
            0x07, 0x7f, 0xdd, 0x90, 0x06, 0x7c, 0x51, 0x6b, 0xac, 0xb3, 0xba, 0x90, 0xde, 0xdf, 0x72, 0x0f,
        };
        const actual = c.stream.output.getWritten()[5 + 16 ..]; // skip header and iv
        try testing.expectEqualSlices(u8, &expected, actual);
    }
}

test "Handshake.verifyData" {
    var h = try ClientT(TestStream).Handshake.init();
    h.cipher_suite_tag = .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    h.initCipher();
    h.master_secret = example.master_secret;

    // add handshake messages to transcript
    for (example.handshake_messages) |msg| {
        h.transcript.update(msg[tls.record_header_len..]);
    }

    // expect verify data
    const verify_data = h.verifyData();
    try testing.expectEqualStrings(
        "1400000ccf919626f1360c536aaad73a",
        &bytesToHex(verify_data, .lower),
    );
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

    pub fn writevAll(self: *TestStream, iovecs: []posix.iovec_const) !void {
        for (iovecs) |iovec| {
            var buf: []const u8 = undefined;
            buf.ptr = iovec.iov_base;
            buf.len = iovec.iov_len;
            _ = try self.output.write(buf);
        }
    }

    pub fn read(self: *TestStream, buffer: []u8) !usize {
        return self.input.read(buffer);
    }
};

const TestRnd = struct {
    idx: u8 = 0,

    pub fn fillFn(self: *@This(), buf: []u8) void {
        for (buf) |*v| {
            v.* = self.idx;
            self.idx +%= 1;
        }
    }
};

const Record = struct {
    content_type: tls.ContentType,
    protocol_version: tls.ProtocolVersion,
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
                    const protocol_version: tls.ProtocolVersion = @enumFromInt(std.mem.readInt(u16, record_header[1..3], .big));
                    const payload_len = std.mem.readInt(u16, record_header[3..5], .big);
                    if (payload_len > tls.max_ciphertext_len)
                        return error.TlsRecordOverflow;
                    // If we have whole record
                    if (buffer[tls.record_header_len..].len >= payload_len) {
                        const payload = buffer[tls.record_header_len .. tls.record_header_len + payload_len];
                        c.start += tls.record_header_len + payload_len;
                        return .{
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
                            std.mem.copyForwards(u8, c.buffer[0..n], c.buffer[c.start..][0..n]);
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

    try testing.expectEqual(.server_hello, try rec.decode(tls12.HandshakeType));
    try testing.expectEqual(45, try rec.decode(u24)); // length
    try testing.expectEqual(.tls_1_2, try rec.decode(tls.ProtocolVersion));
    try testing.expectEqualStrings(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        &bytesToHex(try rec.array(32), .lower),
    ); // server random
    try testing.expectEqual(0, try rec.decode(u8)); // session id len
    try testing.expectEqual(.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, try rec.decode(tls12.CipherSuite));
    try testing.expectEqual(0, try rec.decode(u8)); // compression method
    try testing.expectEqual(5, try rec.decode(u16)); // extension length
    try testing.expectEqual(5, rec.rest().len);
    try rec.skip(5);
    try testing.expect(rec.eof());
}

fn bufPrint(var_name: []const u8, buf: []const u8) void {
    std.debug.print("const {s} = [_]u8{{", .{var_name});
    for (buf, 1..) |b, i| {
        std.debug.print("0x{x:0>2}, ", .{b});
        if (i % 16 == 0)
            std.debug.print("\n", .{});
    }
    std.debug.print("}};\n", .{});
}

test "verify google.com certificate" {
    const stream = TestStream.init(@embedFile("testdata/google.com/server_hello"), "");
    var h = try ClientT(TestStream).Handshake.init();
    h.now_sec = 1714846451;
    h.client_random = @embedFile("testdata/google.com/client_random").*;

    var rdr = recordReader(stream);

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(testing.allocator);
    defer ca_bundle.deinit(testing.allocator);

    try h.serverHello(&rdr, ca_bundle);
}

test "rsa encrypt" {
    var buf: [48 + 270]u8 = undefined;
    //var pre_master_secret: [48]u8 = undefined;
    const pre_master_secret = try hexToBytes(
        &buf,
        "0303e2fd42b5710669646ef67f297985b8e431f2291f8fc4d3a77b08fb173dfefe33bcc4008f54cf601ab987cb0cd913",
    );
    const cert_pub_key = try hexToBytes(
        buf[48..],
        "3082010a0282010100893b748b32b7dee524a8e0add60d84265eb39b0221f99d1a2bf6011707de90bdadccae76b8ed2e7da1d565b573e9aeb3c316a6d5178ce26b2b4085a2e7bdf9f8372935f06407a183dcda00ba28ed9117093c49a306fb2e1ff4798562eb9a08eb7d70557a11c68b446a0e6f4aee9224886e5bdb07c00c02f3e5428d59f8bd2c79ea53e3e60e1331627f294f5185e7344bb27158fa1494c749cce9d9dafc4550189934e839904ef43252acfd670556e513721658b632cef88a05d825ad5aad83989f973cdad7e9362e465c3930a9fbfa9b245fffbdb6c75856b2457854b5848c79b7a4de6022290a56a0890732c12437c3dbed18004ab4754505b1554c254f66410203010001",
    );

    var data: [256]u8 = undefined;
    data[0] = 0x00;
    data[1] = 0x02;
    for (2..256 - 48 - 1) |i| {
        data[i] = 256 - 48 - 1 - 2; //0xff; //@intCast(i);
    }
    data[256 - 48 - 1] = 0x00;
    data[256 - 48 ..].* = pre_master_secret[0..48].*;

    const rsa = Certificate.rsa;
    const pk = try rsa.PublicKey.parseDer(cert_pub_key);
    const key = try rsa.PublicKey.fromBytes(pk.exponent, pk.modulus);
    const v1 = try rsa.encrypt(256, data, key);

    bufPrint("v1", &v1);
}
