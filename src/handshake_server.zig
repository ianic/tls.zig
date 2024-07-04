const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const tls = crypto.tls;
const Certificate = crypto.Certificate;

const Cipher = @import("cipher.zig").Cipher;
const CipherSuite = @import("cipher.zig").CipherSuite;
const Transcript = @import("transcript.zig").Transcript;
const record = @import("record.zig");
const PrivateKey = @import("PrivateKey.zig");

const common = @import("handshake_common.zig");
const HandshakeType = common.HandshakeType;
const BufWriter = common.BufWriter;
const dupe = common.dupe;
const recordHeader = common.recordHeader;
const handshakeHeader = common.handshakeHeader;
const CertificateBuilder = common.CertificateBuilder;
const Authentication = common.Authentication;
const DhKeyPair = common.DhKeyPair;

pub const Options = struct {
    authentication: ?Authentication,
};

pub fn Handshake(comptime Stream: type) type {
    const RecordReaderT = record.Reader(Stream);
    return struct {
        // public key len: x25519 = 32, secp256r1 = 65, secp384r1 = 97
        const max_pub_key_len = 97;
        const supported_named_groups = &[_]tls.NamedGroup{ .x25519, .secp256r1, .secp384r1 };

        server_random: [32]u8 = undefined,
        client_random: [32]u8 = undefined,
        legacy_session_id_buf: [32]u8 = undefined,
        legacy_session_id: []u8 = "",
        cipher_suite: CipherSuite = @enumFromInt(0),

        named_group: tls.NamedGroup = @enumFromInt(0),
        client_pub_key_buf: [max_pub_key_len]u8 = undefined,
        client_pub_key: []u8 = "",
        server_pub_key_buf: [max_pub_key_len]u8 = undefined,
        server_pub_key: []u8 = "",

        signature_scheme: tls.SignatureScheme = @enumFromInt(0),

        transcript: Transcript = .{},
        rec_rdr: *RecordReaderT,
        buffer: []u8,

        cipher: Cipher = undefined,
        write_seq: u64 = 0,

        const HandshakeT = @This();

        pub fn init(buf: []u8, rec_rdr: *RecordReaderT) !HandshakeT {
            return .{
                .rec_rdr = rec_rdr,
                .buffer = buf,
            };
        }

        pub fn handshake(h: *HandshakeT, stream: Stream, opt: Options) !Cipher {
            if (opt.authentication) |a| {
                // required signature scheme in client hello
                h.signature_scheme = a.private_key.signature_scheme;
            }
            try h.readClientHello();
            h.transcript.use(h.cipher_suite.hash());

            const server_flight = brk: {
                var w = BufWriter{ .buf = h.buffer };

                const shared_key = sk_brk: {
                    var seed: [DhKeyPair.seed_len]u8 = undefined;
                    crypto.random.bytes(&seed);
                    var kp = try DhKeyPair.init(seed);
                    h.server_pub_key = dupe(&h.server_pub_key_buf, try kp.publicKey(h.named_group));
                    break :sk_brk try kp.sharedKey(h.named_group, h.client_pub_key);
                };
                {
                    const hello = try h.makeServerHello(w.getFree());
                    h.transcript.update(hello[tls.record_header_len..]);
                    w.pos += hello.len;
                }
                {
                    const handshake_secret = h.transcript.handshakeSecret(shared_key);
                    h.cipher = try Cipher.initTLS13(h.cipher_suite, handshake_secret, .server);
                }
                try w.writeRecord(.change_cipher_spec, &[_]u8{1});
                {
                    const encrypted_extensions = &handshakeHeader(.encrypted_extensions, 2) ++ [_]u8{ 0, 0 };
                    h.transcript.update(encrypted_extensions);
                    try h.writeEncrypted(&w, encrypted_extensions);
                }
                if (opt.authentication) |a| {
                    const cm = CertificateBuilder{
                        .certificates = a.certificates,
                        .private_key = a.private_key,
                        .transcript = &h.transcript,
                        .side = .server,
                    };
                    {
                        const certificate = try cm.makeCertificate(w.getPayload());
                        h.transcript.update(certificate);
                        try h.writeEncrypted(&w, certificate);
                    }
                    {
                        const certificate_verify = try cm.makeCertificateVerify(w.getPayload());
                        h.transcript.update(certificate_verify);
                        try h.writeEncrypted(&w, certificate_verify);
                    }
                }
                {
                    const finished = try h.makeFinished(w.getPayload());
                    h.transcript.update(finished);
                    try h.writeEncrypted(&w, finished);
                }
                break :brk w.getWritten();
            };
            try stream.writeAll(server_flight);

            const app_cipher = brk: {
                const application_secret = h.transcript.applicationSecret();
                break :brk try Cipher.initTLS13(h.cipher_suite, application_secret, .server);
            };

            try h.readClientFlight2();
            return app_cipher;
        }

        fn readClientFlight2(h: *HandshakeT) !void {
            while (true) {
                const rec = (try h.rec_rdr.next() orelse return error.EndOfStream);
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;
                switch (rec.content_type) {
                    .change_cipher_spec => {},
                    .application_data => {
                        const content_type, const cleartext = try h.cipher.decrypt(h.buffer, 0, rec);
                        var d = record.Decoder.init(content_type, cleartext);
                        try d.expectContentType(.handshake);

                        const handshake_type = try d.decode(HandshakeType);
                        const length = try d.decode(u24);
                        if (handshake_type != .finished) return error.TlsUnexpectedMessage;

                        const actual = try d.slice(length);
                        var buf: [Transcript.max_mac_length]u8 = undefined;
                        const expected = h.transcript.clientFinishedTLS13(&buf);
                        if (!mem.eql(u8, expected, actual))
                            return error.TlsDecryptError;

                        h.transcript.update(cleartext);
                        return;
                    },
                    else => return error.TlsUnexpectedMessage,
                }
            }
        }

        fn makeFinished(h: *HandshakeT, buf: []u8) ![]const u8 {
            var w = BufWriter{ .buf = buf };
            const verify_data = h.transcript.serverFinishedTLS13(w.getHandshakePayload());
            try w.advanceHandshake(.finished, verify_data.len);
            return w.getWritten();
        }

        /// Write encrypted handshake message into `w`
        fn writeEncrypted(h: *HandshakeT, w: *BufWriter, cleartext: []const u8) !void {
            const ciphertext = try h.cipher.encrypt(w.getFree(), h.write_seq, .handshake, cleartext);
            w.pos += ciphertext.len;
            h.write_seq += 1;
        }

        fn makeServerHello(h: *HandshakeT, buf: []u8) ![]const u8 {
            const header_len = 9; // tls record header (5 bytes) and handshake header (4 bytes)
            var w = BufWriter{ .buf = buf[header_len..] };

            try w.writeEnum(tls.ProtocolVersion.tls_1_2);
            try w.write(&h.server_random);
            {
                try w.writeInt(@as(u8, @intCast(h.legacy_session_id.len)));
                if (h.legacy_session_id.len > 0) try w.write(h.legacy_session_id);
            }
            try w.writeEnum(h.cipher_suite);
            try w.write(&[_]u8{0}); // compression method

            var e = BufWriter{ .buf = buf[header_len + w.pos + 2 ..] };
            { // supported versions extension
                try e.writeEnum(tls.ExtensionType.supported_versions);
                try e.writeInt(@as(u16, 2));
                try e.writeEnum(tls.ProtocolVersion.tls_1_3);
            }
            { // key share extension
                const key_len: u16 = @intCast(h.server_pub_key.len);
                try e.writeEnum(tls.ExtensionType.key_share);
                try e.writeInt(key_len + 4);
                try e.writeEnum(h.named_group);
                try e.writeInt(key_len);
                try e.write(h.server_pub_key);
            }
            try w.writeInt(@as(u16, @intCast(e.pos))); // extensions length

            const payload_len = w.pos + e.pos;
            buf[0..header_len].* = recordHeader(.handshake, 4 + payload_len) ++
                handshakeHeader(.server_hello, payload_len);

            return buf[0 .. header_len + payload_len];
        }

        fn readClientHello(h: *HandshakeT) !void {
            var d = try h.rec_rdr.nextDecoder();
            try d.expectContentType(.handshake);
            h.transcript.update(d.payload);

            const handshake_type = try d.decode(HandshakeType);
            if (handshake_type != .client_hello) return error.TlsUnexpectedMessage;
            _ = try d.decode(u24); // handshake length
            if (try d.decode(tls.ProtocolVersion) != .tls_1_2) return error.TlsBadVersion;

            h.client_random = (try d.array(32)).*;
            { // legacy session id
                const len = try d.decode(u8);
                h.legacy_session_id = dupe(&h.legacy_session_id_buf, try d.slice(len));
            }
            { // cipher suites
                const end_idx = try d.decode(u16) + d.idx;
                while (d.idx < end_idx) {
                    const cipher_suite = try d.decode(CipherSuite);
                    if (@intFromEnum(h.cipher_suite) == 0 and
                        CipherSuite.includes(&CipherSuite.tls13, cipher_suite))
                    {
                        h.cipher_suite = cipher_suite;
                    }
                }
            }
            try d.skip(2); // compression methods

            // extensions
            const extensions_end_idx = try d.decode(u16) + d.idx;
            while (d.idx < extensions_end_idx) {
                const extension_type = try d.decode(tls.ExtensionType);
                const extension_len = try d.decode(u16);

                switch (extension_type) {
                    .supported_versions => {
                        var tls_1_3_supported = false;
                        const end_idx = try d.decode(u8) + d.idx;
                        while (d.idx < end_idx) {
                            if (try d.decode(tls.ProtocolVersion) == tls.ProtocolVersion.tls_1_3) {
                                tls_1_3_supported = true;
                            }
                        }
                        if (!tls_1_3_supported) return error.TlsIllegalParameter;
                    },
                    .key_share => {
                        var selected_named_group_idx = supported_named_groups.len;
                        const end_idx = try d.decode(u16) + d.idx;
                        while (d.idx < end_idx) {
                            const named_group = try d.decode(tls.NamedGroup);
                            const client_pub_key = try d.slice(try d.decode(u16));
                            for (supported_named_groups, 0..) |supported, idx| {
                                if (named_group == supported and idx < selected_named_group_idx) {
                                    h.named_group = named_group;
                                    h.client_pub_key = dupe(&h.client_pub_key_buf, client_pub_key);
                                    selected_named_group_idx = idx;
                                }
                            }
                        }
                        if (@intFromEnum(h.named_group) == 0)
                            return error.TlsIllegalParameter;
                    },
                    .signature_algorithms => {
                        var found = false;
                        const end_idx = try d.decode(u16) + d.idx;
                        while (d.idx < end_idx) {
                            const signature_scheme = try d.decode(tls.SignatureScheme);
                            if (signature_scheme == h.signature_scheme) found = true;
                        }
                        if (@intFromEnum(h.signature_scheme) != 0 and !found)
                            return error.TlsIllegalParameter;
                    },
                    else => {
                        try d.skip(extension_len);
                    },
                }
            }
        }
    };
}

const testing = std.testing;
const data13 = @import("testdata/tls13.zig");
const testu = @import("testu.zig");

fn testReader(data: []const u8) record.Reader(std.io.FixedBufferStream([]const u8)) {
    return record.reader(std.io.fixedBufferStream(data));
}
const TestHandshake = Handshake(std.io.FixedBufferStream([]const u8));

test "read client hello" {
    var buffer: [1024]u8 = undefined;
    var rec_rdr = testReader(&data13.client_hello);
    var h = try TestHandshake.init(&buffer, &rec_rdr);
    h.signature_scheme = .ecdsa_secp521r1_sha512; // this must be supported in signature_algorithms extension
    try h.readClientHello();

    try testing.expectEqual(CipherSuite.AES_256_GCM_SHA384, h.cipher_suite);
    try testing.expectEqual(.x25519, h.named_group);
    try testing.expectEqualSlices(u8, &data13.client_random, &h.client_random);
    try testing.expectEqualSlices(u8, &data13.client_public_key, h.client_pub_key);
}

test "make server hello" {
    var buffer: [1024]u8 = undefined;
    var h = try TestHandshake.init(&buffer, undefined);
    h.cipher_suite = .AES_256_GCM_SHA384;
    testu.fillFrom(&h.server_random, 0);
    testu.fillFrom(&h.server_pub_key_buf, 0x20);
    h.named_group = .x25519;
    h.server_pub_key = h.server_pub_key_buf[0..32];

    const actual = try h.makeServerHello(&buffer);
    const expected = &testu.hexToBytes(
        \\ 16 03 03 00 5a 02 00 00 56
        \\ 03 03
        \\ 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        \\ 00
        \\ 13 02 00
        \\ 00 2e 00 2b 00 02 03 04
        \\ 00 33 00 24 00 1d 00 20
        \\ 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
    );
    try testing.expectEqualSlices(u8, expected, actual);
}
