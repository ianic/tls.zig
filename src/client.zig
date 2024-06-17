const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;

const consts = @import("consts.zig");
const record = @import("record.zig");
const Cipher = @import("cipher.zig").Cipher;
const Handshake = @import("handshake.zig").Handshake;
pub const Options = @import("handshake.zig").Options;
pub const Stats = @import("handshake.zig").Stats;
pub const CipherSuite = @import("cipher.zig").CipherSuite;
const VecPut = @import("std_copy.zig").VecPut;

pub fn client(stream: anytype) Client(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .reader = record.reader(stream),
    };
}

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
        read_buf: []const u8 = "",

        const ClientT = @This();

        fn initHandshake(c: *ClientT) !HandshakeT {
            return try HandshakeT.init(&c.write_buf, &c.reader);
        }

        pub fn handshake(
            c: *ClientT,
            host: []const u8,
            ca_bundle: ?Certificate.Bundle,
            opt: Options,
        ) !void {
            var h = try c.initHandshake();
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
                h.cipher = try Cipher.init13Handshake(h.cipher_suite_tag, try h.sharedKey(), &h.transcript);
                try h.serverEncryptedFlight1(ca_bundle, host);
                c.cipher = try Cipher.init13Application(h.cipher_suite_tag, &h.transcript);
                try c.send(try h.clientFlight2Tls13());
            } else { // tls 1.2 specific handshake part
                try h.verifySignature12();
                try h.generateKeyMaterial();
                {
                    h.cipher = try Cipher.init12(h.cipher_suite_tag, h.key_material, crypto.random);
                    c.cipher = h.cipher;
                    c.client_sequence = 1;
                }
                try c.send(try h.clientFlight2Tls12());
                { // parse server flight 2
                    try h.serverChangeCipherSpec();
                    // Read encrypted server handshake finished message.
                    const content_type, const cleartext = try c.nextRecord() orelse return error.EndOfStream;
                    try h.verifyServerHandshakeFinished(content_type, cleartext);
                }
            }
        }

        /// Encrypts cleartext and writes it to the underlying stream as single
        /// tls record. Max single tls record payload length is 1<<14 (16K)
        /// bytes.
        pub fn write(c: *ClientT, bytes: []const u8) !usize {
            const n = @min(bytes.len, tls.max_cipertext_inner_record_len);
            try c.writeRecord(.application_data, bytes[0..n]);
            return n;
        }

        /// Encrypts cleartext and writes it to the underlying stream. If needed
        /// splits cleartext into multiple tls record.
        pub fn writeAll(c: *ClientT, bytes: []const u8) !void {
            var index: usize = 0;
            while (index < bytes.len) {
                index += try c.write(bytes[index..]);
            }
        }

        /// Encrypts and writes single tls record to the stream.
        fn writeRecord(c: *ClientT, content_type: tls.ContentType, bytes: []const u8) !void {
            assert(bytes.len <= tls.max_cipertext_inner_record_len);
            const rec = try c.encrypt(&c.write_buf, content_type, bytes);
            try c.send(rec);
        }

        /// Writes buffer to the underlying stream.
        fn send(c: *ClientT, buffer: []const u8) !void {
            var n: usize = 0;
            while (n < buffer.len) {
                n += try c.stream.write(buffer[n..]);
            }
        }

        /// Returns the number of bytes read. If the number read is less than
        /// the space provided it means the stream reached the end.
        pub fn readv(c: *ClientT, iovecs: []std.posix.iovec) !usize {
            var vp: VecPut = .{ .iovecs = iovecs };
            while (true) {
                if (c.read_buf.len == 0) {
                    c.read_buf = try c.next() orelse break;
                }
                const n = vp.put(c.read_buf);
                c.read_buf = c.read_buf[n..];
                if (n < c.read_buf.len) break;
            }
            return vp.total;
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
                    // Reuse reader buffer for cleartext. `rec.header` and
                    // `rec.payload`(ciphertext) are also pointing somewhere in
                    // this buffer. Decrypter is first reading then writing a
                    // block, cleartext has less length then ciphertext,
                    // cleartext starts from the beginning of the buffer, so
                    // ciphertext is always ahead of cleartext.
                    c.reader.buffer[0..c.reader.start],
                    c.server_sequence,
                    rec,
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

const testing = std.testing;
const data12 = @import("testdata/tls12.zig");
const testu = @import("testu.zig");

test "Client encrypt decrypt" {
    var output_buf: [1024]u8 = undefined;
    const stream = testu.Stream.init(&data12.server_pong, &output_buf);
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
    { // decrypt server pong message
        c.server_sequence = 1;
        //try testing.expectEqualStrings("pong", (try c.next()).?);

        var buffer: [9]u8 = undefined;
        var iovecs = [_]std.posix.iovec{
            .{ .base = &buffer, .len = 3 },
            .{ .base = buffer[3..], .len = 3 },
            .{ .base = buffer[6..], .len = 3 },
        };
        const n = try c.readv(iovecs[0..]);
        try testing.expectEqual(4, n);
        try testing.expectEqualStrings("pong", buffer[0..n]);
    }
}

test "Handshake.verifyData" {
    var output_buf: [1024]u8 = undefined;
    const stream = testu.Stream.init(&data12.server_handshake_finished_msgs, &output_buf);
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
    c.cipher = try Cipher.init12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &data12.key_material, crypto.random);

    // check that server verify data matches calculates from hashes of all handshake messages
    h.transcript.update(&data12.client_finished);
    try h.serverChangeCipherSpec();
    const content_type, const cleartext = try c.nextRecord() orelse return error.EndOfStream;
    try h.verifyServerHandshakeFinished(content_type, cleartext);
}
