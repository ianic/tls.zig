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
pub const CipherSuite = @import("cipher.zig").CipherSuite;
pub const PrivateKey = @import("PrivateKey.zig");
const VecPut = @import("std_copy.zig").VecPut;

pub fn client(stream: anytype) Client(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .rec_rdr = record.reader(stream),
    };
}

/// Tls 1.2 and 1.3 client.
///
/// Stream must have read/write functions, and ReaderError/WriteError error
/// sets.
pub fn Client(comptime Stream: type) type {
    const RecordReaderT = record.Reader(Stream);
    const HandshakeT = Handshake(RecordReaderT);
    return struct {
        stream: Stream, // underlying stream
        rec_rdr: RecordReaderT, // reads tls record from underlying stream

        cipher: Cipher = undefined,
        cipher_client_seq: usize = 0,
        cipher_server_seq: usize = 0,

        write_buf: [tls.max_ciphertext_record_len]u8 = undefined,
        read_buf: []const u8 = "",
        received_close_notify: bool = false,

        const ClientT = @This();

        fn initHandshake(c: *ClientT) !HandshakeT {
            return try HandshakeT.init(&c.write_buf, &c.rec_rdr);
        }

        /// Handshake upgrades stream to tls connection.
        ///
        /// tls 1.2 messages:
        ///   client flight 1: client hello
        ///   server flight 1: server hello, certificate, key exchange, hello done
        ///   client flight 2: client key exchange, change cipher spec, handshake finished
        ///   server flight 2: server change cipher spec, handshake finished
        ///
        /// tls 1.3 messages:
        ///   client flight 1: client hello
        ///   server flight 1: server hello
        ///         encrypted: server change cipher spec, certificate, certificate verify, handshake finished
        ///   client flight 2: client change cipher spec, handshake finished
        ///
        pub fn handshake(
            c: *ClientT,
            host: []const u8,
            ca_bundle: ?Certificate.Bundle,
            opt: Options,
        ) !void {
            var h = try c.initHandshake();
            defer if (opt.stats) |stats| stats.update(&h);

            try c.send(try h.clientHello(host, opt));
            try h.serverFlight1(ca_bundle, host);
            if (h.tls_version == .tls_1_3) { // tls 1.3 specific handshake part
                h.cipher = try Cipher.init13Handshake(h.cipher_suite_tag, try h.sharedKey(), &h.transcript);
                try h.serverEncryptedFlight1(ca_bundle, host);
                c.cipher = try Cipher.init13Application(h.cipher_suite_tag, &h.transcript);
                try c.send(try h.clientFlight2Tls13(opt.auth));
            } else { // tls 1.2 specific handshake part
                try h.verifySignature12();
                try h.generateKeyMaterial();
                {
                    h.cipher = try Cipher.init12(h.cipher_suite_tag, h.key_material, crypto.random);
                    c.cipher = h.cipher;
                    c.cipher_client_seq = 1;
                }
                try c.send(try h.clientFlight2Tls12(opt.auth));
                { // parse server flight 2
                    try h.serverChangeCipherSpec();
                    // Read encrypted server handshake finished message.
                    const content_type, const cleartext = try c.nextRecord() orelse return error.EndOfStream;
                    try h.verifyServerHandshakeFinished(content_type, cleartext);
                }
            }
        }

        /// Encrypts and writes single tls record to the stream.
        fn writeRecord(c: *ClientT, content_type: tls.ContentType, bytes: []const u8) !void {
            assert(bytes.len <= tls.max_cipertext_inner_record_len);
            const rec = try c.cipher.encrypt(&c.write_buf, c.cipher_client_seq, content_type, bytes);
            c.cipher_client_seq += 1;
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
        pub fn next(c: *ClientT) ReadError!?[]const u8 {
            const content_type, const data = try c.nextRecord() orelse return null;
            if (content_type != .application_data) return error.TlsUnexpectedMessage;
            return data;
        }

        fn nextRecord(c: *ClientT) ReadError!?struct { tls.ContentType, []const u8 } {
            if (c.eof()) return null;
            while (true) {
                const rec = (try c.rec_rdr.next()) orelse return null;
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

                const content_type, const cleartext = try c.cipher.decrypt(
                    // Reuse reader buffer for cleartext. `rec.header` and
                    // `rec.payload`(ciphertext) are also pointing somewhere in
                    // this buffer. Decrypter is first reading then writing a
                    // block, cleartext has less length then ciphertext,
                    // cleartext starts from the beginning of the buffer, so
                    // ciphertext is always ahead of cleartext.
                    c.rec_rdr.buffer[0..c.rec_rdr.start],
                    c.cipher_server_seq,
                    rec,
                );
                c.cipher_server_seq += 1;

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
                        c.received_close_notify = true;
                        return null;
                    },
                    else => return error.TlsUnexpectedMessage,
                }
                return .{ content_type, cleartext };
            }
        }

        pub fn eof(c: *ClientT) bool {
            return c.received_close_notify and c.read_buf.len == 0;
        }

        pub fn close(c: *ClientT) !void {
            if (c.received_close_notify) return;
            try c.writeRecord(.alert, &consts.close_notify_alert);
        }

        // read, write interface

        pub const ReadError = Stream.ReadError || tls.AlertDescription.Error ||
            error{
            TlsBadVersion,
            TlsUnexpectedMessage,
            TlsRecordOverflow,
            TlsDecryptError,
            TlsBadRecordMac,
            BufferOverflow,
        };
        pub const WriteError = Stream.WriteError ||
            error{BufferOverflow};

        pub const Reader = std.io.Reader(*ClientT, ReadError, read);
        pub const Writer = std.io.Writer(*ClientT, WriteError, write);

        pub fn reader(c: *ClientT) Reader {
            return .{ .context = c };
        }

        pub fn writer(c: *ClientT) Writer {
            return .{ .context = c };
        }

        /// Encrypts cleartext and writes it to the underlying stream as single
        /// tls record. Max single tls record payload length is 1<<14 (16K)
        /// bytes.
        pub fn write(c: *ClientT, bytes: []const u8) WriteError!usize {
            const n = @min(bytes.len, tls.max_cipertext_inner_record_len);
            try c.writeRecord(.application_data, bytes[0..n]);
            return n;
        }

        /// Encrypts cleartext and writes it to the underlying stream. If needed
        /// splits cleartext into multiple tls record.
        pub fn writeAll(c: *ClientT, bytes: []const u8) WriteError!void {
            var index: usize = 0;
            while (index < bytes.len) {
                index += try c.write(bytes[index..]);
            }
        }

        pub fn read(c: *ClientT, buffer: []u8) ReadError!usize {
            if (c.read_buf.len == 0) {
                c.read_buf = try c.next() orelse return 0;
            }
            const n = @min(c.read_buf.len, buffer.len);
            @memcpy(buffer[0..n], c.read_buf[0..n]);
            c.read_buf = c.read_buf[n..];
            return n;
        }

        /// Returns the number of bytes read. If the number read is smaller than
        /// `buffer.len`, it means the stream reached the end.
        pub fn readAll(c: *ClientT, buffer: []u8) ReadError!usize {
            return c.readAtLeast(buffer, buffer.len);
        }

        /// Returns the number of bytes read, calling the underlying read function
        /// the minimal number of times until the buffer has at least `len` bytes
        /// filled. If the number read is less than `len` it means the stream
        /// reached the end.
        pub fn readAtLeast(c: *ClientT, buffer: []u8, len: usize) ReadError!usize {
            assert(len <= buffer.len);
            var index: usize = 0;
            while (index < len) {
                const amt = try c.read(buffer[index..]);
                if (amt == 0) break;
                index += amt;
            }
            return index;
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
                const read_buf_len = c.read_buf.len;
                c.read_buf = c.read_buf[n..];
                if ((n < read_buf_len) or
                    (n == read_buf_len and !c.rec_rdr.hasMore()))
                    break;
            }
            return vp.total;
        }
    };
}

const testing = std.testing;
const data12 = @import("testdata/tls12.zig");
const testu = @import("testu.zig");

test "encrypt decrypt" {
    var output_buf: [1024]u8 = undefined;
    const stream = testu.Stream.init(&(data12.server_pong ** 3), &output_buf);
    var c = client(stream);
    c.cipher = try Cipher.init12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &data12.key_material, testu.random(0));

    c.stream.output.reset();
    { // encrypt verify data from example
        c.cipher_client_seq = 0; //
        _ = testu.random(0x40); // sets iv to 40, 41, ... 4f
        try c.writeRecord(.handshake, &data12.client_finished);
        try testing.expectEqualSlices(u8, &data12.verify_data_encrypted_msg, c.stream.output.getWritten());
    }

    c.stream.output.reset();
    { // encrypt ping
        const cleartext = "ping";
        _ = testu.random(0); // sets iv to 00, 01, ... 0f
        c.cipher_client_seq = 1;

        try c.writeAll(cleartext);
        try testing.expectEqualSlices(u8, &data12.encrypted_ping_msg, c.stream.output.getWritten());
    }
    { // decrypt server pong message
        c.cipher_server_seq = 1;
        try testing.expectEqualStrings("pong", (try c.next()).?);
    }
    { // test reader interface
        c.cipher_server_seq = 1;
        var rdr = c.reader();
        var buffer: [4]u8 = undefined;
        const n = try rdr.readAll(&buffer);
        try testing.expectEqualStrings("pong", buffer[0..n]);
    }
    { // test readv interface
        c.cipher_server_seq = 1;
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

test "handshake verify server finished message" {
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
