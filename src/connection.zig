const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;

const proto = @import("protocol.zig");
const record = @import("record.zig");
const cipher = @import("cipher.zig");
const Cipher = cipher.Cipher;

pub fn connection(stream: anytype) Connection(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .rec_rdr = record.reader(stream),
    };
}

pub fn Connection(comptime Stream: type) type {
    return struct {
        stream: Stream, // underlying stream
        rec_rdr: record.Reader(Stream),
        cipher: Cipher = undefined,

        max_encrypt_seq: u64 = std.math.maxInt(u64) - 1,
        key_update_requested: bool = false,

        read_buf: []const u8 = "",
        received_close_notify: bool = false,

        const Self = @This();

        /// Encrypts and writes single tls record to the stream.
        fn writeRecord(c: *Self, content_type: proto.ContentType, bytes: []const u8) !void {
            assert(bytes.len <= cipher.max_cleartext_len);
            var write_buf: [cipher.max_ciphertext_record_len]u8 = undefined;
            // If key update is requested send key update message and update
            // my encryption keys.
            if (c.cipher.encryptSeq() >= c.max_encrypt_seq or @atomicLoad(bool, &c.key_update_requested, .monotonic)) {
                @atomicStore(bool, &c.key_update_requested, false, .monotonic);

                // If the request_update field is set to "update_requested",
                // then the receiver MUST send a KeyUpdate of its own with
                // request_update set to "update_not_requested" prior to sending
                // its next Application Data record. This mechanism allows
                // either side to force an update to the entire connection, but
                // causes an implementation which receives multiple KeyUpdates
                // while it is silent to respond with a single update.
                //
                // rfc: https://datatracker.ietf.org/doc/html/rfc8446#autoid-57
                const key_update = &record.handshakeHeader(.key_update, 1) ++ [_]u8{0};
                const rec = try c.cipher.encrypt(&write_buf, .handshake, key_update);
                try c.stream.writeAll(rec);
                try c.cipher.keyUpdateEncrypt();
            }
            const rec = try c.cipher.encrypt(&write_buf, content_type, bytes);
            try c.stream.writeAll(rec);
        }

        fn writeAlert(c: *Self, err: anyerror) !void {
            const cleartext = proto.alertFromError(err);
            var buf: [128]u8 = undefined;
            const ciphertext = try c.cipher.encrypt(&buf, .alert, &cleartext);
            c.stream.writeAll(ciphertext) catch {};
        }

        /// Returns next record of cleartext data.
        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try client.next()) |buf| { ... }
        pub fn next(c: *Self) ReadError!?[]const u8 {
            const content_type, const data = c.nextRecord() catch |err| {
                // Write alert on tls errors.
                // Stream errors return to the caller.
                if (mem.startsWith(u8, @errorName(err), "Tls"))
                    try c.writeAlert(err);
                return err;
            } orelse return null;
            if (content_type != .application_data) return error.TlsUnexpectedMessage;
            return data;
        }

        fn nextRecord(c: *Self) ReadError!?struct { proto.ContentType, []const u8 } {
            if (c.eof()) return null;
            while (true) {
                const content_type, const cleartext = try c.rec_rdr.nextDecrypt(&c.cipher) orelse return null;

                switch (content_type) {
                    .application_data => {},
                    .handshake => {
                        const handshake_type: proto.Handshake = @enumFromInt(cleartext[0]);
                        switch (handshake_type) {
                            // skip new session ticket and read next record
                            .new_session_ticket => continue,
                            .key_update => {
                                if (cleartext.len != 5) return error.TlsDecodeError;
                                // rfc: Upon receiving a KeyUpdate, the receiver MUST
                                // update its receiving keys.
                                try c.cipher.keyUpdateDecrypt();
                                const key: proto.KeyUpdateRequest = @enumFromInt(cleartext[4]);
                                switch (key) {
                                    .update_requested => {
                                        @atomicStore(bool, &c.key_update_requested, true, .monotonic);
                                    },
                                    .update_not_requested => {},
                                    else => return error.TlsIllegalParameter,
                                }
                                // this record is handled read next
                                continue;
                            },
                            else => {},
                        }
                    },
                    .alert => {
                        if (cleartext.len < 2) return error.TlsUnexpectedMessage;
                        try proto.Alert.parse(cleartext[0..2].*).toError();
                        // server side clean shutdown
                        c.received_close_notify = true;
                        return null;
                    },
                    else => return error.TlsUnexpectedMessage,
                }
                return .{ content_type, cleartext };
            }
        }

        pub fn eof(c: *Self) bool {
            return c.received_close_notify and c.read_buf.len == 0;
        }

        pub fn close(c: *Self) !void {
            if (c.received_close_notify) return;
            try c.writeRecord(.alert, &proto.Alert.closeNotify());
        }

        // read, write interface

        pub const ReadError = Stream.ReadError || proto.Alert.Error ||
            error{
                TlsBadVersion,
                TlsUnexpectedMessage,
                TlsRecordOverflow,
                TlsDecryptError,
                TlsDecodeError,
                TlsBadRecordMac,
                TlsIllegalParameter,
                TlsCipherNoSpaceLeft,
            };
        pub const WriteError = Stream.WriteError ||
            error{
                TlsCipherNoSpaceLeft,
                TlsUnexpectedMessage,
            };

        pub const Reader = std.io.Reader(*Self, ReadError, read);
        pub const Writer = std.io.Writer(*Self, WriteError, write);

        pub fn reader(c: *Self) Reader {
            return .{ .context = c };
        }

        pub fn writer(c: *Self) Writer {
            return .{ .context = c };
        }

        /// Encrypts cleartext and writes it to the underlying stream as single
        /// tls record. Max single tls record payload length is 1<<14 (16K)
        /// bytes.
        pub fn write(c: *Self, bytes: []const u8) WriteError!usize {
            const n = @min(bytes.len, cipher.max_cleartext_len);
            try c.writeRecord(.application_data, bytes[0..n]);
            return n;
        }

        /// Encrypts cleartext and writes it to the underlying stream. If needed
        /// splits cleartext into multiple tls record.
        pub fn writeAll(c: *Self, bytes: []const u8) WriteError!void {
            var index: usize = 0;
            while (index < bytes.len) {
                index += try c.write(bytes[index..]);
            }
        }

        pub fn read(c: *Self, buffer: []u8) ReadError!usize {
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
        pub fn readAll(c: *Self, buffer: []u8) ReadError!usize {
            return c.readAtLeast(buffer, buffer.len);
        }

        /// Returns the number of bytes read, calling the underlying read function
        /// the minimal number of times until the buffer has at least `len` bytes
        /// filled. If the number read is less than `len` it means the stream
        /// reached the end.
        pub fn readAtLeast(c: *Self, buffer: []u8, len: usize) ReadError!usize {
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
        pub fn readv(c: *Self, iovecs: []std.posix.iovec) !usize {
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
    var conn: Connection(@TypeOf(stream)) = .{ .stream = stream, .rec_rdr = record.reader(stream) };
    conn.cipher = try Cipher.initTls12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &data12.key_material, .client);
    conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.rnd = testu.random(0); // use fixed rng

    conn.stream.output.reset();
    { // encrypt verify data from example
        _ = testu.random(0x40); // sets iv to 40, 41, ... 4f
        try conn.writeRecord(.handshake, &data12.client_finished);
        try testing.expectEqualSlices(u8, &data12.verify_data_encrypted_msg, conn.stream.output.getWritten());
    }

    conn.stream.output.reset();
    { // encrypt ping
        const cleartext = "ping";
        _ = testu.random(0); // sets iv to 00, 01, ... 0f
        //conn.encrypt_seq = 1;

        try conn.writeAll(cleartext);
        try testing.expectEqualSlices(u8, &data12.encrypted_ping_msg, conn.stream.output.getWritten());
    }
    { // decrypt server pong message
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.decrypt_seq = 1;
        try testing.expectEqualStrings("pong", (try conn.next()).?);
    }
    { // test reader interface
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.decrypt_seq = 1;
        var rdr = conn.reader();
        var buffer: [4]u8 = undefined;
        const n = try rdr.readAll(&buffer);
        try testing.expectEqualStrings("pong", buffer[0..n]);
    }
    { // test readv interface
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.decrypt_seq = 1;
        var buffer: [9]u8 = undefined;
        var iovecs = [_]std.posix.iovec{
            .{ .base = &buffer, .len = 3 },
            .{ .base = buffer[3..], .len = 3 },
            .{ .base = buffer[6..], .len = 3 },
        };
        const n = try conn.readv(iovecs[0..]);
        try testing.expectEqual(4, n);
        try testing.expectEqualStrings("pong", buffer[0..n]);
    }
}

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
};

test "client/server connection" {
    const BufReaderWriter = struct {
        buf: []u8,
        wp: usize = 0,
        rp: usize = 0,

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) !usize {
            if (self.wp == self.buf.len) return error.NoSpaceLeft;

            const n = @min(bytes.len, self.buf.len - self.wp);
            @memcpy(self.buf[self.wp..][0..n], bytes[0..n]);
            self.wp += n;
            return n;
        }

        pub fn writeAll(self: *Self, bytes: []const u8) !void {
            var n: usize = 0;
            while (n < bytes.len) {
                n += try self.write(bytes[n..]);
            }
        }

        pub fn read(self: *Self, bytes: []u8) !usize {
            const n = @min(bytes.len, self.wp - self.rp);
            if (n == 0) return 0;
            @memcpy(bytes[0..n], self.buf[self.rp..][0..n]);
            self.rp += n;
            if (self.rp == self.wp) {
                self.wp = 0;
                self.rp = 0;
            }
            return n;
        }
    };

    const TestStream = struct {
        inner_stream: *BufReaderWriter,
        const Self = @This();
        pub const ReadError = error{};
        pub const WriteError = error{NoSpaceLeft};
        pub fn read(self: *Self, bytes: []u8) !usize {
            return try self.inner_stream.read(bytes);
        }
        pub fn writeAll(self: *Self, bytes: []const u8) !void {
            return try self.inner_stream.writeAll(bytes);
        }
    };

    const buf_len = 32 * 1024;
    const tls_records_in_buf = (std.math.divCeil(comptime_int, buf_len, cipher.max_cleartext_len) catch unreachable);
    const overhead: usize = tls_records_in_buf * @import("cipher.zig").encrypt_overhead_tls_13;
    var buf: [buf_len + overhead]u8 = undefined;
    var inner_stream = BufReaderWriter{ .buf = &buf };

    const cipher_client, const cipher_server = brk: {
        const Transcript = @import("transcript.zig").Transcript;
        const CipherSuite = @import("cipher.zig").CipherSuite;
        const cipher_suite: CipherSuite = .AES_256_GCM_SHA384;

        var rnd: [128]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        const secret = Transcript.Secret{
            .client = rnd[0..64],
            .server = rnd[64..],
        };

        break :brk .{
            try Cipher.initTls13(cipher_suite, secret, .client),
            try Cipher.initTls13(cipher_suite, secret, .server),
        };
    };

    var conn1 = connection(TestStream{ .inner_stream = &inner_stream });
    conn1.cipher = cipher_client;

    var conn2 = connection(TestStream{ .inner_stream = &inner_stream });
    conn2.cipher = cipher_server;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();
    var send_buf: [buf_len]u8 = undefined;
    var recv_buf: [buf_len]u8 = undefined;
    random.bytes(&send_buf); // fill send buffer with random bytes

    for (0..16) |_| {
        const n = buf_len; //random.uintLessThan(usize, buf_len);

        const sent = send_buf[0..n];
        try conn1.writeAll(sent);
        const r = try conn2.readAll(&recv_buf);
        const received = recv_buf[0..r];

        try testing.expectEqual(n, r);
        try testing.expectEqualSlices(u8, sent, received);
    }
}

pub const NonBlock = struct {
    const Self = @This();

    cipher: Cipher,

    pub fn init(c: Cipher) Self {
        return .{ .cipher = c };
    }

    /// Required ciphertext buffer length for the given cleartext length.
    pub fn encryptedLength(self: Self, cleartext_len: usize) usize {
        const records_count = cleartext_len / cipher.max_cleartext_len;
        if (records_count == 0) return self.cipher.recordLen(cleartext_len);
        const last_chunk_len = cleartext_len - cipher.max_cleartext_len * records_count;
        return self.cipher.recordLen(cipher.max_cleartext_len) * records_count +
            if (last_chunk_len == 0) 0 else self.cipher.recordLen(last_chunk_len);
    }

    /// Encrypts cleartext into ciphertext.
    /// If ciphertext.len is >= encryptedLength(cleartext.len) whole
    /// cleartext will be consumed.
    pub fn encrypt(
        self: *Self,
        /// Cleartext data to encrypt
        cleartext: []const u8,
        /// Write buffer for ciphertext; encrypted data
        ciphertext: []u8,
    ) !struct {
        /// Number of bytes consumed from cleartext
        cleartext_pos: usize = 0,
        /// Unused part of the provided cleartext buffer
        unused_cleartext: []const u8,
        /// Encrypted ciphertext data
        ciphertext: []u8,
    } {
        var cleartext_pos: usize = 0;
        var ciphertext_pos: usize = 0;
        while (cleartext_pos < cleartext.len) {
            const cleartext_record_len = @min(cleartext[cleartext_pos..].len, cipher.max_cleartext_len);
            if (self.cipher.recordLen(cleartext_record_len) > (ciphertext.len - ciphertext_pos)) break; // not enough space in ciphertext
            const cleartext_record = cleartext[cleartext_pos..][0..cleartext_record_len];
            const ciphertext_record = try self.cipher.encrypt(
                ciphertext[ciphertext_pos..],
                .application_data,
                cleartext_record,
            );
            cleartext_pos += cleartext_record_len;
            ciphertext_pos += ciphertext_record.len;
        }
        return .{
            .cleartext_pos = cleartext_pos,
            .unused_cleartext = cleartext[cleartext_pos..],
            .ciphertext = ciphertext[0..ciphertext_pos],
        };
    }

    /// Decrypts ciphertext into cleartext.
    /// NOTE: It is safe to reuses ciphertext buffer for cleartext data.
    pub fn decrypt(
        self: *Self,
        /// Ciphertext data recieved from the other side of the tls connection
        ciphertext: []const u8,
        /// Write buffer for cleartext; decrypted data
        cleartext: []u8,
    ) !struct {
        /// Number of bytes consumed from provided ciphertext buffer
        ciphertext_pos: usize,
        /// Unconsumed part of the provided ciphertext buffer
        unused_ciphertext: []const u8,
        /// Decrypted cleartext data
        cleartext: []u8,
        /// Is clear notify alert received
        closed: bool = false,
    } {
        // Part of the ciphertext buffer filled with cleartext
        var cleartext_len: usize = 0;
        var rdr = record.bufferReader(ciphertext);
        while (true) {
            // Find full tls record
            const rec = (try rdr.next()) orelse break;
            if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

            // Decrypt record
            const content_type, const cleartext_rec = try self.cipher.decrypt(cleartext[cleartext_len..], rec);

            switch (content_type) {
                // Move cleartext pointer
                .application_data => cleartext_len += cleartext_rec.len,
                .handshake => {
                    // TODO: handle key_update and new_session_ticket
                    continue;
                },
                .alert => {
                    if (cleartext.len < 2) return error.TlsUnexpectedMessage;
                    try proto.Alert.parse(cleartext_rec[0..2].*).toError();
                    return .{
                        .ciphertext_pos = rdr.bytesRead(),
                        .unused_ciphertext = ciphertext[rdr.bytesRead()..],
                        .cleartext = cleartext[0..cleartext_len],
                        .closed = true,
                    };
                },
                else => return error.TlsUnexpectedMessage,
            }
        }

        return .{
            .ciphertext_pos = rdr.bytesRead(),
            .unused_ciphertext = ciphertext[rdr.bytesRead()..],
            .cleartext = cleartext[0..cleartext_len],
        };
    }

    pub fn close(self: *Self, ciphertext: []u8) ![]const u8 {
        return try self.cipher.encrypt(ciphertext, .alert, &proto.Alert.closeNotify());
    }
};

test "nonblock encrypt" {
    const data13 = @import("testdata/tls13.zig");
    const client_cipher, _ = cipher.testCiphers();
    var conn = NonBlock.init(client_cipher);

    const cleartext = "ping";
    try testing.expectEqual(26, conn.encryptedLength(cleartext.len));

    var ciphertext: [32]u8 = undefined;

    // while ciphertext buffer is not enough for cleartext record
    for (0..25) |i| {
        const res = try conn.encrypt(cleartext, ciphertext[0..i]);
        try testing.expectEqual(0, res.cleartext_pos);
        try testing.expectEqual(0, res.ciphertext.len);
    }

    // with enough big buffer
    const res = try conn.encrypt(cleartext, &ciphertext);
    try testing.expectEqual(cleartext.len, res.cleartext_pos);
    try testing.expectEqual(26, res.ciphertext.len);
    try testing.expectEqualSlices(u8, &data13.client_ping_wrapped, res.ciphertext);
}
