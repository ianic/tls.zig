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

/// Asynchronous, non-blocking tls connection. Does not depend on inner network
/// stream reader. For use in io_uring or similar completion based io.
///
/// This implementation works for both client and server tls handsake type; that
/// is why it is generic over handshake type and options.
///
/// Handler should connect this library with upstream application and downstream
/// tcp connection.
///
/// Handler methods which will be called:
///
///   onConnect()           - notification that tls handshake is done
///   onRecv(cleartext)     - cleartext data to pass to the application
///   send(buf)             - ciphertext to pass to the underlying tcp connection
///
/// Interface provided to the handler:
///
///   onConnect()        - should be called after tcp connection is established
///   onRecv(ciphertext) - data received on the underlying tcp connection
///   send               - data to send by the underlying tcp connection
///   onSend             - notification that tcp is done coping buffer to the kernel
///
/// Handler should establish tcp connection and call onConnect(). That will
/// fire handler.send with tls hello (in the case of client handshake type).
/// For each raw tcp data handler should call onRecv(). During handshake that
/// data will be consumed here. When handshake succeeds we will have cipher,
/// release handshake and call handler.onRecv() with decrypted cleartext data.
///
/// After handshake handler can call send with cleartext data, that will be
/// encrypted and pass to handler.send(). Any raw ciphertext received
/// on tcp should be pass to onRecv() to decrypt and pass to
/// handler.onRecv().
///
pub fn Async(comptime Handler: type, comptime HandshakeType: type, comptime Options: type) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        handler: Handler,
        handshake: ?*HandshakeType = null,
        cipher: ?Cipher = null,

        pub fn init(allocator: mem.Allocator, handler: Handler, opt: Options) !Self {
            const handshake = try allocator.create(HandshakeType);
            errdefer allocator.destroy(handshake);
            try handshake.init(opt);
            return .{
                .allocator = allocator,
                .handler = handler,
                .handshake = handshake,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.handshake) |handshake|
                self.allocator.destroy(handshake);
        }

        // ----------------- Handler interface

        /// Notification that tcp connection has been established. For client
        /// tls handshake type this will start tls handshake.
        pub fn onConnect(self: *Self) !void {
            try self.handshakeSend();
        }

        /// Notification that underlying tcp connection has received data. It
        /// will be used in handshake or if handshake is done it will be
        /// decrypted and handler's onRecv will be called with cleartext data.
        pub fn onRecv(self: *Self, ciphertext: []u8) !usize {
            return if (self.handshake) |_|
                try self.handshakeRecv(ciphertext)
            else
                try self.decrypt(ciphertext);
        }

        /// Handler call this when need to send data. Cleartext data will be
        /// encrypted and sent to the underlying tcp connection by calling
        /// handler's send method with ciphertext data.
        pub fn send(self: *Self, cleartext: []const u8) !void {
            if (self.handshake != null) return error.InvalidState;
            // Allocate ciphertext buffer
            const ciphertext = try self.allocator.alloc(u8, self.encryptedLength(cleartext.len));
            errdefer self.allocator.free(ciphertext);
            // Fill ciphertext with encrypted tls records
            const cleartext_index, const ciphertext_index = try self.encrypt(cleartext, ciphertext);
            //
            assert(ciphertext_index == ciphertext.len);
            assert(cleartext_index == cleartext.len);
            try self.handler.send(ciphertext);
        }

        /// Required ciphertext buffer length for the given cleartext length.
        fn encryptedLength(self: *Self, cleartext_len: usize) usize {
            const records_count = cleartext_len / cipher.max_cleartext_len;

            // if we have cipher return exact buffer size
            if (self.cipher) |*chp| {
                return if (records_count == 0)
                    chp.recordLen(cleartext_len)
                else brk: {
                    const last_chunk_len = cleartext_len - cipher.max_cleartext_len * records_count;
                    break :brk chp.recordLen(cipher.max_cleartext_len) * records_count +
                        if (last_chunk_len == 0) 0 else chp.recordLen(last_chunk_len);
                };
            }

            // max, works for all ciphers
            return cipher.max_ciphertext_record_len * (1 + records_count);
        }

        /// Encrypts cleartext into ciphertext. Returns number of bytes consumed
        /// from cleartext and number of bytes written to the ciphertext.
        fn encrypt(self: *Self, cleartext: []const u8, ciphertext: []u8) !struct { usize, usize } {
            const chp = &(self.cipher orelse return error.InvalidState);
            var cleartext_index: usize = 0;
            var ciphertext_index: usize = 0;
            while (cleartext_index < cleartext.len) {
                const cleartext_record_len = @min(cleartext[cleartext_index..].len, cipher.max_cleartext_len);
                if (chp.recordLen(cleartext_record_len) > (ciphertext.len - ciphertext_index)) break; // not enough space in ciphertext
                const cleartext_record = cleartext[cleartext_index..][0..cleartext_record_len];
                const ciphertext_record = try chp.encrypt(ciphertext[ciphertext_index..], .application_data, cleartext_record);
                cleartext_index += cleartext_record_len;
                ciphertext_index += ciphertext_record.len;
            }
            return .{ cleartext_index, ciphertext_index };
        }

        /// Notification that buffer allocated in send is copied to the kernel,
        /// it is safe to free it now.
        pub fn onSend(self: *Self, ciphertext: []const u8) void {
            if (self.handshake) |_| {
                // Nothing to release during handshake, handshake uses static
                // write buffer.
                self.checkHandshakeDone();
            } else {
                self.allocator.free(ciphertext);
            }
        }

        // ----------------- Handler interface end

        /// NOTE: decrypt reuses provided ciphertext buffer for cleartext data
        fn decrypt(self: *Self, ciphertext: []u8) !usize {
            // Part of the ciphertext buffer filled with cleartext
            var cleartext_len: usize = 0;
            const ret = self.decrypt_(ciphertext, &cleartext_len);
            if (cleartext_len > 0)
                try self.handler.onRecv(ciphertext[0..cleartext_len]);
            return ret;
        }

        /// Returns number of bytes consumed from ciphertext.
        /// cleartext_len defines part of ciphertext with decrypted cleartext data.
        fn decrypt_(self: *Self, ciphertext: []u8, cleartext_len: *usize) !usize {
            const chp = &(self.cipher orelse return error.InvalidState);
            var rdr = record.bufferReader(ciphertext);
            while (true) {
                // Find full tls record
                const rec = (try rdr.next()) orelse break;
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

                // Decrypt record
                const content_type, const cleartext = try chp.decrypt(ciphertext[cleartext_len.*..], rec);

                switch (content_type) {
                    // Move cleartext pointer
                    .application_data => cleartext_len.* += cleartext.len,
                    .handshake => {
                        // TODO: handle key_update and new_session_ticket
                        continue;
                    },
                    .alert => {
                        if (cleartext.len < 2) return error.TlsUnexpectedMessage;
                        try proto.Alert.parse(cleartext[0..2].*).toError();
                        return error.EndOfFile; // close notify received
                    },
                    else => return error.TlsUnexpectedMessage,
                }
            }
            return rdr.bytesRead();
        }

        fn handshakeRecv(self: *Self, buf: []u8) !usize {
            var handshake = self.handshake orelse unreachable;
            const n = handshake.recv(buf) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => return err,
            };
            self.checkHandshakeDone();
            if (n > 0) try self.handshakeSend();
            return n;
        }

        fn checkHandshakeDone(self: *Self) void {
            var handshake = self.handshake orelse unreachable;
            if (!handshake.done()) return;

            self.cipher = handshake.inner.cipher;
            self.allocator.destroy(handshake);
            self.handshake = null;

            self.handler.onConnect();
        }

        fn handshakeSend(self: *Self) !void {
            var handshake = self.handshake orelse return;
            if (try handshake.send()) |buf|
                try self.handler.send(buf);
        }
    };
}

test "async decrypt" {
    const Handler = struct {
        const Self = @This();
        allocator: mem.Allocator,
        bytes: []u8 = &.{},

        pub fn onRecv(self: *Self, cleartext: []const u8) !void {
            // append cleartext to self.bytes
            self.bytes = try self.allocator.realloc(self.bytes, self.bytes.len + cleartext.len);
            @memcpy(self.bytes[self.bytes.len - cleartext.len ..], cleartext);
        }
    };
    var handler: Handler = .{
        .allocator = testing.allocator,
    };
    defer testing.allocator.free(handler.bytes);

    var client_cipher, const server_cipher = cipher.testCiphers();

    var conn: Async(*Handler, void, void) = .{
        .allocator = undefined,
        .handshake = null,
        .cipher = server_cipher,
        .handler = &handler,
    };
    defer conn.deinit();

    var ciphertext: [1024]u8 = undefined;
    var ciphertext_len: usize = 0;

    var cleartext: [512]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    prng.random().bytes(&cleartext);

    { // expect handler.onRecv to be called with cleartext
        ciphertext_len = (try client_cipher.encrypt(&ciphertext, .application_data, &cleartext)).len;
        try testing.expectEqual(ciphertext_len, try conn.decrypt(ciphertext[0..ciphertext_len]));
        try testing.expectEqualSlices(u8, handler.bytes, &cleartext);
    }
    { // expect handler.onRecv to be called with cleartext and decrypt to return error.EndOfFile
        // split cleartext into two tls records
        ciphertext_len = (try client_cipher.encrypt(&ciphertext, .application_data, cleartext[0 .. cleartext.len / 2])).len;
        ciphertext_len += (try client_cipher.encrypt(ciphertext[ciphertext_len..], .application_data, cleartext[cleartext.len / 2 ..])).len;
        // add close notify alert record at the end
        ciphertext_len += (try client_cipher.encrypt(ciphertext[ciphertext_len..], .alert, &proto.Alert.closeNotify())).len;
        try testing.expectEqual(580, ciphertext_len);

        try testing.expectError(error.EndOfFile, conn.decrypt(ciphertext[0..ciphertext_len]));
        try testing.expectEqualSlices(u8, handler.bytes[cleartext.len..], &cleartext);
    }
}

test "async encrypt" {
    const data13 = @import("testdata/tls13.zig");
    const client_cipher, _ = cipher.testCiphers();

    const Handler = struct {};
    var conn: Async(*Handler, void, void) = .{
        .allocator = undefined,
        .handshake = null,
        .cipher = client_cipher,
        .handler = undefined,
    };
    defer conn.deinit();

    const cleartext = "ping";
    try testing.expectEqual(26, conn.encryptedLength(cleartext.len));

    var ciphertext: [32]u8 = undefined;

    // while ciphertext buffer is not enough for cleartext record
    for (0..25) |i| {
        const cleartext_index, const ciphertext_index = try conn.encrypt(cleartext, ciphertext[0..i]);
        try testing.expectEqual(0, cleartext_index);
        try testing.expectEqual(0, ciphertext_index);
    }

    // with enough big buffer
    const cleartext_index, const ciphertext_index = try conn.encrypt(cleartext, &ciphertext);
    try testing.expectEqual(cleartext.len, cleartext_index);
    try testing.expectEqual(26, ciphertext_index);
    try testing.expectEqualSlices(u8, &data13.client_ping_wrapped, ciphertext[0..ciphertext_index]);
}

/// Non blocking connection.
///
/// Caller should call handshake until connection is established (isConnected
/// returns true). Handshake is called with data received from tls peer and
/// send_buffer in which handshake will preapre data to be sent to the peer.
/// Client starts tls handshake by calling handshake with empty received data.
///
/// After connection is established. Caller can use encrypt to prepare
/// ciphertext data from cleartext to send to the peer. And decrypt with
/// ciphertext received from the peer to get cleartext sent by the peer.
pub fn NonBlocking(comptime HandshakeType: type, comptime Options: type) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        hsk: ?*HandshakeType = null,
        cipher: ?Cipher = null,

        pub fn init(allocator: mem.Allocator, opt: Options) !Self {
            const hsk = try allocator.create(HandshakeType);
            errdefer allocator.destroy(hsk);
            try hsk.init(opt);
            return .{
                .allocator = allocator,
                .hsk = hsk,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.hsk) |hsk|
                self.allocator.destroy(hsk);
        }

        /// Returns number of bytes consumed from received data and number of
        /// bytes prepared in send_buffer.
        pub fn handshake(self: *Self, received_data: []u8, send_buffer: []u8) !struct { usize, usize } {
            var hsk = self.hsk orelse return error.InvalidState;
            assert(self.cipher == null);
            assert(send_buffer.len >= cipher.max_ciphertext_record_len);
            hsk.inner.buffer = send_buffer;

            const received_index = if (received_data.len > 0)
                hsk.recv(received_data) catch |err| switch (err) {
                    error.EndOfStream => 0,
                    else => return err,
                }
            else
                0;

            const send_index: usize = if (try hsk.send()) |buf| buf.len else 0;
            if (hsk.done()) {
                self.cipher = hsk.inner.cipher;
                self.allocator.destroy(hsk);
                self.hsk = null;
            }

            return .{ received_index, send_index };
        }

        /// True when handshake is finished and encrypt/decrypt can be be used.
        pub fn isConnected(self: *Self) bool {
            return self.cipher != null;
        }

        /// Required ciphertext buffer length for the given cleartext length.
        pub fn encryptedLength(self: *Self, cleartext_len: usize) usize {
            const records_count = cleartext_len / cipher.max_cleartext_len;

            // if we have cipher return exact buffer size
            if (self.cipher) |*chp| {
                return if (records_count == 0)
                    chp.recordLen(cleartext_len)
                else brk: {
                    const last_chunk_len = cleartext_len - cipher.max_cleartext_len * records_count;
                    break :brk chp.recordLen(cipher.max_cleartext_len) * records_count +
                        if (last_chunk_len == 0) 0 else chp.recordLen(last_chunk_len);
                };
            }

            // max, works for all ciphers
            return cipher.max_ciphertext_record_len * (1 + records_count);
        }

        /// Encrypts cleartext into ciphertext. Returns number of bytes consumed
        /// from cleartext and number of bytes written to the ciphertext.
        /// If ciphertext.len is >= encryptedLength(cleartext.len) whole
        /// cleartext will be consumed.
        pub fn encrypt(self: *Self, cleartext: []const u8, ciphertext: []u8) !struct { usize, usize } {
            const chp = &(self.cipher orelse return error.InvalidState);
            var cleartext_index: usize = 0;
            var ciphertext_index: usize = 0;
            while (cleartext_index < cleartext.len) {
                const cleartext_record_len = @min(cleartext[cleartext_index..].len, cipher.max_cleartext_len);
                if (chp.recordLen(cleartext_record_len) > (ciphertext.len - ciphertext_index)) break; // not enough space in ciphertext
                const cleartext_record = cleartext[cleartext_index..][0..cleartext_record_len];
                const ciphertext_record = try chp.encrypt(ciphertext[ciphertext_index..], .application_data, cleartext_record);
                cleartext_index += cleartext_record_len;
                ciphertext_index += ciphertext_record.len;
            }
            return .{ cleartext_index, ciphertext_index };
        }

        /// Returns number of bytes consumed from ciphertext, number of bytes of
        /// decrypted cleartext  data  in the  provided  ciphretext buffer  and
        /// whether the tls connection is closed.
        ///
        /// NOTE: decrypt reuses provided ciphertext buffer for cleartext data
        pub fn decrypt(self: *Self, ciphertext: []u8) !struct { usize, usize, bool } {
            const chp = &(self.cipher orelse return error.InvalidState);

            // Part of the ciphertext buffer filled with cleartext
            var cleartext_len: usize = 0;
            var rdr = record.bufferReader(ciphertext);
            while (true) {
                // Find full tls record
                const rec = (try rdr.next()) orelse break;
                if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

                // Decrypt record
                const content_type, const cleartext = try chp.decrypt(ciphertext[cleartext_len..], rec);

                switch (content_type) {
                    // Move cleartext pointer
                    .application_data => cleartext_len += cleartext.len,
                    .handshake => {
                        // TODO: handle key_update and new_session_ticket
                        continue;
                    },
                    .alert => {
                        if (cleartext.len < 2) return error.TlsUnexpectedMessage;
                        try proto.Alert.parse(cleartext[0..2].*).toError();
                        // return error.EndOfFile;
                        // close notify received
                        return .{ rdr.bytesRead(), cleartext_len, true };
                    },
                    else => return error.TlsUnexpectedMessage,
                }
            }

            return .{ rdr.bytesRead(), cleartext_len, false };
        }
    };
}
