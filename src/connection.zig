const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Io = std.Io;
const assert = std.debug.assert;

const proto = @import("protocol.zig");
const record = @import("record.zig");
const Record = record.Record;
const cipher = @import("cipher.zig");
const Cipher = cipher.Cipher;
const SessionResumption = @import("handshake_client.zig").Options.SessionResumption;

const log = std.log.scoped(.tls);

pub const Connection = struct {
    /// Underlying network connection stream reader/writer pair.
    input: *Io.Reader, // source of the encrypted (ciphertext) data
    output: *Io.Writer, // sink to send encrypted (ciphertext) data
    cipher: Cipher,

    max_encrypt_seq: u64 = std.math.maxInt(u64) - 1,
    key_update_requested: bool = false,
    received_close_notify: bool = false,
    close_alert: proto.Alert = .close_notify,
    /// Part of the cleartext record returned from next but not yet read by client.
    cleartext_buf: []const u8 = &.{},

    session_resumption: ?*SessionResumption = null,
    session_resumption_secret_idx: ?usize = null,

    /// ALPN protocol negotiated during TLS handshake (e.g., "h2", "http/1.1").
    /// Points into static data or the options slice; valid for the connection lifetime.
    alpn_protocol: ?[]const u8 = null,

    const Self = @This();

    /// Encrypts and writes single tls record to the stream.
    fn writeRecord(c: *Self, content_type: proto.ContentType, bytes: []const u8) !void {
        assert(bytes.len <= cipher.max_cleartext_len);
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
            try c.encryptWrite(.handshake, key_update);
            try c.cipher.keyUpdateEncrypt();
        }
        try c.encryptWrite(content_type, bytes);
    }

    fn encryptWrite(c: *Self, content_type: proto.ContentType, bytes: []const u8) !void {
        const encrypted_len = c.cipher.recordLen(bytes.len);
        const writable = try c.output.writableSliceGreedy(encrypted_len);
        const rec = try c.cipher.encrypt(writable, content_type, bytes);
        c.output.advance(rec.len);
        try c.output.flush();
    }

    /// Returns next record of cleartext data. Null on end of stream.
    /// Can be used in iterator like loop without memcpy to another buffer:
    ///   while (try client.next()) |buf| { ... }
    pub fn next(c: *Self) anyerror!?[]const u8 {
        return c.nextRecord(&.{}) catch |err| {
            if (err == error.EndOfStream) return null;
            // Write alert on tls errors.
            // Stream errors return to the caller.
            if (mem.startsWith(u8, @errorName(err), "Tls"))
                @atomicStore(proto.Alert, &c.close_alert, proto.Alert.fromError(err), .monotonic);
            return err;
        };
    }

    /// Decrypt next tls record into buffer, if buffer is not big enough reuse
    /// input ciphertext buffer for cleartext. Returns cleartext of the next tls
    /// record.
    fn nextRecord(c: *Self, buffer: []u8) ![]const u8 {
        assert(c.cleartext_buf.len == 0);
        if (@atomicLoad(bool, &c.received_close_notify, .monotonic)) return error.EndOfStream;
        while (true) {
            const rec = try Record.read(c.input);
            if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

            // If provided buffer is not big enough reuse input buffer for
            // cleartext. `rec.header` and `rec.payload`(ciphertext) are
            // pointing somewhere in this buffer. Decrypter is first reading
            // then writing a block, cleartext has less length then ciphertext,
            // cleartext starts from the beginning of the buffer, so ciphertext
            // is always ahead of cleartext.
            const cleartext_buf = if (buffer.len >= rec.payload.len) buffer else @constCast(rec.buffer);
            const content_type, const cleartext = try c.cipher.decrypt(cleartext_buf, rec);

            switch (content_type) {
                .application_data => {},
                .handshake => {
                    // rfc 8446: implementations MUST NOT send zero-length
                    // fragments of Handshake types.
                    if (cleartext.len == 0) return error.TlsUnexpectedMessage;
                    const handshake_type: proto.Handshake = @enumFromInt(cleartext[0]);
                    switch (handshake_type) {
                        .new_session_ticket => {
                            if (c.session_resumption) |r| {
                                r.pushTicket(cleartext, c.session_resumption_secret_idx.?) catch {};
                            }
                            continue;
                        },
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
                    @atomicStore(bool, &c.received_close_notify, true, .monotonic);
                    return error.EndOfStream;
                },
                else => return error.TlsUnexpectedMessage,
            }
            return cleartext;
        }
    }

    pub fn eof(c: *Self) bool {
        return @atomicLoad(bool, &c.received_close_notify, .monotonic) and c.cleartext_buf.len == 0;
    }

    pub fn close(c: *Self) anyerror!void {
        if (@atomicLoad(bool, &c.received_close_notify, .monotonic)) return;
        const alert = @atomicLoad(proto.Alert, &c.close_alert, .monotonic);
        try c.writeRecord(.alert, &alert.format());
    }

    // write/read

    /// Encrypts cleartext and writes it to the underlying stream as single
    /// tls record. Max single tls record payload length is 1<<14 (16K)
    /// bytes.
    pub fn write(c: *Self, bytes: []const u8) !usize {
        if (bytes.len == 0) return 0;
        const encrypt_overhead = c.cipher.encryptOverhead();
        assert(c.output.buffer.len > encrypt_overhead);
        // Find maximum number of bytes which can fit into output buffer as encrypted ciphertext
        const n = @min(bytes.len, cipher.max_cleartext_len, c.output.buffer.len - encrypt_overhead);
        try c.writeRecord(.application_data, bytes[0..n]);
        return n;
    }

    /// Encrypts cleartext and writes it to the underlying stream. If needed
    /// splits cleartext into multiple tls record.
    pub fn writeAll(c: *Self, bytes: []const u8) !void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try c.write(bytes[index..]);
        }
    }

    pub fn read(c: *Self, buffer: []u8) !usize {
        if (c.cleartext_buf.len == 0) {
            const cleartext = c.nextRecord(buffer) catch |err| {
                if (err == error.EndOfStream) return 0;
                if (mem.startsWith(u8, @errorName(err), "Tls"))
                    @atomicStore(proto.Alert, &c.close_alert, proto.Alert.fromError(err), .monotonic);
                return err;
            };
            if (cleartext.ptr == buffer.ptr) {
                // provided buffer is used for cleartext
                return cleartext.len;
            }
            // Buffer was too small input ciphertext buffer was used for cleartext
            // Store reference to the cleartext
            c.cleartext_buf = cleartext;
        }
        // move part of the cleartext_buf into provided buffer
        const n = @min(c.cleartext_buf.len, buffer.len);
        @memmove(buffer[0..n], c.cleartext_buf[0..n]);
        c.cleartext_buf = c.cleartext_buf[n..];
        return n;
    }

    /// Returns the number of bytes read. If the number read is smaller than
    /// `buffer.len`, it means the stream reached the end.
    pub fn readAll(c: *Self, buffer: []u8) !usize {
        return c.readAtLeast(buffer, buffer.len);
    }

    /// Returns the number of bytes read, calling the underlying read function
    /// the minimal number of times until the buffer has at least `len` bytes
    /// filled. If the number read is less than `len` it means the stream
    /// reached the end.
    pub fn readAtLeast(c: *Self, buffer: []u8, len: usize) !usize {
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
            if (c.cleartext_buf.len == 0) {
                c.cleartext_buf = try c.next() orelse break;
            }
            const n = vp.put(c.cleartext_buf);
            const read_buf_len = c.cleartext_buf.len;
            c.cleartext_buf = c.cleartext_buf[n..];
            if (n < read_buf_len or vp.idx >= vp.iovecs.len) break;
        }
        return vp.total;
    }

    // Io.Reader interface

    pub const Reader = struct {
        conn: *Connection,
        interface: Io.Reader,
        err: ?Error = null,

        pub const Error = @typeInfo(@typeInfo(@TypeOf(Connection.read)).@"fn".return_type.?).error_union.error_set;

        pub fn init(c: *Connection, buffer: []u8) Reader {
            return .{
                .conn = c,
                .interface = .{
                    .vtable = &.{
                        .stream = stream,
                    },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const self: *Reader = @fieldParentPtr("interface", r);
            const buf = limit.slice(try w.writableSliceGreedy(1));
            const n = self.conn.read(buf) catch |err| {
                self.err = err;
                if (err == error.EndOfStream) return error.EndOfStream;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            w.advance(n);
            return n;
        }
    };

    /// There is no strict requirement on buffer size.
    /// If the buffer is big enough tls record will be decrypted directly into
    /// provided buffer. If not input buffer will be used for record decryption
    /// and than cleartext will be copied to the reader buffer when needed.
    pub fn reader(c: *Self, buffer: []u8) Reader {
        return .init(c, buffer);
    }

    // Io.Writer interface

    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,
        err: ?Error = null,

        pub const Error = @typeInfo(@typeInfo(@TypeOf(Connection.writeAll)).@"fn".return_type.?).error_union.error_set;

        pub fn init(c: *Connection, buffer: []u8) Writer {
            return .{
                .conn = c,
                .interface = .{
                    .vtable = &.{
                        .drain = drain,
                    },
                    .buffer = buffer,
                    .end = 0,
                },
            };
        }

        fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            // w.buffer is consumed first
            try self.writeAll(w.buffered());
            w.end = 0;

            if (data.len == 0) return 0;
            // Followed by each slice of `data` in order
            var n: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                try self.writeAll(bytes);
                n += bytes.len;
            }

            // Last element of `data` is repeated as necessary so that it is
            // written `splat` number of times, which may be zero.
            const pattern = data[data.len - 1];
            switch (pattern.len) {
                0 => {},
                1 => {
                    var buffer: [cipher.max_cleartext_len]u8 = undefined;
                    @memset(&buffer, pattern[0]);
                    var remaining = splat;
                    while (remaining > 0) {
                        const chunk_len = @min(remaining, buffer.len);
                        try self.writeAll(buffer[0..chunk_len]);
                        remaining -= chunk_len;
                    }
                    n += splat;
                },
                else => for (0..splat) |_| {
                    try self.writeAll(pattern);
                    n += pattern.len;
                },
            }

            // Number of bytes consumed from `data` is returned, excluding bytes
            // from w.buffer.
            return n;
        }

        fn writeAll(self: *Writer, bytes: []const u8) Io.Writer.Error!void {
            self.conn.writeAll(bytes) catch |err| {
                self.err = err;
                return error.WriteFailed;
            };
        }
    };

    pub fn writer(c: *Self, buffer: []u8) Writer {
        return .init(c, buffer);
    }
};

const testing = std.testing;
const data12 = @import("testdata/tls12.zig");
const testu = @import("testu.zig");

test "encrypt decrypt" {
    const rng_impl: std.Random.IoSource = .{ .io = testing.io };
    const rng = rng_impl.interface();
    var output_buf: [1024]u8 = undefined;
    // Records are decrypted in place inside the reader's buffer, so the test
    // data has to be writable; `var` makes a mutable copy of it.
    var input_data = data12.server_pong ** 5;
    var stream_reader: Io.Reader = .fixed(&input_data);
    var stream_writer: Io.Writer = .fixed(&output_buf);
    var conn: Connection = .{
        .input = &stream_reader,
        .output = &stream_writer,
        .cipher = try Cipher.initTls12(.ECDHE_RSA_WITH_AES_128_CBC_SHA, &data12.key_material, .client, rng),
    };
    conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.rng = testu.random(0); // use fixed rng

    { // encrypt verify data from example
        _ = testu.random(0x40); // sets iv to 40, 41, ... 4f
        try conn.writeRecord(.handshake, &data12.client_finished);
        try testing.expectEqualSlices(u8, &data12.verify_data_encrypted_msg, conn.output.buffered());
    }
    _ = conn.output.consumeAll(); // reset writer buffer
    { // encrypt ping
        const cleartext = "ping";
        _ = testu.random(0); // sets iv to 00, 01, ... 0f

        try conn.writeAll(cleartext);
        try testing.expectEqualSlices(u8, &data12.encrypted_ping_msg, conn.output.buffered());
    }
    _ = conn.output.consumeAll();
    { // writer interface
        const cleartext = "ping";
        _ = testu.random(0); // sets iv to 00, 01, ... 0f
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.encrypt_seq = 1; // reset sequence

        var writer = conn.writer(&.{});
        var w = &writer.interface;
        try w.writeAll(cleartext);
        try testing.expectEqualSlices(u8, &data12.encrypted_ping_msg, conn.output.buffered());
    }
    { // decrypt server pong message
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.decrypt_seq = 1;
        try testing.expectEqualStrings("pong", (try conn.next()).?);
    }
    { // test reader interface
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.decrypt_seq = 1;
        var buffer: [2]u8 = undefined;
        var reader = conn.reader(&buffer);
        var rdr = &reader.interface;
        try testing.expectEqualStrings("", conn.cleartext_buf);
        try testing.expectEqualStrings("po", try rdr.take(rdr.buffer.len));
        // cleartext record part which didn't fit into reader buffer
        try testing.expectEqualStrings("ng", conn.cleartext_buf);
        try testing.expectEqualStrings("n", try rdr.take(1));
        try testing.expectEqualStrings("", conn.cleartext_buf);
        try testing.expectEqualStrings("g", try rdr.take(1));
    }
    { // reader discard
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.decrypt_seq = 1;
        var buffer: [5]u8 = undefined;
        var reader = conn.reader(&buffer);
        var rdr = &reader.interface;
        try testing.expectEqual(1, try rdr.discard(.limited(1)));
        try testing.expectEqualStrings("ong", conn.cleartext_buf);
        try testing.expectEqual(3, try rdr.discard(.limited(3)));
    }
    { // test readv interface
        conn.cipher.ECDHE_RSA_WITH_AES_128_CBC_SHA.decrypt_seq = 1;
        var buffer: [4]u8 = undefined;
        var iovecs = [_]std.posix.iovec{
            .{ .base = buffer[0..2], .len = 2 },
            .{ .base = buffer[2..4], .len = 2 },
        };
        const n = try conn.readv(iovecs[0..]);
        try testing.expectEqual(4, n);
        try testing.expectEqualStrings("pong", buffer[0..n]);
        // must not have pulled a record the caller had no room for
        try testing.expectEqualStrings("", conn.cleartext_buf);
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
    const rng_impl: std.Random.IoSource = .{ .io = testing.io };
    const rng = rng_impl.interface();

    // create ciphers pair
    const cipher_client, const cipher_server = brk: {
        const Transcript = @import("transcript.zig").Transcript;
        const CipherSuite = @import("cipher.zig").CipherSuite;
        const cipher_suite: CipherSuite = .AES_256_GCM_SHA384;

        var rnd_buf: [128]u8 = undefined;
        rng.bytes(&rnd_buf);
        const secret = Transcript.Secret{
            .client = rnd_buf[0..64],
            .server = rnd_buf[64..],
        };

        break :brk .{
            try Cipher.initTls13(cipher_suite, secret, .client),
            try Cipher.initTls13(cipher_suite, secret, .server),
        };
    };

    var client_conn: Connection = .{
        .input = undefined,
        .output = undefined,
        .cipher = cipher_client,
    };
    var server_conn: Connection = .{
        .input = undefined,
        .output = undefined,
        .cipher = cipher_server,
    };

    // big enough cleartext to produce multiple tls records
    var cleartext_buf: [cipher.max_cleartext_len * 5]u8 = undefined;
    // fill cleartext_buf with random bytes
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();
    random.bytes(&cleartext_buf);

    // cleartext -> client_conn -> ciphertext -> server_conn -> cleartext
    for (0..16) |_| {
        // use random part of cleartext_buf
        const n = random.intRangeAtMost(usize, cipher.max_cleartext_len + 1, cleartext_buf.len);
        const client_cleartext = cleartext_buf[0..n];

        // prepare ciphertext buffer
        var ciphertext_buf: [cleartext_buf.len]u8 = undefined;
        var w: Io.Writer = .fixed(&ciphertext_buf);
        client_conn.output = &w;

        // write cleartext to the server side
        try client_conn.writeAll(client_cleartext);
        const ciphertext_len = NonBlock.init(cipher_client).encryptedLength(n);
        try testing.expectEqual(ciphertext_len, w.buffered().len);

        // feed ciphertext from client to the server
        var r: Io.Reader = .fixed(w.buffered());
        server_conn.input = &r;
        var server_cleartext_buf: [cleartext_buf.len]u8 = undefined;
        // read cleartext from the server connection
        const nr = try server_conn.readAll(&server_cleartext_buf);
        const server_cleartext = server_cleartext_buf[0..nr];

        try testing.expectEqual(n, nr);
        try testing.expectEqualSlices(u8, client_cleartext, server_cleartext);
    }
}

pub const NonBlock = struct {
    const Self = @This();

    inner: Connection,

    pub fn init(c: Cipher) Self {
        return .{ .inner = .{ .cipher = c, .input = undefined, .output = undefined } };
    }

    /// Required ciphertext buffer length for the given cleartext length.
    pub fn encryptedLength(self: Self, cleartext_len: usize) usize {
        const c = self.inner.cipher;
        // Walk the same chunking `encrypt` walks, so the key update records
        // it emits are counted too. No cleartext means no records at all,
        // which the loop already gives.
        const key_update = &record.handshakeHeader(.key_update, 1) ++ [_]u8{0};
        var total: usize = 0;
        var pos: usize = 0;
        var seq = c.encryptSeq();
        var update_requested = @atomicLoad(bool, &self.inner.key_update_requested, .monotonic);
        while (pos < cleartext_len) {
            if (update_requested or seq >= self.inner.max_encrypt_seq) {
                total += c.recordLen(key_update.len);
                seq = 0;
                update_requested = false;
            }
            const n = @min(cleartext_len - pos, cipher.max_cleartext_len);
            total += c.recordLen(n);
            seq +%= 1;
            pos += n;
        }
        return total;
    }

    fn reset(self: *Self) void {
        self.inner.input = undefined;
        self.inner.output = undefined;
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
        defer self.reset();
        var output: Io.Writer = .fixed(ciphertext);
        self.inner.output = &output;

        var n: usize = 0;
        while (n < cleartext.len and output.end < output.buffer.len) {
            n += try self.inner.write(cleartext[n..]);
        }
        return .{
            .cleartext_pos = n,
            .unused_cleartext = cleartext[n..],
            .ciphertext = output.buffered(),
        };
    }

    /// Decrypts ciphertext into cleartext.
    /// NOTE: It is safe to reuse ciphertext buffer for cleartext data.
    pub fn decrypt(
        self: *Self,
        /// Ciphertext data received from the other side of the tls connection
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
        defer self.reset();
        var input: Io.Reader = .fixed(ciphertext);
        self.inner.input = &input;

        var n: usize = 0;
        while (n < cleartext.len) {
            const nn = self.inner.read(cleartext[n..]) catch |err| switch (err) {
                error.InputBufferUndersize => break,
                else => return err,
            };
            if (nn == 0) break;
            n += nn;
        }

        return .{
            .ciphertext_pos = input.seek,
            .unused_ciphertext = input.buffered(),
            .cleartext = cleartext[0..n],
            .closed = @atomicLoad(bool, &self.inner.received_close_notify, .monotonic),
        };
    }

    pub fn close(self: *Self, ciphertext: []u8) ![]const u8 {
        return try self.inner.cipher.encrypt(ciphertext, .alert, &proto.Alert.closeNotify());
    }
};

test "nonblock encrypt" {
    const data13 = @import("testdata/tls13.zig");
    const client_cipher, _ = cipher.testCiphers();
    var conn = NonBlock.init(client_cipher);

    const cleartext = "ping";
    try testing.expectEqual(26, conn.encryptedLength(cleartext.len));
    var ciphertext: [32]u8 = undefined;

    // with enough big buffer
    {
        const res = try conn.encrypt(cleartext, &ciphertext);
        try testing.expectEqual(cleartext.len, res.cleartext_pos);
        try testing.expectEqual(26, res.ciphertext.len);
        try testing.expectEqualSlices(u8, &data13.client_ping_wrapped, res.ciphertext);
    }

    // while ciphertext buffer is not enough for cleartext record
    for (conn.inner.cipher.encryptOverhead() + 1..ciphertext.len) |i| {
        const res = try conn.encrypt(cleartext, ciphertext[0..i]);
        const expected_used_cleartext = @min(cleartext.len, i - conn.inner.cipher.encryptOverhead());
        try testing.expectEqual(expected_used_cleartext, res.cleartext_pos);
        try testing.expectEqual(expected_used_cleartext + conn.inner.cipher.encryptOverhead(), res.ciphertext.len);
    }
}

test "nonblock decrypt" {
    const data13 = @import("testdata/tls13.zig");
    _, const server_cipher = cipher.testCiphers();
    var conn = NonBlock.init(server_cipher);

    const ciphertext = data13.client_ping_wrapped;
    var cleartext_buf: [32]u8 = undefined;

    for (1..ciphertext.len - 1) |i| {
        const res = try conn.decrypt(ciphertext[0..i], &cleartext_buf);
        try testing.expectEqual(0, res.ciphertext_pos);
        try testing.expectEqual(0, res.cleartext.len);
        try testing.expectEqual(i, res.unused_ciphertext.len);
    }

    const res = try conn.decrypt(&ciphertext, &cleartext_buf);
    try testing.expectEqualSlices(u8, "ping", res.cleartext);
}

test "handshake record with an empty body" {
    const data13 = @import("testdata/tls13.zig");
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

    // A record whose inner plaintext is nothing but the content type byte.
    // `Cipher.encrypt` cannot produce one, so build it by hand; with sequence
    // number 0 the nonce is the iv unchanged.
    var rec: [record.header_len + 1 + Aes256Gcm.tag_length]u8 = undefined;
    rec[0..record.header_len].* = record.header(.application_data, 1 + Aes256Gcm.tag_length);
    var ciphertext: [1]u8 = .{@intFromEnum(proto.ContentType.handshake)};
    var auth_tag: [Aes256Gcm.tag_length]u8 = undefined;
    Aes256Gcm.encrypt(
        &ciphertext,
        &auth_tag,
        &ciphertext,
        rec[0..record.header_len],
        data13.server_application_iv,
        data13.server_application_key,
    );
    rec[record.header_len..][0..1].* = ciphertext;
    rec[record.header_len + 1 ..][0..Aes256Gcm.tag_length].* = auth_tag;

    const client_cipher, _ = cipher.testCiphers();
    var input: Io.Reader = .fixed(&rec);
    var output_buf: [128]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buf);
    var conn: Connection = .{ .input = &input, .output = &output, .cipher = client_cipher };

    var buf: [128]u8 = undefined;
    try testing.expectError(error.TlsUnexpectedMessage, conn.nextRecord(&buf));
}

test "write with nothing to write" {
    const client_cipher, _ = cipher.testCiphers();
    var output_buf: [256]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buf);
    var input: Io.Reader = .fixed("");
    var conn: Connection = .{ .input = &input, .output = &output, .cipher = client_cipher };

    try testing.expectEqual(0, try conn.write(""));
    try testing.expectEqual(0, output.buffered().len);
}

test "nonblock key update is included in encryptedLength" {
    const Transcript = @import("transcript.zig").Transcript;
    const client_secret = [_]u8{1} ** 48;
    const server_secret = [_]u8{2} ** 48;
    const secret: Transcript.Secret = .{
        .client = &client_secret,
        .server = &server_secret,
    };
    var client = NonBlock.init(try Cipher.initTls13(.AES_256_GCM_SHA384, secret, .client));
    var server = NonBlock.init(try Cipher.initTls13(.AES_256_GCM_SHA384, secret, .server));

    // The peer asks for a key update, so our next record has to be preceded
    // by one of our own.
    var in_buf: [128]u8 = undefined;
    const key_update = &record.handshakeHeader(.key_update, 1) ++ [_]u8{1}; // update_requested
    const requested = try server.inner.cipher.encrypt(&in_buf, .handshake, key_update);
    var cleartext_buf: [64]u8 = undefined;
    _ = try client.decrypt(requested, &cleartext_buf);
    try testing.expect(@atomicLoad(bool, &client.inner.key_update_requested, .monotonic));

    // Size the buffer the way `encrypt` documents, and everything fits.
    const cleartext = "ping";
    const encrypted_len = client.encryptedLength(cleartext.len);
    try testing.expect(encrypted_len > client.inner.cipher.recordLen(cleartext.len));
    var ciphertext_buf: [128]u8 = undefined;
    const encrypted = try client.encrypt(cleartext, ciphertext_buf[0..encrypted_len]);
    try testing.expectEqual(cleartext.len, encrypted.cleartext_pos);
    try testing.expectEqual(encrypted_len, encrypted.ciphertext.len);

    // The peer reads the data through our KeyUpdate response.
    const decrypted = try server.decrypt(encrypted.ciphertext, &cleartext_buf);
    try testing.expectEqualSlices(u8, cleartext, decrypted.cleartext);
    try testing.expectEqual(encrypted_len, decrypted.ciphertext_pos);
}
