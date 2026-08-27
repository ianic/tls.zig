const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const assert = std.debug.assert;

const proto = @import("protocol.zig");
const record = @import("record.zig");
const Record = record.Record;
const cipher = @import("cipher.zig");
const Cipher = cipher.Cipher;
const SessionResumption = @import("handshake_client.zig").Options.SessionResumption;

/// Established TLS connection: encrypts writes, decrypts reads, and tracks
/// the close/alert state shared by the two directions.
///
/// One concurrent reader plus one concurrent writer are supported: the
/// cipher's encrypt and decrypt halves are disjoint, and the shared fields
/// are accessed atomically. `close` writes to `output`, so it belongs to
/// the writing task, or to teardown after both tasks are done.
pub const Connection = struct {
    /// Underlying network connection stream reader/writer pair.
    input: *Io.Reader, // source of the encrypted (ciphertext) data
    output: *Io.Writer, // sink to send encrypted (ciphertext) data
    cipher: Cipher,

    /// Require the peer to send close_notify before closing the transport.
    /// Without this, a close at a record boundary is a clean end of stream.
    ///
    /// An EOF in the middle of a record is always an error, either way.
    strict_close_notify: bool = false,

    max_encrypt_seq: u64 = std.math.maxInt(u64) - 1,
    key_update_requested: bool = false,
    /// Shared by both directions; accessed atomically, transitions only
    /// move forward (`open` toward `closed`/`failed`).
    state: State = .open,
    /// Queued by the read side, sent by `close`; handed over through the
    /// release/acquire pair on `state`.
    pending_alert: ?proto.Alert = null,
    /// Part of the cleartext record returned from next but not yet read by client.
    cleartext_buf: []const u8 = &.{},

    session_resumption: ?*SessionResumption = null,
    session_resumption_secret_idx: ?usize = null,

    /// ALPN protocol negotiated during TLS handshake (e.g., "h2", "http/1.1").
    /// Points into static data or the options slice; valid for the connection lifetime.
    alpn_protocol: ?[]const u8 = null,

    const Self = @This();

    pub const State = enum {
        /// Usable in both directions.
        open,
        /// We sent close_notify; the peer may still be sending.
        close_sent,
        /// Peer sent close_notify; we may still send.
        peer_closed,
        /// Both sides sent close_notify.
        closed,
        /// Reading hit a protocol error; `close` will send the alert.
        fatal_alert_pending,
        /// Terminal. Nothing further is sent or received.
        ///
        /// A peer that closes its write side without close_notify lands
        /// here too, which forecloses answering it over a TCP half-close.
        /// That is deliberate: TLS has no half-close, and RFC 8446 6.1
        /// requires close_notify before closing the write side, so such a
        /// peer is non-conformant and there is nothing useful to say back.
        failed,
    };

    pub const ReadError = error{
        ReadFailed,
        InputBufferUndersize,
        TlsConnectionTruncated,
        TlsRecordOverflow,
        TlsBadVersion,
        TlsCipherNoSpaceLeft,
        TlsBadRecordMac,
        TlsDecryptError,
        TlsDecodeError,
        TlsUnexpectedMessage,
        TlsIllegalParameter,
        TlsConnectionFailed,
    } || proto.Alert.Error;

    pub const WriteError = error{
        WriteFailed,
        TlsCipherNoSpaceLeft,
        TlsUnexpectedMessage,
        TlsConnectionFailed,
    };

    /// `EndOfStream` means the peer sent close_notify. `EndOfInput` means the
    /// input simply ran out; what that means depends on what the input is, so
    /// `nextRecord` does not decide. For a transport it is the peer closing
    /// without close_notify (`read`/`next` call `inputEnded`); for a caller
    /// buffer it means come back with more (`NonBlock.decrypt` stops).
    const RecordError = ReadError || error{ EndOfStream, EndOfInput };

    fn queueAlert(c: *Self, err: RecordError) void {
        const alert = switch (err) {
            // Ours to deal with, and `forLocalError` would read them as an
            // internal error worth telling the peer about. They are not: the
            // input or a buffer simply ran short, and the caller may retry.
            error.EndOfInput,
            error.InputBufferUndersize,
            error.TlsCipherNoSpaceLeft,
            => return,
            else => proto.Alert.forLocalError(err) orelse return,
        };
        // Once close_notify has gone out, it promised that no more messages
        // will follow. A later read-side failure therefore terminates the
        // connection without queuing an alert.
        var state = @atomicLoad(State, &c.state, .monotonic);
        while (state == .open) {
            c.pending_alert = alert;
            // Release pairs with the acquire in `encodeClose`; CAS so the
            // terminal `.failed` stays terminal.
            state = @cmpxchgWeak(State, &c.state, state, .fatal_alert_pending, .release, .monotonic) orelse return;
        }
        if (state == .close_sent) c.fail();
    }

    fn keyUpdateNeeded(c: *const Self) bool {
        return c.cipher.encryptSeq() >= c.max_encrypt_seq or
            @atomicLoad(bool, &c.key_update_requested, .monotonic);
    }

    /// True when a key update must go out before the next record: the
    /// cipher ran up to its sequence limit, or the peer requested one. The
    /// request flag is claimed -- exchanged for false -- before the update
    /// it decides is sent, so a request the read side stores between the
    /// claim and the send stays set and is answered before the record
    /// after this one. Clearing the flag after the send instead would
    /// erase such a request. The update sent for this claim also answers
    /// any requests received up to it, so claiming on the sequence-limit
    /// path too costs nothing (rfc 8446: multiple KeyUpdates received
    /// while silent get a single response).
    fn claimKeyUpdate(c: *Self) bool {
        const requested = @atomicLoad(bool, &c.key_update_requested, .monotonic) and
            @atomicRmw(bool, &c.key_update_requested, .Xchg, false, .monotonic);
        return requested or c.cipher.encryptSeq() >= c.max_encrypt_seq;
    }

    /// Encrypts and writes single tls record to the stream.
    fn writeRecord(c: *Self, content_type: proto.ContentType, bytes: []const u8) WriteError!void {
        assert(bytes.len <= cipher.max_cleartext_len);
        // If key update is requested send key update message and update
        // my encryption keys.
        if (c.claimKeyUpdate()) {
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
            c.cipher.keyUpdateEncrypt() catch |err| {
                c.fail();
                return err;
            };
        }
        try c.encryptWrite(content_type, bytes);
    }

    /// `.failed` is terminal in both directions, so it is a plain atomic
    /// store: whatever transition it races with, failed wins.
    fn fail(c: *Self) void {
        @atomicStore(State, &c.state, .failed, .monotonic);
    }

    fn encryptWrite(c: *Self, content_type: proto.ContentType, bytes: []const u8) WriteError!void {
        const encrypted_len = c.cipher.recordLen(bytes.len);
        const writable = c.output.writableSliceGreedy(encrypted_len) catch {
            c.fail();
            return error.WriteFailed;
        };
        const rec = c.cipher.encrypt(writable, content_type, bytes) catch |err| {
            c.fail();
            return err;
        };
        c.output.advance(rec.len);
        c.output.flush() catch {
            c.fail();
            return error.WriteFailed;
        };
    }

    /// Returns next record of cleartext data. Null on end of stream.
    /// Can be used in iterator like loop without memcpy to another buffer:
    ///   while (try client.next()) |buf| { ... }
    pub fn next(c: *Self) ReadError!?[]const u8 {
        return c.nextRecord(&.{}) catch |err| switch (err) {
            error.EndOfStream => null,
            error.EndOfInput => if (c.inputEnded()) |e| return e else null,
            else => {
                c.queueAlert(err);
                return @errorCast(err);
            },
        };
    }

    /// Decrypt next tls record into buffer, if buffer is not big enough reuse
    /// input ciphertext buffer for cleartext. Returns cleartext of the next tls
    /// record.
    fn nextRecord(c: *Self, buffer: []u8) RecordError![]const u8 {
        assert(c.cleartext_buf.len == 0);
        switch (@atomicLoad(State, &c.state, .monotonic)) {
            .open, .close_sent => {},
            .peer_closed, .closed => return error.EndOfStream,
            .fatal_alert_pending, .failed => return error.TlsConnectionFailed,
        }
        while (true) {
            const rec = Record.read(c.input) catch |err| switch (err) {
                // Only `nextRecord`'s callers can say what running out means.
                error.EndOfStream => return error.EndOfInput,
                else => |e| return e,
            };
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
                    // Decide on the description alone; see `Alert.parse`.
                    const alert = proto.Alert.parse(cleartext[0..2].*).description;
                    if (alert == .user_canceled) continue;
                    if (alert == .close_notify) {
                        // open -> peer_closed, close_sent -> closed. Either
                        // CAS loses only to the write side racing a close of
                        // its own, in which case the state it moved to is
                        // the one to advance from; `.failed` stays put.
                        if (@cmpxchgStrong(State, &c.state, .open, .peer_closed, .monotonic, .monotonic)) |cur| {
                            if (cur == .close_sent) {
                                _ = @cmpxchgStrong(State, &c.state, .close_sent, .closed, .monotonic, .monotonic);
                            }
                        }
                        return error.EndOfStream;
                    }
                    c.fail();
                    // toError only succeeds for close_notify and
                    // user_canceled, both handled above. Don't rely on that
                    // holding for peer controlled input.
                    alert.toError() catch |err| return err;
                    return error.TlsUnexpectedMessage;
                },
                else => return error.TlsUnexpectedMessage,
            }
            return cleartext;
        }
    }

    pub fn eof(c: *Self) bool {
        const state = @atomicLoad(State, &c.state, .monotonic);
        return (state == .peer_closed or state == .closed) and c.cleartext_buf.len == 0;
    }

    fn encodeClose(c: *Self, ciphertext: []u8) WriteError!?[]const u8 {
        // The acquire pairs with the release in `queueAlert`: seeing
        // `.fatal_alert_pending` means seeing `pending_alert` too, and from
        // then on the read side never touches it again, so this side owns it.
        const state = @atomicLoad(State, &c.state, .acquire);
        const cleartext, const next_state: State = switch (state) {
            .open => .{ proto.Alert.closeNotify(), .close_sent },
            .peer_closed => .{ proto.Alert.closeNotify(), .closed },
            .fatal_alert_pending => .{ [2]u8{
                @intFromEnum(proto.Alert.Level.fatal),
                @intFromEnum(c.pending_alert.?),
            }, .failed },
            .close_sent, .closed, .failed => return null,
        };

        if (ciphertext.len < c.cipher.recordLen(cleartext.len))
            return error.TlsCipherNoSpaceLeft;
        const rec = c.cipher.encrypt(ciphertext, .alert, &cleartext) catch |err| {
            if (state == .fatal_alert_pending) c.pending_alert = null;
            c.fail();
            return err;
        };
        if (state == .fatal_alert_pending) c.pending_alert = null;

        // Commit. Encrypting advanced the cipher sequence, so a lost race
        // must not re-encode; the record already made stays valid to send
        // and only the resulting state merges. Only the transitions out of
        // `.open` can lose (from the other two, the read side is already
        // done making transitions): to the peer's own close_notify, in
        // which case both sides are now closed, or to a read-side failure
        // or queued alert, in which case the connection is done and the
        // alert -- which would have to follow our close record -- is
        // dropped.
        if (@cmpxchgStrong(State, &c.state, state, next_state, .monotonic, .monotonic)) |cur| {
            const merged: ?State = switch (cur) {
                .peer_closed => .closed,
                .failed, .fatal_alert_pending => .failed,
                // A lenient transport EOF won the race. It closed the whole
                // connection, so discard the close_notify we just encoded.
                .closed => null,
                // The remaining states are this side's own transitions,
                // which it cannot have raced with itself.
                .open, .close_sent => unreachable,
            };
            if (merged) |s| {
                @atomicStore(State, &c.state, s, .monotonic);
            } else {
                return null;
            }
        }
        return rec;
    }

    /// Closes the write side of the connection. Sends a queued fatal alert if
    /// reading failed, otherwise sends close_notify. Repeated calls are no-ops.
    pub fn close(c: *Self) WriteError!void {
        // Early out only; `encodeClose` re-reads the state and decides.
        switch (@atomicLoad(State, &c.state, .monotonic)) {
            .close_sent, .closed, .failed => return,
            else => {},
        }
        const writable = c.output.writableSliceGreedy(c.cipher.recordLen(2)) catch {
            // `pending_alert`, if set, is left in place: this side may not
            // have observed the publishing state yet, so it may not touch
            // the field. Nobody reads it after `.failed` anyway.
            c.fail();
            return error.WriteFailed;
        };
        const rec = (try c.encodeClose(writable)) orelse return;
        c.output.advance(rec.len);
        c.output.flush() catch {
            c.fail();
            return error.WriteFailed;
        };
    }

    // write/read

    /// Encrypts cleartext and writes it to the underlying stream as single
    /// tls record. Max single tls record payload length is 1<<14 (16K)
    /// bytes.
    pub fn write(c: *Self, bytes: []const u8) WriteError!usize {
        if (bytes.len == 0) return 0;
        switch (@atomicLoad(State, &c.state, .monotonic)) {
            .open, .peer_closed => {},
            else => return error.TlsConnectionFailed,
        }
        const encrypt_overhead = c.cipher.encryptOverhead();
        assert(c.output.buffer.len > encrypt_overhead);
        // Find maximum number of bytes which can fit into output buffer as encrypted ciphertext
        const n = @min(bytes.len, cipher.max_cleartext_len, c.output.buffer.len - encrypt_overhead);
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

    /// The transport ran out of input. Null means take it as a clean end of
    /// stream.
    ///
    /// Stopping mid-record is a truncation however you read it: bytes were
    /// cut. Stopping between records only means the peer skipped close_notify,
    /// which many servers do, so it is a clean end unless the caller asked to
    /// be told. Either way the peer can be truncating us, and only the layer
    /// above knows whether it can tell -- HTTP with a Content-Length can.
    fn inputEnded(c: *Self) ?ReadError {
        if (c.input.bufferedLen() == 0 and !c.strict_close_notify) {
            // The transport is gone, not just the peer's TLS write side, so
            // there is nowhere left to send our own close_notify: go straight
            // to closed and leave `close` with nothing to do.
            var state = @atomicLoad(State, &c.state, .monotonic);
            while (true) switch (state) {
                .open, .close_sent => {
                    state = @cmpxchgWeak(State, &c.state, state, .closed, .monotonic, .monotonic) orelse return null;
                },
                .peer_closed, .closed => return null,
                // A failure that raced with the blocked read remains
                // terminal; EOF must not revive it as a clean close.
                .fatal_alert_pending, .failed => return error.TlsConnectionFailed,
            };
        }
        c.fail();
        return error.TlsConnectionTruncated;
    }

    /// Cleartext into `buffer`, passing `EndOfStream`/`EndOfInput` up for the
    /// caller to interpret.
    fn readCleartext(c: *Self, buffer: []u8) RecordError!usize {
        if (c.cleartext_buf.len == 0) {
            const cleartext = c.nextRecord(buffer) catch |err| switch (err) {
                error.EndOfStream, error.EndOfInput => return err,
                else => {
                    c.queueAlert(err);
                    return err;
                },
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

    pub fn read(c: *Self, buffer: []u8) ReadError!usize {
        return c.readCleartext(buffer) catch |err| switch (err) {
            error.EndOfStream => 0,
            error.EndOfInput => if (c.inputEnded()) |e| return e else 0,
            else => |e| return @errorCast(e),
        };
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
    pub fn readv(c: *Self, iovecs: []std.posix.iovec) ReadError!usize {
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
        const nr = try server_conn.readAll(server_cleartext_buf[0..n]);
        const server_cleartext = server_cleartext_buf[0..nr];

        try testing.expectEqual(n, nr);
        try testing.expectEqualSlices(u8, client_cleartext, server_cleartext);
    }
}

test "read queues protocol alert without writing" {
    const client_cipher, var server_cipher = cipher.testCiphers();
    // A complete record header with a version rejected by established TLS
    // connections. The payload is empty, so no decryption is attempted.
    const invalid_record = [_]u8{
        @intFromEnum(proto.ContentType.application_data),
        0x03,
        0x04,
        0,
        0,
    };
    var input: Io.Reader = .fixed(&invalid_record);
    var output_buf: [64]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buf);
    var conn: Connection = .{
        .input = &input,
        .output = &output,
        .cipher = client_cipher,
    };
    var cleartext: [1]u8 = undefined;

    try testing.expectError(error.TlsBadVersion, conn.read(&cleartext));
    try testing.expectEqual(.fatal_alert_pending, conn.state);
    try testing.expectEqual(0, output.end);
    try testing.expectError(error.TlsConnectionFailed, conn.write("data"));

    try conn.close();
    try testing.expectEqual(.failed, conn.state);
    try testing.expect(output.end > 0);
    const content_type, const alert = try server_cipher.decrypt(
        &output_buf,
        Record.init(output.buffered()),
    );
    try testing.expectEqual(.alert, content_type);
    try testing.expectEqualSlices(u8, &.{
        @intFromEnum(proto.Alert.Level.fatal),
        @intFromEnum(proto.Alert.protocol_version),
    }, alert);
    const alert_end = output.end;
    try conn.close();
    try testing.expectEqual(alert_end, output.end);
    try testing.expectError(error.TlsConnectionFailed, conn.read(&cleartext));
}

test "protocol failure after close_notify sends nothing further" {
    const invalid_record = [_]u8{
        @intFromEnum(proto.ContentType.application_data),
        0x03,
        0x04,
        0,
        0,
    };
    var input: Io.Reader = .fixed(&invalid_record);
    var output_buf: [128]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buf);
    const client_cipher, _ = cipher.testCiphers();
    var conn: Connection = .{
        .input = &input,
        .output = &output,
        .cipher = client_cipher,
    };

    try conn.close();
    try testing.expectEqual(.close_sent, conn.state);
    const close_end = output.end;

    var cleartext: [1]u8 = undefined;
    try testing.expectError(error.TlsBadVersion, conn.read(&cleartext));
    try testing.expectEqual(.failed, conn.state);
    try testing.expectEqual(@as(?proto.Alert, null), conn.pending_alert);

    try conn.close();
    try testing.expectEqual(close_end, output.end);
}

test "reader records ReadFailed for a lower-layer failure" {
    const FailingReader = struct {
        interface: Io.Reader,
        err: ?error{Canceled} = null,

        fn init(buffer: []u8) @This() {
            return .{
                .interface = .{
                    .vtable = &.{ .stream = stream },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(r: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
            const self: *@This() = @fieldParentPtr("interface", r);
            self.err = error.Canceled;
            return error.ReadFailed;
        }
    };

    const client_cipher, _ = cipher.testCiphers();
    var transport_buf: [record.header_len]u8 = undefined;
    var transport_reader = FailingReader.init(&transport_buf);
    var conn: Connection = .{
        .input = &transport_reader.interface,
        .output = undefined,
        .cipher = client_cipher,
    };
    var tls_buf: [1]u8 = undefined;
    var tls_reader = conn.reader(&tls_buf);

    // The interface still reports the generic error, as it must, but `err`
    // now says which layer failed instead of echoing it back.
    try testing.expectError(error.ReadFailed, tls_reader.interface.take(1));
    try testing.expectEqual(error.ReadFailed, tls_reader.err.?);
    try testing.expectEqual(error.Canceled, transport_reader.err.?);
    try testing.expectEqual(.open, conn.state);
}

/// Yields `prefix` and then ends the stream.
const PartialReader = struct {
    interface: Io.Reader,
    prefix: []const u8,

    fn init(buffer: []u8, prefix: []const u8) @This() {
        return .{
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .prefix = prefix,
        };
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *@This() = @fieldParentPtr("interface", r);
        if (self.prefix.len == 0) return error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = @min(dest.len, self.prefix.len);
        @memcpy(dest[0..n], self.prefix[0..n]);
        w.advance(n);
        self.prefix = self.prefix[n..];
        return n;
    }
};

test "transport EOF without close_notify" {
    // Three bytes of a five byte record header, then end of stream.
    const partial_header = [_]u8{ @intFromEnum(proto.ContentType.application_data), 0x03, 0x03 };

    const cases = [_]struct {
        prefix: []const u8,
        strict: bool,
        expected: ?anyerror,
        state: Connection.State,
    }{
        // Between records the peer only skipped close_notify: a clean end.
        .{ .prefix = "", .strict = false, .expected = null, .state = .closed },
        // Unless the caller asked to be told.
        .{ .prefix = "", .strict = true, .expected = error.TlsConnectionTruncated, .state = .failed },
        // Mid-record bytes were cut, which is a truncation either way.
        .{ .prefix = &partial_header, .strict = false, .expected = error.TlsConnectionTruncated, .state = .failed },
        .{ .prefix = &partial_header, .strict = true, .expected = error.TlsConnectionTruncated, .state = .failed },
    };

    for (cases) |case| {
        const client_cipher, _ = cipher.testCiphers();
        var input_buf: [record.header_len]u8 = undefined;
        var input = PartialReader.init(&input_buf, case.prefix);
        var conn: Connection = .{
            .input = &input.interface,
            .output = undefined,
            .cipher = client_cipher,
            .strict_close_notify = case.strict,
        };

        if (case.expected) |err| {
            try testing.expectError(err, conn.next());
        } else {
            try testing.expectEqual(@as(?[]const u8, null), try conn.next());
        }
        try testing.expectEqual(case.state, conn.state);
        try testing.expectEqual(@as(?proto.Alert, null), conn.pending_alert);
    }
}

test "transport EOF does not overwrite a terminal state" {
    const cases = [_]Connection.State{ .fatal_alert_pending, .failed };
    for (cases) |state| {
        const client_cipher, _ = cipher.testCiphers();
        var input: Io.Reader = .fixed(&.{});
        var conn: Connection = .{
            .input = &input,
            .output = undefined,
            .cipher = client_cipher,
            .state = state,
            .pending_alert = if (state == .fatal_alert_pending) .decode_error else null,
        };

        try testing.expectEqual(error.TlsConnectionFailed, conn.inputEnded().?);
        try testing.expectEqual(state, conn.state);
    }
}

test "peer close_notify is answered by close" {
    const client_cipher, var server_cipher = cipher.testCiphers();
    var peer_buf: [64]u8 = undefined;
    const peer_close = try server_cipher.encrypt(&peer_buf, .alert, &proto.Alert.closeNotify());
    var input: Io.Reader = .fixed(peer_close);
    var output_buf: [64]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buf);
    var conn: Connection = .{
        .input = &input,
        .output = &output,
        .cipher = client_cipher,
    };
    var cleartext: [1]u8 = undefined;

    try testing.expectEqual(0, try conn.read(&cleartext));
    try testing.expectEqual(.peer_closed, conn.state);
    try testing.expectEqual(0, output.end);

    try conn.close();
    try testing.expectEqual(.closed, conn.state);
    const content_type, const response = try server_cipher.decrypt(
        &peer_buf,
        Record.init(output.buffered()),
    );
    try testing.expectEqual(.alert, content_type);
    try testing.expectEqualSlices(u8, &proto.Alert.closeNotify(), response);
}

test "failed fatal alert write is terminal and is not retried" {
    const FailingWriter = struct {
        interface: Io.Writer,

        fn init(buffer: []u8) @This() {
            return .{
                .interface = .{
                    .vtable = &.{ .drain = drain },
                    .buffer = buffer,
                    .end = 0,
                },
            };
        }

        fn drain(_: *Io.Writer, _: []const []const u8, _: usize) Io.Writer.Error!usize {
            return error.WriteFailed;
        }
    };

    const client_cipher, _ = cipher.testCiphers();
    var output_buf: [64]u8 = undefined;
    var output = FailingWriter.init(&output_buf);
    var conn: Connection = .{
        .input = undefined,
        .output = &output.interface,
        .cipher = client_cipher,
        .state = .fatal_alert_pending,
        .pending_alert = .decode_error,
    };

    try testing.expectError(error.WriteFailed, conn.close());
    try testing.expectEqual(.failed, conn.state);
    try testing.expectEqual(@as(?proto.Alert, null), conn.pending_alert);
    const end = output.interface.end;
    try conn.close();
    try testing.expectEqual(end, output.interface.end);
    try testing.expectError(error.TlsConnectionFailed, conn.write("data"));
}

/// Sans-io connection: pure encrypt/decrypt over caller-provided buffers.
///
/// Each NonBlock is single-task: unlike the blocking `Connection`, nothing
/// here is synchronized. For concurrent use make two copies of the same
/// cipher, encrypt with one and decrypt with the other, and forward
/// `inner.key_update_requested` (atomic) from the decrypting copy to the
/// encrypting one.
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
    ) Connection.WriteError!struct {
        /// Number of bytes consumed from cleartext
        cleartext_pos: usize = 0,
        /// Unused part of the provided cleartext buffer
        unused_cleartext: []const u8,
        /// Encrypted ciphertext data
        ciphertext: []u8,
    } {
        switch (self.inner.state) {
            .open, .peer_closed => {},
            else => return error.TlsConnectionFailed,
        }
        const key_update = &record.handshakeHeader(.key_update, 1) ++ [_]u8{0};
        var n: usize = 0;
        var out_pos: usize = 0;
        while (n < cleartext.len) {
            // Peek, so bailing for buffer space does not consume the
            // request; claim once the update is sure to go out.
            if (self.inner.keyUpdateNeeded()) {
                const update_len = self.inner.cipher.recordLen(key_update.len);
                if (ciphertext.len - out_pos < update_len) {
                    if (out_pos == 0) return error.TlsCipherNoSpaceLeft;
                    break;
                }
                _ = self.inner.claimKeyUpdate();
                const rec = self.inner.cipher.encrypt(ciphertext[out_pos..], .handshake, key_update) catch |err| {
                    self.inner.state = .failed;
                    return err;
                };
                out_pos += rec.len;
                self.inner.cipher.keyUpdateEncrypt() catch |err| {
                    self.inner.state = .failed;
                    return err;
                };
            }

            const overhead = self.inner.cipher.encryptOverhead();
            if (ciphertext.len - out_pos <= overhead) break;
            const chunk_len = @min(
                cleartext.len - n,
                cipher.max_cleartext_len,
                ciphertext.len - out_pos - overhead,
            );
            const rec = self.inner.cipher.encrypt(
                ciphertext[out_pos..],
                .application_data,
                cleartext[n..][0..chunk_len],
            ) catch |err| {
                self.inner.state = .failed;
                return err;
            };
            out_pos += rec.len;
            n += chunk_len;
        }
        return .{
            .cleartext_pos = n,
            .unused_cleartext = cleartext[n..],
            .ciphertext = ciphertext[0..out_pos],
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
    ) Connection.ReadError!struct {
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
            const nn = self.inner.readCleartext(cleartext[n..]) catch |err| switch (err) {
                // Running out of ciphertext is the normal case here: the
                // caller accumulates it and calls again with more. Only a
                // transport can be said to have ended.
                error.EndOfInput => break,
                error.EndOfStream => break,
                error.InputBufferUndersize => break,
                else => |e| return @errorCast(e),
            };
            if (nn == 0) break;
            n += nn;
        }

        return .{
            .ciphertext_pos = input.seek,
            .unused_ciphertext = input.buffered(),
            .cleartext = cleartext[0..n],
            .closed = self.inner.state == .peer_closed or self.inner.state == .closed,
        };
    }

    pub fn close(self: *Self, ciphertext: []u8) Connection.WriteError![]const u8 {
        return (try self.inner.encodeClose(ciphertext)) orelse &.{};
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

test "nonblock decrypt with a trailing partial record" {
    const data13 = @import("testdata/tls13.zig");
    _, const server_cipher = cipher.testCiphers();

    const rec = data13.client_ping_wrapped;
    var buf: [2 * rec.len]u8 = undefined;
    @memcpy(buf[0..rec.len], &rec);
    @memcpy(buf[rec.len..], &rec);

    // One complete record followed by any partial second record must
    // decrypt the first and leave the tail unconsumed, without failing
    // the connection state.
    for (1..rec.len - 1) |i| {
        var conn = NonBlock.init(server_cipher);
        var cleartext_buf: [32]u8 = undefined;
        const res = try conn.decrypt(buf[0 .. rec.len + i], &cleartext_buf);
        try testing.expectEqual(rec.len, res.ciphertext_pos);
        try testing.expectEqualSlices(u8, "ping", res.cleartext);
        try testing.expectEqual(i, res.unused_ciphertext.len);
        try testing.expectEqual(.open, conn.inner.state);
    }
}
test "nonblock close uses pending fatal alert and state" {
    const client_cipher, _ = cipher.testCiphers();
    var conn = NonBlock.init(client_cipher);
    const invalid_record = [_]u8{
        @intFromEnum(proto.ContentType.application_data),
        0x03,
        0x04,
        0,
        0,
    };
    var cleartext_buf: [1]u8 = undefined;
    try testing.expectError(error.TlsBadVersion, conn.decrypt(&invalid_record, &cleartext_buf));
    try testing.expectEqual(.fatal_alert_pending, conn.inner.state);

    var ciphertext_buf: [64]u8 = undefined;
    const fatal_alert = try conn.close(&ciphertext_buf);
    try testing.expect(fatal_alert.len > 0);
    try testing.expectEqual(.failed, conn.inner.state);
    try testing.expectEqual(0, (try conn.close(&ciphertext_buf)).len);
    try testing.expectError(error.TlsConnectionFailed, conn.encrypt("data", &ciphertext_buf));
}

test "nonblock graceful close is idempotent" {
    const client_cipher, _ = cipher.testCiphers();
    var conn = NonBlock.init(client_cipher);
    var ciphertext_buf: [64]u8 = undefined;

    try testing.expect((try conn.close(&ciphertext_buf)).len > 0);
    try testing.expectEqual(.close_sent, conn.inner.state);
    try testing.expectEqual(0, (try conn.close(&ciphertext_buf)).len);
    try testing.expectError(error.TlsConnectionFailed, conn.encrypt("data", &ciphertext_buf));
}

/// A matched TLS 1.3 cipher pair with real (fixed) secrets, so key updates
/// derive working keys on both sides; `cipher.testCiphers` leaves the
/// secrets undefined.
fn testTls13CipherPair() !struct { Cipher, Cipher } {
    const Transcript = @import("transcript.zig").Transcript;
    const client_secret = [_]u8{1} ** 48;
    const server_secret = [_]u8{2} ** 48;
    const secret: Transcript.Secret = .{
        .client = &client_secret,
        .server = &server_secret,
    };
    return .{
        try Cipher.initTls13(.AES_256_GCM_SHA384, secret, .client),
        try Cipher.initTls13(.AES_256_GCM_SHA384, secret, .server),
    };
}

test "Connection: close orderings converge on closed" {
    { // The peer closes first; we may finish writing before our own close.
        const pair = try testTls13CipherPair();
        var peer = NonBlock.init(pair[1]);
        var close_buf: [64]u8 = undefined;
        const peer_close = try peer.close(&close_buf);

        var in_buf: [64]u8 = undefined;
        @memcpy(in_buf[0..peer_close.len], peer_close);
        var input: Io.Reader = .fixed(in_buf[0..peer_close.len]);
        var out_buf: [64]u8 = undefined;
        var output: Io.Writer = .fixed(&out_buf);
        var conn: Connection = .{ .input = &input, .output = &output, .cipher = pair[0] };

        try testing.expect((try conn.next()) == null);
        try testing.expectEqual(.peer_closed, conn.state);
        try conn.writeAll("data");
        try conn.close();
        try testing.expectEqual(.closed, conn.state);

        var cleartext_buf: [16]u8 = undefined;
        const received = try peer.decrypt(output.buffered(), &cleartext_buf);
        try testing.expectEqualStrings("data", received.cleartext);
        try testing.expect(received.closed);
    }
    { // We close first; the peer's close_notify completes the pair.
        const pair = try testTls13CipherPair();
        var peer = NonBlock.init(pair[1]);
        var close_buf: [64]u8 = undefined;
        const peer_close = try peer.close(&close_buf);

        var in_buf: [64]u8 = undefined;
        @memcpy(in_buf[0..peer_close.len], peer_close);
        var input: Io.Reader = .fixed(in_buf[0..peer_close.len]);
        var out_buf: [64]u8 = undefined;
        var output: Io.Writer = .fixed(&out_buf);
        var conn: Connection = .{ .input = &input, .output = &output, .cipher = pair[0] };

        try conn.close();
        try testing.expectEqual(.close_sent, conn.state);
        try testing.expectError(error.TlsConnectionFailed, conn.write("data"));
        try testing.expect((try conn.next()) == null);
        try testing.expectEqual(.closed, conn.state);
        // Close already sent; nothing further goes out.
        const sent = output.end;
        try conn.close();
        try testing.expectEqual(sent, output.end);
    }
}

test "NonBlock: peer close leaves the write side usable" {
    const pair = try testTls13CipherPair();
    var conn = NonBlock.init(pair[0]);
    var peer = NonBlock.init(pair[1]);

    var peer_close_buf: [64]u8 = undefined;
    const peer_close = try peer.close(&peer_close_buf);
    var cleartext_buf: [16]u8 = undefined;
    const closed = try conn.decrypt(peer_close, &cleartext_buf);
    try testing.expect(closed.closed);
    try testing.expectEqual(.peer_closed, conn.inner.state);

    var data_buf: [64]u8 = undefined;
    const encrypted = try conn.encrypt("data", &data_buf);
    const received = try peer.decrypt(encrypted.ciphertext, &cleartext_buf);
    try testing.expectEqualStrings("data", received.cleartext);

    var close_buf: [64]u8 = undefined;
    const close_notify = try conn.close(&close_buf);
    const peer_closed = try peer.decrypt(close_notify, &cleartext_buf);
    try testing.expect(peer_closed.closed);
}

test "Connection: concurrent reader and writer" {
    if (builtin.single_threaded) return error.SkipZigTest;

    // One task reading, one task writing and finally closing, per the
    // concurrency contract on `Connection`. The interesting assertions are
    // the invariants at the end of every round: all cleartext arrived
    // through a mid-stream key update, and the close handshake converged on
    // `.closed` no matter how the two sides interleaved. Run under
    // -fsanitize-thread this is also the data-race test for the shared
    // state machine.
    const msg = "0123456789abcdef";
    const rounds = 50;

    const Tasks = struct {
        fn reader(c: *Connection, total: *usize) void {
            while (c.next() catch null) |cleartext| total.* += cleartext.len;
        }
        fn writer(c: *Connection) void {
            for (0..16) |_| {
                // Stops early when the peer's close_notify wins the race;
                // the close below still answers it.
                c.writeAll(msg) catch break; // fails once the peer closed
            }
            c.close() catch {};
        }
    };

    for (0..rounds) |_| {
        const pair = try testTls13CipherPair();
        var server_cipher = pair[1];

        // Preload the transport with the peer's whole session: data, a key
        // update demanding a response, more data under the new key, and
        // finally close_notify.
        var in_buf: [2048]u8 = undefined;
        var in_len: usize = 0;
        var expected: usize = 0;
        for (0..4) |_| {
            in_len += (try server_cipher.encrypt(in_buf[in_len..], .application_data, msg)).len;
            expected += msg.len;
        }
        {
            const key_update = &record.handshakeHeader(.key_update, 1) ++ [_]u8{1}; // update_requested
            in_len += (try server_cipher.encrypt(in_buf[in_len..], .handshake, key_update)).len;
            try server_cipher.keyUpdateEncrypt();
        }
        for (0..4) |_| {
            in_len += (try server_cipher.encrypt(in_buf[in_len..], .application_data, msg)).len;
            expected += msg.len;
        }
        in_len += (try server_cipher.encrypt(in_buf[in_len..], .alert, &proto.Alert.closeNotify())).len;

        var input: Io.Reader = .fixed(in_buf[0..in_len]);
        var out_buf: [8192]u8 = undefined;
        var output: Io.Writer = .fixed(&out_buf);
        var conn: Connection = .{
            .input = &input,
            .output = &output,
            .cipher = pair[0],
            // Force encrypt-side key updates mid-stream as well.
            .max_encrypt_seq = 5,
        };

        var total: usize = 0;
        const rt = try std.Thread.spawn(.{}, Tasks.reader, .{ &conn, &total });
        const wt = try std.Thread.spawn(.{}, Tasks.writer, .{&conn});
        rt.join();
        wt.join();

        try testing.expectEqual(expected, total);
        try testing.expectEqual(.closed, @atomicLoad(Connection.State, &conn.state, .monotonic));
    }
}

test "Connection: boundary EOF races close" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const Tasks = struct {
        fn wait(go: *const bool) void {
            while (!@atomicLoad(bool, go, .acquire)) std.atomic.spinLoopHint();
        }

        fn reader(c: *Connection, go: *const bool, err: *?Connection.ReadError) void {
            wait(go);
            _ = c.next() catch |e| {
                err.* = e;
                return;
            };
        }

        fn writer(c: *Connection, go: *const bool, err: *?Connection.WriteError) void {
            wait(go);
            c.close() catch |e| {
                err.* = e;
            };
        }
    };

    // The default, non-strict EOF path moves directly to closed. It may race
    // a close which has already encoded close_notify but not committed its
    // state transition yet. Either transition may win, but neither may revive
    // the connection or treat the other's resulting `.closed` as impossible.
    for (0..50) |_| {
        const pair = try testTls13CipherPair();
        var input_buf: [record.header_len]u8 = undefined;
        var input = PartialReader.init(&input_buf, "");
        var out_buf: [64]u8 = undefined;
        var output: Io.Writer = .fixed(&out_buf);
        var conn: Connection = .{ .input = &input.interface, .output = &output, .cipher = pair[0] };
        var go = false;
        var read_err: ?Connection.ReadError = null;
        var write_err: ?Connection.WriteError = null;

        const rt = try std.Thread.spawn(.{}, Tasks.reader, .{ &conn, &go, &read_err });
        const wt = try std.Thread.spawn(.{}, Tasks.writer, .{ &conn, &go, &write_err });
        @atomicStore(bool, &go, true, .release);
        rt.join();
        wt.join();

        try testing.expectEqual(@as(?Connection.ReadError, null), read_err);
        try testing.expectEqual(@as(?Connection.WriteError, null), write_err);
        try testing.expectEqual(.closed, @atomicLoad(Connection.State, &conn.state, .monotonic));
    }
}

test "Connection: concurrent close races a queued fatal alert" {
    if (builtin.single_threaded) return error.SkipZigTest;

    // The reader hits a garbage record and queues a fatal alert while the
    // writer is closing. If the alert wins, `close` sends it; if close_notify
    // wins, the alert is dropped because nothing may follow it. Either way
    // the protocol failure leaves the connection failed, never cleanly closed.
    const msg = "0123456789abcdef";
    const rounds = 50;

    const Tasks = struct {
        fn reader(c: *Connection) void {
            while (c.next() catch null) |_| {}
        }
        fn writer(c: *Connection) void {
            for (0..4) |_| c.writeAll(msg) catch break;
            c.close() catch {};
        }
    };

    for (0..rounds) |_| {
        const pair = try testTls13CipherPair();
        var server_cipher = pair[1];

        var in_buf: [1024]u8 = undefined;
        var in_len: usize = 0;
        for (0..4) |_| {
            in_len += (try server_cipher.encrypt(in_buf[in_len..], .application_data, msg)).len;
        }
        const tail = (try server_cipher.encrypt(in_buf[in_len..], .application_data, msg)).len;
        in_buf[in_len + tail - 1] +%= 1; // corrupt the last record's tag
        in_len += tail;

        var input: Io.Reader = .fixed(in_buf[0..in_len]);
        var out_buf: [4096]u8 = undefined;
        var output: Io.Writer = .fixed(&out_buf);
        var conn: Connection = .{ .input = &input, .output = &output, .cipher = pair[0] };

        const rt = try std.Thread.spawn(.{}, Tasks.reader, .{&conn});
        const wt = try std.Thread.spawn(.{}, Tasks.writer, .{&conn});
        rt.join();
        wt.join();

        try testing.expectEqual(.failed, @atomicLoad(Connection.State, &conn.state, .monotonic));
    }
}

test "Connection: peer key update request is claimed, answered, and round-trips" {
    const pair = try testTls13CipherPair();
    var input: Io.Reader = .fixed(&.{});
    var out_buf: [1024]u8 = undefined;
    var output: Io.Writer = .fixed(&out_buf);
    var conn: Connection = .{ .input = &input, .output = &output, .cipher = pair[0] };
    var peer = NonBlock.init(pair[1]);

    // As if the read side had just processed the peer's update_requested.
    @atomicStore(bool, &conn.key_update_requested, true, .monotonic);
    try conn.writeAll("ping");
    // Claimed before the response was sent, not cleared after it: a
    // request stored between the two would survive to the next record.
    try testing.expect(!@atomicLoad(bool, &conn.key_update_requested, .monotonic));

    // The peer processes the KeyUpdate response transparently and reads
    // the data under this side's new key.
    var cleartext_buf: [64]u8 = undefined;
    const res = try peer.decrypt(out_buf[0..output.end], &cleartext_buf);
    try testing.expectEqualStrings("ping", res.cleartext);
}
