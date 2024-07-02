const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;

const record = @import("record.zig");
const Cipher = @import("cipher.zig").Cipher;
const HandshakeType = @import("handshake.zig").HandshakeType;
const Handshake = @import("handshake_server.zig").Handshake;
const Options = @import("handshake_server.zig").Options;

const VecPut = @import("client.zig").VecPut;

pub fn server(stream: anytype) Server(@TypeOf(stream)) {
    return .{
        .stream = stream,
        .rec_rdr = record.reader(stream),
    };
}

pub fn Server(comptime Stream: type) type {
    const RecordReaderT = record.Reader(Stream);
    const HandshakeT = Handshake(Stream);
    return struct {
        stream: Stream, // underlying stream
        rec_rdr: RecordReaderT, // reads tls record from underlying stream

        cipher: Cipher = undefined,
        cipher_client_seq: usize = 0,
        cipher_server_seq: usize = 0,

        write_buf: [tls.max_ciphertext_record_len]u8 = undefined,
        read_buf: []const u8 = "",
        received_close_notify: bool = false,

        const ServerT = @This();

        /// Handshake upgrades stream to tls connection.
        pub fn handshake(c: *ServerT, opt: Options) !void {
            var h = try HandshakeT.init(&c.write_buf, &c.rec_rdr);
            c.cipher = try h.handshake(c.stream, opt);
        }

        /// Encrypts and writes single tls record to the stream.
        fn writeRecord(c: *ServerT, content_type: tls.ContentType, bytes: []const u8) !void {
            assert(bytes.len <= tls.max_cipertext_inner_record_len);
            const rec = try c.cipher.encrypt(&c.write_buf, c.cipher_client_seq, content_type, bytes);
            c.cipher_client_seq += 1;
            try c.stream.writeAll(rec);
        }

        /// Returns next record of cleartext data.
        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try client.next()) |buf| { ... }
        pub fn next(c: *ServerT) ReadError!?[]const u8 {
            const content_type, const data = try c.nextRecord() orelse return null;
            if (content_type != .application_data) return error.TlsUnexpectedMessage;
            return data;
        }

        fn nextRecord(c: *ServerT) ReadError!?struct { tls.ContentType, []const u8 } {
            if (c.eof()) return null;
            while (true) {
                const content_type, const cleartext = try c.rec_rdr.nextDecrypt(c.cipher, c.cipher_server_seq) orelse return null;
                c.cipher_server_seq += 1;

                switch (content_type) {
                    .application_data => {},
                    .handshake => {
                        const handshake_type: HandshakeType = @enumFromInt(cleartext[0]);
                        // skip new session ticket and read next record
                        if (handshake_type == .new_session_ticket)
                            continue;
                    },
                    .alert => {
                        if (cleartext.len < 2) return error.TlsAlertUnknown;
                        const level: tls.AlertLevel = @enumFromInt(cleartext[0]);
                        const desc: tls.AlertDescription = @enumFromInt(cleartext[1]);
                        _ = level;
                        try desc.toError();
                        // server side clean shutdown
                        c.received_close_notify = true;
                        return null;
                    },
                    else => return error.TlsUnexpectedMessage,
                }
                return .{ content_type, cleartext };
            }
        }

        pub fn eof(c: *ServerT) bool {
            return c.received_close_notify and c.read_buf.len == 0;
        }

        pub fn close(c: *ServerT) !void {
            if (c.received_close_notify) return;
            const close_notify_alert = [2]u8{
                @intFromEnum(tls.AlertLevel.warning),
                @intFromEnum(tls.AlertDescription.close_notify),
            };
            try c.writeRecord(.alert, &close_notify_alert);
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

        pub const Reader = std.io.Reader(*ServerT, ReadError, read);
        pub const Writer = std.io.Writer(*ServerT, WriteError, write);

        pub fn reader(c: *ServerT) Reader {
            return .{ .context = c };
        }

        pub fn writer(c: *ServerT) Writer {
            return .{ .context = c };
        }

        /// Encrypts cleartext and writes it to the underlying stream as single
        /// tls record. Max single tls record payload length is 1<<14 (16K)
        /// bytes.
        pub fn write(c: *ServerT, bytes: []const u8) WriteError!usize {
            const n = @min(bytes.len, tls.max_cipertext_inner_record_len);
            try c.writeRecord(.application_data, bytes[0..n]);
            return n;
        }

        /// Encrypts cleartext and writes it to the underlying stream. If needed
        /// splits cleartext into multiple tls record.
        pub fn writeAll(c: *ServerT, bytes: []const u8) WriteError!void {
            var index: usize = 0;
            while (index < bytes.len) {
                index += try c.write(bytes[index..]);
            }
        }

        pub fn read(c: *ServerT, buffer: []u8) ReadError!usize {
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
        pub fn readAll(c: *ServerT, buffer: []u8) ReadError!usize {
            return c.readAtLeast(buffer, buffer.len);
        }

        /// Returns the number of bytes read, calling the underlying read function
        /// the minimal number of times until the buffer has at least `len` bytes
        /// filled. If the number read is less than `len` it means the stream
        /// reached the end.
        pub fn readAtLeast(c: *ServerT, buffer: []u8, len: usize) ReadError!usize {
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
        pub fn readv(c: *ServerT, iovecs: []std.posix.iovec) !usize {
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
