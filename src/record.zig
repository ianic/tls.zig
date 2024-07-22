const std = @import("std");
const mem = std.mem;

const proto = @import("protocol.zig");
const cipher = @import("cipher.zig");
const Cipher = cipher.Cipher;
const record = @import("record.zig");

pub const header_len = 5;

pub fn header(content_type: proto.ContentType, payload_len: usize) [header_len]u8 {
    const int2 = std.crypto.tls.int2;
    return [1]u8{@intFromEnum(content_type)} ++
        int2(@intFromEnum(proto.Version.tls_1_2)) ++
        int2(@intCast(payload_len));
}

pub fn handshakeHeader(handshake_type: proto.HandshakeType, payload_len: usize) [4]u8 {
    const int3 = std.crypto.tls.int3;
    return [1]u8{@intFromEnum(handshake_type)} ++ int3(@intCast(payload_len));
}

pub fn reader(inner_reader: anytype) Reader(@TypeOf(inner_reader)) {
    return .{ .inner_reader = inner_reader };
}

pub fn Reader(comptime InnerReader: type) type {
    return struct {
        inner_reader: InnerReader,

        buffer: [cipher.max_ciphertext_record_len]u8 = undefined,
        start: usize = 0,
        end: usize = 0,

        const ReaderT = @This();

        pub fn nextDecoder(r: *ReaderT) !Decoder {
            const rec = (try r.next()) orelse return error.EndOfStream;
            if (@intFromEnum(rec.protocol_version) != 0x0300 and
                @intFromEnum(rec.protocol_version) != 0x0301 and
                rec.protocol_version != .tls_1_2)
                return error.TlsBadVersion;
            return .{
                .content_type = rec.content_type,
                .payload = rec.payload,
            };
        }

        pub fn contentType(buf: []const u8) proto.ContentType {
            return @enumFromInt(buf[0]);
        }

        pub fn protocolVersion(buf: []const u8) proto.Version {
            return @enumFromInt(mem.readInt(u16, buf[1..3], .big));
        }

        pub fn next(r: *ReaderT) !?Record {
            while (true) {
                const buffer = r.buffer[r.start..r.end];
                // If we have 5 bytes header.
                if (buffer.len >= record.header_len) {
                    const record_header = buffer[0..record.header_len];
                    const payload_len = mem.readInt(u16, record_header[3..5], .big);
                    if (payload_len > cipher.max_ciphertext_len)
                        return error.TlsRecordOverflow;
                    const record_len = record.header_len + payload_len;
                    // If we have whole record
                    if (buffer.len >= record_len) {
                        r.start += record_len;
                        return Record.init(buffer[0..record_len]);
                    }
                }
                { // Move dirty part to the start of the buffer.
                    const n = r.end - r.start;
                    if (n > 0 and r.start > 0) {
                        if (r.start > n) {
                            @memcpy(r.buffer[0..n], r.buffer[r.start..][0..n]);
                        } else {
                            mem.copyForwards(u8, r.buffer[0..n], r.buffer[r.start..][0..n]);
                        }
                    }
                    r.start = 0;
                    r.end = n;
                }
                { // Read more from inner_reader.
                    const n = try r.inner_reader.read(r.buffer[r.end..]);
                    if (n == 0) return null;
                    r.end += n;
                }
            }
        }

        pub fn nextDecrypt(r: *ReaderT, cph: *Cipher) !?struct { proto.ContentType, []const u8 } {
            const rec = (try r.next()) orelse return null;
            if (rec.protocol_version != .tls_1_2) return error.TlsBadVersion;

            return try cph.decrypt(
                // Reuse reader buffer for cleartext. `rec.header` and
                // `rec.payload`(ciphertext) are also pointing somewhere in
                // this buffer. Decrypter is first reading then writing a
                // block, cleartext has less length then ciphertext,
                // cleartext starts from the beginning of the buffer, so
                // ciphertext is always ahead of cleartext.
                r.buffer[0..r.start],
                rec,
            );
        }

        pub fn hasMore(r: *ReaderT) bool {
            return r.end > r.start;
        }
    };
}

pub const Record = struct {
    content_type: proto.ContentType,
    protocol_version: proto.Version = .tls_1_2,
    header: []const u8,
    payload: []const u8,

    pub fn init(buffer: []const u8) Record {
        return .{
            .content_type = @enumFromInt(buffer[0]),
            .protocol_version = @enumFromInt(mem.readInt(u16, buffer[1..3], .big)),
            .header = buffer[0..record.header_len],
            .payload = buffer[record.header_len..],
        };
    }

    pub fn decoder(r: @This()) Decoder {
        return Decoder.init(r.content_type, @constCast(r.payload));
    }
};

pub const Decoder = struct {
    content_type: proto.ContentType,
    payload: []const u8,
    idx: usize = 0,

    pub fn init(content_type: proto.ContentType, payload: []u8) Decoder {
        return .{
            .content_type = content_type,
            .payload = payload,
        };
    }

    pub fn decode(d: *Decoder, comptime T: type) !T {
        switch (@typeInfo(T)) {
            .Int => |info| switch (info.bits) {
                8 => {
                    try skip(d, 1);
                    return d.payload[d.idx - 1];
                },
                16 => {
                    try skip(d, 2);
                    const b0: u16 = d.payload[d.idx - 2];
                    const b1: u16 = d.payload[d.idx - 1];
                    return (b0 << 8) | b1;
                },
                24 => {
                    try skip(d, 3);
                    const b0: u24 = d.payload[d.idx - 3];
                    const b1: u24 = d.payload[d.idx - 2];
                    const b2: u24 = d.payload[d.idx - 1];
                    return (b0 << 16) | (b1 << 8) | b2;
                },
                else => @compileError("unsupported int type: " ++ @typeName(T)),
            },
            .Enum => |info| {
                const int = try d.decode(info.tag_type);
                if (info.is_exhaustive) @compileError("exhaustive enum cannot be used");
                return @as(T, @enumFromInt(int));
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }

    pub fn array(d: *Decoder, comptime len: usize) !*const [len]u8 {
        try d.skip(len);
        return d.payload[d.idx - len ..][0..len];
    }

    pub fn slice(d: *Decoder, len: usize) ![]const u8 {
        try d.skip(len);
        return d.payload[d.idx - len ..][0..len];
    }

    pub fn skip(d: *Decoder, amt: usize) !void {
        if (d.idx + amt > d.payload.len) return error.TlsDecodeError;
        d.idx += amt;
    }

    pub fn rest(d: Decoder) []const u8 {
        return d.payload[d.idx..];
    }

    pub fn eof(d: Decoder) bool {
        return d.idx == d.payload.len;
    }

    pub fn expectContentType(d: *Decoder, content_type: proto.ContentType) !void {
        if (d.content_type == content_type) return;

        switch (d.content_type) {
            .alert => try d.raiseAlert(),
            else => return error.TlsUnexpectedMessage,
        }
    }

    pub fn raiseAlert(d: *Decoder) !void {
        if (d.payload.len < 2) return error.TlsUnexpectedMessage;
        _ = try d.decode(proto.AlertLevel);
        const desc = try d.decode(proto.AlertDescription);
        try desc.toError();
        return error.TlsAlertCloseNotify;
    }
};

const testing = std.testing;
const data12 = @import("testdata/tls12.zig");
const testu = @import("testu.zig");
const CipherSuite = @import("cipher.zig").CipherSuite;

test Reader {
    var fbs = std.io.fixedBufferStream(&data12.server_responses);
    var rdr = reader(fbs.reader());

    const expected = [_]struct {
        content_type: proto.ContentType,
        payload_len: usize,
    }{
        .{ .content_type = .handshake, .payload_len = 49 },
        .{ .content_type = .handshake, .payload_len = 815 },
        .{ .content_type = .handshake, .payload_len = 300 },
        .{ .content_type = .handshake, .payload_len = 4 },
        .{ .content_type = .change_cipher_spec, .payload_len = 1 },
        .{ .content_type = .handshake, .payload_len = 64 },
    };
    for (expected) |e| {
        const rec = (try rdr.next()).?;
        try testing.expectEqual(e.content_type, rec.content_type);
        try testing.expectEqual(e.payload_len, rec.payload.len);
        try testing.expectEqual(.tls_1_2, rec.protocol_version);
    }
}

test Decoder {
    var fbs = std.io.fixedBufferStream(&data12.server_responses);
    var rdr = reader(fbs.reader());

    var d = (try rdr.nextDecoder());
    try testing.expectEqual(.handshake, d.content_type);

    try testing.expectEqual(.server_hello, try d.decode(proto.HandshakeType));
    try testing.expectEqual(45, try d.decode(u24)); // length
    try testing.expectEqual(.tls_1_2, try d.decode(proto.Version));
    try testing.expectEqualStrings(
        &testu.hexToBytes("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
        try d.array(32),
    ); // server random
    try testing.expectEqual(0, try d.decode(u8)); // session id len
    try testing.expectEqual(.ECDHE_RSA_WITH_AES_128_CBC_SHA, try d.decode(CipherSuite));
    try testing.expectEqual(0, try d.decode(u8)); // compression method
    try testing.expectEqual(5, try d.decode(u16)); // extension length
    try testing.expectEqual(5, d.rest().len);
    try d.skip(5);
    try testing.expect(d.eof());
}
