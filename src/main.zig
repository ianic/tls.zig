const std = @import("std");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    //var arena_instance = std.heap.ArenaAllocator.init(gpa);
    //const arena = arena_instance.allocator();

    const url = "https://google.com";
    const uri = try std.Uri.parse(url);

    var tcp = try std.net.tcpConnectToHost(gpa, uri.host.?.percent_encoded, 443);
    defer tcp.close();

    try tcp.writeAll(&client_hello);

    var file = try std.fs.cwd().createFile("server_hello", .{});
    defer file.close();

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try tcp.readAll(&buf);
        //std.debug.print("{x}\n", .{buf});
        try file.writer().writeAll(buf[0..n]);
        if (n < buf.len) break;
    }
}

const client_hello = [_]u8{
    0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00,
    0xa1, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x20, 0xcc, 0xa8,
    0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b,
    0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14,
    0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
    0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00,
    0x00, 0x58, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16,
    0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65,
    0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x05,
    0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00,
    0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00,
    0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00,
    0x10, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x05,
    0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02,
    0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12,
    0x00, 0x00,
};

const testing = std.testing;

const server_hello = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0x31, 0x02, 0x00, 0x00,
    0x2d, 0x03, 0x03, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
    0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
    0x8d, 0x8e, 0x8f, 0x00, 0xc0, 0x13, 0x00, 0x00,
    0x05, 0xff, 0x01, 0x00, 0x01, 0x00,
};

test "parse server hello" {
    var stream = std.io.fixedBufferStream(&server_hello);
    const reader = stream.reader();

    const rh = try RecordHeader.parse(reader);
    try testing.expectEqual(RecordHeader.Kind.handshake, rh.kind);
    try testing.expectEqual(0x31, rh.size);

    const hh = try HandshakeHeader.parse(reader);
    try testing.expectEqual(HandshakeHeader.Kind.server_hello, hh.kind);
    try testing.expectEqual(0x2d, hh.size);

    const sh = try ServerHello.parse(reader);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    }, &sh.random);
    try testing.expectEqual(5, sh.extension_length);
}

// const Handshake = struct {
//     pub fn serverHello(self: *Handshake, reader: anytype) !void {
//         const record_type = try reader.readByte();
//     }
// };

const RecordHeader = struct {
    const Kind = enum(u8) {
        alert = 0x15,
        handshake = 0x16,
        data = 0x17,
    };

    kind: Kind,
    version: ProtocolVersion,
    size: u16,

    fn parse(reader: anytype) !RecordHeader {
        const k = try reader.readByte();
        if (k < 0x15 or k > 0x17) return error.UnknownRecordHeaderKind;
        const p = try reader.readInt(u16, .big);
        if (p != 0x0303) return error.UnknownRecordHeaderVersion;
        const size = try reader.readInt(u16, .big);
        return .{
            .kind = @enumFromInt(k),
            .version = .tls12,
            .size = size,
        };
    }
};

const ProtocolVersion = enum(u16) {
    tls12 = 0x0303,
};

const ChiperSuite = enum(u16) {
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
};

const HandshakeHeader = struct {
    const Kind = enum(u8) {
        server_hello = 0x02,
    };
    kind: Kind,
    size: u24,

    fn parse(reader: anytype) !HandshakeHeader {
        const k = try reader.readByte();
        if (k < 0x02 or k > 0x02) return error.UnknownHandshakeHeaderKind;
        const size = try reader.readInt(u24, .big);
        return .{
            .kind = @enumFromInt(k),
            .size = size,
        };
    }
};

const ServerHello = struct {
    version: ProtocolVersion,
    random: [32]u8,
    session_id: u8,
    chiper_suite: ChiperSuite,
    extension_length: u16,

    fn parse(reader: anytype) !ServerHello {
        const v = try reader.readInt(u16, .big);
        if (v != 0x0303) return error.UnknownServerHelloVersion;

        var random: [32]u8 = undefined;
        try reader.readNoEof(&random);

        const session_id = try reader.readByte();

        const cs = try reader.readInt(u16, .big);
        if (cs != 0xc013) return error.UnknownServerHelloChiperSuite;

        const cm = try reader.readByte();
        _ = cm; // compression method

        const el = try reader.readInt(u16, .big);
        try reader.skipBytes(el, .{});

        return .{
            .version = @enumFromInt(v),
            .random = random,
            .session_id = session_id,
            .chiper_suite = @enumFromInt(cs),
            .extension_length = el,
        };
    }
};

// test "enum" {
//     const e: RecordHeader.Kind = @enumFromInt(0x14);
//     std.debug.print("e: {}\n", .{e});
// }
