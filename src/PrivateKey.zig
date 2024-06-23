const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const KeyAlgo = Certificate.Parsed.PubKeyAlgo;

bytes: []const u8,
algo: KeyAlgo,

allocated_bytes: ?[]const u8 = null,

const PrivateKey = @This();

const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

pub fn parsePem(gpa: Allocator, buf: []const u8) !PrivateKey {
    const begin_marker = "-----BEGIN PRIVATE KEY-----";
    const end_marker = "-----END PRIVATE KEY-----";

    const begin_marker_start = std.mem.indexOfPos(u8, buf, 0, begin_marker) orelse
        return error.MissingEndMarker;
    const key_start = begin_marker_start + begin_marker.len;
    const key_end = std.mem.indexOfPos(u8, buf, key_start, end_marker) orelse
        return error.MissingEndMarker;

    const encoded = std.mem.trim(u8, buf[key_start..key_end], " \t\r\n");
    const decoded_size_upper_bound = encoded.len / 4 * 3;
    const decoded = try gpa.alloc(u8, decoded_size_upper_bound);
    errdefer gpa.free(decoded);
    const n = try base64.decode(decoded, encoded);

    var k = try parseDer(decoded[0..n]);
    k.allocated_bytes = decoded;
    return k;
}

pub fn parseDer(buf: []const u8) !PrivateKey {
    const info_seq = try der.Element.parse(buf, 0);
    const version = try der.Element.parse(buf, info_seq.slice.start);

    const algo_seq = try der.Element.parse(buf, version.slice.end);
    const algo_cat = try der.Element.parse(buf, algo_seq.slice.start);
    const category = try Certificate.parseAlgorithmCategory(buf, algo_cat);
    const key_algo: KeyAlgo = switch (category) {
        .rsaEncryption => .{ .rsaEncryption = {} },

        .X9_62_id_ecPublicKey => brk: {
            const algo_param = try der.Element.parse(buf, algo_cat.slice.end);
            const named_curve = try Certificate.parseNamedCurve(buf, algo_param);
            break :brk .{ .X9_62_id_ecPublicKey = named_curve };
        },
        .curveEd25519 => .{ .curveEd25519 = {} },
    };

    const key_str = try der.Element.parse(buf, algo_seq.slice.end);
    const key_seq = try der.Element.parse(buf, key_str.slice.start);
    const key_int = try der.Element.parse(buf, key_seq.slice.start);
    const key = try der.Element.parse(buf, key_int.slice.end);

    return .{
        .bytes = buf[key.slice.start..key.slice.end],
        .algo = key_algo,
        .allocated_bytes = null,
    };
}

pub fn fromFile(gpa: Allocator, file: std.fs.File) !PrivateKey {
    const buf = try file.readToEndAlloc(gpa, 1024 * 1024);
    defer gpa.free(buf);
    return try parsePem(gpa, buf);
}

pub fn deinit(k: *PrivateKey, gpa: Allocator) void {
    if (k.allocated_bytes) |b| {
        gpa.free(b);
    }
}

const testing = std.testing;
const testu = @import("testu.zig");

test "parse ec pem" {
    const gpa = testing.allocator;

    const data = @embedFile("testdata/ec_private_key.pem");
    var pk = try parsePem(gpa, data);
    defer pk.deinit(gpa);

    const priv_key = "10 35 3d ca 1b 15 1d 06 aa 71 b8 ef f3 19 22 43 78 f3 20 98 1e b1 2f 2b 64 7e 71 d0 30 2a 90 aa e5 eb 99 c3 90 65 3d c1 26 19 be 3f 08 20 9b 01 ";

    try testing.expectEqualSlices(u8, &testu.hexStr3(priv_key), pk.bytes);
    try testing.expectEqual(KeyAlgo{ .X9_62_id_ecPublicKey = .secp384r1 }, pk.algo);
}

test "parse rsa pem" {
    const gpa = testing.allocator;

    const data = @embedFile("testdata/rsa_private_key.pem");
    var pk = try parsePem(gpa, data);
    defer pk.deinit(gpa);
    testu.bufPrint("key", pk.bytes);
}
