const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const KeyAlgo = Certificate.Parsed.PubKeyAlgo;

priv_key: []const u8,
priv_key_algo: KeyAlgo,
pub_key: []const u8,

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
    const algo = try der.Element.parse(buf, algo_seq.slice.start);
    const category = try Certificate.parseAlgorithmCategory(buf, algo);
    const key_algo: KeyAlgo = switch (category) {
        .rsaEncryption => .{ .rsaEncryption = {} },

        .X9_62_id_ecPublicKey => brk: {
            const algo_param = try der.Element.parse(buf, algo.slice.end);
            const named_curve = try Certificate.parseNamedCurve(buf, algo_param);
            break :brk .{ .X9_62_id_ecPublicKey = named_curve };
        },
        .curveEd25519 => .{ .curveEd25519 = {} },
    };

    const key_str = try der.Element.parse(buf, algo_seq.slice.end);
    const key_seq = try der.Element.parse(buf, key_str.slice.start);
    const key_int = try der.Element.parse(buf, key_seq.slice.start);
    const key = try der.Element.parse(buf, key_int.slice.end);

    const pub_key: []const u8 = switch (category) {
        .X9_62_id_ecPublicKey => brk: {
            const pub_key_seq = try der.Element.parse(buf, key.slice.end);
            const pub_key_elem = try der.Element.parse(buf, pub_key_seq.slice.start);
            const pub_key = try Certificate.parseBitString(.{ .buffer = buf, .index = 0 }, pub_key_elem);
            break :brk buf[pub_key.start..pub_key.end];
        },
        else => buf[0..0],
    };

    return .{
        .priv_key = buf[key.slice.start..key.slice.end],
        .priv_key_algo = key_algo,
        .pub_key = pub_key,
        .allocated_bytes = null,
    };
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
    const pub_key = "04 ca c4 17 3a 91 fa 80 a6 20 3e 67 4a c8 8d 5c 1a 65 a0 4d 1a 73 f8 51 9e 53 a9 57 b0 43 f7 4f f7 f0 50 09 c6 b6 48 9a 6c 5d ab 86 2d c5 0f 98 ae 2c 28 54 31 19 ee 9d 7f 3a bd 3b 9d 25 a3 ba 87 10 e2 29 c0 30 5d 85 1a 7e a2 a0 7a b0 dd a1 32 d0 8f 6e 9e 9e cb 3b 14 96 6d c5 53 28 4d f4 3d ";

    try testing.expectEqualSlices(u8, &testu.hexStr3(priv_key), pk.priv_key);
    try testing.expectEqualSlices(u8, &testu.hexStr3(pub_key), pk.pub_key);
    try testing.expectEqual(KeyAlgo{ .X9_62_id_ecPublicKey = .secp384r1 }, pk.priv_key_algo);
}

test "parse rsa pem" {
    const gpa = testing.allocator;

    const data = @embedFile("testdata/rsa_private_key.pem");
    var pk = try parsePem(gpa, data);
    defer pk.deinit(gpa);
    testu.bufPrint("key", pk.priv_key);

    // const priv_key = "10 35 3d ca 1b 15 1d 06 aa 71 b8 ef f3 19 22 43 78 f3 20 98 1e b1 2f 2b 64 7e 71 d0 30 2a 90 aa e5 eb 99 c3 90 65 3d c1 26 19 be 3f 08 20 9b 01 ";
    // const pub_key = "04 ca c4 17 3a 91 fa 80 a6 20 3e 67 4a c8 8d 5c 1a 65 a0 4d 1a 73 f8 51 9e 53 a9 57 b0 43 f7 4f f7 f0 50 09 c6 b6 48 9a 6c 5d ab 86 2d c5 0f 98 ae 2c 28 54 31 19 ee 9d 7f 3a bd 3b 9d 25 a3 ba 87 10 e2 29 c0 30 5d 85 1a 7e a2 a0 7a b0 dd a1 32 d0 8f 6e 9e 9e cb 3b 14 96 6d c5 53 28 4d f4 3d ";

    // try testing.expectEqualSlices(u8, &testu.hexStr3(priv_key), pk.priv_key);
    // try testing.expectEqualSlices(u8, &testu.hexStr3(pub_key), pk.pub_key);
    // try testing.expectEqual(PubKeyAlgo{ .X9_62_id_ecPublicKey = .secp384r1 }, pk.priv_key_algo);
}
