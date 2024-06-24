const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const KeyAlgo = Certificate.Parsed.PubKeyAlgo;

bytes: []const u8,
algo: KeyAlgo,
modulus: []const u8,
private_exponent: []const u8,
public_exponent: []const u8,

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

    const empty = buf[0..0];
    switch (category) {
        .rsaEncryption => {
            const modulus = try der.Element.parse(buf, key_int.slice.end);
            const public_exponent = try der.Element.parse(buf, modulus.slice.end);
            const private_exponent = try der.Element.parse(buf, public_exponent.slice.end);

            return .{
                .bytes = empty,
                .modulus = buf[modulus.slice.start..modulus.slice.end],
                .public_exponent = buf[public_exponent.slice.start..public_exponent.slice.end],
                .private_exponent = buf[private_exponent.slice.start..private_exponent.slice.end],
                .algo = key_algo,
            };
        },
        .X9_62_id_ecPublicKey => {
            const key = try der.Element.parse(buf, key_int.slice.end);
            return .{
                .bytes = buf[key.slice.start..key.slice.end],
                .modulus = empty,
                .public_exponent = empty,
                .private_exponent = empty,
                .algo = key_algo,
            };
        },
        else => unreachable,
    }
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

    // expected results from:
    // $ openssl pkey -in testdata/rsa_private_key.pem -text -noout
    const modulus =
        "00:de:f7:23:e6:75:cc:6f:dd:d5:6e:0f:8c:09:f8:" ++
        "62:e3:60:1b:c0:7d:8c:d5:04:50:2c:36:e2:3b:f7:" ++
        "33:9f:a1:14:af:be:cf:1a:0f:4c:f5:cb:39:70:0e:" ++
        "3b:97:d6:21:f7:48:91:79:ca:7c:68:fc:ea:62:a1:" ++
        "5a:72:4f:78:57:0e:cc:f2:a3:50:05:f1:4c:ca:51:" ++
        "73:10:9a:18:8e:71:f5:b4:c7:3e:be:4c:ef:37:d4:" ++
        "84:4b:82:1c:ec:08:a3:cc:07:3d:5c:0b:e5:85:3f:" ++
        "fe:b6:44:77:8f:3c:6a:2f:33:c3:5d:f6:f2:29:46:" ++
        "04:25:7e:05:d9:f8:3b:2d:a4:40:66:9f:0d:6d:1a:" ++
        "fa:bc:0a:c5:8b:86:43:30:ef:14:20:41:9d:b5:cc:" ++
        "3e:63:b5:48:04:27:c9:5c:d3:62:28:5f:f5:b6:e4:" ++
        "77:49:99:ac:84:4a:a6:67:a5:9a:1a:37:c7:60:4c:" ++
        "ba:c1:70:cf:57:64:4a:21:ea:05:53:10:ec:94:71:" ++
        "4a:43:04:83:00:aa:5a:28:bc:f2:8c:58:14:92:d2:" ++
        "83:17:f4:7b:29:0f:e7:87:a2:47:b2:53:19:12:23:" ++
        "fb:4b:ce:5a:f8:a1:84:f9:b1:f3:bf:e3:fa:10:f8:" ++
        "ad:af:87:ce:03:0e:a0:2c:13:71:57:c4:55:44:48:" ++
        "44:cb:";
    const public_exponent = "01 00 01 ";
    const private_exponent =
        "50:3b:80:98:aa:a5:11:50:33:40:32:aa:02:e0:75:" ++
        "bd:3a:55:62:34:0b:9c:8f:bb:c5:dd:4e:15:a4:03:" ++
        "d8:9a:5f:56:4a:84:3d:ed:69:95:3d:37:03:02:ac:" ++
        "21:1c:36:06:c4:ff:4c:63:37:d7:93:c3:48:10:a5:" ++
        "fa:62:6c:7c:6f:60:02:a4:0f:e4:c3:8b:0d:76:b7:" ++
        "c0:2e:a3:4d:86:e6:92:d1:eb:db:10:d6:38:31:ea:" ++
        "15:3d:d1:e8:81:c7:67:60:e7:8c:9a:df:51:ce:d0:" ++
        "7a:88:32:b9:c1:54:b8:7d:98:fc:d4:23:1a:05:0e:" ++
        "f2:ea:e1:72:29:28:2a:68:b7:90:18:80:1c:21:d6:" ++
        "36:a8:6b:4a:9c:dd:14:b8:9f:85:ee:95:0b:f4:c6:" ++
        "17:02:aa:4d:ea:4d:f9:39:d7:dd:9d:b4:1d:d2:f8:" ++
        "92:46:0f:18:41:80:f4:ea:27:55:29:f8:37:59:bf:" ++
        "43:ec:a3:eb:19:ba:bc:13:06:95:3d:25:4b:c9:72:" ++
        "cf:41:0a:6f:aa:cb:79:d4:7b:fa:b1:09:7c:e2:2f:" ++
        "85:51:44:8b:c6:97:8e:46:f9:6b:ac:08:87:92:ce:" ++
        "af:0b:bf:8c:bd:27:51:8f:09:e4:d3:f9:04:ac:fa:" ++
        "f2:04:70:3e:d9:a6:28:17:c2:2d:74:e9:25:40:02:" ++
        "49:";

    try testing.expectEqualSlices(u8, &testu.hexStr3(modulus), pk.modulus);
    try testing.expectEqualSlices(u8, &testu.hexStr3(public_exponent), pk.public_exponent);
    try testing.expectEqualSlices(u8, &testu.hexStr3(private_exponent), pk.private_exponent);
}

test "rsa create signature" {
    const gpa = testing.allocator;

    const data = @embedFile("testdata/rsa_private_key.pem");
    var pk = try parsePem(gpa, data);
    defer pk.deinit(gpa);

    const rsa = @import("rsa/rsa.zig");
    const public_key = try rsa.PublicKey.fromBytes(pk.modulus, pk.public_exponent);
    const secret_key = try rsa.SecretKey.fromBytes(public_key.modulus, pk.private_exponent);

    const kp = rsa.KeyPair{ .public = public_key, .secret = secret_key };

    const msg = "iso medo u ducan nije reko dobar dan";
    var out: [1024]u8 = undefined;

    //const signature = try kp.signOaep(std.crypto.hash.sha2.Sha256, msg, null, &out);
    const signature = try kp.signPkcsv1_5(std.crypto.hash.sha2.Sha256, msg, &out);
    testu.bufPrint("signature", signature.bytes);
    std.debug.print("len: {}\n", .{signature.bytes.len});
}
