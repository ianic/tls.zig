const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const KeyAlgo = Certificate.Parsed.PubKeyAlgo;
const AlgorithmCategory = Certificate.AlgorithmCategory;
const NamedCurve = Certificate.NamedCurve;
const tls = std.crypto.tls;
const rsa = @import("rsa/rsa.zig");
const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
const max_ecdsa_key_len = 48;

signature_scheme: tls.SignatureScheme,

key: union {
    rsa: rsa.KeyPair,
    ecdsa: [max_ecdsa_key_len]u8,
},

const PrivateKey = @This();

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
    defer gpa.free(decoded);
    errdefer gpa.free(decoded);
    const n = try base64.decode(decoded, encoded);

    return try parseDer(decoded[0..n]);
}

pub fn parseDer(buf: []const u8) !PrivateKey {
    const info_seq = try der.Element.parse(buf, 0);
    const version = try der.Element.parse(buf, info_seq.slice.start);

    const algo_seq = try der.Element.parse(buf, version.slice.end);
    const algo_cat = try der.Element.parse(buf, algo_seq.slice.start);
    const category = try Certificate.parseAlgorithmCategory(buf, algo_cat);

    const key_str = try der.Element.parse(buf, algo_seq.slice.end);
    const key_seq = try der.Element.parse(buf, key_str.slice.start);
    const key_int = try der.Element.parse(buf, key_seq.slice.start);

    switch (category) {
        .rsaEncryption => {
            const modulus_elem = try der.Element.parse(buf, key_int.slice.end);
            const public_exponent_elem = try der.Element.parse(buf, modulus_elem.slice.end);
            const private_exponent_elem = try der.Element.parse(buf, public_exponent_elem.slice.end);

            const modulus = buf[modulus_elem.slice.start..modulus_elem.slice.end];
            const public_exponent = buf[public_exponent_elem.slice.start..public_exponent_elem.slice.end];
            const private_exponent = buf[private_exponent_elem.slice.start..private_exponent_elem.slice.end];

            const public_key = try rsa.PublicKey.fromBytes(modulus, public_exponent);
            const secret_key = try rsa.SecretKey.fromBytes(public_key.modulus, private_exponent);
            const kp = rsa.KeyPair{ .public = public_key, .secret = secret_key };
            const modulus_len = rsa.byteLen(kp.public.modulus.bits());

            const signature_scheme: tls.SignatureScheme = switch (modulus_len) {
                256 => .rsa_pss_rsae_sha256,
                384 => .rsa_pss_rsae_sha384,
                512 => .rsa_pss_rsae_sha512,
                else => return error.TlsPrivateKeyUnknownLength,
            };
            return .{
                .signature_scheme = signature_scheme,
                .key = .{ .rsa = kp },
            };
        },
        .X9_62_id_ecPublicKey => {
            const key = try der.Element.parse(buf, key_int.slice.end);
            const algo_param = try der.Element.parse(buf, algo_cat.slice.end);
            const secret_key = buf[key.slice.start..key.slice.end];
            const named_curve = try Certificate.parseNamedCurve(buf, algo_param);
            const signature_scheme: tls.SignatureScheme = switch (named_curve) {
                .secp384r1 => .ecdsa_secp384r1_sha384,
                .X9_62_prime256v1 => .ecdsa_secp256r1_sha256,
                else => return error.TlsUnknownSignatureScheme,
            };

            if (secret_key.len > max_ecdsa_key_len) return error.BufferOverflow;
            var ecdsa_key: [max_ecdsa_key_len]u8 = undefined;
            @memcpy(ecdsa_key[0..secret_key.len], secret_key);

            return .{
                .signature_scheme = signature_scheme,
                .key = .{ .ecdsa = ecdsa_key },
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

const testing = std.testing;
const testu = @import("testu.zig");

test "parse ec pem" {
    const gpa = testing.allocator;

    const data = @embedFile("testdata/ec_private_key.pem");
    var pk = try parsePem(gpa, data);
    //defer pk.deinit(gpa);

    const priv_key = &testu.hexToBytes(
        \\ 10 35 3d ca 1b 15 1d 06 aa 71 b8 ef f3 19 22 43
        \\ 78 f3 20 98 1e b1 2f 2b 64 7e 71 d0 30 2a 90 aa
        \\ e5 eb 99 c3 90 65 3d c1 26 19 be 3f 08 20 9b 01
    );

    try testing.expectEqualSlices(u8, priv_key, &pk.key.ecdsa);
    try testing.expectEqual(.ecdsa_secp384r1_sha384, pk.signature_scheme);
}

test "parse rsa pem" {
    const gpa = testing.allocator;

    const data = @embedFile("testdata/rsa_private_key.pem");
    const pk = try parsePem(gpa, data);

    // expected results from:
    // $ openssl pkey -in testdata/rsa_private_key.pem -text -noout
    const modulus = &testu.hexToBytes(
        \\ 00 de f7 23 e6 75 cc 6f dd d5 6e 0f 8c 09 f8
        \\ 62 e3 60 1b c0 7d 8c d5 04 50 2c 36 e2 3b f7
        \\ 33 9f a1 14 af be cf 1a 0f 4c f5 cb 39 70 0e
        \\ 3b 97 d6 21 f7 48 91 79 ca 7c 68 fc ea 62 a1
        \\ 5a 72 4f 78 57 0e cc f2 a3 50 05 f1 4c ca 51
        \\ 73 10 9a 18 8e 71 f5 b4 c7 3e be 4c ef 37 d4
        \\ 84 4b 82 1c ec 08 a3 cc 07 3d 5c 0b e5 85 3f
        \\ fe b6 44 77 8f 3c 6a 2f 33 c3 5d f6 f2 29 46
        \\ 04 25 7e 05 d9 f8 3b 2d a4 40 66 9f 0d 6d 1a
        \\ fa bc 0a c5 8b 86 43 30 ef 14 20 41 9d b5 cc
        \\ 3e 63 b5 48 04 27 c9 5c d3 62 28 5f f5 b6 e4
        \\ 77 49 99 ac 84 4a a6 67 a5 9a 1a 37 c7 60 4c
        \\ ba c1 70 cf 57 64 4a 21 ea 05 53 10 ec 94 71
        \\ 4a 43 04 83 00 aa 5a 28 bc f2 8c 58 14 92 d2
        \\ 83 17 f4 7b 29 0f e7 87 a2 47 b2 53 19 12 23
        \\ fb 4b ce 5a f8 a1 84 f9 b1 f3 bf e3 fa 10 f8
        \\ ad af 87 ce 03 0e a0 2c 13 71 57 c4 55 44 48
        \\ 44 cb
    );
    const public_exponent = &testu.hexToBytes("01 00 01");
    const private_exponent = &testu.hexToBytes(
        \\ 50 3b 80 98 aa a5 11 50 33 40 32 aa 02 e0 75
        \\ bd 3a 55 62 34 0b 9c 8f bb c5 dd 4e 15 a4 03
        \\ d8 9a 5f 56 4a 84 3d ed 69 95 3d 37 03 02 ac
        \\ 21 1c 36 06 c4 ff 4c 63 37 d7 93 c3 48 10 a5
        \\ fa 62 6c 7c 6f 60 02 a4 0f e4 c3 8b 0d 76 b7
        \\ c0 2e a3 4d 86 e6 92 d1 eb db 10 d6 38 31 ea
        \\ 15 3d d1 e8 81 c7 67 60 e7 8c 9a df 51 ce d0
        \\ 7a 88 32 b9 c1 54 b8 7d 98 fc d4 23 1a 05 0e
        \\ f2 ea e1 72 29 28 2a 68 b7 90 18 80 1c 21 d6
        \\ 36 a8 6b 4a 9c dd 14 b8 9f 85 ee 95 0b f4 c6
        \\ 17 02 aa 4d ea 4d f9 39 d7 dd 9d b4 1d d2 f8
        \\ 92 46 0f 18 41 80 f4 ea 27 55 29 f8 37 59 bf
        \\ 43 ec a3 eb 19 ba bc 13 06 95 3d 25 4b c9 72
        \\ cf 41 0a 6f aa cb 79 d4 7b fa b1 09 7c e2 2f
        \\ 85 51 44 8b c6 97 8e 46 f9 6b ac 08 87 92 ce
        \\ af 0b bf 8c bd 27 51 8f 09 e4 d3 f9 04 ac fa
        \\ f2 04 70 3e d9 a6 28 17 c2 2d 74 e9 25 40 02
        \\ 49
    );

    try testing.expectEqual(.rsa_pss_rsae_sha256, pk.signature_scheme);
    const kp = pk.key.rsa;
    {
        var bytes: [modulus.len]u8 = undefined;
        try kp.public.modulus.toBytes(&bytes, .big);
        try testing.expectEqualSlices(u8, modulus, &bytes);
    }
    {
        var bytes: [private_exponent.len]u8 = undefined;
        try kp.public.public_exponent.toBytes(&bytes, .big);
        try testing.expectEqualSlices(u8, public_exponent, bytes[bytes.len - public_exponent.len .. bytes.len]);
    }
    {
        var btytes: [private_exponent.len]u8 = undefined;
        try kp.secret.private_exponent.toBytes(&btytes, .big);
        try testing.expectEqualSlices(u8, private_exponent, &btytes);
    }
}
