const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const tls = crypto.tls;
pub const int2 = tls.int2;
const int3 = tls.int3;

// tls.HandshakeType is missing server_key_exchange, server_hello_done
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

pub inline fn int1(x: u8) [1]u8 {
    return .{x};
}

// int1 from enum
pub inline fn int1e(x: anytype) [1]u8 {
    return int1(@intFromEnum(x));
}

pub inline fn int2e(x: anytype) [2]u8 {
    return int2(@intFromEnum(x));
}

// Returns extension payload and number of padding bytes.
pub inline fn serverNameExtension(host: []const u8) struct { [269]u8, usize } {
    assert(host.len <= 255);
    var ext = int2e(tls.ExtensionType.server_name) ++
        int2(@intCast(host.len + 5)) ++ // byte length of this extension payload
        int2(@intCast(host.len + 3)) ++ // server_name_list byte count
        [1]u8{0x00} ++ // name_type
        int2(@intCast(host.len)) ++
        [_]u8{0} ** 260;
    @memcpy(ext[9..][0..host.len], host);
    ext[9 + host.len ..][0..2].* = [_]u8{ 0x00, 0x15 };
    ext[9 + host.len + 2 ..][0..2].* = int2(@intCast(260 - host.len - 4));
    return .{ ext, 260 - host.len };
}

pub const CipherSuite = enum(u16) {
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,

    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,

    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,

    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,

    // TLS 1.3
    //TLS_AES_256_GCM_SHA384 = 0x1302,

    AES_128_GCM_SHA256 = 0x1301,
    AES_256_GCM_SHA384 = 0x1302,
    CHACHA20_POLY1305_SHA256 = 0x1303,
    //AES_128_CCM_SHA256 = 0x1304,
    //AES_128_CCM_8_SHA256 = 0x1305,
    //AEGIS_256_SHA512 = 0x1306,
    //AEGIS_128L_SHA256 = 0x1307,

    _,

    // in the order of preference
    pub const supported = [_]CipherSuite{
        .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

        .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,

        .TLS_RSA_WITH_AES_128_CBC_SHA256,
    };

    pub const supported13 = [_]CipherSuite{
        .CHACHA20_POLY1305_SHA256,
        .AES_256_GCM_SHA384,
        .AES_128_GCM_SHA256,
    };

    pub fn validate(cs: CipherSuite) !void {
        for (supported) |s| {
            if (cs == s) return;
        }
        for (supported13) |s| {
            if (cs == s) return;
        }
        return error.TlsIllegalParameter;
    }

    pub const KeyExchangeAlgorithm = enum {
        ecdhe,
        rsa,
    };

    // Random premaster secret, encrypted with publich key from certificate.
    // No server key exchange message.
    pub fn keyExchange(s: CipherSuite) KeyExchangeAlgorithm {
        return switch (s) {
            .TLS_RSA_WITH_AES_128_CBC_SHA,
            .TLS_RSA_WITH_AES_128_CBC_SHA256,
            .TLS_RSA_WITH_AES_256_CBC_SHA256,
            => .rsa,
            else => .ecdhe,
        };
    }

    pub const Cipher = enum {
        // tls 1.2
        aes_128_cbc_sha,
        aes_128_cbc_sha256,
        aes_256_cbc_sha384,
        aes_128_gcm,
        aes_256_gcm,
        // tls 1.3
        aes_256_gcm_sha384,
        aes_128_gcm_sha256,
        chacha20_poly1305_sha256,
    };

    pub fn cipher(cs: CipherSuite) !Cipher {
        return switch (cs) {
            // tls 1.2
            .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            => .aes_128_cbc_sha,
            .TLS_RSA_WITH_AES_128_CBC_SHA256,
            => .aes_128_cbc_sha256,
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            => .aes_256_cbc_sha384,
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            => .aes_128_gcm,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            => .aes_256_gcm,
            // tls 1.3
            .AES_256_GCM_SHA384 => .aes_256_gcm_sha384,
            .AES_128_GCM_SHA256 => .aes_128_gcm_sha256,
            .CHACHA20_POLY1305_SHA256 => .chacha20_poly1305_sha256,
            else => return error.TlsIllegalParameter,
        };
    }

    pub const Hash = enum {
        sha256,
        sha384,
    };

    pub fn hash(cs: CipherSuite) Hash {
        return switch (cs) {
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .AES_256_GCM_SHA384,
            => .sha384,
            else => .sha256,
        };
    }
};

pub const CurveType = enum(u8) {
    named_curve = 0x03,
    _,
};

pub const extension = struct {
    pub const status_request = [_]u8{ 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 };
    pub const ec_point_formats = [_]u8{ 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 };
    pub const renegotiation_info = [_]u8{ 0xff, 0x01, 0x00, 0x01, 0x00 };
    pub const sct = [_]u8{ 0x00, 0x12, 0x00, 0x00 };
};

pub const hello = struct {
    pub const no_compression = [_]u8{ 0x01, 0x00 };
    pub const no_session_id = [_]u8{0x00};
    pub const protocol_version = int2e(tls.ProtocolVersion.tls_1_2);
};

pub inline fn handshakeHeader(handshake_type: HandshakeType, payload_len: usize) [9]u8 {
    return recordHeader(.handshake, 4 + payload_len) ++
        int1e(handshake_type) ++
        int3(@intCast(payload_len));
}

pub inline fn recordHeader(content_type: tls.ContentType, payload_len: usize) [5]u8 {
    return int1e(content_type) ++
        int2e(tls.ProtocolVersion.tls_1_2) ++
        int2(@intCast(payload_len));
}

pub const explicit_iv_len = 8;

pub const close_notify_alert = [2]u8{
    @intFromEnum(tls.AlertLevel.warning),
    @intFromEnum(tls.AlertDescription.close_notify),
};

pub const handshake_finished_header = [_]u8{ 0x14, 0x00, 0x00, 0x0c };

// HelloRetryRequest message uses the same structure as the ServerHello, but
// with Random set to the special value of the SHA-256 of "HelloRetryRequest"
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
const hello_retry_request_magic = "\xCF\x21\xAD\x74\xE5\x9A\x61\x11\xBE\x1D\x8C\x02\x1E\x65\xB8\x91\xC2\xA2\x11\x16\x7A\xBB\x8C\x5E\x07\x9E\x09\xE2\xC8\xA8\x33\x9C";

pub fn isServerHelloRetryRequest(server_random: []const u8) bool {
    return std.mem.eql(u8, server_random, hello_retry_request_magic);
}

const testing = std.testing;

test "tls1.3 ciphers" {
    {
        const cs: CipherSuite = .AES_256_GCM_SHA384;
        try cs.validate();
        try testing.expectEqual(cs.cipher(), .aes_256_gcm_sha384);
        try testing.expectEqual(cs.hash(), .sha384);
        try testing.expectEqual(cs.keyExchange(), .ecdhe);
    }
    {
        const cs: CipherSuite = .AES_128_GCM_SHA256;
        try cs.validate();
        try testing.expectEqual(.aes_128_gcm_sha256, cs.cipher());
        try testing.expectEqual(.sha256, cs.hash());
        try testing.expectEqual(.ecdhe, cs.keyExchange());
    }
    for (CipherSuite.supported) |cs| {
        try cs.validate();
        _ = try cs.cipher();
        _ = cs.hash();
        _ = cs.keyExchange();
    }
}
