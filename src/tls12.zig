const std = @import("std");
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

pub inline fn serverNameExtensionHeader(host_len: u16) [9]u8 {
    return int2e(tls.ExtensionType.server_name) ++
        int2(host_len + 5) ++ // byte length of this extension payload
        int2(host_len + 3) ++ // server_name_list byte count
        [1]u8{0x00} ++ // name_type
        int2(host_len);
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
    TLS_AES_256_GCM_SHA384 = 0x1302,
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
        .TLS_AES_256_GCM_SHA384,
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
        aes_128_cbc_sha,
        aes_128_cbc_sha256,
        aes_128_gcm,
        aes_256_gcm,

        aes_256_gcm_sha384,
    };

    pub fn cipher(cs: CipherSuite) !Cipher {
        return switch (cs) {
            .TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            => .aes_128_cbc_sha,
            .TLS_RSA_WITH_AES_128_CBC_SHA256,
            => .aes_128_cbc_sha256,
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            => .aes_128_gcm,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            => .aes_256_gcm,

            .TLS_AES_256_GCM_SHA384 => .aes_256_gcm_sha384,
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
            .TLS_AES_256_GCM_SHA384,
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
