const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const int2 = tls.int2;
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
    AES_128_CBC_SHA = 0xc013,
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
