const std = @import("std");
const proto = @import("protocol.zig");
const common = @import("handshake_common.zig");

const record = @import("record.zig");
const connection = @import("connection.zig").connection;
const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;
const HandshakeServer = @import("handshake_server.zig").Handshake;
const HandshakeClient = @import("handshake_client.zig").Handshake;
pub const Connection = @import("connection.zig").Connection;

pub fn client(stream: anytype, opt: config.Client) !Connection(@TypeOf(stream)) {
    const Stream = @TypeOf(stream);
    var conn = connection(stream);
    var write_buf: [max_ciphertext_record_len]u8 = undefined;
    var h = HandshakeClient(Stream).init(&write_buf, &conn.rec_rdr);
    conn.cipher = try h.handshake(conn.stream, opt);
    return conn;
}

pub fn server(stream: anytype, opt: config.Server) !Connection(@TypeOf(stream)) {
    const Stream = @TypeOf(stream);
    var conn = connection(stream);
    var write_buf: [max_ciphertext_record_len]u8 = undefined;
    var h = HandshakeServer(Stream).init(&write_buf, &conn.rec_rdr);
    conn.cipher = try h.handshake(conn.stream, opt);
    return conn;
}

pub const config = struct {
    pub const CipherSuite = @import("cipher.zig").CipherSuite;
    pub const PrivateKey = @import("PrivateKey.zig");
    pub const NamedGroup = proto.NamedGroup;
    pub const Version = proto.Version;
    pub const CertBundle = common.CertBundle;
    pub const CertKeyPair = common.CertKeyPair;

    pub const cipher_suites = @import("cipher.zig").cipher_suites;
    pub const key_log = @import("key_log.zig");

    pub const Client = @import("handshake_client.zig").Options;
    pub const Server = @import("handshake_server.zig").Options;
};

pub const asyn = struct {
    const Async = @import("connection.zig").Async;
    const _hc = @import("handshake_client.zig");
    const _hs = @import("handshake_server.zig");

    pub fn Client(T: type) type {
        return Async(T, _hc.Async, _hc.Options);
    }
    pub fn Server(T: type) type {
        return Async(T, _hs.Async, _hs.Options);
    }
};

test {
    _ = @import("handshake_common.zig");
    _ = @import("handshake_server.zig");
    _ = @import("handshake_client.zig");

    _ = @import("connection.zig");
    _ = @import("cipher.zig");
    _ = @import("record.zig");
    _ = @import("transcript.zig");
    _ = @import("PrivateKey.zig");
}

pub const CertBundle = @compileError("deprecated: use config.CertBundle, see:https://github.com/ianic/tls.zig/commit/c028a2845d546298fdac3a1d3e3849090c8fc1ff");
