const std = @import("std");
const proto = @import("protocol.zig");
const common = @import("handshake_common.zig");

const record = @import("record.zig");
const connection = @import("connection.zig").connection;
pub const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;
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

pub const nb = struct {
    const NonBlocking = @import("connection.zig").NonBlocking;

    const _hc = @import("handshake_client.zig");
    const _hs = @import("handshake_server.zig");

    pub fn Client() type {
        return NonBlocking(_hc.Async, _hc.Options);
    }
    pub fn Server() type {
        return NonBlocking(_hs.Async, _hs.Options);
    }

    pub const HandshakeClient = _hc.Async;
    pub const HandshakeServer = _hs.Async;
    pub const Connection = @import("connection.zig").NBConnection;
};

test "non blocking handshake and connection" {
    const testing = std.testing;

    // data from server to the client
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    // data from client to the server
    var cs_buf: [max_ciphertext_record_len]u8 = undefined;

    // client/server handshake produces ciphers
    const cli_cipher, const srv_cipher = brk: {
        var cli = nb.HandshakeClient.init(.{
            .root_ca = .{},
            .host = &.{},
            .insecure_skip_verify = true,
        });
        var srv = nb.HandshakeServer.init(.{ .auth = null });

        // client flight1; client hello is in buf1
        var cr = try cli.run(&sc_buf, &cs_buf);
        try testing.expectEqual(0, cr.recv_pos);
        try testing.expect(cr.send.len > 0);
        try testing.expect(!cli.done());

        { // short read, partial buffer received
            for (0..cr.send_pos) |i| {
                const sr = try srv.run(cs_buf[0..i], &sc_buf);
                try testing.expectEqual(0, sr.recv_pos);
                try testing.expectEqual(0, sr.send_pos);
            }
        }

        // server flight 1; server parses client hello from buf2 and writes server hello into buf1
        var sr = try srv.run(&cs_buf, &sc_buf);
        try testing.expectEqual(sr.recv_pos, cr.send_pos);
        try testing.expect(sr.send.len > 0);
        try testing.expect(!srv.done());

        { // short read, partial buffer received
            for (0..sr.send_pos) |i| {
                cr = try cli.run(sc_buf[0..i], &cs_buf);
                try testing.expectEqual(0, cr.recv_pos);
                try testing.expectEqual(0, cr.send_pos);
            }
        }

        // client flight 2; client parses server hello from buf1 and writes finished into buf2
        cr = try cli.run(&sc_buf, &cs_buf);
        try testing.expectEqual(sr.send_pos, cr.recv_pos);
        try testing.expect(cr.send.len > 0);
        try testing.expect(cli.done()); // client is done
        try testing.expect(cli.cipher() != null);

        // server parses client finished
        sr = try srv.run(&cs_buf, &sc_buf);
        try testing.expectEqual(sr.recv_pos, cr.send_pos);
        try testing.expectEqual(0, sr.send.len);
        try testing.expect(srv.done()); // server is done
        try testing.expect(srv.cipher() != null);

        break :brk .{ cli.cipher().?, srv.cipher().? };
    };
    { // use ciphers in connection
        var cli = nb.Connection.init(cli_cipher);
        var srv = nb.Connection.init(srv_cipher);

        const cleartext = "Lorem ipsum dolor sit amet";
        { // client to server
            const e = try cli.encrypt(cleartext, &cs_buf);
            try testing.expectEqual(cleartext.len, e.cleartext_pos);
            try testing.expect(e.ciphertext.len > cleartext.len);
            try testing.expect(e.unused_cleartext.len == 0);

            const d = try srv.decrypt(e.ciphertext, &sc_buf);
            try testing.expectEqualSlices(u8, cleartext, d.cleartext);
            try testing.expectEqual(e.ciphertext.len, d.ciphertext_pos);
            try testing.expectEqual(0, d.unused_ciphertext.len);
        }
        { // server to client
            const e = try srv.encrypt(cleartext, &sc_buf);
            const d = try cli.decrypt(e.ciphertext, &cs_buf);
            try testing.expectEqualSlices(u8, cleartext, d.cleartext);
        }
        { // server sends close
            const close_buf = try srv.close(&sc_buf);
            const d = try cli.decrypt(close_buf, &cs_buf);
            try testing.expectEqual(close_buf.len, d.ciphertext_pos);
            try testing.expectEqual(0, d.unused_ciphertext.len);
            try testing.expect(d.closed);
        }
    }
}

test {
    // _ = nb;
    // _ = @import("handshake_common.zig");
    // _ = @import("handshake_server.zig");
    // _ = @import("handshake_client.zig");

    // _ = @import("connection.zig");
    // _ = @import("cipher.zig");
    // _ = @import("record.zig");
    // _ = @import("transcript.zig");
    // _ = @import("PrivateKey.zig");
}

pub const CertBundle = @compileError("deprecated: use config.CertBundle, see:https://github.com/ianic/tls.zig/commit/c028a2845d546298fdac3a1d3e3849090c8fc1ff");
