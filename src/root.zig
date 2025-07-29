pub const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;
/// Suggested stream reader/writer buffer sizes:
/// Minimal buffer big enough for any tls ciphertext record.
pub const stream_reader_buffer_len = max_ciphertext_record_len; // 16645 bytes
/// Minimal buffer to fit any ciphertext record produced with this tls
/// implementation.
pub const stream_writer_buffer_len = @import("cipher.zig").max_encrypted_record_len; // 16469 bytes

pub const Connection = @import("connection.zig").Connection;

const handshake = struct {
    const Client = @import("handshake_client.zig").Handshake;
    const Server = @import("handshake_server.zig").Handshake;
};

/// Upgrades existing stream to the tls connection by the client tls handshake.
pub inline fn client(stream: anytype, opt: config.Client) !Connection {
    var reader_buf: [stream_reader_buffer_len]u8 = undefined;
    var writer_buf: [stream_writer_buffer_len]u8 = undefined;
    var reader = stream.reader(&reader_buf);
    var writer = stream.writer(&writer_buf);
    const stream_reader = if (@hasField(@TypeOf(reader), "interface")) &reader.interface else reader.interface();
    const stream_writer = &writer.interface;

    var hc: handshake.Client = .{
        .stream_reader = stream_reader,
        .stream_writer = stream_writer,
    };
    const cipher, const session_resumption_secret_idx = try hc.handshake(opt);
    return .{
        .cipher = cipher,
        .stream_reader = stream_reader,
        .stream_writer = stream_writer,
        .session_resumption_secret_idx = session_resumption_secret_idx,
        .session_resumption = opt.session_resumption,
    };
}

/// Upgrades existing stream to the tls connection by the server side tls handshake.
pub inline fn server(stream: anytype, opt: config.Server) !Connection {
    var reader_buf: [stream_reader_buffer_len]u8 = undefined;
    var writer_buf: [stream_writer_buffer_len]u8 = undefined;
    var reader = stream.reader(&reader_buf);
    var writer = stream.writer(&writer_buf);
    const stream_reader = if (@hasField(@TypeOf(reader), "interface")) &reader.interface else reader.interface();
    const stream_writer = &writer.interface;

    var hs: handshake.Server = .{
        .stream_reader = stream_reader,
        .stream_writer = stream_writer,
    };
    const cipher = try hs.handshake(opt);
    return .{
        .cipher = cipher,
        .stream_reader = stream_reader,
        .stream_writer = stream_writer,
    };
}

pub const config = struct {
    const proto = @import("protocol.zig");
    const common = @import("handshake_common.zig");

    pub const CipherSuite = @import("cipher.zig").CipherSuite;
    pub const PrivateKey = @import("PrivateKey.zig");
    pub const NamedGroup = proto.NamedGroup;
    pub const Version = proto.Version;
    pub const cert = common.cert;
    pub const CertKeyPair = common.CertKeyPair;

    pub const cipher_suites = @import("cipher.zig").cipher_suites;
    pub const key_log = @import("key_log.zig");

    pub const Client = @import("handshake_client.zig").Options;
    pub const Server = @import("handshake_server.zig").Options;
};

/// Non-blocking client/server handshake and connection. Handshake produces
/// cipher used in connection to encrypt data for sending and decrypt received
/// data.
pub const nonblock = struct {
    pub const Client = @import("handshake_client.zig").NonBlock;
    pub const Server = @import("handshake_server.zig").NonBlock;
    pub const Connection = @import("connection.zig").NonBlock;
};

test "nonblock handshake and connection" {
    const testing = @import("std").testing;

    // data from server to the client
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    // data from client to the server
    var cs_buf: [max_ciphertext_record_len]u8 = undefined;

    // client/server handshake produces ciphers
    const cli_cipher, const srv_cipher = brk: {
        var cli = nonblock.Client.init(.{
            .root_ca = .{},
            .host = &.{},
            .insecure_skip_verify = true,
        });
        var srv = nonblock.Server.init(.{ .auth = null });

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
        var cli = nonblock.Connection.init(cli_cipher);
        var srv = nonblock.Connection.init(srv_cipher);

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
    _ = @import("handshake_common.zig");
    _ = @import("handshake_server.zig");
    _ = @import("handshake_client.zig");

    _ = @import("connection.zig");
    _ = @import("cipher.zig");
    _ = @import("record.zig");
    _ = @import("transcript.zig");
    _ = @import("PrivateKey.zig");
}
