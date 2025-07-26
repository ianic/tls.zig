const std = @import("std");
const proto = @import("protocol.zig");
const common = @import("handshake_common.zig");
const record = @import("record.zig");
pub const Connection = @import("connection.zig").Connection;
const handshake = struct {
    const Client = @import("handshake_client.zig").Handshake;
    const Server = @import("handshake_server.zig").Handshake;
};

pub const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;
/// Suggested stream reader/writer buffer sizes:
/// Minimal buffer big enough for any tls ciphertext record.
pub const stream_reader_buffer_len = max_ciphertext_record_len; // 16645 bytes
/// Minimal buffer to fit any ciphertext record produced with this tls
/// implementation.
pub const stream_writer_buffer_len = @import("cipher.zig").max_encrypted_record_len; // 16469 bytes

/// Upgrades existing stream to the tls connection by the client tls handshake.
pub inline fn client(stream: anytype, opt: config.Client) !Connection {
    var reader_buf: [stream_reader_buffer_len]u8 = undefined;
    var writer_buf: [stream_writer_buffer_len]u8 = undefined;
    var reader = stream.reader(&reader_buf);
    var writer = stream.writer(&writer_buf);
    const stream_reader = reader.interface();
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
    const stream_reader = reader.interface();
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

// /// Callback based non blocking variant
// pub const callback = struct {
//     pub fn Client(T: type) type {
//         return Callback(T, nonblock.Client, config.Client);
//     }
//     pub fn Server(T: type) type {
//         return Callback(T, nonblock.Server, config.Server);
//     }
// };

const testing = std.testing;

test "nonblock handshake and connection" {

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

// const mem = std.mem;
// const assert = std.debug.assert;
// const Cipher = @import("cipher.zig").Cipher;

// /// Callback based non-blocking tls connection. Does not depend on inner network
// /// stream reader. For use in io_uring or similar completion based io.
// ///
// /// This implementation works for both client and server tls handshake type; that
// /// is why it is generic over handshake type and options.
// ///
// /// Handler should connect this library with upstream application and downstream
// /// tcp connection.
// ///
// /// Handler has to provide this methods:
// ///
// ///   onConnect()           - notification that tls handshake is done
// ///   onRecv(cleartext)     - cleartext data to pass to the application
// ///   send(buf)             - ciphertext to pass to the underlying tcp connection
// ///
// /// Interface provided to the handler:
// ///
// ///   onConnect()        - should be called after tcp connection is established, starts handshake
// ///   onRecv(ciphertext) - data received on the underlying tcp connection
// ///   send(cleartext)    - data to send to the peer
// ///   onSend             - notification that tcp is done coping buffer to the kernel
// ///
// /// Handler should establish tcp connection and call onConnect(). That will
// /// fire handler.send with tls hello (in the case of client handshake type).
// /// For each raw tcp data handler should call onRecv(). During handshake that
// /// data will be consumed here. When handshake succeeds we will have cipher,
// /// release handshake and call handler.onConnect notification.
// ///
// /// After handshake handler can call send with cleartext data, that will be
// /// encrypted and pass to handler.send(). Any raw ciphertext received
// /// on tcp should be pass to onRecv() to decrypt and pass to
// /// handler.onRecv().
// ///
// pub fn Callback(comptime Handler: type, comptime HandshakeType: type, comptime Options: type) type {
//     return struct {
//         const Self = @This();

//         allocator: mem.Allocator,
//         handler: Handler,
//         handshake: ?*HandshakeType = null,
//         connection: ?nonblock.Connection = null,

//         pub fn init(allocator: mem.Allocator, handler: Handler, opt: Options) !Self {
//             const handshake = try allocator.create(HandshakeType);
//             handshake.* = HandshakeType.init(opt);
//             return .{
//                 .allocator = allocator,
//                 .handler = handler,
//                 .handshake = handshake,
//             };
//         }

//         pub fn deinit(self: *Self) void {
//             if (self.handshake) |handshake|
//                 self.allocator.destroy(handshake);
//             self.* = undefined;
//         }

//         fn handshakeRun(self: *Self, recv_buf: []const u8) !usize {
//             var handshake = self.handshake orelse unreachable;

//             var send_buf: [max_ciphertext_record_len]u8 = undefined;
//             const res = try handshake.run(recv_buf, &send_buf);
//             if (res.send.len > 0) {
//                 const buf = try self.allocator.dupe(u8, res.send);
//                 try self.handler.send(buf);
//             }

//             if (handshake.done()) {
//                 self.connection = nonblock.Connection.init(handshake.inner.cipher);
//                 self.allocator.destroy(handshake);
//                 self.handshake = null;
//                 self.handler.onConnect();
//             }
//             return res.recv_pos;
//         }

//         // ----------------- Handler interface

//         /// Notification that tcp connection has been established. For client
//         /// tls handshake type this will start tls handshake.
//         pub fn onConnect(self: *Self) !void {
//             _ = try self.handshakeRun(&.{});
//         }

//         /// Notification that underlying tcp connection has received data. It
//         /// will be used in handshake or if handshake is done it will be
//         /// decrypted and handler's onRecv will be called with cleartext data.
//         pub fn onRecv(self: *Self, ciphertext: []u8) !usize {
//             if (self.handshake) |_| return try self.handshakeRun(ciphertext);

//             var conn = &(self.connection orelse unreachable);
//             const res = try conn.decrypt(ciphertext, ciphertext);
//             if (res.cleartext.len > 0)
//                 try self.handler.onRecv(res.cleartext);
//             if (res.closed) return error.EndOfStream;
//             return res.ciphertext_pos;
//         }

//         /// Handler call this when need to send data. Cleartext data will be
//         /// encrypted and sent to the underlying tcp connection by calling
//         /// handler's send method with ciphertext data.
//         pub fn send(self: *Self, cleartext: []const u8) !void {
//             var conn = &(self.connection orelse return error.InvalidState);
//             if (cleartext.len == 0) return;

//             // Allocate ciphertext buffer
//             const ciphertext = try self.allocator.alloc(u8, conn.encryptedLength(cleartext.len));
//             errdefer self.allocator.free(ciphertext);
//             // Fill ciphertext with encrypted tls records
//             const res = try conn.encrypt(cleartext, ciphertext);
//             assert(res.cleartext_pos == cleartext.len);
//             assert(res.unused_cleartext.len == 0);
//             assert(res.ciphertext.len == ciphertext.len);
//             try self.handler.send(ciphertext);
//         }

//         /// Notification that buffer allocated in send is copied to the kernel,
//         /// it is safe to free it now.
//         pub fn onSend(self: *Self, ciphertext: []const u8) void {
//             self.allocator.free(ciphertext);
//         }
//     };
// }

// test "callback decrypt" {
//     const Handler = struct {
//         const Self = @This();
//         allocator: mem.Allocator,
//         bytes: []u8 = &.{},

//         pub fn onRecv(self: *Self, cleartext: []const u8) !void {
//             // append cleartext to self.bytes
//             self.bytes = try self.allocator.realloc(self.bytes, self.bytes.len + cleartext.len);
//             @memcpy(self.bytes[self.bytes.len - cleartext.len ..], cleartext);
//         }
//         pub fn onConnect(_: *Self) void {}
//         pub fn send(_: *Self, _: []const u8) !void {}
//     };
//     var handler: Handler = .{
//         .allocator = testing.allocator,
//     };
//     defer testing.allocator.free(handler.bytes);

//     var client_cipher, const server_cipher = @import("cipher.zig").testCiphers();

//     var conn: callback.Server(*Handler) = .{
//         .allocator = undefined,
//         .handshake = null,
//         .connection = nonblock.Connection.init(server_cipher),
//         .handler = &handler,
//     };
//     defer conn.deinit();

//     var ciphertext: [1024]u8 = undefined;
//     var ciphertext_len: usize = 0;

//     var cleartext: [512]u8 = undefined;
//     var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
//     prng.random().bytes(&cleartext);

//     { // expect handler.onRecv to be called with cleartext
//         ciphertext_len = (try client_cipher.encrypt(&ciphertext, .application_data, &cleartext)).len;
//         try testing.expectEqual(ciphertext_len, try conn.onRecv(ciphertext[0..ciphertext_len]));
//         try testing.expectEqualSlices(u8, handler.bytes, &cleartext);
//     }
//     { // expect handler.onRecv to be called with cleartext and decrypt to return error.EndOfStream
//         // split cleartext into two tls records
//         ciphertext_len = (try client_cipher.encrypt(&ciphertext, .application_data, cleartext[0 .. cleartext.len / 2])).len;
//         ciphertext_len += (try client_cipher.encrypt(ciphertext[ciphertext_len..], .application_data, cleartext[cleartext.len / 2 ..])).len;
//         // add close notify alert record at the end
//         ciphertext_len += (try client_cipher.encrypt(ciphertext[ciphertext_len..], .alert, &proto.Alert.closeNotify())).len;
//         try testing.expectEqual(580, ciphertext_len);

//         try testing.expectError(error.EndOfStream, conn.onRecv(ciphertext[0..ciphertext_len]));
//         try testing.expectEqualSlices(u8, handler.bytes[cleartext.len..], &cleartext);
//     }
// }
