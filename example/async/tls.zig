const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const mem = std.mem;
const io = @import("io/io.zig");
const Tcp = @import("tcp.zig").Tcp;
const tls = @import("tls");

const log = std.log.scoped(.tls);

pub fn Tls(comptime ClientType: type) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        client: ClientType,
        tcp_conn: Tcp(*Self),
        tls_conn: tls.AsyncConnection(*Self),

        state: State = .closed,

        const State = enum {
            closed,
            connecting, // establishing tcp connection
            handshake, // tcp connected, doing tls handshake
            connected, // tls handshake done, client can send/receive
        };

        pub fn init(
            self: *Self,
            allocator: mem.Allocator,
            ev: *io.Ev,
            client: ClientType,
        ) void {
            self.* = .{
                .allocator = allocator,
                .tcp_conn = Tcp(*Self).init(allocator, ev, self),
                .client = client,
                .tls_conn = undefined,
            };
        }

        pub fn deinit(self: *Self) void {
            self.tcp_conn.deinit();
        }

        // ----------------- client api

        pub fn connect(self: *Self, address: net.Address, opt: tls.ClientOptions) !void {
            self.tls_conn = try tls.AsyncConnection(*Self).init(self.allocator, self, opt);
            self.tcp_conn.connect(address);
            self.state = .connecting;
        }

        pub fn send(self: *Self, cleartext: []const u8) !void {
            if (self.state != .connected) return error.InvalidState;
            self.tls_conn.send(cleartext) catch |err| {
                log.err("tls conn send {}", .{err});
                self.tcp_conn.close();
            };
        }

        pub fn close(self: *Self) void {
            self.tcp_conn.close();
        }

        // ----------------- tcp callbacks

        /// tcp is connected start tls handshake
        pub fn onConnect(self: *Self) !void {
            self.state = .handshake;
            self.tls_conn.startHandshake() catch |err| {
                log.err("tls conn onConnect {}", .{err});
                self.tcp_conn.close();
            };
        }

        /// Ciphertext bytes received from tcp, pass it to tls.
        /// Tls will decrypt it and call onRecvCleartext.
        pub fn onRecv(self: *Self, ciphertext: []const u8) !usize {
            return self.tls_conn.onRecv(ciphertext) catch |err| brk: {
                log.err("tls conn onRecv {}", .{err});
                self.tcp_conn.close();
                break :brk 0;
            };
        }

        /// Tcp connection is closed.
        pub fn onClose(self: *Self) void {
            self.state = .closed;
            self.client.onClose();
        }

        /// Ciphertext is copied to the kernel tcp buffers.
        /// Safe to release it now.
        pub fn onSend(self: *Self, ciphertext: []const u8) void {
            self.tls_conn.onSend(ciphertext);
        }

        // ----------------- tls callbacks

        /// tls handshake finished
        pub fn onHandshake(self: *Self) void {
            self.state = .connected;
            self.client.onConnect() catch |err| {
                log.err("client onConnect {}", .{err});
                self.tcp_conn.close();
            };
        }

        /// decrypted cleartext received from tcp
        pub fn onRecvCleartext(self: *Self, cleartext: []const u8) !void {
            try self.client.onRecv(cleartext);
        }

        /// tls sends ciphertext to tcp
        pub fn sendCiphertext(self: *Self, ciphertext: []const u8) !void {
            try self.tcp_conn.send(ciphertext);
        }
    };
}
