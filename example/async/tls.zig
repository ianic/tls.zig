const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const mem = std.mem;
const posix = std.posix;
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
        recv_buf: RecvBuf,
        tls_conn: tls.AsyncConnection(*Self),

        state: State = .closed,

        const State = enum {
            closed,
            connecting,
            handshake,
            connected,
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
                .recv_buf = RecvBuf.init(allocator),
                .tls_conn = undefined,
            };
        }

        pub fn deinit(self: *Self) void {
            self.tcp_conn.deinit();
            self.recv_buf.free();
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

        // tcp is connected start tls handshake
        pub fn onConnect(self: *Self) !void {
            self.state = .handshake;
            self.tls_conn.onConnect() catch |err| {
                log.err("tls conn onConnect {}", .{err});
                self.tcp_conn.close();
            };
        }

        // ciphertext bytes received
        pub fn onRecv(self: *Self, ciphertext: []const u8) !void {
            const buf = try self.recv_buf.append(ciphertext);
            log.debug("onRecv {} {}", .{ ciphertext.len, buf.len });
            const n = self.tls_conn.onRecv(buf) catch |err| brk: {
                log.err("tls conn onRecv {}", .{err});
                self.tcp_conn.close();
                break :brk 0;
            };
            try self.recv_buf.set(buf[n..]);
        }

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

pub const RecvBuf = struct {
    allocator: mem.Allocator,
    buf: []u8 = &.{},

    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn free(self: *Self) void {
        self.allocator.free(self.buf);
        self.buf = &.{};
    }

    pub fn append(self: *Self, bytes: []const u8) ![]const u8 {
        if (self.buf.len == 0) return bytes;
        const old_len = self.buf.len;
        self.buf = try self.allocator.realloc(self.buf, old_len + bytes.len);
        @memcpy(self.buf[old_len..], bytes);
        return self.buf;
    }

    pub fn set(self: *Self, bytes: []const u8) !void {
        if (bytes.len == 0) return self.free();
        if (self.buf.len == bytes.len and self.buf.ptr == bytes.ptr) return;

        const new_buf = try self.allocator.dupe(u8, bytes);
        self.free();
        self.buf = new_buf;
    }
};
