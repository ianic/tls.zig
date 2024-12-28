const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const io = @import("io/io.zig");
const Tcp = @import("tcp.zig").Tcp;
const tls = @import("tls");

const log = std.log.scoped(.tls);

pub fn Tls(comptime AppType: type) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        app: AppType,
        conn: Tcp(*Self),
        handshake: ?*tls.AsyncHandshakeClient = null,
        recv_buf: RecvBuf,

        pub fn init(
            self: *Self,
            allocator: mem.Allocator,
            ev: *io.Ev,
            app: AppType,
        ) void {
            self.* = .{
                .allocator = allocator,
                .conn = Tcp(*Self).init(ev, self),
                .app = app,
                .recv_buf = RecvBuf.init(allocator),
            };
        }

        pub fn connect(self: *Self, address: net.Address, opt: tls.ClientOptions) !void {
            const handshake = try self.allocator.create(tls.AsyncHandshakeClient);
            errdefer self.allocator.destroy(handshake);
            try handshake.init(opt);
            try self.conn.connect(address);
            self.handshake = handshake;
        }

        pub fn onConnect(self: *Self) !void {
            log.debug("onConnect", .{});
            try self.send();
        }

        pub fn onRecv(self: *Self, bytes: []const u8) !void {
            log.debug("onRecv bytes.len {}", .{bytes.len});
            if (self.handshake) |h| {
                const buf = try self.recv_buf.append(bytes);
                log.debug("onRecv buf.len {}", .{buf.len});
                const n = h.recv(buf) catch |err| switch (err) {
                    error.EndOfStream => 0,
                    else => return err,
                };
                log.debug("onRecv n: {}, bytes.len {}, state: {}, done: {}", .{ n, bytes.len, h.state, h.done() });
                if (n < buf.len) {
                    try self.recv_buf.set(buf[n..]);
                } else {
                    self.recv_buf.free();
                }
                if (n > 0) try self.send();
            }
        }

        fn send(self: *Self) !void {
            if (self.handshake) |h| {
                if (try h.send()) |buf| try self.conn.send(buf);
            }
        }

        pub fn onSend(self: *Self, _: ?anyerror) !void {
            if (self.handshake) |h| {
                log.debug("onSend state: {}, done: {}", .{ h.state, h.done() });
            }
            try self.send();
        }

        pub fn onClose(self: *Self) void {
            _ = self;
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
