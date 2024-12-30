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
        cipher: tls.Cipher = undefined,
        recv_buf: RecvBuf,
        write_buf: [tls.max_ciphertext_record_len]u8 = undefined,

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
            try self.handshakeSend();
        }

        pub fn onRecv(self: *Self, bytes: []const u8) !void {
            // log.debug("onRecv bytes.len {}", .{bytes.len});
            const buf = try self.recv_buf.append(bytes);
            if (self.handshake) |h| {
                // log.debug("onRecv buf.len {}", .{buf.len});
                const n = h.recv(buf) catch |err| switch (err) {
                    error.EndOfStream => 0,
                    else => {
                        log.err("handshake {}", .{err});
                        return self.conn.shutdown();
                    },
                };
                log.debug("onRecv n: {}, buf.len {}, state: {}, done: {}", .{ n, buf.len, h.state, h.done() });
                try self.checkHandshakeDone();
                if (n < buf.len) {
                    try self.recv_buf.set(buf[n..]);
                } else {
                    self.recv_buf.free();
                }
                if (n > 0) try self.handshakeSend();
                return;
            }

            self.decrypt(buf) catch |err| {
                log.err("decrypt {}", .{err});
                return self.conn.shutdown();
            };
        }

        fn decrypt(self: *Self, buf: []const u8) !void {
            const InnerReader = std.io.FixedBufferStream([]const u8);
            var rr = tls.record.reader(InnerReader{ .buffer = buf, .pos = 0 });

            while (true) {
                const content_type, const cleartext = try rr.nextDecrypt(&self.cipher) orelse break;
                assert(content_type == .application_data);
                try self.app.onRecv(cleartext);
            }
            const ir = &rr.inner_reader;
            const unread = (ir.buffer.len - ir.pos) + (rr.end - rr.start);
            const n = buf.len - unread;
            if (n < buf.len) {
                try self.recv_buf.set(buf[n..]);
            } else {
                self.recv_buf.free();
            }
        }

        fn checkHandshakeDone(self: *Self) !void {
            if (self.handshake) |h| {
                if (h.done()) {
                    log.debug("handshake done", .{});
                    self.cipher = h.appCipher().?;
                    self.allocator.destroy(h);
                    self.handshake = null;
                    try self.app.onConnect();
                }
            }
        }

        fn handshakeSend(self: *Self) io.Error!void {
            if (self.handshake) |h| {
                if (h.send() catch |err| {
                    log.err("handshake send {}", .{err});
                    return self.conn.shutdown();
                }) |buf| {
                    self.conn.send(buf) catch |err| switch (err) {
                        error.InvalidState => {
                            log.err("handshake conn send {}", .{err});
                            return self.conn.shutdown();
                        },
                        else => |e| return e,
                    };
                }
            }
        }

        pub fn send(self: *Self, buf: []const u8) !void {
            const rec = self.cipher.encrypt(&self.write_buf, .application_data, buf) catch |err| {
                log.err("encrypt {}", .{err});
                return self.conn.shutdown();
            };
            self.conn.send(rec) catch |err| switch (err) {
                error.InvalidState => {
                    log.err("conn send {}", .{err});
                    return self.conn.shutdown();
                },
                else => |e| return e,
            };
        }

        pub fn onSend(self: *Self, _: ?anyerror) !void {
            try self.checkHandshakeDone();
            try self.handshakeSend();
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
