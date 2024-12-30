const std = @import("std");
const net = std.net;
const mem = std.mem;
const assert = std.debug.assert;
const io = @import("io/io.zig");
const posix = std.posix;
const log = std.log.scoped(.tcp);

pub fn Tcp(comptime ClientType: type) type {
    return struct {
        const Self = @This();

        allocator: mem.Allocator,
        ev: *io.Ev,
        client: ClientType,
        address: std.net.Address = undefined,
        socket: posix.socket_t = 0,

        connect_op: io.Op = .{},
        close_op: io.Op = .{},
        recv_op: io.Op = .{},
        send_op: io.Op = .{},
        send_list: std.ArrayList(posix.iovec_const),
        send_iov: []posix.iovec_const = &.{},
        send_msghdr: posix.msghdr_const = .{ .iov = undefined, .iovlen = 0, .name = null, .namelen = 0, .control = null, .controllen = 0, .flags = 0 },

        state: State = .closed,

        const State = enum {
            closed,
            connecting,
            connected,
            closing,
        };

        pub fn init(allocator: mem.Allocator, ev: *io.Ev, client: ClientType) Self {
            return .{
                .allocator = allocator,
                .ev = ev,
                .client = client,
                .send_list = std.ArrayList(posix.iovec_const).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.send_iov);
            self.send_list.deinit();
        }

        /// Start connect operation. `onConnect` callback will be fired when
        /// finished.
        pub fn connect(self: *Self, address: net.Address) void {
            assert(self.state == .closed);
            assert(!self.connect_op.active());
            assert(!self.send_op.active());
            assert(!self.recv_op.active());
            assert(self.socket == 0);

            self.address = address;
            self.connect_op = io.Op.connect(
                .{
                    .domain = address.any.family,
                    .addr = &self.address,
                },
                self,
                onConnect,
                onConnectFail,
            );
            self.ev.submit(&self.connect_op);
            self.state = .connecting;
        }

        fn onConnect(self: *Self, socket: posix.socket_t) io.Error!void {
            log.debug("{} connected", .{self.address});

            self.socket = socket;
            self.state = .connected;
            self.recv_op = io.Op.recv(self.socket, self, onRecv, onRecvFail);
            self.ev.submit(&self.recv_op);

            try self.client.onConnect();
        }

        fn onConnectFail(self: *Self, err: ?anyerror) void {
            if (err) |e| log.info("{} connect failed {}", .{ self.address, e });
            self.close();
        }

        /// Send `buf` to the tcp connection. It is client's responsibility to
        /// ensure lifetime of `buf` until `onSend(buf)` is called.
        pub fn send(self: *Self, buf: []const u8) io.Error!void {
            if (self.state == .closed)
                return self.client.onSend(buf);

            try self.send_list.append(.{ .base = buf.ptr, .len = buf.len });
            try self.sendPending();
        }

        /// Start send operation for buffers accumulated in send_list.
        fn sendPending(self: *Self) !void {
            if (self.send_op.active() or self.send_list.items.len == 0) return;

            // Move send_list buffers to send_iov, and prepare msghdr. send_list
            // can accumulate new buffers while send_iov is in the kernel.
            self.send_iov = try self.send_list.toOwnedSlice();
            self.send_msghdr.iov = self.send_iov.ptr;
            self.send_msghdr.iovlen = @intCast(self.send_iov.len);
            // Start send operation
            self.send_op = io.Op.sendv(self.socket, &self.send_msghdr, self, onSend, onSendFail);
            self.ev.submit(&self.send_op);
        }

        /// Send operation is completed, release pending resources and notify
        /// client that we are done with sending their buffers.
        fn sendRelease(self: *Self) void {
            if (self.send_iov.len == 0) return;

            const send_iov = self.send_iov;
            { // Reset pending send state
                self.send_iov = &.{};
                self.send_msghdr.iov = self.send_iov.ptr;
                self.send_msghdr.iovlen = 0;
            }
            { // Call client callback for each sent buffer
                for (send_iov) |vec| {
                    var buf: []const u8 = undefined;
                    buf.ptr = vec.base;
                    buf.len = vec.len;
                    self.client.onSend(buf);
                }
                self.allocator.free(send_iov);
            }
        }

        fn onSend(self: *Self) io.Error!void {
            // log.debug("{} onSend", .{self.address});
            self.sendRelease();
            try self.sendPending();
        }

        fn onSendFail(self: *Self, err: anyerror) io.Error!void {
            switch (err) {
                error.BrokenPipe, error.ConnectionResetByPeer => {},
                else => log.err("{} send failed {}", .{ self.address, err }),
            }
            self.sendRelease();
            self.close();
        }

        fn onRecv(self: *Self, bytes: []const u8) io.Error!void {
            try self.client.onRecv(bytes);

            if (!self.recv_op.hasMore() and self.state == .connected)
                self.ev.submit(&self.recv_op);
        }

        fn onRecvFail(self: *Self, err: anyerror) io.Error!void {
            switch (err) {
                error.EndOfFile, error.ConnectionResetByPeer => {},
                else => log.err("{} recv failed {}", .{ self.address, err }),
            }
            self.close();
        }

        fn onCancel(self: *Self, _: ?anyerror) void {
            self.close();
        }

        pub fn close(self: *Self) void {
            if (self.state == .closed) return;
            if (self.state != .closing) self.state = .closing;

            if (self.connect_op.active() and !self.close_op.active()) {
                self.close_op = io.Op.cancel(&self.connect_op, self, onCancel);
                return self.ev.submit(&self.close_op);
            }
            if (self.socket != 0 and !self.close_op.active()) {
                self.close_op = io.Op.shutdown(self.socket, self, onCancel);
                self.socket = 0;
                return self.ev.submit(&self.close_op);
            }
            if (self.recv_op.active() and !self.close_op.active()) {
                self.close_op = io.Op.cancel(&self.recv_op, self, onCancel);
                return self.ev.submit(&self.close_op);
            }

            if (self.connect_op.active() or
                self.recv_op.active() or
                self.send_op.active() or
                self.close_op.active())
                return;

            self.state = .closed;
            self.client.onClose();
            self.sendRelease();
            log.debug("{} closed", .{self.address});
        }
    };
}
