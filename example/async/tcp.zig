const std = @import("std");
const net = std.net;
const assert = std.debug.assert;
const io = @import("io/io.zig");
const posix = std.posix;
const log = std.log.scoped(.tcp);

pub fn Tcp(comptime AppType: type) type {
    return struct {
        const Self = @This();

        ev: *io.Ev,
        app: AppType,
        address: std.net.Address = undefined,
        socket: posix.socket_t = 0,

        connect_op: io.Op = .{},
        send_op: io.Op = .{},
        recv_op: io.Op = .{},
        close_op: io.Op = .{},

        state: State = .closed,

        const State = enum {
            closed,
            connecting,
            connected,
            closing,
        };

        pub fn init(ev: *io.Ev, app: AppType) Self {
            return .{ .ev = ev, .app = app };
        }

        pub fn connect(self: *Self, address: net.Address) !void {
            if (self.state != .closed) return error.InvalidState;

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
            self.socket = socket;
            self.state = .connected;
            self.recv_op = io.Op.recv(self.socket, self, onRecv, onRecvFail);
            self.ev.submit(&self.recv_op);
            self.app.onConnect() catch return error.OutOfMemory; // TODO
            log.debug("{} connected", .{self.address});
        }

        fn onConnectFail(self: *Self, err: ?anyerror) void {
            if (err) |e| log.info("{} connect failed {}", .{ self.address, e });
            self.shutdown();
        }

        pub fn send(self: *Self, buf: []const u8) !void {
            if (self.state != .connected) return error.InvalidState;
            if (self.send_op.active()) return error.SendActive;

            assert(!self.send_op.active());
            self.send_op = io.Op.send(self.socket, buf, self, onSend, onSendFail);
            self.ev.submit(&self.send_op);
        }

        fn onSend(self: *Self) io.Error!void {
            self.app.onSend(null);
            log.debug("{} send", .{self.address});
        }

        fn onSendFail(self: *Self, err: anyerror) io.Error!void {
            self.app.onSend(err);
            switch (err) {
                error.BrokenPipe, error.ConnectionResetByPeer => {},
                else => log.err("{} send failed {}", .{ self.address, err }),
            }
            self.shutdown();
        }

        fn onRecv(self: *Self, bytes: []const u8) io.Error!void {
            try self.app.onRecv(bytes);
            if (!self.recv_op.hasMore() and self.state == .connected)
                self.ev.submit(&self.recv_op);
        }

        fn onRecvFail(self: *Self, err: anyerror) io.Error!void {
            switch (err) {
                error.EndOfFile, error.ConnectionResetByPeer => {},
                else => log.err("{} recv failed {}", .{ self.address, err }),
            }
            self.shutdown();
        }

        fn onCancel(self: *Self, _: ?anyerror) void {
            self.shutdown();
        }

        pub fn shutdown(self: *Self) void {
            if (self.state == .closed) return;
            if (self.state != .closing) self.state = .closing;

            log.debug("{} closing", .{self.address});

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
            self.app.onClose();
            log.debug("{} closed", .{self.address});
        }
    };
}
