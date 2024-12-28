const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const io = @import("io/io.zig");
const posix = std.posix;

const log = std.log.scoped(.main);

pub fn main() !void {
    //const host = "www.cloudflare.com";
    const host = "www.google.com";
    const port = 443;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var root_ca = try tls.CertBundle.fromSystem(allocator);
    defer root_ca.deinit(allocator);

    const list = try std.net.getAddressList(allocator, host, port);
    defer list.deinit();
    if (list.addrs.len == 0) return error.UnknownHostName;
    if (list.addrs.len > 0)
        std.debug.print("list.addrs: {any}\n", .{list.addrs});
    const addr = list.addrs[0];

    var ev: io.Ev = undefined;
    try ev.init(allocator, .{});
    defer ev.deinit();

    var http: Http = undefined;
    try http.init(allocator, &ev, host, addr);

    catchSignals();
    var prev: u64 = 0;
    while (true) {
        const ts = ev.timestamp + 2 * std.time.ns_per_s;
        ev.tickTs(ts) catch |err| {
            switch (err) {
                error.SignalInterrupt => {},
                else => log.err("{}", .{err}),
            }
            break;
        };

        //log.debug("tick {}", .{ev.timestamp - prev});
        prev = ev.timestamp;

        const sig = signal.load(.monotonic);
        if (sig != 0) {
            signal.store(0, .release);
            switch (sig) {
                posix.SIG.TERM, posix.SIG.INT => break,
                else => {},
            }
        }

        if (ev.metric.all.active() == 0) break;
    }

    //try sync(allocator, root_ca);
}

var signal = std.atomic.Value(c_int).init(0);

fn catchSignals() void {
    var act = posix.Sigaction{
        .handler = .{
            .handler = struct {
                fn wrapper(sig: c_int) callconv(.C) void {
                    signal.store(sig, .release);
                }
            }.wrapper,
        },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.USR1, &act, null);
    posix.sigaction(posix.SIG.USR2, &act, null);
    posix.sigaction(posix.SIG.PIPE, &act, null);
}

const Tcp = @import("tcp.zig").Tcp;

const Http = struct {
    const Self = @This();
    allocator: mem.Allocator,
    host: []const u8,
    conn: Tcp(*Http),
    request: []const u8 = &.{},

    fn init(
        self: *Self,
        allocator: mem.Allocator,
        ev: *io.Ev,
        host: []const u8,
        address: std.net.Address,
    ) !void {
        self.* = .{
            .allocator = allocator,
            .host = host,
            .conn = Tcp(*Http).init(ev, self),
        };
        try self.conn.connect(address);
    }

    pub fn onConnect(self: *Self) !void {
        self.request = try std.fmt.allocPrint(self.allocator, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{self.host});
        try self.conn.send(self.request);
    }

    pub fn onRecv(self: *Self, bytes: []const u8) !void {
        log.debug("recv {} bytes: {s}", .{ bytes.len, bytes[0..@min(64, bytes.len)] });
        _ = self;
    }

    pub fn onSend(self: *Self, _: ?anyerror) void {
        self.allocator.free(self.request);
    }

    pub fn onClose(self: *Self) void {
        _ = self;
    }
};

const Conn = struct {
    ev: *io.Ev,
    allocator: mem.Allocator,
    address: std.net.Address,
    socket: posix.socket_t = 0,
    connect_op: io.Op = .{},
    send_op: io.Op = .{},
    recv_op: io.Op = .{},
    close_op: io.Op = .{},
    request: []const u8 = &.{},

    const Self = @This();

    fn init(self: *Self, allocator: mem.Allocator, ev: *io.Ev, address: std.net.Address) !void {
        self.* = .{
            .allocator = allocator,
            .ev = ev,
            .address = address,
        };
        errdefer self.deinit();
        try self.reconnect();
    }

    fn deinit(self: *Self) void {
        self.freeRequest();
    }

    fn get(self: *Self, host: []const u8) !void {
        self.request = try std.fmt.allocPrint(self.allocator, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
    }

    fn freeRequest(self: *Self) void {
        self.allocator.free(self.request);
        self.request = &.{};
    }

    fn reconnect(self: *Self) io.Error!void {
        assert(!self.connect_op.active());
        assert(!self.send_op.active());
        assert(!self.recv_op.active());
        assert(self.socket == 0);

        self.connect_op = io.Op.connect(
            .{
                .domain = self.address.any.family,
                .addr = &self.address,
            },
            self,
            onConnect,
            onConnectFail,
        );
        self.ev.submit(&self.connect_op);
    }

    fn onConnect(self: *Self, socket: posix.socket_t) io.Error!void {
        self.socket = socket;

        self.send_op = io.Op.send(self.socket, self.request, self, onSend, onSendFail);
        self.ev.submit(&self.send_op);

        self.recv_op = io.Op.recv(self.socket, self, onRecv, onRecvFail);
        self.ev.submit(&self.recv_op);

        log.debug("{} connected", .{self.address});
    }

    fn onConnectFail(self: *Self, err: ?anyerror) void {
        if (err) |e|
            log.info("{} connect failed {}", .{ self.address, e });
        self.shutdown();
    }

    fn onSend(self: *Self) io.Error!void {
        self.freeRequest();
        log.debug("{} send done", .{self.address});
    }

    fn onSendFail(self: *Self, err: anyerror) io.Error!void {
        self.freeRequest();
        switch (err) {
            error.BrokenPipe, error.ConnectionResetByPeer => {},
            else => log.err("{} send failed {}", .{ self.address, err }),
        }
        self.shutdown();
    }

    fn onRecv(self: *Self, bytes: []const u8) io.Error!void {
        log.debug("recv {} bytes: {s}", .{ bytes.len, bytes[0..@min(64, bytes.len)] });
        //std.debug.print("{} {s}", .{ bytes.len, bytes });
        if (!self.recv_op.hasMore())
            self.shutdown();
        // self.handleResponse(bytes) catch |err| {
        //     log.err("{} handle reponse failed {}", .{ self.address, err });
        //     self.shutdown();
        // };
    }

    fn onRecvFail(self: *Self, err: anyerror) io.Error!void {
        switch (err) {
            error.EndOfFile, error.ConnectionResetByPeer => {},
            else => log.err("{} recv failed {}", .{ self.address, err }),
        }
        self.shutdown();
    }

    fn onClose(self: *Conn, _: ?anyerror) void {
        self.shutdown();
    }

    fn shutdown(self: *Self) void {
        log.debug("{} shutdown", .{self.address});

        if (self.connect_op.active() and !self.close_op.active()) {
            self.close_op = io.Op.cancel(&self.connect_op, self, onClose);
            return self.ev.submit(&self.close_op);
        }
        if (self.socket != 0 and !self.close_op.active()) {
            self.close_op = io.Op.shutdown(self.socket, self, onClose);
            self.socket = 0;
            return self.ev.submit(&self.close_op);
        }
        if (self.recv_op.active() and !self.close_op.active()) {
            self.close_op = io.Op.cancel(&self.recv_op, self, onClose);
            return self.ev.submit(&self.close_op);
        }

        if (self.connect_op.active() or
            self.recv_op.active() or
            self.send_op.active() or
            self.close_op.active())
            return;

        log.debug("{} shutdown done", .{self.address});
    }
};

fn sync(allocator: mem.Allocator, root_ca: tls.CertBundle, host: []const u8, port: u16) !void {
    // Make tcp connection
    var tcp = try std.net.tcpConnectToHost(allocator, host, port);
    defer tcp.close();

    // Upgrade tcp connection to tls
    var diagnostic: tls.ClientOptions.Diagnostic = .{};
    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
        .diagnostic = &diagnostic,
    });

    // Send http GET request
    var buf: [64]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
    try conn.writeAll(req);

    // Show response
    var n: usize = 0;
    while (try conn.next()) |data| {
        n += data.len;
        std.debug.print("{s}", .{data});
        if (std.ascii.endsWithIgnoreCase(
            std.mem.trimRight(u8, data, "\r\n"),
            "</html>",
        )) break;
    }
    try conn.close();

    std.debug.print("{} bytes read\n{}\n", .{ n, diagnostic });
}
