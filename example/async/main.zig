const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const io = @import("io/io.zig");
const posix = std.posix;

const log = std.log.scoped(.main);

pub fn main() !void {
    const host = "www.supersport.hr";
    //const host = "www.cloudflare.com";
    //const host = "www.google.com";
    const port = 443;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const list = try std.net.getAddressList(allocator, host, port);
    defer list.deinit();
    if (list.addrs.len == 0) return error.UnknownHostName;
    if (list.addrs.len > 0)
        std.debug.print("list.addrs: {any}\n", .{list.addrs});
    const addr = list.addrs[0];

    var ev: io.Ev = undefined;
    try ev.init(allocator, .{});
    defer ev.deinit();

    // var http: Http = undefined;
    // try http.init(allocator, &ev, host, addr);

    var root_ca = try tls.CertBundle.fromSystem(allocator);
    defer root_ca.deinit(allocator);

    const opt: tls.ClientOptions = .{
        .host = host,
        .root_ca = root_ca,
        //.cipher_suites = tls.cipher_suites.tls12,
        .key_log_callback = tls.key_log.callback,
    };
    var https: Https = undefined;
    try https.init(allocator, &ev, host, addr, opt);
    defer https.deinit();

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
    log.debug("done", .{});

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

const Tls = @import("tls.zig").Tls;

const Https = struct {
    const Self = @This();
    allocator: mem.Allocator,
    host: []const u8,
    conn: Tls(*Https),

    fn init(
        self: *Self,
        allocator: mem.Allocator,
        ev: *io.Ev,
        host: []const u8,
        address: std.net.Address,
        opt: tls.ClientOptions,
    ) !void {
        self.* = .{
            .allocator = allocator,
            .host = host,
            .conn = undefined,
        };
        self.conn.init(allocator, ev, self);
        errdefer self.conn.deinit();
        try self.conn.connect(address, opt);
    }

    fn deinit(self: *Self) void {
        self.conn.deinit();
    }

    pub fn onConnect(self: *Self) !void {
        const request = try std.fmt.allocPrint(self.allocator, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{self.host});
        try self.conn.send(request);
    }

    pub fn onRecv(self: *Self, bytes: []const u8) !void {
        log.debug("recv {} bytes: {s}", .{ bytes.len, bytes }); //bytes[0..@min(128, bytes.len)] });

        if (std.ascii.endsWithIgnoreCase(
            std.mem.trimRight(u8, bytes, "\r\n"),
            "</html>",
        ) or std.ascii.endsWithIgnoreCase(bytes, "\r\n0\r\n\r\n")) self.conn.close();
    }

    pub fn onClose(self: *Self) void {
        log.debug("onClose", .{});
        _ = self;
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
