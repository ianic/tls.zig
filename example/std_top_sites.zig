const std = @import("std");
const tls = @import("tls");
const http = std.http;

const cmn = @import("common.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator, .n_jobs = 32 });

    try get(allocator, "google.com");

    var counter: cmn.Counter = .{};
    //var rdr = cmn.CsvReader.init(@embedFile("moz_top500.csv"));
    var rdr = cmn.CsvReader.init(@embedFile("domains"));
    while (rdr.next()) |domain| {
        if (domain.len == 0) continue;
        if (cmn.skipDomain(domain)) {
            std.debug.print("➰ {s:<25} SKIP\n", .{domain});
            counter.add(.skip);
            continue;
        }
        try pool.spawn(run, .{ allocator, domain, &counter });
    }
    pool.deinit();
    counter.show();
}

const header_buffer_size = 16 * 1024;

fn run(allocator: std.mem.Allocator, domain: []const u8, counter: *cmn.Counter) void {
    get(allocator, domain) catch |err| {
        switch (err) {
            error.TlsInitializationFailed => {
                std.debug.print("❌ {s}\n", .{domain});
                counter.add(.fail);
            },
            else => {
                std.debug.print("➖ {s} {}\n", .{ domain, err });
                counter.add(.err);
            },
        }
        return;
    };
    std.debug.print("✔️ {s}\n", .{domain});
    counter.add(.success);
}

pub fn get(allocator: std.mem.Allocator, domain: []const u8) !void {
    var client: http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var url_buffer: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "https://{s}", .{domain});
    const uri = try std.Uri.parse(url);
    const conn = try connWithTimeout(allocator, &client, uri);

    var server_header_buffer: [header_buffer_size]u8 = undefined;
    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .connection = conn,
    });
    defer req.deinit();
    try req.send();
    try req.wait();
}

fn connWithTimeout(allocator: std.mem.Allocator, client: *http.Client, uri: std.Uri) !*http.Client.Connection {
    const root_ca = try tls.config.CertBundle.fromSystem(allocator);
    client.ca_bundle = root_ca.bundle;

    const conn = try client.connectTcp(uri.host.?.percent_encoded, 443, .tls);

    const fd = conn.stream.handle;
    const read_timeout: std.posix.timeval = if (@hasField(std.posix.timeval, "tv_sec"))
        .{ .tv_sec = 5, .tv_usec = 0 }
    else
        .{ .sec = 5, .usec = 0 };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.toBytes(read_timeout)[0..]);
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.toBytes(read_timeout)[0..]);

    return conn;
}
