const std = @import("std");
const tls = @import("tls");
const http = std.http;

const cmn = @import("common.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator, .n_jobs = 32 });

    var counter: cmn.Counter = .{};
    var rdr = cmn.CsvReader.init(@embedFile("moz_top500.csv"));
    while (rdr.next()) |domain| {
        if (cmn.skipDomain(domain)) {
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
                std.debug.print("➖ {s} error {}\n", .{ domain, err });
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

    var server_header_buffer: [header_buffer_size]u8 = undefined;
    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
    });
    defer req.deinit();
    try req.send();
    try req.wait();
}
