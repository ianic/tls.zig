const std = @import("std");
const tls = @import("tls");
const http = std.http;

const cmn = @import("common.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const top_sites = try cmn.topSites(gpa);
    defer top_sites.deinit();

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = gpa, .n_jobs = 32 });

    var counter: cmn.Counter = .{};
    for (top_sites.value) |site| {
        if (site.rank == 194) {
            counter.add(.skip);
            continue;
        }
        const domain = site.rootDomain;

        try pool.spawn(getTop, .{ gpa, domain, &counter });
    }
    pool.deinit();
    counter.show();
}

const header_buffer_size = 16 * 1024;

fn getTop(gpa: std.mem.Allocator, domain: []const u8, counter: *cmn.Counter) void {
    get(gpa, domain) catch |err| {
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

pub fn get(gpa: std.mem.Allocator, domain: []const u8) !void {
    var client: http.Client = .{ .allocator = gpa };
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
