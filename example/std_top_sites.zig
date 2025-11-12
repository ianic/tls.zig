const std = @import("std");
const tls = @import("tls");
const http = std.http;

const cmn = @import("common.zig");
const curl = @import("top_sites.zig").curl;
const log = std.log.scoped(.main);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator, .n_jobs = 32 });

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
    //std.debug.print("-> {s:<25}\n", .{domain});
    get(allocator, domain) catch |err| {
        switch (err) {
            error.TlsInitializationFailed => {
                curl(allocator, domain) catch |curl_err| {
                    std.debug.print("➖ {s:<25} {} curl: {}\n", .{ domain, err, curl_err });
                    counter.add(.err);
                    return;
                };
                std.debug.print("❌ {s:<25}\n", .{domain});
                counter.add(.fail);
            },
            else => {
                std.debug.print("➖ {s:<25} {}\n", .{ domain, err });
                counter.add(.err);
            },
        }
        return;
    };
    //std.debug.print("✔️ {s}\n", .{domain});
    counter.add(.success);
}

pub fn get(allocator: std.mem.Allocator, domain: []const u8) !void {
    const root_ca = try tls.config.cert.fromSystem(allocator);
    var client: http.Client = .{ .allocator = allocator, .ca_bundle = root_ca };
    defer client.deinit();

    var url_buffer: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "https://{s}", .{domain});

    _ = try client.fetch(.{
        .redirect_behavior = .unhandled,
        .location = .{ .url = url },
        .keep_alive = false,
    });
}
