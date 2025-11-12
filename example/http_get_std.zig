const std = @import("std");

pub const std_options = std.Options{ .http_enable_ssl_key_log_file = true };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1) {
        const domain = args[1];

        var client: std.http.Client = .{ .allocator = allocator };
        defer client.deinit();

        // Add https:// prefix if needed
        const url = brk: {
            const scheme = "https://";
            if (domain.len >= scheme.len and std.mem.eql(u8, domain[0..scheme.len], scheme))
                break :brk domain;

            var url_buf: [128]u8 = undefined;
            break :brk try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});
        };

        const result = try client.fetch(.{
            .redirect_behavior = .unhandled,
            .location = .{ .url = url },
            .keep_alive = false,
        });
        std.debug.print("uri: {s} status: {s}\n", .{ url, @tagName(result.status) });
    }
}

test "case" {
    //const url = "https://y.at";
    const url = "https://www.gov.br";
    var client: std.http.Client = .{ .allocator = std.testing.allocator };
    defer client.deinit();

    _ = try client.fetch(.{
        .location = .{ .url = url },
        //.redirect_behavior = .unhandled,
        //.keep_alive = false,
    });
}
