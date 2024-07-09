const std = @import("std");

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

        const uri = try std.Uri.parse(url);
        var server_header_buffer: [16 * 1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{ .server_header_buffer = &server_header_buffer });
        defer req.deinit();

        try req.send();
        try req.wait();
    }
}
