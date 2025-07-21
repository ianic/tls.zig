const std = @import("std");
const tls = @import("tls");

pub fn main() !void {
    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const allocator = dbga.allocator();

    const url = "https://ziglang.org";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Load system root certificates
    var root_ca = try tls.config.cert.fromSystem(allocator);
    defer root_ca.deinit(allocator);

    // Collect resumption data
    var resumption: tls.config.Client.SessionResumption = .init(allocator);
    defer resumption.deinit();

    const config: tls.config.Client = .{
        .host = host,
        .root_ca = root_ca,
        .session_resumption = &resumption,
        .key_log_callback = tls.config.key_log.callback,
    };

    {
        // Establish tcp connection
        var tcp = try std.net.tcpConnectToHost(allocator, host, port);
        defer tcp.close();

        // Upgrade tcp connection to tls
        var conn = try tls.client(tcp, config);

        // Send http GET request
        var buf: [64]u8 = undefined;
        const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
        try conn.writeAll(req);

        // Print response
        while (try conn.next()) |data| {
            //std.debug.print("{s}", .{data});
            std.debug.print("{d} ", .{data.len});
        }

        try conn.close();
    }
    try resumption.print();

    {
        // Establish tcp connection
        var tcp = try std.net.tcpConnectToHost(allocator, host, port);
        defer tcp.close();

        // Upgrade tcp connection to tls
        var conn = try tls.client(tcp, config);

        // Send http GET request
        var buf: [64]u8 = undefined;
        const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
        try conn.writeAll(req);

        std.debug.print("response: ", .{});
        // Print response
        while (try conn.next()) |data| {
            //std.debug.print("{s}", .{data});
            std.debug.print("{d}\n", .{data.len});
        }

        try conn.close();
    }

    try resumption.print();
}
