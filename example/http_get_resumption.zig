const std = @import("std");
const tls = @import("tls");
const cmn = @import("common.zig");

pub fn main() !void {
    var dbga = std.heap.DebugAllocator(.{}){};
    defer _ = dbga.deinit();
    const allocator = dbga.allocator();

    var url: []const u8 = "https://ziglang.org";

    // Get url from args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len > 1) url = args[1];

    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Load system root certificates
    var root_ca = try tls.config.cert.fromSystem(allocator);
    defer root_ca.deinit(allocator);

    // Prepare config with session resumption collector
    var session_resumption: tls.config.Client.SessionResumption = .init(allocator);
    defer session_resumption.deinit();
    var diagnostic: tls.config.Client.Diagnostic = .{};
    const config: tls.config.Client = .{
        .host = host,
        .root_ca = root_ca,
        .session_resumption = &session_resumption,
        .key_log_callback = tls.config.key_log.callback,
        .diagnostic = &diagnostic,
    };

    // Make multiple connections. After the first one other should use session
    // resumption if supported by server.
    for (0..4) |_| {
        // Establish tcp connection
        var tcp = try std.net.tcpConnectToHost(allocator, host, port);
        defer tcp.close();

        // Upgrade tcp connection to tls
        var conn = try tls.client(tcp, config);

        // Send http GET request
        var buf: [64]u8 = undefined;
        const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
        try conn.writeAll(req);

        // Consume response
        while (try conn.next()) |_| {
            // std.debug.print("{s}", .{data});
        }
        try conn.close();

        cmn.showDiagnostic(config.diagnostic.?, url);
        std.debug.print("resumption tickets: {}, used: {}\n", .{
            session_resumption.tickets.items.len,
            session_resumption.used_tickets,
        });
    }

    std.debug.print("\n", .{});
    try session_resumption.print();
}
