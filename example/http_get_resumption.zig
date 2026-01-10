const std = @import("std");
const tls = @import("tls");
const cmn = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const now = try std.Io.Clock.real.now(io);

    // Get url from args
    var url: []const u8 = "https://ziglang.org";
    if (args.len > 1) url = args[1];
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Load system root certificates
    var root_ca = try tls.config.cert.fromSystem(gpa, io);
    defer root_ca.deinit(gpa);

    // Prepare config with session resumption collector
    var session_resumption: tls.config.Client.SessionResumption = .init(gpa, now);
    defer session_resumption.deinit();
    var diagnostic: tls.config.Client.Diagnostic = .{};
    const config: tls.config.Client = .{
        .host = host,
        .root_ca = root_ca,
        .session_resumption = &session_resumption,
        .key_log_callback = tls.config.key_log.init(init.minimal.environ),
        .diagnostic = &diagnostic,
        .now = now,
    };

    // Make multiple connections. After the first one other should use session
    // resumption if supported by server.
    for (0..4) |_| {
        // Establish tcp connection
        const host_name = try std.Io.net.HostName.init(host);
        const tcp = try host_name.connect(io, port, .{ .mode = .stream });
        defer tcp.close(io);

        // Upgrade tcp connection to tls
        var conn = try tls.clientFromStream(io, tcp, config);

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
