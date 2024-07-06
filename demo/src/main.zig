const std = @import("std");
const tls = @import("tls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const url = "https://ziglang.org";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Establish tcp connection
    var tcp = try std.net.tcpConnectToHost(allocator, host, port);
    defer tcp.close();

    // Load system root certificates
    var root_ca: std.crypto.Certificate.Bundle = .{};
    try root_ca.rescan(allocator);
    defer root_ca.deinit(allocator);

    // Upgrade tcp connection to tls
    var conn = try tls.client(tcp, .{
        .host = host,
        .root_ca = root_ca,
    });

    // Send http GET request
    var buf: [64]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try conn.writeAll(req);

    // Print response
    while (try conn.next()) |data| {
        std.debug.print("{s}", .{data});
    }
    try conn.close();
}
