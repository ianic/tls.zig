const std = @import("std");
const tls = @import("tls");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const url = "https://ziglang.org";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = 443;

    // Establish tcp connection
    var tcp = try std.net.tcpConnectToHost(gpa, host, port);
    defer tcp.close();

    // Upgrade tcp connection to tls
    var ca_bundle: std.crypto.Certificate.Bundle = .{};
    try ca_bundle.rescan(gpa);
    defer ca_bundle.deinit(gpa);
    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle, .{});

    // Send http GET request
    var buf: [64]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try cli.writeAll(req);

    // Print response
    while (try cli.next()) |data| {
        std.debug.print("{s}", .{data});
    }
    try cli.close();
}
