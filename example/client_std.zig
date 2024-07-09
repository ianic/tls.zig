const std = @import("std");
const Certificate = std.crypto.Certificate;

const host = "localhost";
const port = 9443;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // Init certificate bundle with ca
    const dir = try std.fs.cwd().openDir("example/cert", .{});
    var root_ca: Certificate.Bundle = .{};
    defer root_ca.deinit(allocator);
    try root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    var tcp = try std.net.tcpConnectToHost(allocator, host, port);
    defer tcp.close();

    var cli = try std.crypto.tls.Client.init(tcp, root_ca, host);

    var buf: [4 * 1024]u8 = undefined;
    while (true) {
        const n = try cli.read(tcp, &buf);
        //std.debug.print("{s}", .{buf[0..n]});
        if (n == 0) break;
    }
    _ = try cli.writeEnd(tcp, "", true);
}
