const std = @import("std");
const tls = @import("client.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    const arena = arena_instance.allocator();

    const args = try std.process.argsAlloc(arena);
    if (args.len > 1) {
        const url = args[1];
        _ = try get(gpa, url);

        return;
    }
}

pub fn get(gpa: std.mem.Allocator, url: []const u8) !void {
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, 443);
    defer tcp.close();

    var cli = tls.client(tcp);
    try cli.handshake(host);

    var buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    _ = try cli.write(req);

    while (try cli.next()) |data| {
        std.debug.print("{s}", .{data});
    }

    // while (true) {
    //     const n = try cli.read(&buf);
    //     std.debug.print("{s}", .{buf[0..n]});
    //     if (n == 0) break;
    // }
    // var file = try std.fs.cwd().createFile("server_hello", .{});
    // defer file.close();
    // var buf: [4096]u8 = undefined;
    // while (true) {
    //     const n = try tcp.readAll(&buf);
    //     //std.debug.print("{x}\n", .{buf});
    //     try file.writer().writeAll(buf[0..n]);
    //     if (n < buf.len) break;
    // }
}

pub fn main__() !void {
    const gpa = std.heap.page_allocator;
    //var arena_instance = std.heap.ArenaAllocator.init(gpa);
    //const arena = arena_instance.allocator();

    const url = "https://localhost";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, 8443);
    defer tcp.close();

    //try tcp.writeAll(&client_hello);

    var cli = tls(tcp);
    try cli.handshake("example.ulfheim.net");
    std.debug.print("handshake finished\n", .{});
}

// Using curl to test different ciphers:
// Cipher code for curl can be found at:
// https://github.com/curl/curl/blob/cf337d851ae0120ec5ed801ad7eb128561bd8cf6/lib/vtls/sectransp.c#L729
//
// Example of
// not supported:
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-SHA https://github.com
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-SHA https://www.supersport.hr
// supported:
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://www.supersport.hr
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://github.com
//
