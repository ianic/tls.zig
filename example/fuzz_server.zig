const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var cert, const key = try tls.loadX509KeyPair(allocator, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer cert.deinit(allocator);

    const opt: tls.ServerOptions = .{
        .auth = .{
            .certificates = cert,
            .private_key = key,
        },
    };

    // Tcp listener
    const port = 4433;
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{ .reuse_address = true });

    while (true) {
        // try acceptUpgrade(&server, opt);

        acceptUpgrade(&server, opt) catch |err| {
            std.debug.print("tls failed with {}\n", .{err});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
            continue;
        };
    }
}

fn acceptUpgrade(server: *std.net.Server, opt: tls.ServerOptions) !void {
    const tcp = try server.accept();
    defer tcp.stream.close();

    var conn = try tls.server(tcp.stream, opt);
    // if (try conn.next()) |buf| {
    //     std.debug.print("{s}", .{buf});
    //     //std.debug.print("received: {d}\n", .{buf.len});
    // }
    while (try conn.next()) |buf| {
        std.debug.print("{s}", .{buf});
        if (std.mem.indexOf(u8, buf, "keyupdate")) |_| {
            conn.key_update_requested = true;
        }
        //std.debug.print("received: {d}\n", .{buf.len});
        if (std.ascii.endsWithIgnoreCase(buf, "\r\n\r\n")) break;
    }
    try conn.writeAll(http_ok);
    try conn.close();
}

const http_ok = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nHello World!";
