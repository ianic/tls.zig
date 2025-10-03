const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var rsa_auth = try tls.config.CertKeyPair.fromFilePath(allocator, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer rsa_auth.deinit(allocator);

    var ec_auth = try tls.config.CertKeyPair.fromFilePath(allocator, dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer ec_auth.deinit(allocator);

    // ca to check client certificate
    var client_root_ca = try tls.config.cert.fromFilePath(allocator, dir, "minica.pem");
    defer client_root_ca.deinit(allocator);

    const opt1: tls.config.Server = .{ .auth = &rsa_auth };
    const opt2: tls.config.Server = .{
        .client_auth = .{
            .auth_type = .request,
            .root_ca = client_root_ca,
        },
        .auth = &rsa_auth,
    };
    const opt4: tls.config.Server = .{ .auth = &ec_auth };

    const s1 = try std.Thread.spawn(.{}, runServer, .{ 4433, opt1 });
    const s3 = try std.Thread.spawn(.{}, runEchoServer, .{ 4435, opt1 });

    const s2 = try std.Thread.spawn(.{}, runServer, .{ 4434, opt2 });
    const s4 = try std.Thread.spawn(.{}, runServer, .{ 4436, opt4 });

    s1.join();
    s2.join();
    s3.join();
    s4.join();
}

fn runServer(port: u16, opt: tls.config.Server) !void {
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{ .reuse_address = true });

    while (true) {
        acceptUpgrade(&server, opt) catch |err| {
            if (err == error.TlsAlertCloseNotify) {
                std.debug.print("c", .{});
            } else {
                std.debug.print("e", .{});
            }
            if (@errorReturnTrace()) |trace| {
                std.debug.print("\n{}\n", .{err});
                std.debug.dumpStackTrace(trace);
            }
            continue;
        };
        std.debug.print(".", .{});
    }
}

fn acceptUpgrade(server: *std.net.Server, opt: tls.config.Server) !void {
    const tcp = try server.accept();
    defer tcp.stream.close();

    var conn = try tls.serverFromStream(tcp.stream, opt);
    while (try conn.next()) |buf| {
        //std.debug.print("{s}", .{buf});
        if (std.mem.indexOf(u8, buf, "keyupdate")) |_| {
            conn.key_update_requested = true;
        }
        //std.debug.print("received: {d}\n", .{buf.len});
        if (std.ascii.endsWithIgnoreCase(buf, "\r\n\r\n")) break;
    }
    try conn.writeAll(http_ok);
    try conn.close();
}

fn runEchoServer(port: u16, opt: tls.config.Server) !void {
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{ .reuse_address = true });

    while (true) {
        acceptEcho(&server, opt) catch |err| {
            std.debug.print("e", .{});
            if (@errorReturnTrace()) |trace| {
                std.debug.print("\n{}\n", .{err});
                std.debug.dumpStackTrace(trace);
            }
            continue;
        };
        std.debug.print(".", .{});
    }
}

fn acceptEcho(server: *std.net.Server, opt: tls.config.Server) !void {
    const tcp = try server.accept();
    defer tcp.stream.close();

    var conn = try tls.serverFromStream(tcp.stream, opt);
    while (try conn.next()) |buf| try conn.writeAll(buf);
    try conn.close();
}

const http_ok = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nHello World!";
