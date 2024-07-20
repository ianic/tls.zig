const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var cert, const key = try tls.loadX509KeyPair(allocator, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer cert.deinit(allocator);

    var cert_ec, const key_ec = try tls.loadX509KeyPair(allocator, dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer cert_ec.deinit(allocator);

    // ca to check client certificate
    var client_root_ca: Certificate.Bundle = .{};
    defer client_root_ca.deinit(allocator);
    try client_root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    const opt1: tls.ServerOptions = .{
        .auth = .{
            .certificates = cert,
            .private_key = key,
        },
    };
    const opt2: tls.ServerOptions = .{
        .client_auth = .{
            .auth_type = .request,
            .root_ca = client_root_ca,
        },
        .auth = .{
            .certificates = cert,
            .private_key = key,
        },
    };

    const opt4: tls.ServerOptions = .{
        .auth = .{
            .certificates = cert_ec,
            .private_key = key_ec,
        },
    };

    const s1 = try std.Thread.spawn(.{}, runServer, .{ 4433, opt1 });
    const s3 = try std.Thread.spawn(.{}, runEchoServer, .{ 4435, opt1 });

    const s2 = try std.Thread.spawn(.{}, runServer, .{ 4434, opt2 });
    const s4 = try std.Thread.spawn(.{}, runServer, .{ 4436, opt4 });

    s1.join();
    s2.join();
    s3.join();
    s4.join();
}

fn runServer(port: u16, opt: tls.ServerOptions) !void {
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{ .reuse_address = true });

    while (true) {
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

fn runEchoServer(port: u16, opt: tls.ServerOptions) !void {
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{ .reuse_address = true });

    while (true) {
        acceptEcho(&server, opt) catch |err| {
            std.debug.print("tls failed with {}\n", .{err});
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
            continue;
        };
    }
}

fn acceptEcho(server: *std.net.Server, opt: tls.ServerOptions) !void {
    const tcp = try server.accept();
    defer tcp.stream.close();

    var conn = try tls.server(tcp.stream, opt);
    while (try conn.next()) |buf| try conn.writeAll(buf);
    try conn.close();
}

const http_ok = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nHello World!";
