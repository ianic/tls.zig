const std = @import("std");
const tls = @import("tls");
const Io = std.Io;
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});

    var rsa_auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer rsa_auth.deinit(allocator);

    var ec_auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer ec_auth.deinit(allocator);

    // ca to check client certificate
    var client_root_ca = try tls.config.cert.fromFilePath(allocator, io, dir, "minica.pem");
    defer client_root_ca.deinit(allocator);

    const now = try std.Io.Clock.real.now(io);

    const opt1: tls.config.Server = .{
        .auth = &rsa_auth,
        .now = now,
    };
    const opt2: tls.config.Server = .{
        .client_auth = .{
            .auth_type = .request,
            .root_ca = client_root_ca,
        },
        .auth = &rsa_auth,
        .now = now,
    };
    const opt4: tls.config.Server = .{
        .auth = &ec_auth,
        .now = now,
    };

    const s1 = try std.Thread.spawn(.{}, runServer, .{ io, 4433, opt1 });
    const s3 = try std.Thread.spawn(.{}, runEchoServer, .{ io, 4435, opt1 });

    const s2 = try std.Thread.spawn(.{}, runServer, .{ io, 4434, opt2 });
    const s4 = try std.Thread.spawn(.{}, runServer, .{ io, 4436, opt4 });

    s1.join();
    s2.join();
    s3.join();
    s4.join();
}

fn runServer(io: Io, port: u16, opt: tls.config.Server) !void {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var server = try address.listen(io, .{ .reuse_address = true, .mode = .stream });

    while (true) {
        acceptUpgrade(io, &server, opt) catch |err| {
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

fn acceptUpgrade(io: Io, server: *std.Io.net.Server, opt: tls.config.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);

    var conn = try tls.serverFromStream(io, stream, opt);
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

fn runEchoServer(io: Io, port: u16, opt: tls.config.Server) !void {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var server = try address.listen(io, .{ .reuse_address = true, .mode = .stream });

    while (true) {
        acceptEcho(io, &server, opt) catch |err| {
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

fn acceptEcho(io: Io, server: *std.Io.net.Server, opt: tls.config.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);

    var conn = try tls.serverFromStream(io, stream, opt);
    while (try conn.next()) |buf| try conn.writeAll(buf);
    try conn.close();
}

const http_ok = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain\r\n\r\nHello World!";
