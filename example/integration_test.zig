const std = @import("std");
const tls = @import("tls");
const Io = std.Io;
const Certificate = std.crypto.Certificate;

const data = @embedFile("cert/random");

const testing = std.testing;
const host = "localhost";
const address = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;

const client_keys = [_][]const u8{
    "client_ec",
    "client_rsa",
    "client_ec_prime256v1",
    "client_ec_secp384r1",
    // "client_ec_secp521r1",
    "client_rsa_2048",
    "client_rsa_3072",
    "client_rsa_4096",
};

fn acceptSend(io: Io, server: *Io.net.Server, opt: tls.config.Server, clients: usize) !void {
    for (0..clients) |_| {
        const stream = try server.accept(io);
        defer stream.close(io);
        var conn = tls.serverFromStream(io, stream, opt) catch |err| {
            switch (err) {
                error.EndOfStream,
                error.TlsCertificateRequired,
                => continue,
                else => {
                    std.debug.print("unexpected server error: {}\n", .{err});
                    unreachable;
                },
            }
        };

        try conn.writeAll(data);
        try conn.close();
    }
}

fn connectReceive(io: Io, addr: Io.net.IpAddress, opt_: tls.config.Client) !void {
    var tcp = try addr.connect(io, .{ .mode = .stream });
    defer tcp.close(io);
    var opt = opt_;
    opt.key_log_callback = tls.config.key_log.callback;
    var conn = try tls.clientFromStream(io, tcp, opt);

    var n: usize = 0;
    //var i: usize = 0;
    while (try conn.next()) |chunk| {
        try testing.expectEqualSlices(u8, data[n..][0..chunk.len], chunk);
        n += chunk.len;
        //std.debug.print("{} {}\n", .{ i, chunk.len });
        //i  += 1;
    }
    try testing.expectEqual(data.len, n);
    try testing.expect(conn.eof());
}

test "server without certificate" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = try std.Io.Clock.real.now(io);

    const opt: tls.config.Server = .{ .auth = null, .now = now };
    var server = try address.listen(io, .{ .reuse_address = true });
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ io, &server, opt, 2 });
    // client with insecure_skip_verify connects
    try connectReceive(io, server.socket.address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{}, .now = now });
    // if insecure_skip_verify is not set connection fails
    try testing.expectError(
        error.TlsUnexpectedMessage,
        connectReceive(io, server.socket.address, .{ .host = host, .root_ca = .{}, .now = now }),
    );
    thr.join();
}

test "server with ec key key pair" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = try std.Io.Clock.real.now(io);

    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});

    var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer auth.deinit(allocator);

    var root_ca = try tls.config.cert.fromFilePath(allocator, io, dir, "minica.pem");
    defer root_ca.deinit(allocator);

    const opt: tls.config.Server = .{ .auth = &auth, .now = now };
    var server = try address.listen(io, .{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ io, &server, opt, 3 });
    // client with insecure_skip_verify connects, server sends certificates but client skips verification
    try connectReceive(io, server.socket.address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{}, .now = now });
    // client with root certificates connects; server certificates are validated
    try connectReceive(io, server.socket.address, .{ .host = host, .root_ca = root_ca, .now = now });
    // client without insecure_skip_verify but not root ca fails; client can't verify server certificates
    try testing.expectError(
        error.CertificateIssuerNotFound,
        connectReceive(io, server.socket.address, .{ .host = host, .root_ca = .{}, .now = now }),
    );
    thr.join();
}

test "server with rsa key key pair" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = try std.Io.Clock.real.now(io);

    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});

    var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer auth.deinit(allocator);

    var root_ca = try tls.config.cert.fromFilePath(allocator, io, dir, "minica.pem");
    defer root_ca.deinit(allocator);

    const opt: tls.config.Server = .{ .auth = &auth, .now = now };
    var server = try address.listen(io, .{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ io, &server, opt, 3 });
    // client with insecure_skip_verify connects, server sends certificates but client skips verification
    try connectReceive(io, server.socket.address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{}, .now = now });
    // client with root certificates connects; server certificates are validated
    try connectReceive(io, server.socket.address, .{ .host = host, .root_ca = root_ca, .now = now });
    // client without insecure_skip_verify but not root ca fails; client can't verify server certificates
    try testing.expectError(
        error.CertificateIssuerNotFound,
        connectReceive(io, server.socket.address, .{ .host = host, .root_ca = .{}, .now = now }),
    );
    thr.join();
}

test "server request client authentication" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = try std.Io.Clock.real.now(io);
    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});

    var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer auth.deinit(allocator);

    var root_ca = try tls.config.cert.fromFilePath(allocator, io, dir, "minica.pem");
    defer root_ca.deinit(allocator);

    const opt: tls.config.Server = .{
        .client_auth = .{
            .auth_type = .request,
            .root_ca = root_ca,
        },
        .auth = &auth,
        .now = now,
    };
    var server = try address.listen(io, .{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ io, &server, opt, 2 + client_keys.len });

    // client with insecure_skip_verify connects, server sends certificates but client skips verification
    try connectReceive(io, server.socket.address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{}, .now = now });

    // 'normal' client connect, it's not sending client certificates but server don't require it
    try connectReceive(io, server.socket.address, .{ .host = host, .root_ca = root_ca, .now = now });

    // client with client certificate
    for (client_keys) |sub_path| {
        const cert_dir = try dir.openDir(io, sub_path, .{});

        var client_auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, cert_dir, "cert.pem", "key.pem");
        defer client_auth.deinit(allocator);

        const client_opt: tls.config.Client = .{
            .host = host,
            .root_ca = root_ca,
            .auth = &client_auth,
            .now = now,
        };
        try connectReceive(io, server.socket.address, client_opt);
    }

    thr.join();
}

test "server require client authentication" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = try std.Io.Clock.real.now(io);
    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});

    var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer auth.deinit(allocator);

    var root_ca = try tls.config.cert.fromFilePath(allocator, io, dir, "minica.pem");
    defer root_ca.deinit(allocator);

    const opt: tls.config.Server = .{
        .client_auth = .{
            .auth_type = .require,
            .root_ca = root_ca,
        },
        .auth = &auth,
        .now = now,
    };
    var server = try address.listen(io, .{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ io, &server, opt, 1 + client_keys.len });

    // 'normal' client without client certificates can't connect; server REQUIRES client certificate
    try testing.expectError(
        error.TlsAlertCertificateRequired,
        connectReceive(io, server.socket.address, .{ .host = host, .root_ca = root_ca, .now = now }),
    );

    // load client certificate and connect
    for (client_keys) |sub_path| {
        const cert_dir = try dir.openDir(io, sub_path, .{});
        var client_auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, cert_dir, "cert.pem", "key.pem");
        defer client_auth.deinit(allocator);
        const client_opt: tls.config.Client = .{
            .host = host,
            .root_ca = root_ca,
            .auth = &client_auth,
            .now = now,
        };
        try connectReceive(io, server.socket.address, client_opt);
    }

    thr.join();
}

test "server send key update" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now = try std.Io.Clock.real.now(io);

    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});
    var buf: [256]u8 = undefined;
    const root = buf[0..try dir.realPath(io, &buf)];

    const server_cert_path = try std.fs.path.join(allocator, &.{ root, "localhost_rsa/cert.pem" });
    defer allocator.free(server_cert_path);
    const server_key_path = try std.fs.path.join(allocator, &.{ root, "localhost_rsa/key.pem" });
    defer allocator.free(server_key_path);
    const ca_cert_path = try std.fs.path.join(allocator, &.{ root, "minica.pem" });
    defer allocator.free(ca_cert_path);

    var auth = try tls.config.CertKeyPair.fromFilePathAbsolute(
        allocator,
        io,
        server_cert_path,
        server_key_path,
    );
    defer auth.deinit(allocator);

    var root_ca = try tls.config.cert.fromFilePathAbsolute(allocator, io, ca_cert_path);
    defer root_ca.deinit(allocator);

    const opt: tls.config.Server = .{ .auth = &auth, .now = now };
    var server = try address.listen(io, .{});
    const thr = try std.Thread.spawn(.{}, acceptSendKeyUpdate, .{ io, &server, opt });
    // client will receive key multiple  times
    try connectReceive(io, server.socket.address, .{ .host = host, .root_ca = root_ca, .now = now });
    thr.join();
}

fn acceptSendKeyUpdate(io: Io, server: *Io.net.Server, opt: tls.config.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var conn = try tls.serverFromStream(io, stream, opt);
    conn.max_encrypt_seq = 8;
    try conn.writeAll(data);
    try conn.close();
}
