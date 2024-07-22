const std = @import("std");
const tls = @import("tls");
const net = std.net;
const Certificate = std.crypto.Certificate;

const data = @embedFile("cert/pg2600.txt");

const testing = std.testing;
const host = "localhost";
const address = net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
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

fn acceptSend(server: *net.Server, opt: tls.ServerOptions, clients: usize) !void {
    for (0..clients) |_| {
        const tcp = try server.accept();
        defer tcp.stream.close();
        var conn = tls.server(tcp.stream, opt) catch |err| {
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

fn connectReceive(addr: net.Address, opt_: tls.ClientOptions) !void {
    var tcp = try net.tcpConnectToAddress(addr);
    defer tcp.close();
    var opt = opt_;
    opt.key_log_callback = tls.key_log.callback;
    var conn = try tls.client(tcp, opt);

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

fn loadX509KeyPair(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    cert_path: []const u8,
    key_path: []const u8,
) !struct { Certificate.Bundle, tls.PrivateKey } {
    var cert: Certificate.Bundle = .{};

    try cert.addCertsFromFilePath(allocator, dir, cert_path);

    const key_file = try dir.openFile(key_path, .{});
    const key = try tls.PrivateKey.fromFile(allocator, key_file);
    key_file.close();

    return .{ cert, key };
}

test "server without certificate" {
    const opt: tls.ServerOptions = .{ .auth = null };

    var server = try address.listen(.{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ &server, opt, 2 });
    // client with insecure_skip_verify connects
    try connectReceive(server.listen_address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{} });
    // if insecure_skip_verify is not set connection fails
    try testing.expectError(
        error.TlsUnexpectedMessage,
        connectReceive(server.listen_address, .{ .host = host, .root_ca = .{} }),
    );
    thr.join();
}

test "server with ec key key pair" {
    const allocator = testing.allocator;
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var cert, const key = try loadX509KeyPair(allocator, dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer cert.deinit(allocator);

    var root_ca: Certificate.Bundle = .{};
    defer root_ca.deinit(allocator);
    try root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    const opt: tls.ServerOptions = .{
        .auth = .{
            .cert = cert,
            .key = key,
        },
    };
    var server = try address.listen(.{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ &server, opt, 3 });
    // client with insecure_skip_verify connects, server sends certificates but client skips verification
    try connectReceive(server.listen_address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{} });
    // client with root certificates connects; server certificates are validated
    try connectReceive(server.listen_address, .{ .host = host, .root_ca = root_ca });
    // client without insecure_skip_verify but not root ca fails; client can't verify server certificates
    try testing.expectError(
        error.CertificateIssuerNotFound,
        connectReceive(server.listen_address, .{ .host = host, .root_ca = .{} }),
    );
    thr.join();
}

test "server with rsa key key pair" {
    const allocator = testing.allocator;
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var cert, const key = try loadX509KeyPair(allocator, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer cert.deinit(allocator);

    var root_ca: Certificate.Bundle = .{};
    defer root_ca.deinit(allocator);
    try root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    const opt: tls.ServerOptions = .{
        .auth = .{
            .cert = cert,
            .key = key,
        },
    };
    var server = try address.listen(.{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ &server, opt, 3 });
    // client with insecure_skip_verify connects, server sends certificates but client skips verification
    try connectReceive(server.listen_address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{} });
    // client with root certificates connects; server certificates are validated
    try connectReceive(server.listen_address, .{ .host = host, .root_ca = root_ca });
    // client without insecure_skip_verify but not root ca fails; client can't verify server certificates
    try testing.expectError(
        error.CertificateIssuerNotFound,
        connectReceive(server.listen_address, .{ .host = host, .root_ca = .{} }),
    );
    thr.join();
}

test "server request client authentication" {
    const allocator = testing.allocator;
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var root_ca: Certificate.Bundle = .{};
    defer root_ca.deinit(allocator);
    try root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    var cert, const key = try loadX509KeyPair(allocator, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer cert.deinit(allocator);
    const opt: tls.ServerOptions = .{
        .client_auth = .{
            .auth_type = .request,
            .root_ca = root_ca,
        },
        .auth = .{
            .cert = cert,
            .key = key,
        },
    };
    var server = try address.listen(.{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ &server, opt, 2 + client_keys.len });

    // client with insecure_skip_verify connects, server sends certificates but client skips verification
    try connectReceive(server.listen_address, .{ .insecure_skip_verify = true, .host = host, .root_ca = .{} });

    // 'normal' client connect, it's not sending client certificates but server don't require it
    try connectReceive(server.listen_address, .{ .host = host, .root_ca = root_ca });

    // client with client certificate
    for (client_keys) |sub_path| {
        const cert_dir = try dir.openDir(sub_path, .{});
        var client_cert, const client_key = try loadX509KeyPair(allocator, cert_dir, "cert.pem", "key.pem");
        defer client_cert.deinit(allocator);
        const client_opt: tls.ClientOptions = .{
            .host = host,
            .root_ca = root_ca,
            .auth = .{
                .cert = client_cert,
                .key = client_key,
            },
        };
        try connectReceive(server.listen_address, client_opt);
    }

    thr.join();
}

test "server require client authentication" {
    const allocator = testing.allocator;
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var root_ca: Certificate.Bundle = .{};
    defer root_ca.deinit(allocator);
    try root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    var cert, const key = try loadX509KeyPair(allocator, dir, "localhost_rsa/cert.pem", "localhost_rsa/key.pem");
    defer cert.deinit(allocator);
    const opt: tls.ServerOptions = .{
        .client_auth = .{
            .auth_type = .require,
            .root_ca = root_ca,
        },
        .auth = .{
            .cert = cert,
            .key = key,
        },
    };
    var server = try address.listen(.{});
    const thr = try std.Thread.spawn(.{}, acceptSend, .{ &server, opt, 1 + client_keys.len });

    // 'normal' client without client certificates can't connect; server REQUIRES client certificate
    try testing.expectError(
        error.TlsAlertCertificateRequired,
        connectReceive(server.listen_address, .{ .host = host, .root_ca = root_ca }),
    );

    // load client certificate and connect
    for (client_keys) |sub_path| {
        const cert_dir = try dir.openDir(sub_path, .{});
        var client_cert, const client_key = try loadX509KeyPair(allocator, cert_dir, "cert.pem", "key.pem");
        defer client_cert.deinit(allocator);
        const client_opt: tls.ClientOptions = .{
            .host = host,
            .root_ca = root_ca,
            .auth = .{
                .cert = client_cert,
                .key = client_key,
            },
        };
        try connectReceive(server.listen_address, client_opt);
    }

    thr.join();
}

test "server send key update" {
    const allocator = testing.allocator;
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    var cert, const key = try loadX509KeyPair(allocator, dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer cert.deinit(allocator);

    var root_ca: Certificate.Bundle = .{};
    defer root_ca.deinit(allocator);
    try root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    const opt: tls.ServerOptions = .{
        .auth = .{
            .cert = cert,
            .key = key,
        },
    };
    var server = try address.listen(.{});
    const thr = try std.Thread.spawn(.{}, acceptSendKeyUpdate, .{ &server, opt });
    // client will receive key multiple  times
    try connectReceive(server.listen_address, .{ .host = host, .root_ca = root_ca });
    thr.join();
}

fn acceptSendKeyUpdate(server: *net.Server, opt: tls.ServerOptions) !void {
    const tcp = try server.accept();
    defer tcp.stream.close();
    var conn = try tls.server(tcp.stream, opt);
    conn.max_encrypt_seq = 8;
    try conn.writeAll(data);
    try conn.close();
}
