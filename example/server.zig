const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const file_name = if (args.len > 1) args[1] else "example/cert/pg2600.txt";
    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});

    // Load server certificate key pair
    var auth = try tls.config.CertKeyPair.fromFilePath(gpa, io, dir, "localhost_ec/cert.pem", "localhost_ec/key.pem");
    defer auth.deinit(gpa);
    // try auth.bundle.addCertsFromFilePath(allocator, dir, "minica.pem");

    // // Load ca to check client certificate
    // var client_root_ca = try tls.config.cert.fromFile(allocator, dir, "minica.pem");
    // defer client_root_ca.deinit(allocator);

    // Tcp listener
    const port = 9443;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var server = try address.listen(io, .{
        .mode = .stream,
        .reuse_address = true,
    });

    const pg_file = try std.Io.Dir.cwd().openFile(io, file_name, .{});
    defer pg_file.close(io);

    var buf: [32 * 1024]u8 = undefined;
    while (true) {
        // Tcp accept
        const stream = try server.accept(io);
        defer stream.close(io);

        // Upgrade tcp to tls
        var conn = tls.serverFromStream(io, stream, .{
            // .client_auth = .{
            //     .auth_type = .request,
            //     .root_ca = client_root_ca,
            // },
            .auth = &auth,
            .now = try std.Io.Clock.real.now(io),
            .random = (std.Random.IoSource{ .io = io }).interface(),
        }) catch |err| {
            std.debug.print("tls failed with {}\n", .{err});
            continue;
        };

        // for testing key update
        // conn.max_encrypt_seq = 10;

        while (true) {
            const n = try pg_file.readPositional(io, &.{&buf}, 0);
            try conn.writeAll(buf[0..n]);
            if (n < buf.len) break;
        }
        try conn.close();
    }
}
