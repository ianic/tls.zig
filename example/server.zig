const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const file_name = if (args.len > 1) args[1] else "example/cert/pg2600.txt";
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    // Load server certificate
    var certificates: Certificate.Bundle = .{};
    defer certificates.deinit(allocator);
    try certificates.addCertsFromFilePath(allocator, dir, "localhost_ec/cert.pem");

    // Load server private key
    const private_key_file = try dir.openFile("localhost_ec/key.pem", .{});
    const private_key = try tls.PrivateKey.fromFile(allocator, private_key_file);
    private_key_file.close();

    // // Load ca to check client certificate
    // var client_root_ca: Certificate.Bundle = .{};
    // defer client_root_ca.deinit(allocator);
    // try client_root_ca.addCertsFromFilePath(allocator, dir, "minica.pem");

    // Tcp listener
    const port = 9443;
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{
        .reuse_address = true,
    });

    const pg_file = try std.fs.cwd().openFile(file_name, .{});
    defer pg_file.close();

    var buf: [32 * 1024]u8 = undefined;
    while (true) {
        // Tcp accept
        const tcp = try server.accept();
        // std.debug.print("accepted {}\n", .{tcp.address});
        defer tcp.stream.close();

        // Upgrade tcp to tls
        var conn = tls.server(tcp.stream, .{
            // .client_auth = .{
            //     .auth_type = .request,
            //     .root_ca = client_root_ca,
            // },
            .authentication = .{
                .certificates = certificates,
                .private_key = private_key,
            },
        }) catch |err| {
            std.debug.print("tls failed with {}\n", .{err});
            continue;
        };

        // for testing key update
        // conn.max_encrypt_seq = 10;

        try pg_file.seekTo(0);
        while (true) {
            const n = try pg_file.read(&buf);
            try conn.writeAll(buf[0..n]);
            if (n < buf.len) break;
        }
        try conn.close();
    }
}
