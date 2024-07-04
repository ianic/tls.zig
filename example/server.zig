const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    // Load server certificate
    var certificates: Certificate.Bundle = .{};
    defer certificates.deinit(gpa);
    try certificates.addCertsFromFilePath(gpa, dir, "localhost_ec/cert.pem");
    // try certificates.addCertsFromFilePath(gpa, dir, "minica.pem");

    // Load server private key
    const private_key_file = try dir.openFile("localhost_ec/key.pem", .{});
    const private_key = try tls.PrivateKey.fromFile(gpa, private_key_file);
    private_key_file.close();

    // Tcp listener
    const port = 9443;
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{
        .reuse_address = true,
    });

    var buf: [4096]u8 = undefined;
    while (true) {
        // Tcp accept
        const tcp = try server.accept();
        std.debug.print("accepted {}\n", .{tcp.address});
        defer tcp.stream.close();

        // Upgrade tcp to tls
        var conn = try tls.server(tcp.stream, .{
            .authentication = .{
                .certificates = certificates,
                .private_key = private_key,
            },
        });

        const pg_file = try std.fs.cwd().openFile("example/cert/pg2600.txt", .{});
        defer pg_file.close();

        while (true) {
            const n = try pg_file.read(&buf);
            try conn.writeAll(buf[0..n]);
            if (n < buf.len) break;
        }
        try conn.close();
    }
}
