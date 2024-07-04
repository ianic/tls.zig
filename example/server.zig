const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
//const cmn = @import("common.zig");

pub fn main() !void {
    // const gpa = std.heap.page_allocator;
    // const dir = try std.fs.cwd().openDir("example/cert", .{});

    // var certificates: Certificate.Bundle = .{};
    // defer certificates.deinit(gpa);
    // try certificates.addCertsFromFilePath(gpa, dir, "localhost_rsa/cert.pem");
    // //try certificates.addCertsFromFilePath(gpa, dir, "minica.pem");

    // const file = try dir.openFile("localhost_rsa/key.pem", .{});
    // const private_key = try tls.PrivateKey.fromFile(gpa, file);
    // file.close();

    const port = 9443;
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    var server = try address.listen(.{
        .reuse_address = true,
    });

    var buf: [4096]u8 = undefined;
    while (true) {
        const tcp = try server.accept();
        std.debug.print("accepted {}\n", .{tcp.address});
        defer tcp.stream.close();

        var conn = try tls.server(tcp.stream, .{
            .authentication = null,
            // .authentication = .{
            //     .certificates = certificates,
            //     .private_key = private_key,
            // },
        });

        const pg_file = try std.fs.cwd().openFile("example/go_tls_server/pg2600.txt", .{});
        defer pg_file.close();

        while (true) {
            const n = try pg_file.read(&buf);
            try conn.writeAll(buf[0..n]);
            if (n < buf.len) break;
        }
        try conn.close();
    }
}
