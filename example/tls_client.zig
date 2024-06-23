const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

// Start server from go_tls_server folder:
// $ cd example/go_tls_server && ./run.sh
// It will generate certificate and start Go server.
// Then run example:
//   zig build example_tls_client
//   or
//   zig-out/bin/tls_client
// After connecting server will stream a large text file.
pub fn main() !void {
    const gpa = std.heap.page_allocator;

    // Init certificate bundle with server certificate
    //var ca_bundle: Certificate.Bundle = .{};
    var ca_bundle = try cmn.initCaBundle(gpa);
    defer ca_bundle.deinit(gpa);
    // assuming we are running binary from project root
    var dir = try std.fs.cwd().openDir("example/go_tls_server", .{ .iterate = true });
    try ca_bundle.addCertsFromDir(gpa, dir);
    dir = try std.fs.cwd().openDir("example/go_client_server", .{ .iterate = true });
    try ca_bundle.addCertsFromDir(gpa, dir);

    // Make tcp connection
    const host = "localhost";
    const port = 8443;

    // const host = "irc.libera.chat";
    // const port = 6697;

    var tcp = try std.net.tcpConnectToHost(gpa, host, port);
    defer tcp.close();

    var certs: Certificate.Bundle = .{};
    try certs.addCertsFromFilePathAbsolute(gpa, "/home/ianic/Code/tls.zig/example/go_client_server/client-cert.pem");
    try certs.addCertsFromFilePathAbsolute(gpa, "/home/ianic/Code/tls.zig/example/go_client_server/minica.pem");

    const private_key = &[_]u8{
        0x10, 0x35, 0x3d, 0xca, 0x1b, 0x15, 0x1d, 0x06, 0xaa, 0x71, 0xb8, 0xef, 0xf3, 0x19, 0x22,
        0x43, 0x78, 0xf3, 0x20, 0x98, 0x1e, 0xb1, 0x2f, 0x2b, 0x64, 0x7e, 0x71, 0xd0, 0x30, 0x2a,
        0x90, 0xaa, 0xe5, 0xeb, 0x99, 0xc3, 0x90, 0x65, 0x3d, 0xc1, 0x26, 0x19, 0xbe, 0x3f, 0x08,
        0x20, 0x9b, 0x01,
    };
    const signature_scheme: std.crypto.tls.SignatureScheme = .ecdsa_secp384r1_sha384;

    // Upgrade tcp connection to tls client
    var cli = tls.client(tcp);
    var stats: tls.Stats = .{};
    try cli.handshake(host, ca_bundle, .{
        //.cipher_suites = &tls.CipherSuite.tls12_secure,
        .stats = &stats,
        .auth = .{
            .certificates = certs,
            .private_key = private_key,
            .signature_scheme = signature_scheme,
        },
    });

    // Show response
    var n: usize = 0;
    while (try cli.next()) |data| {
        n += data.len;
        std.debug.print("{s}", .{data});
    }
    try cli.close();
    std.debug.print("{} bytes read\n", .{n});
    cmn.showStats(&stats, host);
}
