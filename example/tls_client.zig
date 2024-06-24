const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

// Create ca, server and client certificates:
// $ cd example && ./cert.sh
//
// Start server from go_tls_server folder:
// $ cd example/go_tls_server && go run server.go
//
// Then run this client:
//   zig build example_tls_client
//   or
//   zig build && zig-out/bin/tls_client
//
pub fn main() !void {
    const gpa = std.heap.page_allocator;
    // We are running binary from project root
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    // Init certificate bundle with ca
    var ca_bundle: Certificate.Bundle = .{};
    defer ca_bundle.deinit(gpa);
    try ca_bundle.addCertsFromFilePath(gpa, dir, "minica.pem");

    // Make tcp connection
    const host = "localhost";
    const port = 8443;
    var tcp = try std.net.tcpConnectToHost(gpa, host, port);
    defer tcp.close();

    // Prepare client authentication
    var client_certificates: Certificate.Bundle = .{};
    try client_certificates.addCertsFromFilePath(gpa, dir, "client-rsa/cert.pem");
    const file = try dir.openFile("client-rsa/key.pem", .{});
    defer file.close();
    const client_private_key = try tls.PrivateKey.fromFile(gpa, file);

    // Upgrade tcp connection to tls client
    var cli = tls.client(tcp);
    var stats: tls.Options.Stats = .{};
    try cli.handshake(host, ca_bundle, .{
        .stats = &stats,
        .auth = .{
            .certificates = client_certificates,
            .private_key = client_private_key,
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
