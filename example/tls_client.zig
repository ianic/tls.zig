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

    var file = try std.fs.openFileAbsolute("/home/ianic/Code/tls.zig/example/go_client_server/client-key.pem", .{});
    defer file.close();
    const private_key = try tls.PrivateKey.fromFile(gpa, file);

    // Upgrade tcp connection to tls client
    var cli = tls.client(tcp);
    var stats: tls.Stats = .{};
    try cli.handshake(host, ca_bundle, .{
        //.cipher_suites = &tls.CipherSuite.tls12_secure,
        .stats = &stats,
        .auth = .{
            .certificates = certs,
            .private_key = private_key,
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
