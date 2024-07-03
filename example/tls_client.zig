const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

// Start server from go_tls_server folder:
// $ cd example/go_tls_server && ./run_file_server.sh
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
    const port = 9443;
    var tcp = try std.net.tcpConnectToHost(gpa, host, port);
    defer tcp.close();

    // Upgrade tcp connection to tls client
    var cli = tls.client(tcp);
    var stats: tls.Options.Stats = .{};
    try cli.handshake(host, ca_bundle, .{
        //.cipher_suites = &tls.CipherSuite.tls13,
        .cipher_suites = &.{tls.CipherSuite.AES_256_GCM_SHA384},
        .stats = &stats,
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
