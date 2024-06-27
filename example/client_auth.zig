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

    const host = "localhost";
    const port = 8443;

    // const tls12_384 = [_]tls.CipherSuite{
    //     .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    //     .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    //     //.ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    // };
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
    //
    for ([_][]const tls.CipherSuite{
        &tls.CipherSuite.tls13,
        &tls.CipherSuite.tls12,
    }) |cipher_suites| {
        for (client_keys) |sub_path| {
            // Make tcp connection
            var tcp = try std.net.tcpConnectToHost(gpa, host, port);
            defer tcp.close();

            // Prepare client authentication
            const cert_dir = try dir.openDir(sub_path, .{});
            var client_certificates: Certificate.Bundle = .{};
            try client_certificates.addCertsFromFilePath(gpa, cert_dir, "cert.pem");
            const file = try cert_dir.openFile("key.pem", .{});
            defer file.close();
            const client_private_key = try tls.PrivateKey.fromFile(gpa, file);

            // Upgrade tcp connection to tls client
            var cli = tls.client(tcp);
            var stats: tls.Options.Stats = .{};
            try cli.handshake(host, ca_bundle, .{
                .cipher_suites = cipher_suites,
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
                // std.debug.print("{s}", .{data});
            }
            try cli.close();
            // std.debug.print("{} bytes read\n", .{n});
            cmn.showStats(&stats, host);
            std.debug.print("{s}\n", .{sub_path});
        }
    }
}
