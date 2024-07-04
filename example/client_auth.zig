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
//   zig build example_client_auth
//   or
//   zig build && zig-out/bin/client_auth
//
pub fn main() !void {
    const gpa = std.heap.page_allocator;
    // We are running binary from project root
    const dir = try std.fs.cwd().openDir("example/cert", .{});

    // Init certificate bundle with ca
    var root_ca: Certificate.Bundle = .{};
    defer root_ca.deinit(gpa);
    try root_ca.addCertsFromFilePath(gpa, dir, "minica.pem");

    const host = "localhost";
    const port = 8443;

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
            var certificates: Certificate.Bundle = .{};
            defer certificates.deinit(gpa);
            try certificates.addCertsFromFilePath(gpa, cert_dir, "cert.pem");

            const private_key_file = try cert_dir.openFile("key.pem", .{});
            defer private_key_file.close();
            const private_key = try tls.PrivateKey.fromFile(gpa, private_key_file);

            // Upgrade tcp connection to tls client
            var diagnostic: tls.ClientOptions.Diagnostic = .{};
            var cli = try tls.client(tcp, .{
                .host = host,
                .root_ca = root_ca,
                .cipher_suites = cipher_suites,
                .authentication = .{
                    .certificates = certificates,
                    .private_key = private_key,
                },
                .diagnostic = &diagnostic,
            });

            // Show response
            var n: usize = 0;
            while (try cli.next()) |data| {
                n += data.len;
                // std.debug.print("{s}", .{data});
            }
            try cli.close();
            // std.debug.print("{} bytes read\n", .{n});
            cmn.showDiagnostic(&diagnostic, host);
            std.debug.print("{s}\n", .{sub_path});
        }
    }
}
