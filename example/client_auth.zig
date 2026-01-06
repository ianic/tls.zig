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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // We are running binary from project root
    const dir = try std.Io.Dir.cwd().openDir(io, "example/cert", .{});

    // Init certificate bundle with ca
    var root_ca = try tls.config.cert.fromFilePath(allocator, io, dir, "minica.pem");
    defer root_ca.deinit(allocator);

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
    for ([_][]const tls.config.CipherSuite{
        tls.config.cipher_suites.tls13,
        tls.config.cipher_suites.tls12,
    }) |cipher_suites| {
        for (client_keys) |sub_path| {
            // Make tcp connection
            const host_name = try std.Io.net.HostName.init(host);
            var tcp = try host_name.connect(io, port, .{ .mode = .stream });
            defer tcp.close(io);

            // Prepare client authentication key pair
            const cert_dir = try dir.openDir(io, sub_path, .{});

            var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, cert_dir, "cert.pem", "key.pem");
            defer auth.deinit(allocator);

            // Upgrade tcp connection to tls client
            var diagnostic: tls.config.Client.Diagnostic = .{};
            var cli = try tls.clientFromStream(io, tcp, .{
                .host = host,
                .root_ca = root_ca,
                .cipher_suites = cipher_suites,
                .auth = &auth,
                .diagnostic = &diagnostic,
                .key_log_callback = tls.config.key_log.callback,
                .now = try std.Io.Clock.real.now(io),
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
