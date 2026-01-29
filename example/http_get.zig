const std = @import("std");
const tls = @import("tls");
const cmn = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len > 1) {
        const domain = args[1];

        var ca_bundle = try tls.config.cert.fromSystem(gpa, io);
        defer ca_bundle.deinit(gpa);

        const rng_impl: std.Random.IoSource = .{ .io = io };
        try cmn.get(io, domain, null, true, true, .{
            .host = "",
            .root_ca = ca_bundle,
            // to force specific cipher:
            //   .cipher_suites = &[_]tls.CipherSuite{.CHACHA20_POLY1305_SHA256},
            // to force cipher from specific tls version:
            //   .cipher_suites = tls.config.cipher_suites.tls12,
            .cipher_suites = tls.config.cipher_suites.secure,
            .key_log_callback = tls.config.key_log.init(init.minimal.environ),
            .now = try std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
        });
    }
}
