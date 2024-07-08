const std = @import("std");
const tls = @import("tls");
const cmn = @import("common.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1) {
        const domain = args[1];

        var ca_bundle = try cmn.initCaBundle(allocator);
        defer ca_bundle.deinit(allocator);

        try cmn.get(allocator, domain, null, true, true, .{
            .host = "",
            .root_ca = ca_bundle,
            .named_groups = tls.ClientOptions.named_groups_all,
            //.named_groups = &[_]std.crypto.tls.NamedGroup{.secp384r1},
            // to force specific cipher:
            // .cipher_suites = &[_]tls.CipherSuite{.CHACHA20_POLY1305_SHA256},
            // to force cipher from specific tls version:
            // .cipher_suites = &tls.CipherSuite.tls12,
        });
    }
}
