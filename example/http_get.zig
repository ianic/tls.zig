const std = @import("std");
const tls = @import("tls");
const cmn = @import("common.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer gpa.free(args);

    if (args.len > 1) {
        const domain = args[1];

        var ca_bundle = try cmn.initCaBundle(gpa);
        defer ca_bundle.deinit(gpa);

        try cmn.get(gpa, domain, null, ca_bundle, true, true, .{
            // to force specific cipher:
            // .cipher_suites = &[_]tls.CipherSuite{.CHACHA20_POLY1305_SHA256},
            // to force cipher from specific tls version:
            // .cipher_suites = &tls.CipherSuite.tls12,
        });
    }
}
