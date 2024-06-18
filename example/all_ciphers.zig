const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer gpa.free(args);

    var ca_bundle = try cmn.initCaBundle(gpa);
    defer ca_bundle.deinit(gpa);

    if (args.len > 1) {
        return try run(gpa, ca_bundle, args[1]);
    }
    try run(gpa, ca_bundle, "cloudflare.com");
}

fn run(gpa: std.mem.Allocator, ca_bundle: Certificate.Bundle, domain: []const u8) !void {
    for (tls.CipherSuite.all) |cs| {
        cmn.get(gpa, domain, null, ca_bundle, false, false, .{
            .cipher_suites = &[_]tls.CipherSuite{cs},
        }) catch |err| {
            std.debug.print("❌ {s} {s} {}\n", .{ @tagName(cs), domain, err });
            continue;
        };
        std.debug.print("✔️ {s} {s}\n", .{ @tagName(cs), domain });
    }
}
