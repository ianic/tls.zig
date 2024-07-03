const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer gpa.free(args);

    var root_ca = try cmn.initCaBundle(gpa);
    defer root_ca.deinit(gpa);

    if (args.len > 1) {
        return try run(gpa, root_ca, args[1]);
    }
    try run(gpa, root_ca, "cloudflare.com");
}

fn run(gpa: std.mem.Allocator, root_ca: Certificate.Bundle, domain: []const u8) !void {
    for (tls.CipherSuite.all) |cs| {
        cmn.get(gpa, domain, null, false, false, .{
            .root_ca = root_ca,
            .host = "",
            .cipher_suites = &[_]tls.CipherSuite{cs},
        }) catch |err| {
            std.debug.print("❌ {s} {s} {}\n", .{ @tagName(cs), domain, err });
            continue;
        };
        std.debug.print("✔️ {s} {s}\n", .{ @tagName(cs), domain });
    }
}
