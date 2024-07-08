const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var root_ca = try cmn.initCaBundle(allocator);
    defer root_ca.deinit(allocator);

    if (args.len > 1) {
        return try run(allocator, root_ca, args[1]);
    }
    try run(allocator, root_ca, "cloudflare.com");
}

fn run(allocator: std.mem.Allocator, root_ca: Certificate.Bundle, domain: []const u8) !void {
    for (tls.CipherSuite.all) |cs| {
        cmn.get(allocator, domain, null, false, false, .{
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
