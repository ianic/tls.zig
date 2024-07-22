const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var root_ca = try tls.CertBundle.fromSystem(allocator);
    defer root_ca.deinit(allocator);

    const domain = if (args.len > 1) args[1] else "cloudflare.com";
    const fail_count = run(allocator, root_ca, domain);
    if (fail_count > 0) std.posix.exit(1);
}

fn run(allocator: std.mem.Allocator, root_ca: tls.CertBundle, domain: []const u8) usize {
    var fail_count: usize = 0;
    for (tls.cipher_suites.all) |cs| {
        cmn.get(allocator, domain, null, false, false, .{
            .root_ca = root_ca,
            .host = "",
            .cipher_suites = &[_]tls.CipherSuite{cs},
        }) catch |err| {
            std.debug.print("❌ {s} {s} {}\n", .{ @tagName(cs), domain, err });
            fail_count += 1;
            continue;
        };
        std.debug.print("✔️ {s} {s}\n", .{ @tagName(cs), domain });
    }
    return fail_count;
}
