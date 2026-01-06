const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var root_ca = try tls.config.cert.fromSystem(allocator, io);
    defer root_ca.deinit(allocator);

    const domain = if (args.len > 1) args[1] else "cloudflare.com";
    const fail_count = run(io, root_ca, domain, try std.Io.Clock.real.now(io));
    if (fail_count > 0) std.process.exit(1);
}

fn run(io: std.Io, root_ca: tls.config.cert.Bundle, domain: []const u8, now: std.Io.Timestamp) usize {
    var fail_count: usize = 0;
    for (tls.config.cipher_suites.all) |cs| {
        cmn.get(io, domain, null, false, false, .{
            .root_ca = root_ca,
            .host = "",
            .cipher_suites = &[_]tls.config.CipherSuite{cs},
            .now = now,
        }) catch |err| {
            std.debug.print("❌ {s} {s} {}\n", .{ @tagName(cs), domain, err });
            fail_count += 1;
            continue;
        };
        std.debug.print("✔️ {s} {s}\n", .{ @tagName(cs), domain });
    }
    return fail_count;
}
