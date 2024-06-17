const std = @import("std");
const tls = @import("tls");

pub fn showStats(stats: *tls.Stats, domain: []const u8) void {
    std.debug.print(
        "\n{s}\n\ttls version: {s}\n\tchipher: {s}\n\tnamed group: {s}\n\tsignature scheme: {s}\n",
        .{
            domain,
            if (@intFromEnum(stats.tls_version) == 0) "none" else @tagName(stats.tls_version),
            if (@intFromEnum(stats.cipher_suite_tag) == 0) "none" else @tagName(stats.cipher_suite_tag),
            if (@intFromEnum(stats.named_group) == 0) "none" else @tagName(stats.named_group),
            if (@intFromEnum(stats.signature_scheme) == 0) "none" else @tagName(stats.signature_scheme),
        },
    );
}
