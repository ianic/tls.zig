const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const cmn = @import("common.zig");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const top_sites = try cmn.topSites(gpa);
    defer top_sites.deinit();

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = gpa, .n_jobs = 32 });

    var root_ca = try cmn.initCaBundle(gpa);
    defer root_ca.deinit(gpa);

    var counter: cmn.Counter = .{};
    for (top_sites.value) |site| {
        const domain = site.rootDomain;
        if (cmn.skipDomain(domain)) {
            counter.add(.skip);
            continue;
        }
        try pool.spawn(run, .{ gpa, domain, root_ca, &counter });
    }
    pool.deinit();
    counter.show();
}

pub fn run(gpa: std.mem.Allocator, domain: []const u8, root_ca: Certificate.Bundle, counter: *cmn.Counter) void {
    var diagnostic: tls.ClientOptions.Diagnostic = .{};
    var opt: tls.ClientOptions = .{
        .host = "",
        .root_ca = root_ca,
        .diagnostic = &diagnostic,
    };

    if (cmn.inList(domain, &cmn.noKeyber)) {
        opt.disable_keyber = true;
    }
    cmn.get(gpa, domain, null, false, false, opt) catch |err| {
        curl(gpa, domain) catch |curl_err| {
            std.debug.print("➖ {s} error {} curl error: {}\n", .{ domain, err, curl_err });
            counter.add(.err);
            return;
        };
        std.debug.print("❌ {s} ERROR {}\n", .{ domain, err });
        counter.add(.fail);
        return;
    };
    counter.add(.success);
    std.debug.print("✔️ {s} {s} {s} {s} {s}\n", .{
        domain,
        if (@intFromEnum(diagnostic.tls_version) == 0) "none" else @tagName(diagnostic.tls_version),
        if (@intFromEnum(diagnostic.cipher_suite_tag) == 0) "none" else @tagName(diagnostic.cipher_suite_tag),
        if (@intFromEnum(diagnostic.named_group) == 0) "none" else @tagName(diagnostic.named_group),
        if (@intFromEnum(diagnostic.signature_scheme) == 0) "none" else @tagName(diagnostic.signature_scheme),
    });
}

fn curl(allocator: std.mem.Allocator, domain: []const u8) !void {
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "curl", "-m 10", "-sS", "-w %{errormsg}", url },
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    // ref: https://everything.curl.dev/cmdline/exitcode.html
    switch (result.term) {
        .Exited => |error_code| switch (error_code) {
            0 => return,
            6 => return error.CouldntResolveHost,
            7 => return error.FailedToConnectToHost,
            18, 28 => return error.OperationTimeout,
            60 => return error.Certificate,
            else => {
                std.debug.print("curl error code {}\n", .{error_code});
                return error.Unknown;
            },
        },
        else => {},
    }

    std.debug.print("curl: {s} {}\n", .{ url, result.term });
    std.debug.print("{s}\n", .{result.stdout});
    std.debug.print("{s}\n\n", .{result.stderr});

    return error.CurlFailed;
}
