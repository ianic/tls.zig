const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;
const Io = std.Io;
const cmn = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var root_ca = try tls.config.cert.fromSystem(gpa, io);
    defer root_ca.deinit(gpa);

    // Some other sources of domains list:
    // source: https://moz.com/top500
    // var rdr = cmn.CsvReader.init(@embedFile("domains_with_big_tls_records_in_handshake"));
    var rdr = cmn.CsvReader.init(@embedFile("moz_top500.csv"));
    // source: https://dataforseo.com/free-seo-stats/top-1000-websites
    // var rdr = cmn.CsvReader.init(@embedFile("ranked_domains.csv"));
    // source: https://radar.cloudflare.com/domains
    // var rdr = cmn.CsvReader.init(@embedFile("cloudflare-radar_top-10000-domains_20241209-20241216.csv"));
    // var rdr = cmn.CsvReader.init(@embedFile("domains"));

    var group: Io.Group = .init;
    var tasks: usize = 0;
    var counter: cmn.Counter = .{};
    while (rdr.next()) |domain| {
        if (domain.len == 0) continue;
        tasks += 1;
        // if (cmn.skipDomain(domain)) {
        //     std.debug.print("➰ {s:<25} SKIP\n", .{domain});
        //     counter.add(.skip);
        //     continue;
        // }
        group.async(io, run, .{ gpa, io, domain, root_ca, &counter });
    }

    var elapsed: usize = 0;
    while (counter.total() < tasks) {
        try io.sleep(.fromSeconds(1), .real);
        elapsed += 1;
        if (elapsed > 10) {
            group.cancel(io);
            break;
        }
    }
    try group.await(io);

    counter.show();
    if (counter.failRate() > 0.01) std.process.exit(1);
}

pub fn run(gpa: std.mem.Allocator, io: Io, domain: []const u8, root_ca: tls.config.cert.Bundle, counter: *cmn.Counter) Io.Cancelable!void {
    var diagnostic: tls.config.Client.Diagnostic = .{};
    var opt: tls.config.Client = .{
        .host = "",
        .root_ca = root_ca,
        .diagnostic = &diagnostic,
        .now = std.Io.Clock.real.now(io) catch unreachable,
    };
    if (cmn.inList(domain, &cmn.no_keyber)) {
        opt.named_groups = &[_]tls.config.NamedGroup{ .x25519, .secp256r1 };
    }
    const only_fail = false;
    cmn.get(io, domain, null, false, false, opt) catch |err| {
        switch (err) {
            error.UnknownHostName,
            error.ConnectionTimedOut,
            error.ConnectionRefused,
            error.NetworkUnreachable,
            error.NameServerFailure,
            => {
                counter.add(.err);
                if (!only_fail) {
                    std.debug.print("➖ {s:<25} {}\n", .{ domain, err });
                }
                return;
            },
            // canceled errors
            error.Canceled,
            error.ReadFailed,
            error.WriteFailed,
            => {
                counter.add(.skip);
                if (!only_fail) {
                    std.debug.print("➰ {s:<25} {s}\n", .{ domain, @errorName(err) });
                }
                if (err == error.Canceled) return error.Canceled;
                return;
            },
            else => {
                curl(gpa, io, domain) catch |curl_err| {
                    if (!only_fail) {
                        std.debug.print("➖ {s:<25} {} curl: {}\n", .{ domain, err, curl_err });
                    }
                    counter.add(.err);
                    return;
                };
            },
        }
        std.debug.print("❌ {s:<25} ERROR {}\n", .{ domain, err });
        counter.add(.fail);
        return;
    };
    counter.addSuccess(diagnostic.tls_version);
    counter.max_server_record_len = @max(counter.max_server_record_len, diagnostic.max_server_record_len);
    counter.max_server_cleartext_len = @max(counter.max_server_cleartext_len, diagnostic.max_server_cleartext_len);
    counter.max_client_record_len = @max(counter.max_client_record_len, diagnostic.max_client_record_len);
    if (!only_fail) {
        std.debug.print("✔️ {s:<25} {s} {s:<40} {s:<20} {s:<25} {d:>5} {d:>5} {d:>5}\n", .{
            domain,
            if (@intFromEnum(diagnostic.tls_version) == 0) "none" else @tagName(diagnostic.tls_version),
            if (@intFromEnum(diagnostic.cipher_suite_tag) == 0) "none" else @tagName(diagnostic.cipher_suite_tag),
            if (@intFromEnum(diagnostic.named_group) == 0) "none" else @tagName(diagnostic.named_group),
            if (@intFromEnum(diagnostic.signature_scheme) == 0) "none" else @tagName(diagnostic.signature_scheme),
            diagnostic.max_client_record_len,
            diagnostic.max_server_record_len,
            diagnostic.max_server_cleartext_len,
        });
    }
}

pub fn curl(allocator: std.mem.Allocator, io: std.Io, domain: []const u8) !void {
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});

    const result = try std.process.run(allocator, io, .{
        .argv = &[_][]const u8{ "curl", "-m10", "-sS", "-w %{errormsg}", url },
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    // ref: https://everything.curl.dev/cmdline/exitcode.html
    switch (result.term) {
        .exited => |error_code| switch (error_code) {
            0 => return,
            // curl command is not wroking
            2 => unreachable, //return error.FailedToInitialize,
            3 => return error.UrlMalformed,
            6 => return error.CouldntResolveHost,
            7 => return error.FailedToConnectToHost,
            18, 28 => return error.OperationTimeout,
            35 => return error.SslHandshake,
            60 => return error.Certificate,
            92 => return error.Http2Framing,
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
