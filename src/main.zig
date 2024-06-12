const std = @import("std");
const tls = @import("client.zig");
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    const arena = arena_instance.allocator();

    const args = try std.process.argsAlloc(arena);

    if (args.len > 1) {
        const domain = args[1];

        var ca_bundle = try initCaBundle(gpa);
        defer ca_bundle.deinit(gpa);

        if (std.mem.eql(u8, "top", domain)) {
            try getTopSites(gpa, ca_bundle);
        } else {
            try get(gpa, domain, null, ca_bundle, true, true, .{
                //.stats = &stats,
                //.cipher_suites = &[_]tls.CipherSuite{.AEGIS_128L_SHA256},
                //.cipher_suites = &tls.CipherSuite.tls12,
            });
        }
    }
}

fn initCaBundle(gpa: std.mem.Allocator) !Certificate.Bundle {
    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(gpa);
    return ca_bundle;
}

fn hasPrefix(str: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix|
        if (str.len >= prefix.len and std.mem.eql(u8, str[0..prefix.len], prefix))
            return true;

    return false;
}

pub fn get(
    gpa: std.mem.Allocator,
    domain: []const u8,
    port: ?u16,
    ca_bundle: Certificate.Bundle,
    show_handshake_stat: bool,
    show_response: bool,
    opt_: tls.Options,
) !void {
    var opt = opt_;

    const url = brk: {
        if (hasPrefix(domain, &[_][]const u8{ "https://", "wss://" }))
            break :brk domain;

        var url_buf: [128]u8 = undefined;
        break :brk try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});
    };

    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, if (port) |p| p else 443);
    defer tcp.close();

    const read_timeout: std.posix.timeval = .{ .tv_sec = 10, .tv_usec = 0 };
    try std.posix.setsockopt(tcp.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.toBytes(read_timeout)[0..]);

    if (show_handshake_stat) {
        if (opt.stats == null) {
            var stats: tls.Stats = .{};
            opt.stats = &stats;
        }
    }
    defer if (show_handshake_stat) {
        const stats = opt.stats.?;
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
    };

    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle, opt);

    var buf: [64]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try cli.write(req);

    var n: usize = 0;
    defer if (show_response) std.debug.print("{} bytes read\n", .{n});
    while (try cli.next()) |data| {
        n += data.len;
        if (show_response)
            std.debug.print("{s}", .{data});
        if (std.mem.endsWith(u8, data, "</html>\n")) break;
    }
    try cli.close();
}

pub fn getTop(gpa: std.mem.Allocator, domain: []const u8, ca_bundle: Certificate.Bundle) void {
    var stats: tls.Stats = .{};
    var opt: tls.Options = .{ .stats = &stats };

    if (inList(domain, &noKeyber)) {
        opt.disable_keyber = true;
    }
    get(gpa, domain, null, ca_bundle, false, false, opt) catch |err| {
        curl(gpa, domain) catch |curl_err| {
            std.debug.print("➖ {s} error {} curl error: {}\n", .{ domain, err, curl_err });
            return;
        };
        std.debug.print("❌ {s} ERROR {}\n", .{ domain, err });
        return;
    };
    std.debug.print("✔️ {s} {s} {s} {s} {s}\n", .{
        domain,
        if (@intFromEnum(stats.tls_version) == 0) "none" else @tagName(stats.tls_version),
        if (@intFromEnum(stats.cipher_suite_tag) == 0) "none" else @tagName(stats.cipher_suite_tag),
        if (@intFromEnum(stats.named_group) == 0) "none" else @tagName(stats.named_group),
        if (@intFromEnum(stats.signature_scheme) == 0) "none" else @tagName(stats.signature_scheme),
    });
}

pub fn getTopSites(gpa: std.mem.Allocator, ca_bundle: Certificate.Bundle) !void {
    const top_sites_parsed = try readTopSites(gpa);
    defer top_sites_parsed.deinit();
    const top_sites = top_sites_parsed.value;

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = gpa, .n_jobs = 32 });
    defer pool.deinit();

    for (top_sites) |site| {
        const domain = site.rootDomain;
        if (skipDomain(domain)) continue;
        try pool.spawn(getTop, .{ gpa, domain, ca_bundle });
    }
}

fn readTopSites(gpa: std.mem.Allocator) !std.json.Parsed([]Site) {
    const data = @embedFile("testdata/top-sites.json");
    return std.json.parseFromSlice([]Site, gpa, data, .{ .allocate = .alloc_always });
}

const Site = struct {
    rank: usize,
    rootDomain: []const u8,
    linkingRootDomains: usize,
    domainAuthority: usize,
};

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

fn skipDomain(domain: []const u8) bool {
    for (domainsToSkip) |d| {
        if (std.mem.eql(u8, d, domain)) return true;
    }
    return false;
}

const domainsToSkip = [_][]const u8{
    "dw.com", // timeout after long time, fine on www.dw.com
    "alicdn.com",
    "usnews.com",
};

fn inList(domain: []const u8, list: []const []const u8) bool {
    for (list) |d| {
        if (std.mem.eql(u8, d, domain)) return true;
    }
    return false;
}

const noKeyber = [_][]const u8{
    "secureserver.net",
    "godaddy.com",
};

const testing = std.testing;

test "find domain for cipher" {
    if (true)
        return error.SkipZigTest;

    const gpa = testing.allocator;
    var ca_bundle = try initCaBundle(gpa);
    defer ca_bundle.deinit(gpa);

    const top_sites_parsed = try readTopSites(gpa);
    defer top_sites_parsed.deinit();
    const top_sites = top_sites_parsed.value;

    for (tls.CipherSuite.all) |cs| loop: {
        for (top_sites) |ts| {
            const domain = ts.rootDomain;
            get(gpa, domain, null, ca_bundle, false, false, .{
                .cipher_suites = &[_]tls.CipherSuite{cs},
            }) catch {
                continue;
            };
            std.debug.print("✔️ {s} {s}\n", .{ @tagName(cs), domain });
            break :loop;
        }

        std.debug.print("❌ {s}\n", .{@tagName(cs)});
    }
}

test "one domain all ciphers" {
    const gpa = testing.allocator;
    var ca_bundle = try initCaBundle(gpa);
    defer ca_bundle.deinit(gpa);

    const domain = "cloudflare.com";

    for (tls.CipherSuite.all) |cs| {
        get(gpa, domain, null, ca_bundle, false, false, .{
            .cipher_suites = &[_]tls.CipherSuite{cs},
        }) catch |err| {
            std.debug.print("❌ {s} {s} {}\n", .{ @tagName(cs), domain, err });
            continue;
        };
        std.debug.print("✔️ {s} {s}\n", .{ @tagName(cs), domain });
    }
}

test "extented validation failing" {
    // curl and chorome are also failing on this one
    if (true)
        return error.SkipZigTest;

    const gpa = testing.allocator;
    var ca_bundle = try initCaBundle(gpa);
    defer ca_bundle.deinit(gpa);

    const domain = "extended-validation.badssl.com";
    try get(gpa, domain, null, ca_bundle, false, false, .{});
}

test "badssl" {
    const gpa = testing.allocator;
    var ca_bundle = try initCaBundle(gpa);
    defer ca_bundle.deinit(gpa);

    const badssl_parsed = try readBadssl(gpa);
    defer badssl_parsed.deinit();
    const sets = badssl_parsed.value;

    for (sets) |set| {
        std.debug.print("\n{s}\n{s}\n", .{ set.heading, set.description });
        const fail = YesNo.parse(set.fail);
        const success = YesNo.parse(set.success);
        for (set.subdomains) |sd| {
            //std.debug.print("subdomain: {s}\n", .{sd.subdomain});

            var domain_buf: [128]u8 = undefined;
            const domain = try std.fmt.bufPrint(&domain_buf, "{s}.badssl.com", .{sd.subdomain});

            get(gpa, domain, if (sd.port == 0) null else sd.port, ca_bundle, false, false, .{}) catch |err| {
                std.debug.print(
                    "\t{s} {s} {}\n",
                    .{ fail.emoji(), domain, err },
                );
                //if (!std.mem.eql(u8, sd.subdomain, "extended-validation"))
                try testing.expect(fail != .no);
                continue;
            };
            std.debug.print("\t{s} {s}\n", .{ success.emoji(), domain });
            try testing.expect(success != .no);
        }
    }
}

const YesNo = enum {
    yes,
    no,
    maybe,

    fn emoji(self: YesNo) []const u8 {
        return switch (self) {
            .yes => "✅",
            .no => "❌",
            .maybe => "🆗",
        };
    }

    fn parse(value: []const u8) YesNo {
        if (std.mem.eql(u8, value, "yes")) return .yes;
        if (std.mem.eql(u8, value, "no")) return .no;
        return .maybe;
    }
};

fn readBadssl(gpa: std.mem.Allocator) !std.json.Parsed([]BadsslSet) {
    const data = @embedFile("testdata/badssl.json");
    return std.json.parseFromSlice([]BadsslSet, gpa, data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
}

const BadsslSet = struct {
    heading: []const u8,
    description: []const u8,
    success: []const u8,
    fail: []const u8,
    subdomains: []struct {
        subdomain: []const u8,
        port: u16 = 0,
    },
};

test "localhost tls_server" {
    if (true) return error.SkipZigTest;
    // Start server from tls_server folder:
    // $ cd tls_server && ./run.sh
    // It will generate certificate and start Go server.
    // After connecting server will stream a large text file.
    const gpa = testing.allocator;
    var ca_bundle = try initCaBundle(gpa);
    defer ca_bundle.deinit(gpa);
    // Add server certificate to the bundle.
    const dir = std.fs.cwd().openDir("../tls_server", .{ .iterate = true }) catch brk: {
        break :brk try std.fs.cwd().openDir("tls_server", .{ .iterate = true });
    };
    try ca_bundle.addCertsFromDir(gpa, dir);

    const domain = "localhost";
    const port = 8443;

    try get(gpa, domain, port, ca_bundle, true, true, .{});
}
