const std = @import("std");
const tls = @import("client.zig");
const Certificate = std.crypto.Certificate;

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    const arena = arena_instance.allocator();

    const args = try std.process.argsAlloc(arena);
    if (args.len > 1) {
        const url = args[1];

        if (std.mem.eql(u8, "top", url)) return try getTopSites();

        _ = try get(gpa, url);
        return;
    }
}

pub fn get(gpa: std.mem.Allocator, domain: []const u8) !void {
    // var url_buf: [128]u8 = undefined;
    // const url = try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});

    // const uri = try std.Uri.parse(url);
    // const host = uri.host.?.percent_encoded;

    // var tcp = try std.net.tcpConnectToHost(gpa, host, 443);
    // defer tcp.close();

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(gpa);
    defer ca_bundle.deinit(gpa);

    try get2(gpa, domain, ca_bundle, true);

    // var cli = tls.client(tcp);
    // try cli.handshake(host, ca_bundle);

    // var buf: [128]u8 = undefined;
    // const req = try std.fmt.bufPrint(buf[16..], "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    // try cli.write(&buf, req);

    // while (try cli.next()) |data| {
    //     std.debug.print("{s}", .{data});
    //     if (std.mem.endsWith(u8, data, "</html>\n")) break;
    // }
    // try cli.close();
}

pub fn get2(
    gpa: std.mem.Allocator,
    domain: []const u8,
    ca_bundle: Certificate.Bundle,
    show_response: bool,
) !void {
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});

    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, 443);
    defer tcp.close();

    const read_timeout: std.posix.timeval = .{ .tv_sec = 5, .tv_usec = 0 };
    try std.posix.setsockopt(tcp.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.toBytes(read_timeout)[0..]);

    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle);

    var buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(buf[16..], "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try cli.write(&buf, req);

    var n: usize = 0;
    while (try cli.next()) |data| {
        n += data.len;
        if (show_response)
            std.debug.print("{s}", .{data});
        if (std.mem.endsWith(u8, data, "</html>\n")) break;
    }
    try cli.close();

    //std.debug.print("OK {} bytes\n", .{n});
}

pub fn get3(gpa: std.mem.Allocator, domain: []const u8, ca_bundle: Certificate.Bundle) void {
    while (true) {
        get2(gpa, domain, ca_bundle, false) catch |err| switch (err) {
            error.TemporaryNameServerFailure => {
                continue;
            },
            else => {
                std.debug.print("{s} ERROR {} \n", .{ domain, err });
                break;
            },
        };
        break;
    }
}

pub fn getTopSites() !void {
    const gpa = std.heap.page_allocator;

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(gpa);
    defer ca_bundle.deinit(gpa);

    const top_sites_parsed = try readSites(gpa);
    defer top_sites_parsed.deinit();
    const top_sites = top_sites_parsed.value;
    var stat = struct {
        skipped: usize = 0,
        ok: usize = 0,
        fail: usize = 0,
    }{};

    var threads: [16]std.Thread = undefined;
    var i: usize = 0;
    for (top_sites) |site| {
        //if (filtered(site.rank)) continue;

        // std.debug.print("{d}: {s} ", .{ site.rank, site.rootDomain });
        if (site.rank == 135 or
            site.rank == 244 or
            site.rank == 298 or
            site.rank == 301 or
            site.rank == 307 or
            site.rank == 387 or
            site.rank == 487 or
            site.rank == 112 or
            site.rank == 231 or
            site.rank == 258 or
            site.rank == 276 or
            site.rank == 465 or

            // not responding
            site.rank == 194 or
            site.rank == 293)
        {
            stat.skipped += 1;
            // std.debug.print("SKIP\n", .{});
            continue;
        }

        threads[i] = try std.Thread.spawn(.{}, get3, .{ gpa, site.rootDomain, ca_bundle });
        if (i == threads.len - 1) {
            for (threads) |t| t.join();
            i = 0;
        } else {
            i += 1;
        }

        // get2(gpa, site.rootDomain, ca_bundle) catch |err| {
        //     std.debug.print("ERROR {} \n", .{err});
        //     stat.fail += 1;
        //     continue;
        // };

        stat.ok += 1;
    }
    if (i > 0) {
        while (true) {
            i -= 1;
            threads[i].join();
            if (i == 0) break;
        }
    }

    std.debug.print("{}\n", .{stat});
}

fn readSites(gpa: std.mem.Allocator) !std.json.Parsed([]Site) {
    const data = try std.fs.cwd().readFileAlloc(gpa, "tmp/top-sites.json", 64 * 1024);
    defer gpa.free(data);
    return std.json.parseFromSlice([]Site, gpa, data, .{ .allocate = .alloc_always });
}

const TopSites = struct {
    sites: []Site,
};

const Site = struct {
    rank: usize,
    rootDomain: []const u8,
    linkingRootDomains: usize,
    domainAuthority: usize,
};

// Using curl to test different ciphers:
// Cipher code for curl can be found at:
// https://github.com/curl/curl/blob/cf337d851ae0120ec5ed801ad7eb128561bd8cf6/lib/vtls/sectransp.c#L729
//
// Example of
// not supported:
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-SHA https://github.com
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-SHA https://www.supersport.hr
// supported:
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://www.supersport.hr
// curl --tlsv1.2 --tls-max 1.2 -vv --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://github.com
//

pub fn filtered(site_rank: usize) bool {
    const include = pcks1;
    for (include) |i| {
        if (i == site_rank) return false;
    }
    return true;
}

const missing_pkdc1 = [_]usize{
    178,
    199,
    253,
    264,
    297,
    342,
    349,
    364,
    381,
    388,
    401,
    402,
    411,
    412,
    422,
    432,
    438,
    456,
    464,
    484,
};

const alert_illegal_parameter = [_]usize{
    //    85,
    92,
    101,
    110,
    //    202,
    267,
    272,
    365,
    383,
    419,
    468,
    488,
};

const handshake_failure = [_]usize{
    // 35,
    // 48,
    // 55,
    // 96,
    // 107,
    108,
    // 166,
    // 192,
    // 229,
    // 262,
    //280,
    // 282,
    // 300,
    // 310,
    // 317,
    341,
    // 382,
    // 393,
    397,
    416,
    // 453,
    // 462,
    // 470,
    // 493,
};

const pcks1 = [_]usize{
    23,
    29,
    53,
    // 92,
    // 101,
    // 110,
    // 111,
    112,
    // 114,
    // 130,
    // 141,
    // 158,
    // 178,
    // 181,
    // 199,
    207,
    // 211,
    // 222,
    // 246,
    // 253,
    // 261,
    // 264,
    266,
    // 267,
    // 272,
    // 277,
    // 287,
    // 297,
    // 312,
    // 319,
    // 342,
    // 349,
    // 356,
    // 364,
    // 365,
    // 381,
    // 383,
    // 388,
    // 395,
    // 401,
    // 402,
    // 405,
    407,
    // 411,
    // 412,
    // 419,
    // 422,
    // 423,
    428,
    //    432,
    433,
    // 438,
    // 448,
    // 456,
    // 461,
    // 464,
    469,
    //    472,
    476,
    // 478,
    // 480,
    // 484,
    // 485,
    // 488,
    // 495,
    // 500,
};
