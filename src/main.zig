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

pub fn get(gpa: std.mem.Allocator, url: []const u8) !void {
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, 443);
    defer tcp.close();

    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(gpa);
    defer ca_bundle.deinit(gpa);

    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle);

    var buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(buf[16..], "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try cli.write(&buf, req);

    while (try cli.next()) |data| {
        std.debug.print("{s}", .{data});
    }
    try cli.close();

    // while (true) {
    //     const n = try cli.read(&buf);
    //     std.debug.print("{s}", .{buf[0..n]});
    //     if (n == 0) break;
    // }
    // var file = try std.fs.cwd().createFile("server_hello", .{});
    // defer file.close();
    // var buf: [4096]u8 = undefined;
    // while (true) {
    //     const n = try tcp.readAll(&buf);
    //     //std.debug.print("{x}\n", .{buf});
    //     try file.writer().writeAll(buf[0..n]);
    //     if (n < buf.len) break;
    // }
}

pub fn get2(gpa: std.mem.Allocator, url: []const u8, ca_bundle: Certificate.Bundle) !usize {
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, 443);
    defer tcp.close();

    var cli = tls.client(tcp);
    try cli.handshake(host, ca_bundle);

    var buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(buf[16..], "GET / HTTP/1.0\r\nHost: {s}\r\n\r\n", .{host});
    try cli.write(&buf, req);

    var n: usize = 0;
    while (try cli.next()) |data| {
        n += data.len;
    }
    try cli.close();
    return n;
}

pub fn main__() !void {
    const gpa = std.heap.page_allocator;
    //var arena_instance = std.heap.ArenaAllocator.init(gpa);
    //const arena = arena_instance.allocator();

    const url = "https://localhost";
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, 8443);
    defer tcp.close();

    //try tcp.writeAll(&client_hello);

    var cli = tls(tcp);
    try cli.handshake("example.ulfheim.net");
    std.debug.print("handshake finished\n", .{});
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

    for (top_sites) |site| {
        if (filtered(site.rank)) continue;

        std.debug.print("{d}: {s} ", .{ site.rank, site.rootDomain });
        if (site.rank == 194 or
            site.rank == 195 or
            site.rank == 293)
        {
            stat.skipped += 1;
            std.debug.print("SKIP\n", .{});
            continue;
        }

        var buf: [128]u8 = undefined;
        const url = try std.fmt.bufPrint(&buf, "https://{s}", .{site.rootDomain});
        const size = get2(gpa, url, ca_bundle) catch |err| {
            std.debug.print("ERROR {} \n", .{err});
            stat.fail += 1;
            continue;
        };
        std.debug.print("OK {} bytes\n", .{size});
        stat.ok += 1;
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
