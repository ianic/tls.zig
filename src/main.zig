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

pub fn get2(gpa: std.mem.Allocator, url: []const u8) !usize {
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    var tcp = try std.net.tcpConnectToHost(gpa, host, 443);
    defer tcp.close();

    var cli = tls.client(tcp);
    try cli.handshake(host, null);

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

    const top_sites_parsed = try readSites(gpa);
    defer top_sites_parsed.deinit();
    const top_sites = top_sites_parsed.value;
    var stat = struct {
        skipped: usize = 0,
        ok: usize = 0,
        fail: usize = 0,
    }{};

    for (top_sites) |site| {
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
        const size = get2(gpa, url) catch |err| {
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
