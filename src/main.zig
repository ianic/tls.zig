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
    var ca_bundle: Certificate.Bundle = .{};
    try ca_bundle.rescan(gpa);
    defer ca_bundle.deinit(gpa);
    try get2(gpa, domain, ca_bundle, true);
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

    var threads: [16]std.Thread = undefined;
    var i: usize = 0;
    for (top_sites) |site| {
        if (filtered(site.rank)) {
            // to check with the curl why it is skipped:
            // std.debug.print(
            //     "{d}, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w \"%{{url}} %{{http_code}} %{{errormsg}}\\n\" https://{s}\n",
            //     .{ site.rank, site.rootDomain },
            // );
            continue;
        }

        threads[i] = try std.Thread.spawn(.{}, get3, .{ gpa, site.rootDomain, ca_bundle });
        if (i == threads.len - 1) {
            for (threads) |t| t.join();
            i = 0;
        } else {
            i += 1;
        }
    }
    if (i > 0) {
        while (true) {
            i -= 1;
            threads[i].join();
            if (i == 0) break;
        }
    }
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
    const include = skipped;
    for (include) |i| {
        if (i == site_rank) return false;
    }
    return true;
}
const skipped = [_]usize{
    112, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://planalto.gov.br
    135, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://ytimg.com
    194, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://usnews.com
    231, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://clickbank.net
    244, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://ssl-images-amazon.com
    258, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://doubleclick.net
    276, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://addthis.com
    293, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://alicdn.com
    298, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://example.com
    301, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://akamaihd.net
    307, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://rapidshare.com
    387, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://ggpht.com
    465, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://sedoparking.com
    487, // curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://twimg.com
};

// skipped reasons:
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://planalto.gov.br
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://ytimg.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://usnews.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://clickbank.net
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://ssl-images-amazon.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://doubleclick.net
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://addthis.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://alicdn.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://example.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://akamaihd.net
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://rapidshare.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://ggpht.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://sedoparking.com
// curl -m 10 --tlsv1.2 --tls-max 1.2 -s -o /dev/null -w "%{url} %{http_code} %{errormsg}\n" https://twimg.com
//
// https://planalto.gov.br 000 Operation timed out after 10000 milliseconds with 0 bytes received
// https://ytimg.com 000 Could not resolve host: ytimg.com
// https://usnews.com 000 Operation timed out after 10001 milliseconds with 0 bytes received
// https://clickbank.net 000 Failed to connect to clickbank.net port 443 after 2 ms: Couldn't connect to server
// https://ssl-images-amazon.com 000 Could not resolve host: ssl-images-amazon.com
// https://doubleclick.net 000 Failed to connect to doubleclick.net port 443 after 2 ms: Couldn't connect to server
// https://addthis.com 000 Failed to connect to addthis.com port 443 after 1 ms: Couldn't connect to server
// https://alicdn.com 000 Connection timed out after 10002 milliseconds
// https://example.com 000 Could not resolve host: example.com
// https://akamaihd.net 000 Could not resolve host: akamaihd.net
// https://rapidshare.com 000 Could not resolve host: rapidshare.com
// https://ggpht.com 000 Could not resolve host: ggpht.com
// https://sedoparking.com 000 Failed to connect to sedoparking.com port 443 after 1 ms: Couldn't connect to server
// https://twimg.com 000 Could not resolve host: twimg.com
