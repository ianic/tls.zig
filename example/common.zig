const std = @import("std");
const tls = @import("tls");
const Certificate = std.crypto.Certificate;

pub fn showDiagnostic(stats: *tls.config.Client.Diagnostic, domain: []const u8) void {
    std.debug.print(
        "\n{s}\n\t tls version: {s}\n\t cipher: {s}\n\t named group: {s}\n\t signature scheme: {s}\n\t session resumption: {}\n",
        .{
            domain,
            if (@intFromEnum(stats.tls_version) == 0) "none" else @tagName(stats.tls_version),
            if (@intFromEnum(stats.cipher_suite_tag) == 0) "none" else @tagName(stats.cipher_suite_tag),
            if (@intFromEnum(stats.named_group) == 0) "none" else @tagName(stats.named_group),
            if (@intFromEnum(stats.signature_scheme) == 0) "none" else @tagName(stats.signature_scheme),
            stats.is_session_resumption,
        },
    );
    if (@intFromEnum(stats.client_signature_scheme) != 0) {
        std.debug.print("\t client signature scheme: {s}\n", .{@tagName(stats.client_signature_scheme)});
    }
}

pub const CsvReader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) CsvReader {
        var pos: usize = std.mem.indexOfAnyPos(u8, data, 0, "\n") orelse 0;
        if (pos > 0) pos += 1;
        return .{
            .data = data,
            .pos = pos,
        };
    }

    pub fn next(self: *@This()) ?[]const u8 {
        if (std.mem.indexOfAnyPos(u8, self.data, self.pos, "\n")) |end| {
            defer self.pos = end + 1;
            const line = self.data[self.pos..end];
            if (std.mem.indexOf(u8, line, ",")) |sep1| {
                if (std.mem.indexOfPos(u8, line, sep1 + 1, ",")) |sep2| {
                    if (line[sep1 + 1] == '"') {
                        return line[sep1 + 2 .. sep2 - 1];
                    }
                    return line[sep1 + 1 .. sep2];
                }
            }
            return line;
        }
        return null;
    }
};

test "read file" {
    var r = CsvReader.init(@embedFile("ranked_domains.csv"));
    var i: usize = 1;
    while (r.next()) |_| {
        //std.debug.print("'{s}' {}\n", .{ d, i });
        i += 1;
    }
}

pub const Site = struct {
    rank: usize,
    rootDomain: []const u8,
    linkingRootDomains: usize,
    domainAuthority: usize,
};

pub fn skipDomain(domain: []const u8) bool {
    for (domainsToSkip) |d| {
        if (std.mem.eql(u8, d, domain)) return true;
    }
    return false;
}

pub const domainsToSkip = [_][]const u8{
    "dw.com", // timeout after long time, fine on www.dw.com
    "alicdn.com", //           error.ConnectionTimedOut
    "usnews.com",
    "canada.ca", //            SSL certificate problem: unable to get local issuer certificate
    "nhk.or.jp", //            error error.UnknownHostName curl error: error.CouldntResolveHost
    "army.mil", //             error error.UnknownHostName curl error: error.CouldntResolveHost
    "my-free.website", //      error error.UnknownHostName curl error: error.CouldntResolveHost
    "com.be", //               error error.UnknownHostName curl error: error.CouldntResolveHost
    "ouest-france.fr", //      error error.ConnectionRefused curl error: error.FailedToConnectToHost
    "gouv.qc.ca", //           error error.ConnectionTimedOut curl error: error.OperationTimeout
    "jalan.net", //            error error.ConnectionTimedOut curl error: error.OperationTimeout
    "kroger.com",
    "signalfx.com", // has expired 1.2 certificate, sometime sends 1.3 sometime 1.2, strange
    // should disable keyber
    "godaddy.com",
    "secureserver.net",
    "addthis.com", //               error.ConnectionTimedOut
    "misaq.me", //                  error.ConnectionTimedOut
    "myoppo.com", //                error.ConnectionTimedOut
    "partners-show.com", //         error.ConnectionTimedOut
    "pod.ir", //                    error.ConnectionTimedOut
    "revopush.com", //              error.ConnectionTimedOut
    "tagcommander.com", //          error.ConnectionTimedOut
    "lastline.come", //
    "list-manage.com", //           error.ConnectionTimedOut
};

pub const domainsWithErrors = [_][]const u8{
    // certificate subject name no match
    "list-manage.com",
    // certificate expired or unable to get issuer
    "windows.net",
    "youronlinechoices.com",
    "canada.ca",
    // should disable keyber
    "godaddy.com",
    "secureserver.net",
};

pub fn inList(domain: []const u8, list: []const []const u8) bool {
    for (list) |d| {
        if (std.mem.eql(u8, d, domain)) return true;
    }
    return false;
}

pub const no_keyber = [_][]const u8{
    "secureserver.net",
    "godaddy.com",
    "starfieldtech.com",
    "sedoparking.com",
    "wshareit.com",
    "ushareit.com",
    "platinumai.net",
};

pub const Counter = struct {
    const Result = enum {
        success,
        fail,
        skip,
        err,
    };

    mu: std.Thread.Mutex = .{},

    success: usize = 0,
    fail: usize = 0,
    skip: usize = 0,
    err: usize = 0,
    max_server_record_len: usize = 0,
    max_server_cleartext_len: usize = 0,
    max_client_record_len: usize = 0,

    tls_1_2: usize = 0,
    tls_1_3: usize = 0,

    pub fn add(self: *@This(), res: Result) void {
        self.mu.lock();
        defer self.mu.unlock();

        switch (res) {
            .success => self.success += 1,
            .fail => self.fail += 1,
            .skip => self.skip += 1,
            .err => self.err += 1,
        }
    }

    pub fn addSuccess(self: *@This(), version: tls.config.Version) void {
        self.mu.lock();
        defer self.mu.unlock();

        self.success += 1;
        switch (version) {
            .tls_1_2 => self.tls_1_2 += 1,
            .tls_1_3 => self.tls_1_3 += 1,
            else => unreachable,
        }
    }

    pub fn total(self: @This()) usize {
        return self.success + self.fail + self.skip + self.err;
    }

    pub fn show(self: @This()) void {
        std.debug.print(
            "stats:\n\t total: {}\n\t success: {}\n\t\t tls 1.2: {}\n\t\t tls 1.3: {}\n\t fail: {}\n\t error: {}\n\t skip: {}\n\n",
            .{ self.total(), self.success, self.tls_1_2, self.tls_1_3, self.fail, self.err, self.skip },
        );
        std.debug.print("\t max client record:    {d:>5}\n", .{self.max_client_record_len});
        std.debug.print("\t max server record:    {d:>5}\n", .{self.max_server_record_len});
        std.debug.print("\t max server cleartext: {d:>5}\n", .{self.max_server_cleartext_len});
    }

    pub fn failRate(self: @This()) f64 {
        const all = self.success + self.fail;
        return @as(f64, @floatFromInt(all - self.success)) / @as(f64, @floatFromInt(all));
    }
};

test "failRate" {
    var c: Counter = .{ .success = 6234, .fail = 1, .err = 14 };
    try std.testing.expect(c.failRate() < 0.005);
    std.debug.print("rate: {}\n", .{c.failRate() * 1000});
}

pub fn get(
    allocator: std.mem.Allocator,
    domain: []const u8,
    port: ?u16,
    show_handshake_stat: bool,
    show_response: bool,
    opt_: tls.config.Client,
) !void {
    var opt = opt_;

    // Add https:// prefix if needed
    const url = brk: {
        const scheme = "https://";
        if (domain.len >= scheme.len and std.mem.eql(u8, domain[0..scheme.len], scheme))
            break :brk domain;

        var url_buf: [128]u8 = undefined;
        break :brk try std.fmt.bufPrint(&url_buf, "https://{s}", .{domain});
    };
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;

    // Establish tcp connection
    var tcp: std.net.Stream = undefined;
    var tnsf: usize = 16;
    while (true) {
        tcp = std.net.tcpConnectToHost(allocator, host, if (port) |p| p else 443) catch |err| switch (err) {
            error.TemporaryNameServerFailure => {
                tnsf -= 1;
                if (tnsf == 0) return err;
                continue;
            },
            else => return err,
        };
        break;
    }
    defer tcp.close();
    // Set socket timeout
    const read_timeout: std.posix.timeval = .{ .sec = 10, .usec = 0 };
    try std.posix.setsockopt(tcp.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.toBytes(read_timeout)[0..]);
    try std.posix.setsockopt(tcp.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.toBytes(read_timeout)[0..]);

    // Prepare and show handshake stats
    if (show_handshake_stat and opt.diagnostic == null) {
        var diagnostic: tls.config.Client.Diagnostic = .{};
        opt.diagnostic = &diagnostic;
    }
    defer if (show_handshake_stat) showDiagnostic(opt.diagnostic.?, domain);

    // Upgrade tcp connection to tls
    opt.host = host;
    var cli = try tls.client(tcp, opt);

    // Send http GET request
    var buf: [64]u8 = undefined;
    const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.1\r\nHost: {s}\r\n\r\n", .{host});
    try cli.writeAll(req);

    // Read and print http response
    var n: usize = 0;
    defer if (show_response) std.debug.print("{} bytes read\n", .{n});
    while (cli.next() catch |err| switch (err) {
        error.WouldBlock, error.ConnectionResetByPeer => null,
        error.ReadFailed => null,
        else => return err,
    }) |data| {
        n += data.len;
        if (show_response) std.debug.print("{s}", .{data});

        if (std.ascii.endsWithIgnoreCase(
            std.mem.trimRight(u8, data, "\r\n"),
            "</html>",
        )) break;
    }

    cli.close() catch |err| switch (err) {
        error.BrokenPipe => return,
        error.WriteFailed => return,
        else => return err,
    };
}

fn hasPrefix(str: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix|
        if (str.len >= prefix.len and std.mem.eql(u8, str[0..prefix.len], prefix))
            return true;

    return false;
}

pub const tls12domains = [_][]const u8{
    "change.org",
    "linkedin.com",
    "uol.com.br",
    "esa.int",
    "fastcompany.com",
    "unicef.org",
    "deloitte.com",
    "cisco.com",
    "admin.ch",
    "usda.gov",
    "blackberry.com",
    "excite.co.jp",
    "dictionary.com",
    "leparisien.fr",
    "interia.pl",
    "etsy.com",
    "tes.com",
    "oecd.org",
    "umich.edu",
    "news.com.au",
    "goo.ne.jp",
    "newscientist.com",
    "si.edu",
    "alibaba.com",
    "psu.edu",
    "sciencemag.org",
    "mysql.com",
    "warnerbros.com",
    "zdf.de",
    "jhu.edu",
    "imageshack.com",
    "lg.com",
    "sueddeutsche.de",
    "justice.gov",
    "ted.com",
    "pbs.org",
    "vice.com",
    "playstation.com",
    "seesaa.net",
    "zippyshare.com",
    "sapo.pt",
    "kakao.com",
    "cointernet.com.co",
    "www.privacyshield.gov",
    "harvard.edu",
    "outlook.com",
    "instructables.com",
    "linktr.ee",
    "nbcnews.com",
    "alexa.com",
    "sakura.ne.jp",
    "cornell.edu",
    "latimes.com",
    "prezi.com",
    "cambridge.org",
    "huawei.com",
    "oracle.com",
    "theatlantic.com",
    "qq.com",
    "insider.com",
    "unsplash.com",
    "detik.com",
    "samsung.com",
    "britannica.com",
    "quora.com",
    "liveinternet.ru",
    "thetimes.co.uk",
    "weibo.com",
    "oup.com",
    "hp.com",
    "unesco.org",
    "newyorker.com",
    "calameo.com",
    "gizmodo.com",
    "psychologytoday.com",
    "trustpilot.com",
    "stanford.edu",
    "wired.com",
    "mit.edu",
    "ca.gov",
    "php.net",
    "imageshack.us",
    "reuters.com",
    "nginx.org",
    "cbsnews.com",
    "hatena.ne.jp",
    "mirror.co.uk",
    "un.org",
    "forbes.com",
    "namecheap.com",
    "cdc.gov",
    "mediafire.com",
    "webmd.com",
    "correios.com.br",
    "businessinsider.com",
    "independent.co.uk",
    "4shared.com",
    "planalto.gov.br",
    "wiley.com",
    "nytimes.com",
    "aliexpress.com",
    "mail.ru",
    "nih.gov",
    "jimdofree.com",
};

pub const tls13stdFails = [_][]const u8{
    // fragmented message
    "whatsapp.com",
    "wa.me",
    "facebook.com",
    "instagram.com",
    "m.me",
    "fb.com",
    "fb.me",

    // certificate not part of the chain
    "www.wix.com",
    "terra.com.br",

    // certificate longer than handshake buffer
    "googleblog.com",
    "feedburner.com",
    "g.page",
    "googleusercontent.com",
    "marriott.com",

    // other
    "dailymotion.com", // rsa_pkcs1_sha384 required in client hello signature algorithms extension
    "home.pl", // secp384r1 named group required in client hello supported groups extension

    // certificate problems
    "windows.net", // certificate host mismatch
    "list-manage.com", // certificate host mismatch
    "youronlinechoices.com", // certificate issuer not found

    // keyber, no response on client hello then timeout
    "godaddy.com",
    "secureserver.net",
};
